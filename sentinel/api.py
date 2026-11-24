"""FastAPI app: JSON API for the SOC console plus the static SPA in ``web/``.

Every JSON body that leaves the process is passed through :func:`mask_obj`
(via :class:`MaskedJSONResponse` and the exception handlers), so access key
IDs, secrets and emails are redacted at the edge.

``create_app(settings, components=...)`` accepts pre-built components so tests
can inject fakes; otherwise the real AWS/MCP/agent stack is built at startup.
"""
from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from types import ModuleType
from typing import Any

from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import trace
from .actions import approver_problem, clean_approver
from .config import Settings, load_settings
from .masking import mask_obj, mask_text
from .models import Action, Incident, iso
from .risk import compute_risk

log = logging.getLogger("sentinel.api")

MAX_CHAT_CHARS = 4000
MAX_HISTORY = 12
MAX_HISTORY_ITEMS = 50  # the UI sends the last 12; more is refused (422) rather than stored or forwarded
MAX_REASON_CHARS = 1000
MAX_REQUESTED_BY_CHARS = 100
MAX_SPEAK_CHARS = 2500
MAX_AUDIO_BYTES = 10 * 1024 * 1024
MAX_JSON_BODY_BYTES = 1024 * 1024  # every other /api request body
MULTIPART_OVERHEAD_BYTES = 64 * 1024  # boundaries + part headers around the audio file
TRANSCRIBE_PATH = "/api/voice/transcribe"

DetectFn = Callable[..., Awaitable[dict]]


class MaskedJSONResponse(JSONResponse):
    """JSONResponse that masks every string before serialising."""

    def render(self, content: Any) -> bytes:
        return super().render(mask_obj(jsonable_encoder(content)))


@dataclass
class Components:
    """Everything the API needs at runtime; injectable for tests."""

    aws: Any  # AwsSessionFactory
    store: Any  # SQLiteStore
    hub: Any  # MCPHub
    sources: Any  # DataSources
    agent: Any  # SentinelAgent
    voice: Any  # VoiceService
    reports: Any  # ReportWriter
    actions: ModuleType | Any  # exposes approve / reject / real_action_gate
    run_detection: DetectFn


# --------------------------------------------------------------- body limit
class BodyLimitMiddleware:
    """Refuse oversized /api request bodies with 413 *before* they are buffered or spooled.

    A declared Content-Length over the limit is rejected without reading the body; otherwise the
    bytes are counted as they arrive and the request fails with 413 as soon as it passes the limit
    (chunked uploads included). The transcribe route allows the audio limit plus multipart overhead.
    """

    def __init__(self, app: Any) -> None:
        self.app = app

    @staticmethod
    def limit_for(path: str) -> int | None:
        if path == TRANSCRIBE_PATH:
            return MAX_AUDIO_BYTES + MULTIPART_OVERHEAD_BYTES
        return MAX_JSON_BODY_BYTES if path.startswith("/api/") else None

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        limit = self.limit_for(scope.get("path", "")) if scope["type"] == "http" else None
        if limit is None:
            await self.app(scope, receive, send)
            return
        declared = dict(scope.get("headers") or []).get(b"content-length", b"")
        if declared.strip().isdigit() and int(declared) > limit:
            await MaskedJSONResponse({"detail": "Request body is too large"}, status_code=413)(scope, receive, send)
            return
        received = 0

        async def limited_receive() -> Any:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    raise StarletteHTTPException(413, "Request body is too large")
            return message

        await self.app(scope, limited_receive, send)


# --------------------------------------------------------------------- bodies
class ChatBody(BaseModel):
    message: str = ""
    incident_id: str | None = Field(None, max_length=20)  # the agent also drops ids not in the store
    voice: bool = False
    history: list[dict[str, Any]] = Field(default_factory=list, max_length=MAX_HISTORY_ITEMS)


class DecisionBody(BaseModel):
    approver: str = Field("", max_length=200)  # cleaned and capped to MAX_APPROVER_LEN by _require_approver
    reason: str = Field("", max_length=MAX_REASON_CHARS)


class ReportBody(BaseModel):
    requested_by: str = Field("", max_length=MAX_REQUESTED_BY_CHARS)


class SpeakBody(BaseModel):
    text: str = ""


# ------------------------------------------------------------------- building
async def build_components(settings: Settings) -> Components:
    """Wire the real stack: AWS session, store, MCP hub, sources, agent, voice, reports."""
    from . import actions
    from .agent.loop import SentinelAgent
    from .agent.tools import AgentContext
    from .aws.session import AwsSessionFactory
    from .mcp_hub import build_hub
    from .pipeline import run_detection
    from .reports import ReportWriter
    from .sources import DataSources
    from .store import SQLiteStore
    from .voice import VoiceService

    aws = AwsSessionFactory(settings)
    status = await asyncio.to_thread(aws.status)
    log.info("AWS status: %s", status.label if status.connected else f"offline ({status.reason})")
    store = SQLiteStore(settings.db_path)
    hub = build_hub(settings, aws_live=status.connected)
    sources = DataSources(settings, hub, aws, store)
    agent = SentinelAgent(AgentContext(settings=settings, store=store, sources=sources, aws=aws))
    return Components(
        aws=aws,
        store=store,
        hub=hub,
        sources=sources,
        agent=agent,
        voice=VoiceService(settings, aws),
        reports=ReportWriter(settings, aws),
        actions=actions,
        run_detection=run_detection,
    )


def _install(app: FastAPI, settings: Settings, c: Components) -> None:
    s = app.state
    s.settings = settings
    s.aws, s.store, s.hub, s.sources = c.aws, c.store, c.hub, c.sources
    s.agent, s.voice, s.reports = c.agent, c.voice, c.reports
    s.actions, s.run_detection = c.actions, c.run_detection
    s.detect_lock = asyncio.Lock()
    s.decision_lock = asyncio.Lock()
    s.detection = {"running": False, "last_run_at": None, "last_error": None, "incident_count": 0, "mode": None}
    s.bedrock = {"last_mode": None, "last_error": None}


async def _detect(app: FastAPI) -> dict:
    """Run the detection pipeline once (serialised) and record its outcome."""
    s = app.state
    async with s.detect_lock:
        s.detection["running"] = True
        try:
            result = await s.run_detection(s.sources, s.store, s.settings)
        except Exception as exc:
            s.detection.update(running=False, last_run_at=iso(), last_error=mask_text(f"{type(exc).__name__}: {exc}")[:300])
            raise
        s.detection.update(
            running=False,
            last_run_at=iso(),
            last_error=None,
            incident_count=len(result.get("incidents", [])),
            mode=result.get("mode"),
        )
        return result


async def _initial_detection(app: FastAPI) -> None:
    try:
        await _detect(app)
    except asyncio.CancelledError:
        raise
    except Exception:
        log.exception("Initial detection failed")


# -------------------------------------------------------------------- helpers
async def _aws_snapshot(app: FastAPI) -> tuple[Any, bool]:
    """(AwsStatus, sources.live) without blocking the event loop (STS may be called)."""
    s = app.state
    status, live = await asyncio.to_thread(lambda: (s.aws.status(), bool(s.sources.live)))
    sync = getattr(s.sources, "sync_hub", None)
    if sync is not None:
        await sync(live)
    return status, live


async def _voice_status(app: FastAPI) -> dict:
    """voice.status() off the event loop: it may call STS + Secrets Manager (timeouts, retries)."""
    return await asyncio.to_thread(app.state.voice.status)


def _banner(status: Any, live: bool, fallbacks: list[dict], *, aws_required: bool = False) -> str | None:
    reasons: list[str] = []
    if not live:
        reason = status.reason or "AWS not connected"
        # SENTINEL_MODE=aws: AWS is expected, so say plainly that the fallback is an error.
        reasons.append(f"AWS required (SENTINEL_MODE=aws) but not connected: {reason}" if aws_required else reason)
    if live and not fallbacks:
        return None
    # Components that fell back only because AWS is not connected repeat the reason above: name them once.
    same = [f for f in fallbacks if not live and str(f.get("reason", "")).startswith("AWS not connected")]
    if same:
        reasons[-1] += f" ({', '.join(str(f.get('component', '?')) for f in same)} using offline data)"
    reasons += [f"{f.get('component', '?')}: {f.get('reason', '')}" for f in fallbacks if f not in same]
    return "Offline fallback — " + "; ".join(r for r in reasons if r)


def _require_approver(body: DecisionBody | None) -> DecisionBody:
    body = body or DecisionBody()
    problem = approver_problem(body.approver)
    if problem:  # empty, or a system/agent name: an approval must name a human (CONTRACT invariant 4)
        raise HTTPException(400, problem)
    body.approver = clean_approver(body.approver)
    return body


def _incident_or_404(app: FastAPI, incident_id: str) -> Incident:
    inc = app.state.store.get_incident(incident_id)
    if inc is None:
        raise HTTPException(404, f"Incident {incident_id} not found")
    return inc


def _proposed_action_or_error(app: FastAPI, action_id: str) -> Action:
    action = app.state.store.get_action(action_id)
    if action is None:
        raise HTTPException(404, f"Action {action_id} not found")
    if action.status != "proposed":
        raise HTTPException(409, f"Action {action_id} was already decided ({action.status})")
    return action


def _execution_preview(app: FastAPI, action: Action, incident: Incident | None, aws_connected: bool) -> dict:
    """Would approving this action run for real right now? Uses the ACTIONS gate."""
    if not action.real_capable:
        return {"real": False, "reasons": ["This action type is always simulated"]}
    if incident is None:
        return {"real": False, "reasons": ["Incident not found"]}
    try:
        real, reasons = app.state.actions.real_action_gate(action, incident, app.state.settings, aws_connected, "preview")
    except Exception as exc:  # preview must never break the page
        return {"real": False, "reasons": [f"Gate check failed: {type(exc).__name__}"]}
    return {"real": bool(real), "reasons": list(reasons)}


def _incident_summary(inc: Incident, actions: list[Action]) -> dict:
    d = inc.to_dict()
    d.pop("events", None)
    d["event_count"] = len(inc.events)
    d["risk"] = compute_risk(inc)
    d["pending_actions"] = sum(1 for a in actions if a.incident_id == inc.id and a.status == "proposed")
    return d


def _voice_fallback(exc: Exception) -> MaskedJSONResponse:
    reason = str(exc) or type(exc).__name__
    log.info("Voice fallback to browser: %s", mask_text(reason))
    return MaskedJSONResponse({"fallback": "browser", "reason": reason[:300]}, status_code=503)


# ------------------------------------------------------------------------ app
def create_app(settings: Settings | None = None, *, components: Components | None = None) -> FastAPI:
    """Build the FastAPI app. Pass ``components`` to skip building the real stack."""
    settings = settings or load_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        _install(app, settings, components or await build_components(settings))
        task = asyncio.create_task(_initial_detection(app), name="sentinel-initial-detection")
        try:
            yield
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            try:
                await app.state.hub.close()
            except Exception:
                log.exception("MCP hub shutdown failed")

    app = FastAPI(title="SentinelAI", version="0.1.0", lifespan=lifespan, default_response_class=MaskedJSONResponse)
    app.add_middleware(BodyLimitMiddleware)

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(_: Request, exc: StarletteHTTPException) -> MaskedJSONResponse:
        return MaskedJSONResponse({"detail": exc.detail}, status_code=exc.status_code, headers=exc.headers)

    @app.exception_handler(RequestValidationError)
    async def _validation_error(_: Request, exc: RequestValidationError) -> MaskedJSONResponse:
        errors = [{"loc": e.get("loc"), "msg": e.get("msg"), "type": e.get("type")} for e in exc.errors()]
        return MaskedJSONResponse({"detail": errors}, status_code=422)

    @app.exception_handler(Exception)
    async def _unhandled(_: Request, exc: Exception) -> MaskedJSONResponse:
        log.exception("Unhandled API error")
        return MaskedJSONResponse({"detail": f"{type(exc).__name__}: {str(exc)[:300]}"}, status_code=500)

    # -------------------------------------------------------------- status
    @app.get("/api/status")
    async def status() -> dict:
        s = app.state
        (aws_status, live), voice = await asyncio.gather(_aws_snapshot(app), _voice_status(app))
        fallbacks = list(s.sources.fallbacks.values())
        return {
            "aws": {**aws_status.to_dict(), "label": aws_status.label},
            "mode": "aws" if live else "offline",
            "aws_required": s.settings.mode == "aws",
            "banner": _banner(aws_status, live, fallbacks, aws_required=s.settings.mode == "aws"),
            "fallbacks": fallbacks,
            "settings": s.settings.public_dict(),
            "mcp": s.hub.info(),
            "voice": voice,
            "bedrock": {"model_id": s.settings.bedrock_model_id, **s.bedrock},
            "detection": dict(s.detection),
        }

    @app.post("/api/detect")
    async def detect() -> dict:
        try:
            return await _detect(app)
        except Exception as exc:
            log.exception("Detection failed")
            raise HTTPException(500, f"Detection failed: {type(exc).__name__}: {str(exc)[:200]}") from exc

    # ----------------------------------------------------------- incidents
    @app.get("/api/incidents")
    async def incidents() -> dict:
        store = app.state.store
        actions = store.list_actions()
        return {"incidents": [_incident_summary(i, actions) for i in store.list_incidents()]}

    @app.get("/api/incidents/{incident_id}")
    async def incident(incident_id: str) -> dict:
        inc = _incident_or_404(app, incident_id)
        _, live = await _aws_snapshot(app)
        actions = app.state.store.list_actions(incident_id)
        return {
            "incident": {**inc.to_dict(), "risk": compute_risk(inc)},
            "actions": [{**a.to_dict(), "execution": _execution_preview(app, a, inc, live)} for a in actions],
        }

    # ---------------------------------------------------------------- chat
    @app.post("/api/chat")
    async def chat(body: ChatBody) -> dict:
        message = body.message.strip()
        if not message:
            raise HTTPException(400, "Message is empty")
        if len(message) > MAX_CHAT_CHARS:
            raise HTTPException(400, f"Message is longer than {MAX_CHAT_CHARS} characters")
        s = app.state
        result = await s.agent.ask(
            message,
            incident_id=body.incident_id or None,
            history=body.history[-MAX_HISTORY:],
            voice=body.voice,
        )
        s.bedrock.update(last_mode=result.get("mode"), last_error=result.get("fallback_reason"))
        return result

    # ------------------------------------------------------------- actions
    @app.get("/api/actions")
    async def list_actions(incident_id: str | None = None) -> dict:
        return {"actions": [a.to_dict() for a in app.state.store.list_actions(incident_id)]}

    @app.post("/api/actions/{action_id}/approve")
    async def approve(action_id: str, body: DecisionBody | None = None) -> dict:
        body = _require_approver(body)
        s = app.state
        async with s.decision_lock:
            _proposed_action_or_error(app, action_id)
            try:
                action = await s.actions.approve(
                    action_id, body.approver, store=s.store, settings=s.settings, aws=s.aws, reports=s.reports
                )
            except LookupError as exc:
                raise HTTPException(404, str(exc)) from exc
            except ValueError as exc:
                raise HTTPException(409, str(exc)) from exc
        return action.to_dict()

    @app.post("/api/actions/{action_id}/reject")
    async def reject(action_id: str, body: DecisionBody | None = None) -> dict:
        body = _require_approver(body)
        s = app.state
        async with s.decision_lock:
            _proposed_action_or_error(app, action_id)
            try:
                action = s.actions.reject(action_id, body.approver, store=s.store, reason=body.reason.strip())
            except LookupError as exc:
                raise HTTPException(404, str(exc)) from exc
            except ValueError as exc:
                raise HTTPException(409, str(exc)) from exc
        return action.to_dict()

    # --------------------------------------------------------------- audit
    @app.get("/api/audit")
    async def audit(limit: int = 200) -> dict:
        store = app.state.store
        limit = max(1, min(limit, 1000))
        return {"entries": [e.to_dict() for e in store.list_audit(limit)], "chain_ok": store.verify_audit_chain()}

    # ------------------------------------------------------------- reports
    @app.post("/api/reports/{incident_id}")
    async def write_report(incident_id: str, body: ReportBody | None = None) -> dict:
        s = app.state
        inc = _incident_or_404(app, incident_id)
        _, live = await _aws_snapshot(app)
        actions = s.store.list_actions(incident_id)
        entries = [e for e in reversed(s.store.list_audit(1000)) if e.incident_id == incident_id]
        report = await asyncio.to_thread(s.reports.write, inc, actions, entries, trigger="manual", live=live)
        actor = mask_text(" ".join((body.requested_by if body else "").split())) or "analyst"
        s.store.append_audit(actor, "report_written", incident_id, {"trigger": "manual", **report})
        return report

    @app.get("/api/reports")
    async def list_reports() -> dict:
        s = app.state
        _, live = await _aws_snapshot(app)
        return {"reports": await asyncio.to_thread(s.reports.list, live), "live": live}

    # --------------------------------------------------------------- voice
    @app.get("/api/voice/status")
    async def voice_status() -> dict:
        return await _voice_status(app)

    @app.post("/api/voice/transcribe", response_model=None)
    async def transcribe(file: UploadFile = File(...)) -> dict | MaskedJSONResponse:
        if file.size is not None and file.size > MAX_AUDIO_BYTES:
            raise HTTPException(413, "Audio file is too large")
        audio = await file.read(MAX_AUDIO_BYTES + 1)  # never load more than the limit into memory
        if not audio:
            raise HTTPException(400, "Audio file is empty")
        if len(audio) > MAX_AUDIO_BYTES:
            raise HTTPException(413, "Audio file is too large")
        try:
            return await app.state.voice.transcribe(audio, file.filename or "speech.webm", file.content_type or "audio/webm")
        except Exception as exc:  # VoiceUnavailable or provider failure -> browser speech recognition
            return _voice_fallback(exc)

    @app.post("/api/voice/speak", response_model=None)
    async def speak(body: SpeakBody) -> Response:
        text = mask_text(body.text.strip())[:MAX_SPEAK_CHARS]
        if not text:
            raise HTTPException(400, "Text is empty")
        try:
            audio, mime = await app.state.voice.speak(text)
        except Exception as exc:  # VoiceUnavailable or provider failure -> browser speechSynthesis
            return _voice_fallback(exc)
        return Response(content=audio, media_type=mime or "audio/mpeg", headers={"Cache-Control": "no-store"})

    # --------------------------------------------------------------- trace
    @app.get("/api/trace/recent")
    async def trace_recent(limit: int = 50) -> dict:
        return {"trace": [e.to_dict() for e in trace.recent(max(1, min(limit, 200)))]}

    # -------------------------------------------------------------- static
    @app.middleware("http")
    async def _revalidate_static(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        """Make browsers revalidate the SPA files so edits show up without a hard refresh."""
        response = await call_next(request)
        if not request.url.path.startswith("/api/"):
            response.headers.setdefault("Cache-Control", "no-cache")
        return response

    app.mount("/", StaticFiles(directory=settings.web_dir, html=True, check_dir=False), name="web")
    return app
