"""API tests with injected fake components (no AWS, no MCP, no network)."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi.testclient import TestClient
from starlette.exceptions import HTTPException as StarletteHTTPException

from sentinel.api import Components, create_app
from sentinel.aws.session import AwsStatus
from sentinel.config import load_settings
from sentinel.models import Action, Event, Incident, iso
from sentinel.store import SQLiteStore

KEY = "AKIAIOSFODNN7EXAMPLE"
MASKED = "AKIA…MPLE"


# ------------------------------------------------------------------ fakes
class FakeAws:
    def __init__(self, connected: bool = False):
        self.connected = connected

    def status(self, refresh: bool = False) -> AwsStatus:
        if self.connected:
            return AwsStatus(True, account_suffix="1234", arn_kind="user/sentinel-app", region="ap-south-1")
        return AwsStatus(False, region="ap-south-1", reason="SENTINEL_MODE=offline")


class FakeHub:
    def __init__(self) -> None:
        self.closed = False

    def info(self) -> list[dict]:
        return [{"name": "github", "label": "GitHub MCP (mock)", "command": [], "running": False, "last_error": None}]

    async def close(self) -> None:
        self.closed = True


class FakeSources:
    def __init__(self, aws: FakeAws):
        self.aws = aws
        self.fallbacks: dict[str, dict] = {}

    @property
    def live(self) -> bool:
        return self.aws.connected


class FakeAgent:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    async def ask(self, question: str, incident_id=None, history=None, voice=False) -> dict:
        self.calls.append({"question": question, "incident_id": incident_id, "history": history, "voice": voice})
        return {
            "answer": f"Key {KEY} was used after it was flagged.",
            "mode": "offline",
            "model_id": "apac.amazon.nova-lite-v1:0",
            "fallback_reason": "No AWS credentials",
            "trace": [{"server": "CloudTrail MCP", "tool": "lookup_events", "target": "offline", "ms": 12, "ok": True, "summary": "7 events"}],
            "proposed_actions": [],
        }


class VoiceUnavailable(Exception):
    """Stand-in for sentinel.voice.VoiceUnavailable."""


class FakeVoice:
    def __init__(self, available: bool = False):
        self.available = available

    def status(self) -> dict:
        return {"provider": "elevenlabs" if self.available else "browser", "reason": "" if self.available else "no key", "voice_id": "v", "key_source": None}

    async def transcribe(self, audio: bytes, filename: str, content_type: str) -> dict:
        if not self.available:
            raise VoiceUnavailable("ElevenLabs API key not configured")
        return {"text": "what happened", "provider": "elevenlabs", "ms": 5}

    async def speak(self, text: str) -> tuple[bytes, str]:
        if not self.available:
            raise VoiceUnavailable("ElevenLabs API key not configured")
        return b"ID3fake-mp3", "audio/mpeg"


class FakeReports:
    def __init__(self) -> None:
        self.written: list[dict] = []

    def write(self, incident, actions, audit, *, trigger: str, live: bool) -> dict:
        rep = {"uri": f"var/reports/{incident.id}/r.md", "markdown_key": "r.md", "json_key": "r.json", "live": live}
        self.written.append({"incident": incident.id, "trigger": trigger, "n_actions": len(actions)})
        return rep

    def list(self, live: bool) -> list[dict]:
        return [{"uri": "var/reports/INC-001/r.md"}]


def make_actions_module(store: SQLiteStore) -> SimpleNamespace:
    """Minimal stand-in for sentinel.actions (approve/reject/real_action_gate)."""

    async def approve(action_id, approver, *, store, settings, aws, reports) -> Action:
        a = store.get_action(action_id)
        if a.status != "proposed":
            raise ValueError("already decided")
        a.status, a.decided_by, a.decided_at = "simulated", approver, iso()
        a.result = {"mode": "simulated", "reasons": ["ALLOW_REAL_ACTIONS is false"]}
        store.update_action(a)
        store.append_audit(approver, "action_approved", a.incident_id, {"action_id": a.id})
        return a

    def reject(action_id, approver, *, store, reason="") -> Action:
        a = store.get_action(action_id)
        a.status, a.decided_by, a.decided_at = "rejected", approver, iso()
        store.update_action(a)
        return a

    def real_action_gate(action, incident, settings, aws_connected, approver):
        reasons = [] if aws_connected and settings.allow_real_actions else ["ALLOW_REAL_ACTIONS is false"]
        return (not reasons, reasons)

    return SimpleNamespace(approve=approve, reject=reject, real_action_gate=real_action_gate)


def sample_incident() -> Incident:
    now = iso()
    ev = Event(id="e1", ts=now, source="cloudtrail", kind="AttachUserPolicy", actor="sentinel-demo-victim",
               ip="203.0.113.9", outcome="denied", access_key_id=KEY, error_code="AccessDenied")
    return Incident(
        id="INC-001", title="Leaked AWS key used after GitHub alert", severity="critical", status="open",
        summary=f"Key {KEY} leaked in acme-payments/billing-service.", created_at=now, updated_at=now,
        rule_ids=["R-LEAKED-KEY"], entities={"access_key_id": KEY, "iam_user": "sentinel-demo-victim"},
        events=[ev], evidence=["4 denied escalation attempts"], recommended_actions=["deactivate_access_key"],
        data_mode="synthetic", counts={"post_flag_uses": 5, "denied": 4},
    )


@dataclass
class Harness:
    client: TestClient
    store: SQLiteStore
    hub: FakeHub
    agent: FakeAgent
    reports: FakeReports
    detections: list[int]


def build(*, aws_connected: bool = False, voice_available: bool = False, fallbacks: dict | None = None):
    settings = load_settings(mode="offline")
    store = SQLiteStore(":memory:")
    aws = FakeAws(aws_connected)
    sources = FakeSources(aws)
    sources.fallbacks = fallbacks or {}
    hub, agent, reports = FakeHub(), FakeAgent(), FakeReports()
    detections: list[int] = []

    async def run_detection(src, st, cfg, *, now=None) -> dict:
        inc = sample_incident()
        st.upsert_incident(inc)
        if not st.list_actions(inc.id):
            st.add_action(Action(id="", incident_id=inc.id, type="deactivate_access_key", title="Deactivate leaked access key",
                                 description=f"Set {KEY} to Inactive", real_capable=True))
        detections.append(1)
        return {"incidents": [inc.to_dict()], "suppressed": [], "fallbacks": [], "trace": [], "mode": "offline"}

    comps = Components(aws=aws, store=store, hub=hub, sources=sources, agent=agent, voice=FakeVoice(voice_available),
                       reports=reports, actions=make_actions_module(store), run_detection=run_detection)
    app = create_app(settings, components=comps)
    return app, Harness(client=None, store=store, hub=hub, agent=agent, reports=reports, detections=detections)  # type: ignore[arg-type]


@pytest.fixture
def h():
    app, harness = build()
    with TestClient(app) as client:
        harness.client = client
        client.post("/api/detect")  # deterministic: don't depend on the background task's timing
        yield harness
    assert harness.hub.closed, "hub.close() must run on shutdown"


# ------------------------------------------------------------------ tests
def test_status_offline_banner(h: Harness) -> None:
    r = h.client.get("/api/status")
    assert r.status_code == 200
    body = r.json()
    assert body["mode"] == "offline"
    assert body["aws"]["label"] == "Offline fallback"
    assert body["banner"].startswith("Offline fallback — ")
    assert "SENTINEL_MODE=offline" in body["banner"]
    assert body["bedrock"]["model_id"]
    assert body["voice"]["provider"] == "browser"
    assert body["mcp"][0]["name"] == "github"
    assert body["detection"]["last_run_at"]


def test_status_aws_mode_flags_missing_aws_as_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """SENTINEL_MODE=aws is not just an alias of auto: an offline fallback is reported as an error."""
    app, _ = build()
    with TestClient(app) as c:
        assert c.get("/api/status").json()["aws_required"] is False
        c.app.state.settings.mode = "aws"
        body = c.get("/api/status").json()
    assert body["aws_required"] is True and body["mode"] == "offline"
    assert body["banner"].startswith("Offline fallback — AWS required (SENTINEL_MODE=aws) but not connected: ")

    app, _ = build(aws_connected=True)
    with TestClient(app) as c:
        c.app.state.settings.mode = "aws"
        body = c.get("/api/status").json()
    assert body["aws_required"] is True and body["banner"] is None


def test_status_connected_no_banner_and_fallback_banner() -> None:
    app, _ = build(aws_connected=True)
    with TestClient(app) as c:
        body = c.get("/api/status").json()
    assert body["mode"] == "aws"
    assert body["aws"]["label"] == "AWS: connected (account …1234, ap-south-1)"
    assert body["banner"] is None

    fb = {"cloudtrail": {"component": "cloudtrail", "reason": "No live CloudTrail events yet", "ts": iso()}}
    app, _ = build(aws_connected=True, fallbacks=fb)
    with TestClient(app) as c:
        body = c.get("/api/status").json()
    assert body["banner"] == "Offline fallback — cloudtrail: No live CloudTrail events yet"


def test_offline_banner_names_components_once_instead_of_repeating_the_aws_reason() -> None:
    reason = "AWS not connected: SENTINEL_MODE=offline"
    fb = {
        "cloudtrail": {"component": "cloudtrail", "reason": reason, "ts": iso()},
        "auth": {"component": "auth", "reason": reason, "ts": iso()},
        "logs": {"component": "logs", "reason": "Logs MCP unavailable", "ts": iso()},
    }
    app, _ = build(fallbacks=fb)
    with TestClient(app) as c:
        banner = c.get("/api/status").json()["banner"]
    assert banner == "Offline fallback — SENTINEL_MODE=offline (cloudtrail, auth using offline data); logs: Logs MCP unavailable"


def test_incidents_list_and_detail_are_masked(h: Harness) -> None:
    r = h.client.get("/api/incidents")
    assert r.status_code == 200
    incs = r.json()["incidents"]
    assert [i["id"] for i in incs] == ["INC-001"]
    assert incs[0]["pending_actions"] == 1 and incs[0]["event_count"] == 1
    assert "events" not in incs[0]

    r = h.client.get("/api/incidents/INC-001")
    assert r.status_code == 200
    assert KEY not in r.text and MASKED in r.text
    body = r.json()
    assert body["incident"]["entities"]["access_key_id"] == MASKED
    assert body["actions"][0]["execution"] == {"real": False, "reasons": ["ALLOW_REAL_ACTIONS is false"]}

    assert h.client.get("/api/incidents/INC-999").status_code == 404


def test_chat_masks_answer_and_passes_context(h: Harness) -> None:
    r = h.client.post("/api/chat", json={"message": "  what happened?  ", "incident_id": "INC-001", "history": [{"role": "user", "content": "hi"}]})
    assert r.status_code == 200
    body = r.json()
    assert KEY not in r.text and MASKED in body["answer"]
    assert body["trace"][0]["summary"] == "7 events"
    assert h.agent.calls[-1]["question"] == "what happened?"
    assert h.agent.calls[-1]["incident_id"] == "INC-001"
    status = h.client.get("/api/status").json()
    assert status["bedrock"]["last_mode"] == "offline"

    assert h.client.post("/api/chat", json={"message": "   "}).status_code == 400


def test_approve_requires_approver_and_rejects_double_decision(h: Harness) -> None:
    action_id = h.store.list_actions("INC-001")[0].id
    assert h.client.post(f"/api/actions/{action_id}/approve", json={"approver": "  "}).status_code == 400
    assert h.client.post(f"/api/actions/{action_id}/approve").status_code == 400

    r = h.client.post(f"/api/actions/{action_id}/approve", json={"approver": "Sachin"})
    assert r.status_code == 200
    body = r.json()
    assert body["id"] == action_id and body["status"] == "simulated" and body["decided_by"] == "Sachin"
    assert KEY not in r.text

    again = h.client.post(f"/api/actions/{action_id}/approve", json={"approver": "Sachin"})
    assert again.status_code == 409
    assert h.client.post(f"/api/actions/{action_id}/reject", json={"approver": "Sachin"}).status_code == 409
    assert h.client.post("/api/actions/ACT-9999/approve", json={"approver": "Sachin"}).status_code == 404


@pytest.mark.parametrize("name", ["agent", "sentinel", "Bedrock", "sentinel-rules", "SentinelAI", " system ", "\u202eagent"])
def test_approve_and_reject_refuse_non_human_approvers(h: Harness, name: str) -> None:
    action_id = h.store.list_actions("INC-001")[0].id
    for verb in ("approve", "reject"):
        r = h.client.post(f"/api/actions/{action_id}/{verb}", json={"approver": name})
        assert r.status_code == 400, (verb, r.text)
    assert h.store.get_action(action_id).status == "proposed"
    assert not [e for e in h.store.list_audit() if e.action in ("action_approved", "action_rejected")]


def test_approver_is_bounded_cleaned_and_masked(h: Harness) -> None:
    action_id = h.store.list_actions("INC-001")[0].id
    assert h.client.post(f"/api/actions/{action_id}/approve", json={"approver": "x" * 200_000}).status_code == 422
    r = h.client.post(f"/api/actions/{action_id}/approve", json={"approver": "ev\nil\u202e AKIAIOSFODNN7EXAMPLE"})
    assert r.status_code == 200 and r.json()["decided_by"] == "ev il AKIA…MPLE"
    actors = [e.actor for e in h.store.list_audit() if e.action == "action_approved"]
    assert actors == ["ev il AKIA…MPLE"]  # stored masked, not only masked in the response
    assert h.client.get("/api/audit").json()["chain_ok"] is True


def test_reject(h: Harness) -> None:
    action_id = h.store.list_actions("INC-001")[0].id
    assert h.client.post(f"/api/actions/{action_id}/reject", json={"reason": "no"}).status_code == 400
    r = h.client.post(f"/api/actions/{action_id}/reject", json={"approver": "Sachin", "reason": "false positive"})
    assert r.status_code == 200 and r.json()["status"] == "rejected"
    assert h.client.get("/api/actions", params={"incident_id": "INC-001"}).json()["actions"][0]["status"] == "rejected"


def test_audit_chain(h: Harness) -> None:
    action_id = h.store.list_actions("INC-001")[0].id
    h.client.post(f"/api/actions/{action_id}/approve", json={"approver": "Sachin"})
    r = h.client.get("/api/audit")
    assert r.status_code == 200
    body = r.json()
    assert body["chain_ok"] is True
    assert body["entries"][0]["action"] == "action_approved"
    assert len(body["entries"][0]["hash"]) == 64


def test_reports_generate_and_list(h: Harness) -> None:
    r = h.client.post("/api/reports/INC-001", json={"requested_by": "Sachin"})
    assert r.status_code == 200 and r.json()["uri"].endswith("r.md")
    assert h.reports.written[-1] == {"incident": "INC-001", "trigger": "manual", "n_actions": 1}
    assert h.client.get("/api/audit").json()["entries"][0]["action"] == "report_written"
    assert h.client.get("/api/reports").json()["reports"][0]["uri"]
    assert h.client.post("/api/reports/INC-404").status_code == 404


def test_voice_falls_back_to_browser(h: Harness) -> None:
    r = h.client.post("/api/voice/speak", json={"text": "hello"})
    assert r.status_code == 503
    assert r.json() == {"fallback": "browser", "reason": "ElevenLabs API key not configured"}

    r = h.client.post("/api/voice/transcribe", files={"file": ("speech.webm", b"\x1a\x45audio", "audio/webm")})
    assert r.status_code == 503 and r.json()["fallback"] == "browser"

    assert h.client.post("/api/voice/speak", json={"text": " "}).status_code == 400
    assert h.client.get("/api/voice/status").json()["provider"] == "browser"


def test_voice_available_returns_audio() -> None:
    app, _ = build(voice_available=True)
    with TestClient(app) as c:
        r = c.post("/api/voice/speak", json={"text": "Key deactivated"})
        assert r.status_code == 200
        assert r.headers["content-type"] == "audio/mpeg"
        assert r.content.startswith(b"ID3")
        t = c.post("/api/voice/transcribe", files={"file": ("speech.webm", b"abc", "audio/webm")})
        assert t.json()["text"] == "what happened"


def test_oversized_bodies_are_refused_before_they_are_read() -> None:
    """Uploads are capped before buffering: a declared or streamed body over the limit gets 413, not a full read."""
    from sentinel import api as api_mod

    app, _ = build(voice_available=True)
    with TestClient(app) as c:
        # Declared Content-Length over the limit: rejected without reading the body.
        r = c.post(api_mod.TRANSCRIBE_PATH, content=b"x", headers={
            "content-type": "multipart/form-data; boundary=b",
            "content-length": str(api_mod.MAX_AUDIO_BYTES + api_mod.MULTIPART_OVERHEAD_BYTES + 1)})
        assert r.status_code == 413
        # A file just over the audio limit (inside the multipart allowance) is refused by the route.
        big = b"\x1a" * (api_mod.MAX_AUDIO_BYTES + 1)
        r = c.post(api_mod.TRANSCRIBE_PATH, files={"file": ("speech.webm", big, "audio/webm")})
        assert r.status_code == 413
        # JSON routes get the smaller cap.
        r = c.post("/api/chat", json={"message": "hi", "history": [{"role": "user", "content": "x" * (2 * 1024 * 1024)}]})
        assert r.status_code == 413
        # Normal requests still work.
        assert c.post(api_mod.TRANSCRIBE_PATH, files={"file": ("speech.webm", b"abc", "audio/webm")}).json()["text"] == "what happened"
        assert c.post("/api/chat", json={"message": "hi"}).status_code == 200


def test_body_limit_stops_reading_a_chunked_upload_at_the_limit() -> None:
    """Without a Content-Length the middleware counts bytes and fails at the limit instead of spooling it all."""
    from sentinel import api as api_mod

    chunk = b"x" * (1024 * 1024)
    pulled = 0

    async def receive() -> dict:
        nonlocal pulled
        pulled += 1
        return {"type": "http.request", "body": chunk, "more_body": pulled < 64}  # 64 MiB if fully read

    async def app(scope, receive_, send) -> None:
        while (await receive_()).get("more_body"):
            pass

    mw = api_mod.BodyLimitMiddleware(app)
    scope = {"type": "http", "path": api_mod.TRANSCRIBE_PATH, "headers": []}
    with pytest.raises(StarletteHTTPException) as err:
        asyncio.run(mw(scope, receive, None))
    assert err.value.status_code == 413
    assert pulled == 11  # 10 MiB audio + 64 KiB multipart allowance is passed on the 11th MiB
    assert api_mod.BodyLimitMiddleware.limit_for("/index.html") is None


def test_detect_and_trace(h: Harness) -> None:
    r = h.client.post("/api/detect")
    assert r.status_code == 200
    assert r.json()["mode"] == "offline" and KEY not in r.text
    assert isinstance(h.client.get("/api/trace/recent").json()["trace"], list)


def test_static_index_served(h: Harness) -> None:
    r = h.client.get("/")
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]
    assert "SentinelAI" in r.text
    assert h.client.get("/app.js").status_code == 200
    assert h.client.get("/styles.css").status_code == 200


def test_initial_background_detection_runs() -> None:
    app, harness = build()
    with TestClient(app) as c:
        for _ in range(50):
            if harness.detections:
                break
            c.get("/api/status")
        assert harness.detections, "startup detection should run in the background"
        assert c.get("/api/incidents").json()["incidents"]


def test_free_text_fields_are_bounded(h: Harness) -> None:
    action_id = h.store.list_actions("INC-001")[0].id
    r = h.client.post(f"/api/actions/{action_id}/reject", json={"approver": "ana", "reason": "R" * 5000})
    assert r.status_code == 422 and h.store.get_action(action_id).status == "proposed"
    assert h.client.post("/api/reports/INC-001", json={"requested_by": "x" * 5000}).status_code == 422
    history = [{"role": "user", "content": "hi"}] * 51
    assert h.client.post("/api/chat", json={"message": "hi", "history": history}).status_code == 422
    r = h.client.post("/api/reports/INC-001", json={"requested_by": f"ana\nkey {KEY}"})
    assert r.status_code == 200
    assert h.store.list_audit(1)[0].actor == f"ana key {MASKED}"


def test_voice_status_runs_off_the_event_loop() -> None:
    """voice.status() may call STS + Secrets Manager; it must not block every other request."""
    app, _ = build()
    threads: list[bool] = []

    def status() -> dict:
        try:
            asyncio.get_running_loop()
            threads.append(False)  # called on the event loop
        except RuntimeError:
            threads.append(True)
        return {"provider": "browser", "reason": "x", "voice_id": "v", "key_source": None}

    with TestClient(app) as c:
        app.state.voice.status = status
        assert c.get("/api/status").status_code == 200
        assert c.get("/api/voice/status").json()["provider"] == "browser"
    assert threads == [True, True]
