"""MCP client hub: long-lived stdio connections to SentinelAI's MCP servers.

Each registered server gets one worker task that owns the ``stdio_client`` and
``ClientSession`` contexts (anyio requires entering and exiting them in the same
task) and serves requests from an :class:`asyncio.Queue`. Each request runs as
its own sub-task, so one slow call doesn't block the others. Servers start
lazily on first use. When the transport dies mid-call, the hub restarts the
server and retries that call once.
"""
from __future__ import annotations

import asyncio
import functools
import io
import json
import logging
import os
import re
import shlex
import shutil
import sys
from collections import deque
from collections.abc import Mapping
from contextlib import AsyncExitStack
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TextIO

from mcp import ClientSession, StdioServerParameters
from mcp import MCPError as _ProtocolError
from mcp.client.stdio import stdio_client
from mcp.types import CONNECTION_CLOSED

from .config import ROOT, Settings
from .masking import mask_text

log = logging.getLogger(__name__)

STOP_TIMEOUT_S = 10.0
# Server log levels whose text explains a failed tool call. FastMCP turns any non-ToolError exception into a bare
# "Error executing tool <name>", so the AWS Labs server's `ctx.error(...)` log is the only place the real reason
# (ThrottlingException, AccessDenied, ...) reaches us.
_ERROR_LOG_LEVELS = frozenset({"error", "critical", "alert", "emergency"})
_ACCOUNT_IN_ARN_RE = re.compile(r"(arn:aws[a-z-]*:[a-z0-9-]*:[a-z0-9-]*:)\d{12}(?=:)")
LOCAL_SERVERS = {
    "github": ("github_mock", "GitHub MCP (mock)"),
    "cloudtrail_mock": ("cloudtrail_mock", "CloudTrail MCP (mock)"),
    "identity": ("identity", "Identity MCP"),
    "logs": ("logs", "Logs MCP"),
}
AWSLABS_CLOUDTRAIL = "cloudtrail"
# Environment a third-party server (the AWS Labs CloudTrail MCP) may see: AWS credentials/profile/region,
# process basics, TLS/proxy settings and uv's cache config. Never ELEVENLABS_API_KEY, DEMO_* or other app secrets.
THIRD_PARTY_ENV_KEYS = frozenset({
    "PATH", "HOME", "USER", "LOGNAME", "SHELL", "TERM", "LANG", "TMPDIR", "TEMP", "TMP",
    "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE",
    "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy",
    "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "COMSPEC", "PATHEXT", "APPDATA", "LOCALAPPDATA", "USERPROFILE", "PROGRAMDATA",
})
THIRD_PARTY_ENV_PREFIXES = ("AWS_", "UV_", "XDG_", "LC_")


def third_party_env(environ: Mapping[str, str] | None = None) -> dict[str, str]:
    """The allow-listed subset of ``environ`` (default ``os.environ``) for a third-party MCP server."""
    src = os.environ if environ is None else environ
    return {k: v for k, v in src.items() if k in THIRD_PARTY_ENV_KEYS or k.startswith(THIRD_PARTY_ENV_PREFIXES)}


class MCPError(Exception):
    """A hub call failed: tool error, timeout, spawn failure or crash."""


class _Crashed(Exception):
    """The server's transport died; the hub may restart it and retry."""


_STOP = object()  # queue sentinel: shut the worker down


@dataclass
class _Request:
    op: str  # "call" | "list"
    tool: str
    args: dict[str, Any]
    timeout: float
    future: asyncio.Future[Any]


@dataclass
class _Server:
    name: str
    command: list[str]
    label: str
    env: dict[str, str]
    inherit_env: bool = True  # False: only third_party_env() + env (no app secrets, no PYTHONPATH)
    loop: asyncio.AbstractEventLoop | None = None
    task: asyncio.Task[None] | None = None
    queue: asyncio.Queue[Any] | None = None
    ready: asyncio.Future[None] | None = None
    start_lock: asyncio.Lock | None = None
    last_error: str = ""
    restarts: int = 0
    stopping: bool = False
    log_seq: int = 0  # number of error-level log notifications received so far
    error_logs: deque[tuple[int, str]] = field(default_factory=lambda: deque(maxlen=20))
    inflight: set[asyncio.Task[None]] = field(default_factory=set)

    @property
    def running(self) -> bool:
        return (
            self.task is not None
            and not self.task.done()
            and self.ready is not None
            and self.ready.done()
            and not self.ready.cancelled()
            and self.ready.exception() is None
        )


@functools.cache
def _devnull() -> TextIO:
    return open(os.devnull, "w")  # noqa: SIM115 - process-lifetime handle


def _errlog() -> TextIO:
    """Child stderr: ours when it is a real file, else /dev/null (e.g. under capture)."""
    try:
        sys.stderr.fileno()
        return sys.stderr
    except (AttributeError, OSError, io.UnsupportedOperation):
        return _devnull()


def _log_text(data: Any) -> str:
    """A server log message as one short, masked line (no account ids, no full key ids)."""
    text = data if isinstance(data, str) else json.dumps(data, default=str)
    text = " ".join(text.split())[:300]
    return _ACCOUNT_IN_ARN_RE.sub(lambda m: m.group(1) + "…", mask_text(text))


def _error_text(label: str, tool: str, result: Any, logs: list[str] | None = None) -> str:
    text = result.content[0].text if result.content and hasattr(result.content[0], "text") else ""
    msg = f"{label} {tool} failed: {text[:300] or 'tool error'}"
    extra = [line for line in (logs or []) if line and line not in msg]
    return f"{msg} ({'; '.join(extra[-2:])})" if extra else msg


def _parse_result(label: str, tool: str, result: Any) -> dict[str, Any]:
    """Turn a ``CallToolResult`` into a dict, raising :class:`MCPError` on tool errors."""
    text = result.content[0].text if result.content and hasattr(result.content[0], "text") else ""
    if result.is_error:
        raise MCPError(_error_text(label, tool, result))
    if not text:
        structured = getattr(result, "structured_content", None)
        return structured if isinstance(structured, dict) else {}
    try:
        value = json.loads(text)
    except ValueError as exc:
        raise MCPError(f"{label} {tool} returned non-JSON content") from exc
    return value if isinstance(value, dict) else {"result": value}


class MCPHub:
    """Registry plus lazily started, self-healing stdio MCP clients."""

    def __init__(self, settings: Settings, base_env: dict[str, str] | None = None):
        self.settings = settings
        self.base_env = dict(base_env or {})
        self._servers: dict[str, _Server] = {}
        self.aws_live: bool | None = None  # backend the local servers were registered with (build_hub sets it)

    # ----------------------------------------------------------- registry
    def register(
        self, name: str, command: list[str], *, label: str, env: dict[str, str] | None = None, inherit_env: bool = True
    ) -> None:
        if not command:
            raise ValueError("command must not be empty")
        self._servers[name] = _Server(name=name, command=list(command), label=label, env=dict(env or {}), inherit_env=inherit_env)

    def unregister(self, name: str) -> _Server | None:
        return self._servers.pop(name, None)

    def is_registered(self, name: str) -> bool:
        return name in self._servers

    def info(self) -> list[dict[str, Any]]:
        return [
            {
                "name": s.name,
                "label": s.label,
                "command": list(s.command),
                "running": s.running,
                "last_error": s.last_error,
                "restarts": s.restarts,
            }
            for s in self._servers.values()
        ]

    # ------------------------------------------------------------- public API
    async def call(self, name: str, tool: str, args: dict[str, Any], timeout: float = 45) -> dict[str, Any]:
        """Call ``tool`` and return the parsed JSON of its first text content."""
        srv = self._get(name)
        result = await self._request(srv, "call", tool, args, timeout)
        return _parse_result(srv.label, tool, result)

    async def start(self, name: str, timeout: float = 45) -> None:
        """Start ``name`` now (no-op when running), so a caller's rate-limit slot isn't spent on start-up."""
        await self._ensure_started(self._get(name), timeout)

    async def list_tools(self, name: str) -> list[dict[str, Any]]:
        srv = self._get(name)
        tools = await self._request(srv, "list", "", {}, 45)
        return [{"name": t.name, "description": t.description or "", "input_schema": t.input_schema} for t in tools]

    async def close(self) -> None:
        """Stop every running server (best effort, bounded)."""
        for srv in self._servers.values():
            await self._stop(srv)

    # -------------------------------------------------------------- internals
    def _get(self, name: str) -> _Server:
        try:
            return self._servers[name]
        except KeyError:
            raise MCPError(f"MCP server not registered: {name}") from None

    def _child_env(self, srv: _Server) -> dict[str, str]:
        if not srv.inherit_env:
            return {**third_party_env(), **srv.env}
        return {**os.environ, **self.base_env, **srv.env}

    async def _request(self, srv: _Server, op: str, tool: str, args: dict[str, Any], timeout: float) -> Any:
        for attempt in range(2):
            try:
                return await self._request_once(srv, op, tool, args, timeout)
            except _Crashed as exc:
                if srv.stopping:
                    raise MCPError(f"{srv.label} was stopped") from exc
                srv.last_error = f"crashed: {exc}"
                await self._reap(srv)
                if attempt:
                    raise MCPError(f"{srv.label} crashed again after a restart: {exc}") from exc
                srv.restarts += 1
                log.warning("%s crashed (%s); restarting once", srv.label, exc)
        raise AssertionError("unreachable")

    async def _request_once(self, srv: _Server, op: str, tool: str, args: dict[str, Any], timeout: float) -> Any:
        await self._ensure_started(srv, timeout)
        assert srv.queue is not None
        fut: asyncio.Future[Any] = asyncio.get_running_loop().create_future()
        srv.queue.put_nowait(_Request(op, tool, dict(args), timeout, fut))
        try:
            # The sub-task enforces `timeout` itself; the grace covers queueing.
            return await asyncio.wait_for(fut, timeout + 5)
        except TimeoutError:
            srv.last_error = f"{tool or op} timed out after {timeout:g}s"
            raise MCPError(f"{srv.label} {tool or op} timed out after {timeout:g}s") from None

    async def _ensure_started(self, srv: _Server, timeout: float) -> None:
        loop = asyncio.get_running_loop()
        if srv.loop is not loop:  # first use, or the previous loop is gone (tests, scripts)
            srv.loop, srv.task, srv.queue, srv.ready = loop, None, None, None
            srv.start_lock = asyncio.Lock()
        assert srv.start_lock is not None
        startup_timeout = max(timeout, 30)
        async with srv.start_lock:
            if srv.task is None or srv.task.done():
                srv.stopping = False
                srv.queue = asyncio.Queue()
                srv.ready = loop.create_future()
                srv.task = asyncio.create_task(self._worker(srv, srv.queue, srv.ready), name=f"mcp-{srv.name}")
            ready = srv.ready
            assert ready is not None
            try:
                await asyncio.wait_for(asyncio.shield(ready), startup_timeout)
            except TimeoutError:
                srv.last_error = "start-up timed out"
                srv.task.cancel()
                await asyncio.gather(srv.task, return_exceptions=True)
                raise MCPError(f"{srv.label} did not start within {startup_timeout:g}s") from None
            except asyncio.CancelledError:
                if not ready.cancelled():
                    raise  # our caller was cancelled
                raise MCPError(f"{srv.label} stopped during start-up") from None

    async def _worker(self, srv: _Server, queue: asyncio.Queue[Any], ready: asyncio.Future[None]) -> None:
        params = StdioServerParameters(command=srv.command[0], args=srv.command[1:], env=self._child_env(srv))
        try:
            async with AsyncExitStack() as stack:
                read, write = await stack.enter_async_context(stdio_client(params, errlog=_errlog()))
                async def on_log(params: Any) -> None:
                    if str(getattr(params, "level", "")).lower() in _ERROR_LOG_LEVELS:
                        srv.log_seq += 1
                        srv.error_logs.append((srv.log_seq, _log_text(getattr(params, "data", ""))))

                session = await stack.enter_async_context(ClientSession(read, write, logging_callback=on_log))
                await session.initialize()
                srv.last_error = ""
                ready.set_result(None)
                try:
                    while (req := await queue.get()) is not _STOP:
                        task = asyncio.create_task(self._serve(srv, session, req, queue))
                        srv.inflight.add(task)
                        task.add_done_callback(srv.inflight.discard)
                finally:
                    for task in list(srv.inflight):
                        task.cancel()
                    await asyncio.gather(*srv.inflight, return_exceptions=True)
        except Exception as exc:  # spawn failure, handshake failure, transport teardown noise
            reason = f"{type(exc).__name__}: {exc}"[:300]
            if not ready.done():
                srv.last_error = f"failed to start: {reason}"
                ready.set_exception(MCPError(f"{srv.label} failed to start: {reason}"))
            elif not srv.last_error:
                srv.last_error = reason
        finally:
            if not ready.done():
                ready.cancel()
            self._fail_pending(queue, "server stopped")

    async def _serve(self, srv: _Server, session: ClientSession, req: _Request, queue: asyncio.Queue[Any]) -> None:
        mark = srv.log_seq
        try:
            if req.op == "list":
                value: Any = (await session.list_tools()).tools
            else:
                value = await session.call_tool(req.tool, req.args, read_timeout_seconds=req.timeout)
                if getattr(value, "is_error", False):
                    await asyncio.sleep(0)  # let a log notification sent just before the error response land
                    logs = [text for seq, text in srv.error_logs if seq > mark]
                    if not req.future.done():
                        req.future.set_exception(MCPError(_error_text(srv.label, req.tool, value, logs)))
                    return
        except _ProtocolError as exc:
            if exc.code == CONNECTION_CLOSED:
                self._crash(req, queue, exc.message)
            elif not req.future.done():
                req.future.set_exception(MCPError(f"{srv.label} {req.tool or req.op} failed: {exc.message}"))
            return
        except asyncio.CancelledError:
            if not req.future.done():
                req.future.set_exception(_Crashed("server stopped"))
            raise
        except Exception as exc:  # broken pipe, closed stream: the transport is gone
            self._crash(req, queue, f"{type(exc).__name__}: {exc}")
            return
        if not req.future.done():
            req.future.set_result(value)

    @staticmethod
    def _crash(req: _Request, queue: asyncio.Queue[Any], reason: str) -> None:
        if not req.future.done():
            req.future.set_exception(_Crashed(reason))
        queue.put_nowait(_STOP)  # let the worker tear the dead transport down

    @staticmethod
    def _fail_pending(queue: asyncio.Queue[Any], reason: str) -> None:
        while not queue.empty():
            req = queue.get_nowait()
            if isinstance(req, _Request) and not req.future.done():
                req.future.set_exception(_Crashed(reason))

    async def _stop(self, srv: _Server) -> None:
        if srv.task is None or srv.task.done() or srv.loop is not asyncio.get_running_loop():
            return
        assert srv.queue is not None
        srv.stopping = True
        srv.queue.put_nowait(_STOP)
        await self._reap(srv)

    @staticmethod
    async def _reap(srv: _Server) -> None:
        """Wait (bounded) for a worker that was told to stop; cancel it if it hangs."""
        task = srv.task
        if task is None or task.done():
            return
        done, _ = await asyncio.wait({task}, timeout=STOP_TIMEOUT_S)
        if not done:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)


def _resolve_executable(token: str) -> str | None:
    """Find ``token`` on PATH or in the project / interpreter venv ``bin``."""
    if os.path.sep in token:
        return token if os.access(token, os.X_OK) else None
    found = shutil.which(token)
    if found:
        return found
    for bin_dir in (ROOT / ".venv" / "bin", Path(sys.executable).parent):
        candidate = bin_dir / token
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


def build_hub(settings: Settings, aws_live: bool) -> MCPHub:
    """Register SentinelAI's own servers, plus the AWS Labs CloudTrail server when usable."""
    pythonpath = os.pathsep.join(p for p in (str(ROOT), os.environ.get("PYTHONPATH", "")) if p)
    hub = MCPHub(settings, base_env={"PYTHONPATH": pythonpath})
    _wire(hub, settings, aws_live)
    return hub


def _wire(hub: MCPHub, settings: Settings, aws_live: bool) -> None:
    backend = "aws" if aws_live else "offline"
    hub.aws_live = aws_live
    for name, (module, label) in LOCAL_SERVERS.items():
        hub.register(
            name,
            [sys.executable, "-m", f"sentinel.mcp_servers.{module}"],
            label=label,
            env={"SENTINEL_BACKEND": backend},
        )
    if aws_live:
        command = shlex.split(settings.cloudtrail_mcp_command or "")
        exe = _resolve_executable(command[0]) if command else None
        if exe:
            hub.register(
                AWSLABS_CLOUDTRAIL,
                [exe, *command[1:]],
                label="CloudTrail MCP (AWS Labs)",
                # loguru (the AWS Labs server's logger) ignores FASTMCP_LOG_LEVEL and logs lookup params -- the full
                # leaked key ID -- at INFO to the stderr we share; LOGURU_LEVEL keeps it to errors.
                env={"AWS_REGION": settings.aws_region, "FASTMCP_LOG_LEVEL": "ERROR", "LOGURU_LEVEL": "ERROR"},
                inherit_env=False,  # third-party code: AWS/process env only, never the app's secrets
            )
        else:
            log.info("AWS Labs CloudTrail MCP not available (%r not found); using boto3 directly", command[:1])
    else:
        hub.unregister(AWSLABS_CLOUDTRAIL)


async def rewire_hub(hub: MCPHub, aws_live: bool) -> bool:
    """Follow an AWS connectivity flip after startup; returns True when the hub was rewired.

    Re-registers the local servers with the new ``SENTINEL_BACKEND`` (a running child is stopped and restarts
    lazily on its next call with the new env) and adds/removes the AWS Labs CloudTrail server. The registry is
    updated before any await, so concurrent callers see the new backend and do nothing.
    """
    if hub.aws_live is None or hub.aws_live == aws_live:
        return False
    old = dict(hub._servers)
    _wire(hub, hub.settings, aws_live)
    log.info("AWS connectivity changed; MCP servers now use the %s backend", "aws" if aws_live else "offline")
    for srv in old.values():
        await hub._stop(srv)
    return True
