"""MCPHub against a tiny throwaway stdio MCP server (no dependency on DATA's servers)."""
from __future__ import annotations

import asyncio
import re
import sys
import textwrap
from pathlib import Path

import pytest

from sentinel.config import load_settings
from sentinel.mcp_hub import AWSLABS_CLOUDTRAIL, MCPError, MCPHub, build_hub

TOY_SERVER = textwrap.dedent(
    """
    import os, sys, time
    from pathlib import Path
    from mcp.server.mcpserver import Context, MCPServer

    mcp = MCPServer("toy")
    MARKER = Path(os.environ["TOY_MARKER"])

    @mcp.tool()
    def echo(x: str) -> dict:
        return {"x": x, "pid": os.getpid(), "backend": os.environ.get("TOY_BACKEND", "")}

    @mcp.tool()
    def boom() -> dict:
        raise ValueError("kaput")

    @mcp.tool()
    async def aws_fail(ctx: Context) -> dict:
        # The AWS Labs CloudTrail server's pattern: log the real error, then re-raise (FastMCP hides the text).
        await ctx.error("Error looking up CloudTrail events: An error occurred (ThrottlingException) when calling the "
                        "LookupEvents operation: Rate exceeded for arn:aws:iam::123456789012:user/x key AKIAIOSFODNN7EXAMPLE")
        raise RuntimeError("botocore ClientError")

    @mcp.tool()
    def slow(seconds: float) -> dict:
        time.sleep(seconds)
        return {"slept": seconds}

    @mcp.tool()
    def flaky() -> dict:
        if not MARKER.exists():
            MARKER.write_text("crashed once")
            os._exit(3)
        return {"ok": True}

    @mcp.tool()
    def die() -> dict:
        os._exit(4)

    mcp.run()
    """
)


@pytest.fixture
def hub(tmp_path: Path) -> MCPHub:
    script = tmp_path / "toy_server.py"
    script.write_text(TOY_SERVER)
    h = MCPHub(load_settings(), base_env={"TOY_MARKER": str(tmp_path / "marker")})
    h.register("toy", [sys.executable, str(script)], label="Toy MCP", env={"TOY_BACKEND": "offline"})
    return h


def run(coro):
    return asyncio.run(coro)


def test_call_list_tools_and_info(hub: MCPHub) -> None:
    async def scenario():
        assert hub.info()[0]["running"] is False  # lazy start
        first = await hub.call("toy", "echo", {"x": "hi"})
        second = await hub.call("toy", "echo", {"x": "again"})
        tools = await hub.list_tools("toy")
        info = hub.info()[0]
        await hub.close()
        return first, second, tools, info, hub.info()[0]

    first, second, tools, info, closed = run(scenario())
    assert first["x"] == "hi" and first["backend"] == "offline"
    assert first["pid"] == second["pid"]  # one long-lived process
    names = {t["name"] for t in tools}
    assert {"echo", "boom", "slow", "flaky", "die"} <= names
    assert "x" in next(t for t in tools if t["name"] == "echo")["input_schema"]["properties"]
    assert info["running"] is True and info["label"] == "Toy MCP" and info["last_error"] == ""
    assert closed["running"] is False


def test_concurrent_calls_share_one_server(hub: MCPHub) -> None:
    async def scenario():
        try:
            return await asyncio.gather(*(hub.call("toy", "echo", {"x": str(i)}) for i in range(5)))
        finally:
            await hub.close()

    results = run(scenario())
    assert [r["x"] for r in results] == ["0", "1", "2", "3", "4"]
    assert len({r["pid"] for r in results}) == 1


def test_tool_error_raises_and_server_survives(hub: MCPHub) -> None:
    async def scenario():
        try:
            with pytest.raises(MCPError, match="boom failed"):
                await hub.call("toy", "boom", {})
            return await hub.call("toy", "echo", {"x": "still here"})
        finally:
            await hub.close()

    assert run(scenario())["x"] == "still here"


def test_crash_restarts_once_and_retries(hub: MCPHub) -> None:
    async def scenario():
        try:
            before = await hub.call("toy", "echo", {"x": "a"})
            result = await hub.call("toy", "flaky", {})  # kills the server once, then succeeds
            after = await hub.call("toy", "echo", {"x": "b"})
            return before, result, after, hub.info()[0]
        finally:
            await hub.close()

    before, result, after, info = run(scenario())
    assert result == {"ok": True}
    assert before["pid"] != after["pid"]
    assert info["restarts"] == 1 and info["running"] is True


def test_repeated_crash_gives_up_then_recovers_lazily(hub: MCPHub) -> None:
    async def scenario():
        try:
            with pytest.raises(MCPError, match="crashed again"):
                await hub.call("toy", "die", {})
            error = hub.info()[0]["last_error"]
            return error, await hub.call("toy", "echo", {"x": "back"})
        finally:
            await hub.close()

    error, result = run(scenario())
    assert "crashed" in error
    assert result["x"] == "back"


def test_timeout(hub: MCPHub) -> None:
    async def scenario():
        try:
            with pytest.raises(MCPError):
                await hub.call("toy", "slow", {"seconds": 5}, timeout=0.5)
            return await hub.call("toy", "echo", {"x": "ok"})
        finally:
            await hub.close()

    assert run(scenario())["x"] == "ok"


def test_spawn_failure_and_unknown_server(tmp_path: Path) -> None:
    hub = MCPHub(load_settings())
    hub.register("ghost", [str(tmp_path / "does-not-exist")], label="Ghost MCP")

    async def scenario():
        with pytest.raises(MCPError, match="failed to start"):
            await hub.call("ghost", "anything", {}, timeout=5)
        with pytest.raises(MCPError, match="not registered"):
            await hub.call("nope", "anything", {})
        await hub.close()

    run(scenario())
    info = hub.info()[0]
    assert info["running"] is False and "failed to start" in info["last_error"]


def test_build_hub_offline_registers_local_servers_only() -> None:
    hub = build_hub(load_settings(), aws_live=False)
    names = [s["name"] for s in hub.info()]
    assert names == ["github", "cloudtrail_mock", "identity", "logs"]
    assert not hub.is_registered(AWSLABS_CLOUDTRAIL)
    srv = hub._servers["identity"]
    assert srv.command == [sys.executable, "-m", "sentinel.mcp_servers.identity"]
    env = hub._child_env(srv)
    assert env["SENTINEL_BACKEND"] == "offline"
    assert env["PYTHONPATH"].split(":")[0] == str(Path(__file__).resolve().parent.parent)


def test_build_hub_live_registers_awslabs_when_command_found(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AWS_SECRET_ACCESS_KEY", raising=False)
    settings = load_settings(cloudtrail_mcp_command=f"{sys.executable} -m awslabs.cloudtrail_mcp_server.server")
    hub = build_hub(settings, aws_live=True)
    assert hub.is_registered(AWSLABS_CLOUDTRAIL)
    srv = hub._servers[AWSLABS_CLOUDTRAIL]
    assert srv.command[0] == sys.executable and srv.command[-1] == "awslabs.cloudtrail_mcp_server.server"
    env = hub._child_env(srv)
    assert env["AWS_REGION"] == settings.aws_region and env["FASTMCP_LOG_LEVEL"] == "ERROR"
    assert env["LOGURU_LEVEL"] == "ERROR"  # loguru would print the full looked-up key ID at INFO
    assert "AWS_SECRET_ACCESS_KEY" not in env and "AWS_ACCESS_KEY_ID" not in srv.env
    assert hub._child_env(hub._servers["github"])["SENTINEL_BACKEND"] == "aws"


def test_awslabs_server_gets_allowlisted_env_only(monkeypatch: pytest.MonkeyPatch) -> None:
    """Third-party code sees AWS/process env, never ElevenLabs keys, DEMO_* values or PYTHONPATH."""
    monkeypatch.setenv("ELEVENLABS_API_KEY", "sk_test_not_real")
    monkeypatch.setenv("DEMO_LEAKED_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
    monkeypatch.setenv("AWS_PROFILE", "sentinel-demo")
    monkeypatch.setenv("UV_CACHE_DIR", "/tmp/uv-cache")
    settings = load_settings(cloudtrail_mcp_command=f"{sys.executable} -m awslabs.cloudtrail_mcp_server.server")
    hub = build_hub(settings, aws_live=True)
    env = hub._child_env(hub._servers[AWSLABS_CLOUDTRAIL])
    assert "ELEVENLABS_API_KEY" not in env and "DEMO_LEAKED_ACCESS_KEY_ID" not in env and "PYTHONPATH" not in env
    assert env["AWS_PROFILE"] == "sentinel-demo" and env["UV_CACHE_DIR"] == "/tmp/uv-cache" and env["PATH"]
    assert env["AWS_REGION"] == settings.aws_region
    # SentinelAI's own servers keep the full environment (they load settings from it).
    assert hub._child_env(hub._servers["github"])["ELEVENLABS_API_KEY"] == "sk_test_not_real"


def test_default_awslabs_command_is_pinned() -> None:
    from sentinel.config import DEFAULT_CLOUDTRAIL_MCP_COMMAND

    cmd = load_settings().cloudtrail_mcp_command
    assert cmd == DEFAULT_CLOUDTRAIL_MCP_COMMAND and "@latest" not in cmd
    assert re.fullmatch(r"uvx awslabs\.cloudtrail-mcp-server@\d+\.\d+\.\d+", cmd)


def test_build_hub_live_skips_awslabs_when_command_missing() -> None:
    settings = load_settings(cloudtrail_mcp_command="definitely-not-installed-xyz serve")
    assert not build_hub(settings, aws_live=True).is_registered(AWSLABS_CLOUDTRAIL)


def test_tool_error_carries_the_servers_error_log(hub: MCPHub) -> None:
    """FastMCP replies 'Error executing tool X' for any exception; the hub appends the server's ctx.error() text
    (masked, account id dropped) so callers can see ThrottlingException and retry."""
    async def scenario():
        try:
            with pytest.raises(MCPError) as info:
                await hub.call("toy", "aws_fail", {})
            with pytest.raises(MCPError) as plain:
                await hub.call("toy", "boom", {})  # no log sent: no stale text from the previous call
            return str(info.value), str(plain.value)
        finally:
            await hub.close()

    text, plain = run(scenario())
    assert "Error executing tool aws_fail" in text and "ThrottlingException" in text and "Rate exceeded" in text
    assert "123456789012" not in text and "AKIAIOSFODNN7EXAMPLE" not in text and "AKIA…MPLE" in text
    assert "ThrottlingException" not in plain


def test_start_spawns_server_without_a_call(hub: MCPHub) -> None:
    async def scenario():
        try:
            await hub.start("toy")
            return hub.info()[0]["running"]
        finally:
            await hub.close()

    assert run(scenario()) is True


def test_rewire_hub_follows_aws_connecting_after_an_offline_start(monkeypatch: pytest.MonkeyPatch) -> None:
    """Offline start, then AWS connects: children switch to the aws backend and AWS Labs CloudTrail is registered."""
    from sentinel.mcp_hub import rewire_hub

    settings = load_settings(cloudtrail_mcp_command=f"{sys.executable} -m awslabs.cloudtrail_mcp_server.server")
    hub = build_hub(settings, aws_live=False)
    stopped: list[str] = []

    async def fake_stop(srv):
        stopped.append(srv.name)

    monkeypatch.setattr(hub, "_stop", fake_stop)
    assert run(rewire_hub(hub, False)) is False  # no change: nothing restarts
    assert run(rewire_hub(hub, True)) is True
    assert hub.is_registered(AWSLABS_CLOUDTRAIL)
    assert hub._child_env(hub._servers["identity"])["SENTINEL_BACKEND"] == "aws"
    assert sorted(stopped) == ["cloudtrail_mock", "github", "identity", "logs"]  # restart lazily with the new env
    assert run(rewire_hub(hub, True)) is False
    assert run(rewire_hub(hub, False)) is True  # and back
    assert not hub.is_registered(AWSLABS_CLOUDTRAIL)
    assert hub._child_env(hub._servers["github"])["SENTINEL_BACKEND"] == "offline"


def test_rewire_restarts_a_running_child_with_the_new_backend(hub: MCPHub, monkeypatch: pytest.MonkeyPatch) -> None:
    import sentinel.mcp_hub as mh

    toy = hub._servers["toy"]

    def wire(h, _settings, live):  # stand-in for _wire: re-register the toy server for the new backend
        h.aws_live = live
        h.register("toy", toy.command, label=toy.label, env={"TOY_BACKEND": "aws" if live else "offline"})

    monkeypatch.setattr(mh, "_wire", wire)

    async def scenario():
        hub.aws_live = False
        first = await hub.call("toy", "echo", {"x": "a"})
        assert await mh.rewire_hub(hub, True)
        second = await hub.call("toy", "echo", {"x": "b"})
        await hub.close()
        return first, second

    first, second = run(scenario())
    assert first["backend"] == "offline" and second["backend"] == "aws"
    assert first["pid"] != second["pid"] and toy.running is False  # old child stopped, new one started lazily
