"""GitHub secret-scanning MCP server (mock).

The GitHub side of the demo is always synthetic. With ``SENTINEL_BACKEND=aws`` and
``DEMO_LEAKED_ACCESS_KEY_ID`` set, the INC-001 alert carries the live demo key so it
can be joined with real CloudTrail; otherwise it carries AWS's documented example key.
An explicit ``offline`` argument overrides ``SENTINEL_BACKEND``: ``DataSources`` passes
``offline=not live`` on every call, so a hub started while AWS was unreachable still
serves the live key once AWS connects (``SENTINEL_MODE=offline`` always wins).

Run: ``python -m sentinel.mcp_servers.github_mock`` (stdio).
"""
from __future__ import annotations

import logging
import sys
from datetime import datetime

from mcp.server.mcpserver import MCPServer

from ..config import Settings, leak_flagged_at, load_settings
from ..datasets import backend_choice, synthetic_alerts
from ..models import utcnow

log = logging.getLogger("sentinel.mcp.github")
mcp = MCPServer("GitHub MCP (mock)", log_level="WARNING")

ALERT_STATES = ("open", "resolved", "all")


def flagged_at_for_live(settings: Settings, now: datetime) -> datetime:
    """``DEMO_LEAK_FLAGGED_AT`` if valid, else the start of the CloudTrail lookback window."""
    return leak_flagged_at(settings, now)


@mcp.tool()
def list_secret_scanning_alerts(state: str = "open", offline: bool | None = None) -> dict:
    """List GitHub secret-scanning alerts for the org. state: "open", "resolved" or "all"."""
    state = (state or "open").strip().lower()
    if state not in ALERT_STATES:
        raise ValueError(f"state must be one of {', '.join(ALERT_STATES)}")
    settings = load_settings()
    now = utcnow()
    live_key = settings.demo_leaked_access_key_id
    if offline is None:  # not told: follow the backend this server was started with
        use_live = backend_choice(settings)[0] == "aws"
    else:  # the caller (DataSources) decides per call, so a hub started while AWS was down still follows AWS
        use_live = not offline and not settings.offline_only
    if use_live and live_key:
        alerts = synthetic_alerts(now, live_key=live_key, flagged_at=flagged_at_for_live(settings, now), settings=settings)
        key_source = "env"
    else:
        alerts = synthetic_alerts(now, settings=settings)
        key_source = "offline"
    if state != "all":
        alerts = [a for a in alerts if a.get("state") == state]
    return {"alerts": alerts, "backend": "mock", "key_source": key_source}


def main() -> None:
    logging.basicConfig(stream=sys.stderr, level=logging.WARNING)
    mcp.run()


if __name__ == "__main__":
    main()
