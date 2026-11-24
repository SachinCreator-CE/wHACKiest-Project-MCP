"""Identity MCP server: app authentication events and the user directory.

With ``SENTINEL_BACKEND=aws`` auth events come from CloudWatch Logs
(``FilterLogEvents`` on ``settings.auth_log_group``, via ``sentinel.aws.cloudwatch``).
Any failure there falls back to the synthetic records and reports ``fallback_reason``.
The directory always comes from ``data/identity/users.json``.

Run: ``python -m sentinel.mcp_servers.identity`` (stdio).
"""
from __future__ import annotations

import logging
import sys
from datetime import datetime, timedelta

from mcp.server.mcpserver import MCPServer

from ..aws.session import AwsSessionFactory, safe_reason
from ..config import Settings, load_settings
from ..datasets import backend_choice, load_users, parse_time_expr, synthetic_auth_records
from ..models import parse_ts, utcnow

log = logging.getLogger("sentinel.mcp.identity")
mcp = MCPServer("Identity MCP", log_level="WARNING")

AUTH_EVENTS = ("login_failed", "login_success", "mfa_challenge", "mfa_success", "mfa_failed", "logout")
FAILURE_EVENTS = frozenset({"login_failed", "mfa_failed"})
OUTCOMES = ("failure", "success")
MAX_LIMIT = 10_000

_aws: AwsSessionFactory | None = None  # created lazily, only on the aws backend


def filter_records(
    records: list[dict],
    *,
    user: str | None = None,
    start: datetime | None = None,
    end: datetime | None = None,
    outcome: str | None = None,
) -> list[dict]:
    """Filter auth records by user (case-insensitive), time window and outcome; sorted by ts."""
    out = []
    for rec in records:
        if user and str(rec.get("user", "")).lower() != user.lower():
            continue
        try:
            ts = parse_ts(rec["ts"])
        except (KeyError, ValueError):
            continue  # malformed record: never let it break the query
        if (start and ts < start) or (end and ts > end):
            continue
        event = rec.get("event")
        if outcome == "failure" and event not in FAILURE_EVENTS:
            continue
        if outcome == "success" and event in FAILURE_EVENTS:
            continue
        if outcome in AUTH_EVENTS and event != outcome:
            continue
        out.append(rec)
    out.sort(key=lambda r: parse_ts(r["ts"]))
    return out


def _cloudwatch_events(settings: Settings, user: str | None, start: datetime, end: datetime, limit: int) -> list[dict]:
    global _aws
    from ..aws.cloudwatch import filter_auth_events as cw_filter_auth_events

    if _aws is None:
        _aws = AwsSessionFactory(settings)
    return cw_filter_auth_events(
        _aws, settings.auth_log_group, int(start.timestamp() * 1000), int(end.timestamp() * 1000), user=user, limit=limit
    )


@mcp.tool()
def filter_auth_events(
    user: str | None = None,
    start_time: str | None = None,
    end_time: str | None = None,
    outcome: str | None = None,
    limit: int = 500,
) -> dict:
    """App auth events (logins, MFA) for an optional user and time window.

    start_time/end_time accept ISO-8601 or "N hours ago"/"now" (default: the CloudTrail lookback window).
    outcome is "failure" (login_failed/mfa_failed), "success", or an exact event name.
    """
    if outcome is not None and outcome not in OUTCOMES + AUTH_EVENTS:
        raise ValueError(f"outcome must be one of {', '.join(OUTCOMES + AUTH_EVENTS)}")
    settings = load_settings()
    now = utcnow()
    start = parse_time_expr(start_time, now) or now - timedelta(hours=settings.cloudtrail_lookback_hours)
    end = parse_time_expr(end_time, now) or now
    limit = max(1, min(int(limit), MAX_LIMIT))

    backend, reason = backend_choice(settings)
    records: list[dict] | None = None
    if backend == "aws":
        try:
            records = _cloudwatch_events(settings, user, start, end, limit)
        except Exception as exc:  # incl. ImportError: any failure -> offline fallback
            reason = safe_reason(exc)
            log.warning("CloudWatch Logs unavailable, using offline auth records: %s", reason)
    live = records is not None
    if records is None:
        records = synthetic_auth_records(now, settings=settings)
    events = filter_records(records, user=user, start=start, end=end, outcome=outcome)[-limit:]
    return {
        "events": events,
        "backend": "cloudwatch-logs" if live else "offline",
        "live": live,
        "log_group": settings.auth_log_group,
        "fallback_reason": reason,
    }


@mcp.tool()
def get_user(username: str) -> dict:
    """Directory profile for one user (case-insensitive), or null if unknown."""
    wanted = (username or "").strip().lower()
    match = next((u for u in load_users() if str(u.get("username", "")).lower() == wanted), None)
    return {"user": match}


@mcp.tool()
def list_users() -> dict:
    """All users in the identity directory."""
    return {"users": load_users()}


def main() -> None:
    logging.basicConfig(stream=sys.stderr, level=logging.WARNING)
    mcp.run()


if __name__ == "__main__":
    main()
