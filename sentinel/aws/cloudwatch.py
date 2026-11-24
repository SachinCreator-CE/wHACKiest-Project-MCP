"""CloudWatch Logs helpers for the app-auth log group.

Records are the JSON app-auth records described in the contract, one per log
event. Writing respects the ``PutLogEvents`` limits (10,000 events, 1 MiB per
batch counting 26 bytes of overhead per event, and a 24 h span per batch).
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any

from ..models import iso, parse_ts

log = logging.getLogger(__name__)

MAX_BATCH_EVENTS = 10_000
MAX_BATCH_BYTES = 1_048_576
EVENT_OVERHEAD_BYTES = 26
MAX_BATCH_SPAN_MS = 24 * 3600 * 1000
_SAFE_USER = re.compile(r"^[A-Za-z0-9_.@+-]{1,128}$")


def _error_code(exc: Exception) -> str:
    response = getattr(exc, "response", None)
    return response.get("Error", {}).get("Code", "") if isinstance(response, dict) else ""


def filter_auth_events(
    aws: Any, log_group: str, start_ms: int, end_ms: int, user: str | None = None, limit: int = 500
) -> list[dict[str, Any]]:
    """``FilterLogEvents`` over ``log_group``; returns the newest ``limit`` parsed records sorted by ``ts``.

    FilterLogEvents pages oldest first, so every page is read before trimming to ``limit``
    (stopping early would keep the oldest records and drop what just happened).

    The user match is case-insensitive, like the offline path. CloudWatch JSON filter patterns
    are case-sensitive, so when ``user`` is a safe identifier the pattern ORs its spellings
    (as given, lower-case, capitalised: ``{ $.user = "priya" || $.user = "Priya" }``) and the
    exact case-insensitive check is applied client-side.
    """
    user = (user or "").strip() or None
    kwargs: dict[str, Any] = {"logGroupName": log_group, "startTime": int(start_ms), "endTime": int(end_ms)}
    if user and _SAFE_USER.match(user):
        spellings = list(dict.fromkeys((user, user.lower(), user.lower().capitalize())))
        kwargs["filterPattern"] = "{ " + " || ".join(f'$.user = "{u}"' for u in spellings) + " }"
    paginator = aws.client("logs").get_paginator("filter_log_events")
    records: list[dict[str, Any]] = []
    for page in paginator.paginate(**kwargs):
        for ev in page.get("events", []):
            try:
                rec = json.loads(ev.get("message", ""))
            except ValueError:
                continue  # not one of our JSON records
            if not isinstance(rec, dict) or (user and str(rec.get("user", "")).lower() != user.lower()):
                continue
            rec.setdefault("ts", iso(parse_ts(int(ev.get("timestamp", 0)))))
            records.append(rec)
    records.sort(key=lambda r: str(r["ts"]))
    return records[-max(1, int(limit)):]


def ensure_log_group(aws: Any, log_group: str, retention_days: int = 7) -> bool:
    """Create ``log_group`` if missing and set its retention. Returns True when created."""
    client = aws.client("logs")
    created = True
    try:
        client.create_log_group(logGroupName=log_group)
    except Exception as exc:
        if _error_code(exc) != "ResourceAlreadyExistsException":
            raise
        created = False
    client.put_retention_policy(logGroupName=log_group, retentionInDays=retention_days)
    return created


def _batches(events: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    """Split time-sorted log events into batches that satisfy PutLogEvents limits."""
    batches: list[list[dict[str, Any]]] = []
    current: list[dict[str, Any]] = []
    size = 0
    for ev in events:
        ev_size = len(ev["message"].encode()) + EVENT_OVERHEAD_BYTES
        if current and (
            len(current) >= MAX_BATCH_EVENTS
            or size + ev_size > MAX_BATCH_BYTES
            or ev["timestamp"] - current[0]["timestamp"] > MAX_BATCH_SPAN_MS
        ):
            batches.append(current)
            current, size = [], 0
        current.append(ev)
        size += ev_size
    if current:
        batches.append(current)
    return batches


def put_auth_events(aws: Any, log_group: str, stream: str, records: list[dict[str, Any]]) -> int:
    """Write ``records`` to ``log_group/stream`` (creating the stream). Returns events sent."""
    client = aws.client("logs")
    try:
        client.create_log_stream(logGroupName=log_group, logStreamName=stream)
    except Exception as exc:
        if _error_code(exc) != "ResourceAlreadyExistsException":
            raise
    events = sorted(
        (
            {"timestamp": int(parse_ts(r["ts"]).timestamp() * 1000), "message": json.dumps(r, sort_keys=True)}
            for r in records
        ),
        key=lambda e: e["timestamp"],
    )
    sent = 0
    for batch in _batches(events):
        resp = client.put_log_events(logGroupName=log_group, logStreamName=stream, logEvents=batch)
        if resp.get("rejectedLogEventsInfo"):
            log.warning("CloudWatch rejected some auth events: %s", resp["rejectedLogEventsInfo"])
        sent += len(batch)
    return sent
