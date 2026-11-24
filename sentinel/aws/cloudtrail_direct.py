"""CloudTrail ``LookupEvents`` through boto3, returning AWS Labs-shaped events.

Used when the AWS Labs CloudTrail MCP server can't start. Events keep the raw
boto3 shape with ``EventTime`` serialised to an ISO string, exactly like the
``awslabs.cloudtrail-mcp-server`` ``lookup_events`` tool, so the same
normaliser handles both.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from ..models import iso

LOOKUP_ATTRIBUTE_KEYS = frozenset(
    {"EventId", "EventName", "ReadOnly", "Username", "ResourceType", "ResourceName", "EventSource", "AccessKeyId"}
)
PAGE_SIZE = 50  # LookupEvents maximum


def _serialize(event: dict[str, Any]) -> dict[str, Any]:
    out = dict(event)
    if isinstance(out.get("EventTime"), datetime):
        out["EventTime"] = iso(out["EventTime"])
    return out


def lookup_events_page(
    aws: Any,
    region: str,
    attribute_key: str | None,
    attribute_value: str | None,
    start: datetime,
    end: datetime,
    next_token: str | None = None,
    max_results: int = PAGE_SIZE,
) -> tuple[list[dict[str, Any]], str | None]:
    """One ``LookupEvents`` call. Returns ``(events, next_token)``."""
    kwargs: dict[str, Any] = {"StartTime": start, "EndTime": end, "MaxResults": max(1, min(PAGE_SIZE, max_results))}
    if attribute_key:
        if attribute_key not in LOOKUP_ATTRIBUTE_KEYS:
            raise ValueError(f"unsupported CloudTrail lookup attribute: {attribute_key}")
        kwargs["LookupAttributes"] = [{"AttributeKey": attribute_key, "AttributeValue": attribute_value or ""}]
    if next_token:
        kwargs["NextToken"] = next_token
    resp = aws.client("cloudtrail", region=region).lookup_events(**kwargs)
    return [_serialize(e) for e in resp.get("Events", [])], resp.get("NextToken")


def lookup_events_direct(
    aws: Any,
    region: str,
    attribute_key: str | None,
    attribute_value: str | None,
    start: datetime,
    end: datetime,
    max_events: int = 200,
) -> list[dict[str, Any]]:
    """Paginate ``LookupEvents`` until exhausted or ``max_events`` are collected."""
    events: list[dict[str, Any]] = []
    token: str | None = None
    while len(events) < max_events:
        page, token = lookup_events_page(
            aws, region, attribute_key, attribute_value, start, end, token, min(PAGE_SIZE, max_events - len(events))
        )
        events.extend(page)
        if not token:
            break
    return events[:max_events]
