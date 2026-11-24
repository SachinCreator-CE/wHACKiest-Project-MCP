"""CloudTrail MCP server (mock) with the AWS Labs ``lookup_events`` contract.

Same tool name, parameters and result shape as ``awslabs.cloudtrail-mcp-server``, so
callers can swap between the real server and this one. It serves the synthetic
CloudTrail records and, like CloudTrail Event history, returns management events only,
newest first, paginated with ``next_token``.

Run: ``python -m sentinel.mcp_servers.cloudtrail_mock`` (stdio).
"""
from __future__ import annotations

import json
import logging
import sys
from datetime import datetime

from mcp.server.mcpserver import MCPServer

from ..config import load_settings
from ..datasets import parse_time_expr, synthetic_cloudtrail_records
from ..models import iso, parse_ts, utcnow

mcp = MCPServer("CloudTrail MCP (mock)", log_level="WARNING")

ATTRIBUTE_KEYS = (
    "EventId", "EventName", "ReadOnly", "Username", "ResourceType", "ResourceName", "EventSource", "AccessKeyId",
)
DEFAULT_MAX_RESULTS = 10
MAX_RESULTS_CAP = 50
_TOKEN_PREFIX = "mock:"

# requestParameters key -> CloudTrail resource type, used to build LookupEvents "Resources".
_RESOURCE_PARAMS = {"userName": "AWS::IAM::User", "policyArn": "AWS::IAM::Policy", "bucketName": "AWS::S3::Bucket"}


def resources_for(record: dict) -> list[dict]:
    """LookupEvents-style ``Resources`` derived from the record's request parameters."""
    params = record.get("requestParameters") or {}
    return [
        {"ResourceType": rtype, "ResourceName": str(params[key])}
        for key, rtype in _RESOURCE_PARAMS.items()
        if params.get(key)
    ]


def to_lookup_event(record: dict) -> dict:
    """Wrap a CloudTrail record the way LookupEvents (and the AWS Labs server) returns it."""
    ident = record.get("userIdentity") or {}
    return {
        "EventId": record.get("eventID", ""),
        "EventName": record.get("eventName", ""),
        "ReadOnly": str(bool(record.get("readOnly"))).lower(),
        "AccessKeyId": ident.get("accessKeyId", ""),
        "EventTime": iso(record["eventTime"]),
        "EventSource": record.get("eventSource", ""),
        "Username": ident.get("userName", ""),
        "Resources": resources_for(record),
        "CloudTrailEvent": json.dumps(record, separators=(",", ":")),
    }


def _matches(event: dict, key: str, value: str) -> bool:
    if key in ("ResourceType", "ResourceName"):
        return any(r[key] == value for r in event["Resources"])
    return event[key] == value


def _decode_token(token: str | None) -> int:
    if not token:
        return 0
    if not token.startswith(_TOKEN_PREFIX) or not token[len(_TOKEN_PREFIX):].isdigit():
        raise ValueError("invalid next_token")
    return int(token[len(_TOKEN_PREFIX):])


def query_events(
    records: list[dict],
    *,
    start: datetime,
    end: datetime,
    region: str,
    attribute_key: str | None = None,
    attribute_value: str | None = None,
) -> list[dict]:
    """All matching events (management only, newest first) before pagination."""
    out = []
    for rec in records:
        if rec.get("awsRegion") != region or rec.get("managementEvent") is False:
            continue
        if not start <= parse_ts(rec["eventTime"]) <= end:
            continue
        event = to_lookup_event(rec)
        if attribute_key and not _matches(event, attribute_key, attribute_value or ""):
            continue
        out.append(event)
    out.sort(key=lambda e: (e["EventTime"], e["EventId"]), reverse=True)
    return out


@mcp.tool()
def lookup_events(
    start_time: str | None = None,
    end_time: str | None = None,
    attribute_key: str | None = None,
    attribute_value: str | None = None,
    max_results: int | None = None,
    next_token: str | None = None,
    region: str = "us-east-1",
) -> dict:
    """Look up CloudTrail management events (Event history) in one region.

    start_time/end_time accept ISO-8601 or relative times like "1 day ago", "24 hours ago", "now"
    (defaults: "1 day ago" .. "now"). attribute_key is one of EventId, EventName, ReadOnly, Username,
    ResourceType, ResourceName, EventSource, AccessKeyId. max_results is 1-50 (default 10).
    """
    if attribute_key is not None and attribute_key not in ATTRIBUTE_KEYS:
        raise ValueError(f"attribute_key must be one of {', '.join(ATTRIBUTE_KEYS)}")
    if attribute_key and not attribute_value:
        raise ValueError("attribute_value is required when attribute_key is set")
    now = utcnow()
    start = parse_time_expr(start_time or "1 day ago", now)
    end = parse_time_expr(end_time or "now", now)
    if start > end:
        raise ValueError("start_time must be before end_time")
    page_size = max(1, min(int(max_results or DEFAULT_MAX_RESULTS), MAX_RESULTS_CAP))
    offset = _decode_token(next_token)

    records = synthetic_cloudtrail_records(now, settings=load_settings())
    matched = query_events(
        records, start=start, end=end, region=region, attribute_key=attribute_key, attribute_value=attribute_value
    )
    page = matched[offset:offset + page_size]
    more = offset + page_size < len(matched)
    return {
        "events": page,
        "next_token": f"{_TOKEN_PREFIX}{offset + page_size}" if more else None,
        "query_params": {
            "start_time": iso(start),
            "end_time": iso(end),
            "attribute_key": attribute_key,
            "attribute_value": attribute_value,
            "max_results": page_size,
            "region": region,
        },
    }


def main() -> None:
    logging.basicConfig(stream=sys.stderr, level=logging.WARNING)
    mcp.run()


if __name__ == "__main__":
    main()
