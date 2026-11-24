"""Logs MCP server: raw log datasets.

With ``SENTINEL_BACKEND=aws`` datasets are read from ``s3://{S3_BUCKET}/{S3_RAW_PREFIX}<name>``
(via ``sentinel.aws.s3``); otherwise, or on any failure, from ``data/<name>``. Offline
datasets are time-shifted the same way as the other offline tools so timestamps agree.

Run: ``python -m sentinel.mcp_servers.logs`` (stdio).
"""
from __future__ import annotations

import json
import logging
import sys

from mcp.server.mcpserver import MCPServer

from ..aws.session import AwsSessionFactory, safe_reason
from ..config import Settings, load_settings
from ..datasets import (
    ALERTS_FILE,
    DATASET_SUFFIXES,
    backend_choice,
    list_dataset_names,
    load_records,
    parse_records,
    safe_relpath,
    shift_records,
    synthetic_alerts,
)
from ..models import utcnow

log = logging.getLogger("sentinel.mcp.logs")
mcp = MCPServer("Logs MCP", log_level="WARNING")

MAX_LIMIT = 5_000

_aws: AwsSessionFactory | None = None  # created lazily, only on the aws backend


class BackendUnavailable(Exception):
    """The aws backend is not configured; the message is a safe fallback reason."""


def _aws_factory(settings: Settings) -> AwsSessionFactory:
    global _aws
    if not settings.s3_bucket:
        raise BackendUnavailable("S3_BUCKET is not set")
    if _aws is None:
        _aws = AwsSessionFactory(settings)
    return _aws


def _reason(exc: BaseException) -> str:
    return str(exc) if isinstance(exc, BackendUnavailable) else safe_reason(exc)


def validate_name(name: str) -> str:
    """Dataset names are relative ``.json``/``.jsonl`` paths without ``..``."""
    rel = safe_relpath(name)
    if not rel.endswith(DATASET_SUFFIXES):
        raise ValueError(f"dataset must be a .json or .jsonl file: {name!r}")
    return rel


def filter_contains(records: list[dict], contains: str | None) -> list[dict]:
    """Keep records whose JSON contains ``contains`` (case-insensitive)."""
    if not contains:
        return records
    needle = contains.lower()
    return [r for r in records if needle in json.dumps(r, default=str).lower()]


def _s3_list(settings: Settings) -> list[str]:
    from ..aws.s3 import list_keys

    prefix = settings.s3_raw_prefix
    keys = list_keys(_aws_factory(settings), settings.s3_bucket, prefix)
    names = (str(k["key"])[len(prefix):] for k in keys)
    return sorted(n for n in names if n.endswith(DATASET_SUFFIXES))


def _s3_read(settings: Settings, name: str) -> list[dict]:
    from ..aws.s3 import get_text

    text = get_text(_aws_factory(settings), settings.s3_bucket, f"{settings.s3_raw_prefix}{name}")
    return parse_records(text, name)


class UnknownDataset(LookupError):
    """A well-formed dataset name that does not exist (a caller mistake, not an outage)."""


def _s3_missing(exc: BaseException) -> bool:
    response = getattr(exc, "response", None)
    code = response.get("Error", {}).get("Code", "") if isinstance(response, dict) else ""
    return code in ("NoSuchKey", "404")


def _offline_read(settings: Settings, name: str) -> list[dict]:
    now = utcnow()
    try:
        if name == ALERTS_FILE:
            return synthetic_alerts(now, settings=settings)
        return shift_records(load_records(name, settings), now)
    except FileNotFoundError:
        raise UnknownDataset(f"unknown dataset {name!r}; call list_datasets") from None


@mcp.tool()
def list_datasets() -> dict:
    """Names of the raw log datasets that read_dataset accepts (e.g. "cloudtrail/events.json")."""
    settings = load_settings()
    backend, reason = backend_choice(settings)
    if backend == "aws":
        try:
            return {"datasets": _s3_list(settings), "backend": "s3", "live": True, "fallback_reason": None}
        except Exception as exc:  # incl. ImportError: any failure -> offline fallback
            reason = _reason(exc)
            log.warning("S3 unavailable, listing offline datasets: %s", reason)
    return {"datasets": list_dataset_names(settings), "backend": "offline", "live": False, "fallback_reason": reason}


@mcp.tool()
def read_dataset(name: str, limit: int = 200, contains: str | None = None) -> dict:
    """Read up to `limit` records of a dataset, optionally only those containing `contains` (case-insensitive).

    An unknown dataset is not an error or an outage: the result has empty records and an "error"
    message pointing at list_datasets (no exception, no local path, no fallback).
    """
    rel = validate_name(name)
    limit = max(1, min(int(limit), MAX_LIMIT))
    settings = load_settings()
    backend, reason = backend_choice(settings)
    records: list[dict] | None = None
    s3_missing = False
    if backend == "aws":
        try:
            records = _s3_read(settings, rel)
        except Exception as exc:  # incl. NoSuchKey/ImportError: any failure -> offline fallback
            s3_missing = _s3_missing(exc)
            reason = _reason(exc)
            log.warning("S3 read failed for %s, using offline data: %s", rel, reason)
    live = records is not None
    if records is None:
        try:
            records = _offline_read(settings, rel)
        except UnknownDataset as exc:
            # S3 answered "no such key" and there is no local copy either: S3 itself is fine.
            return {
                "name": rel,
                "records": [],
                "total": 0,
                "error": str(exc),
                "backend": "s3" if s3_missing else "offline",
                "live": s3_missing,
                "fallback_reason": None if s3_missing else reason,
            }
    matched = filter_contains(records, contains)
    return {
        "name": rel,
        "records": matched[:limit],
        "total": len(matched),
        "backend": "s3" if live else "offline",
        "live": live,
        "fallback_reason": reason,
    }


def main() -> None:
    logging.basicConfig(stream=sys.stderr, level=logging.WARNING)
    mcp.run()


if __name__ == "__main__":
    main()
