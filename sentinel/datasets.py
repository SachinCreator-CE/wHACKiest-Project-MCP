"""Synthetic demo dataset (offline backup path) and small shared helpers.

Authored timestamps under ``data/`` are written relative to :data:`ANCHOR`.
:func:`shift_records` moves them so the scenario always looks recent: the
anchor lands ``lead_minutes`` before "now" and every other record keeps its
offset from the anchor.

The INC-001 GitHub alert stores the placeholder :data:`KEY_PLACEHOLDER`; it is
replaced at runtime with the live demo key ID or AWS's documented example key
:data:`OFFLINE_LEAKED_KEY`. No real key ID is ever stored in ``data/``.
"""
from __future__ import annotations

import copy
import json
import os
import re
from datetime import datetime, timedelta
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

from .config import Settings, load_settings
from .models import iso, parse_ts, utcnow

OFFLINE_LEAKED_KEY = "AKIAIOSFODNN7EXAMPLE"
ANCHOR = "2026-11-20T12:00:00Z"
KEY_PLACEHOLDER = "{{DEMO_LEAKED_ACCESS_KEY_ID}}"
INC001_SCENARIO = "INC-001"

ALERTS_FILE = "github/secret_scanning_alerts.json"
CLOUDTRAIL_FILE = "cloudtrail/events.json"
AUTH_FILE = "auth/app_auth.jsonl"
USERS_FILE = "identity/users.json"

DEFAULT_SHIFT_FIELDS = ("ts", "eventTime", "created_at", "EventTime")
ALERT_SHIFT_FIELDS = ("created_at", "updated_at", "resolved_at")
SIMULATION_SCENARIOS = ("INC-002", "benign-arjun")
DATASET_SUFFIXES = (".json", ".jsonl")

_RELATIVE_RE = re.compile(r"^(\d+)\s*(second|sec|minute|min|hour|hr|day|week)s?\s+ago$")
_UNIT_SECONDS = {"second": 1, "sec": 1, "minute": 60, "min": 60, "hour": 3600, "hr": 3600, "day": 86400, "week": 604800}


# --- paths & loading ---------------------------------------------------------------------------

def safe_relpath(rel: str) -> str:
    """Validate a dataset path: relative, POSIX-style, no ``..``. Returns it normalised."""
    if not rel or not isinstance(rel, str):
        raise ValueError("dataset name is required")
    if "\\" in rel or "\x00" in rel:
        raise ValueError(f"invalid dataset name: {rel!r}")
    p = PurePosixPath(rel)
    if p.is_absolute() or ".." in p.parts or re.match(r"^[A-Za-z]:", rel):
        raise ValueError(f"dataset name must be a relative path without '..': {rel!r}")
    return str(p)


def data_path(rel: str, settings: Settings | None = None) -> Path:
    """Absolute path of ``rel`` inside the data directory (rejects traversal)."""
    base = (settings or load_settings()).data_dir.resolve()
    path = (base / safe_relpath(rel)).resolve()
    if not path.is_relative_to(base):
        raise ValueError(f"dataset path escapes the data directory: {rel!r}")
    return path


def parse_records(text: str, name: str) -> list[dict]:
    """Parse ``.jsonl`` (one object per line) or ``.json`` (a list, or CloudTrail's ``{"Records": [...]}``)."""
    if name.endswith(".jsonl"):
        return [json.loads(line) for line in text.splitlines() if line.strip()]
    doc = json.loads(text)
    if isinstance(doc, dict) and isinstance(doc.get("Records"), list):
        doc = doc["Records"]
    if not isinstance(doc, list) or not all(isinstance(r, dict) for r in doc):
        raise ValueError(f"{name}: expected a JSON list of objects")
    return doc


def load_records(rel: str, settings: Settings | None = None) -> list[dict]:
    """Load a dataset file from ``data/`` as a list of dicts."""
    path = data_path(rel, settings)
    return parse_records(path.read_text(encoding="utf-8"), path.name)


def list_dataset_names(settings: Settings | None = None) -> list[str]:
    """Relative POSIX paths of every dataset under ``data/`` (e.g. ``cloudtrail/events.json``)."""
    base = (settings or load_settings()).data_dir
    if not base.is_dir():
        return []
    return sorted(
        p.relative_to(base).as_posix()
        for p in base.rglob("*")
        if p.is_file() and p.suffix in DATASET_SUFFIXES and not any(part.startswith(".") for part in p.relative_to(base).parts)
    )


# --- time handling -----------------------------------------------------------------------------

def _as_dt(value: datetime | str | None) -> datetime:
    return utcnow() if value is None else parse_ts(value)


def parse_time_expr(value: str | datetime | int | float | None, now: datetime | None = None) -> datetime | None:
    """Parse ``"now"``, ``"N hours/days/... ago"``, ISO-8601 or epoch seconds/ms. ``None``/"" -> ``None``."""
    if value is None or (isinstance(value, str) and not value.strip()):
        return None
    now = _as_dt(now)
    if isinstance(value, (datetime, int, float)):
        return parse_ts(value)
    text = value.strip().lower()
    if text == "now":
        return now
    m = _RELATIVE_RE.match(text)
    if m:
        return now - timedelta(seconds=int(m.group(1)) * _UNIT_SECONDS[m.group(2)])
    if text.isdigit():
        return parse_ts(int(text))
    try:
        return parse_ts(value.strip())
    except ValueError as exc:
        raise ValueError(f"unrecognised time {value!r}; use ISO-8601, 'now' or e.g. '24 hours ago'") from exc


def _shift_in_place(obj: Any, delta: timedelta, fields: frozenset[str]) -> None:
    if isinstance(obj, list):
        for item in obj:
            _shift_in_place(item, delta, fields)
        return
    if not isinstance(obj, dict):
        return
    for key, val in obj.items():
        if key in fields and isinstance(val, str) and val:
            try:
                obj[key] = iso(parse_ts(val) + delta)
            except ValueError:
                continue  # not a timestamp: leave untouched
        else:
            _shift_in_place(val, delta, fields)


def shift_records(
    records: Iterable[dict],
    now: datetime | str | None = None,
    anchor: datetime | str = ANCHOR,
    lead_minutes: float = 30,
    fields: Iterable[str] = DEFAULT_SHIFT_FIELDS,
) -> list[dict]:
    """Deep-copy ``records`` and shift every ``fields`` timestamp (at any depth) by ``now - lead - anchor``."""
    delta = _as_dt(now) - timedelta(minutes=lead_minutes) - parse_ts(anchor)
    out = copy.deepcopy(list(records))
    _shift_in_place(out, delta, frozenset(fields))
    return out


# --- scenario builders -------------------------------------------------------------------------

def _replace_placeholder(obj: Any, key: str) -> Any:
    if isinstance(obj, str):
        return obj.replace(KEY_PLACEHOLDER, key)
    if isinstance(obj, dict):
        return {k: _replace_placeholder(v, key) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_replace_placeholder(v, key) for v in obj]
    return obj


def synthetic_alerts(
    now: datetime | str | None = None,
    live_key: str | None = None,
    flagged_at: datetime | str | None = None,
    settings: Settings | None = None,
) -> list[dict]:
    """GitHub secret-scanning alerts with recent timestamps and the INC-001 key filled in."""
    raw = load_records(ALERTS_FILE, settings)
    alerts = shift_records(raw, now, fields=ALERT_SHIFT_FIELDS)
    key = live_key or OFFLINE_LEAKED_KEY
    out: list[dict] = []
    for original, alert in zip(raw, alerts):
        if original.get("access_key_id") == KEY_PLACEHOLDER:
            alert = _replace_placeholder(alert, key)
            if flagged_at is not None:
                alert["created_at"] = alert["updated_at"] = iso(flagged_at)
        out.append(alert)
    return out


def synthetic_cloudtrail_records(now: datetime | str | None = None, settings: Settings | None = None) -> list[dict]:
    """CloudTrail record JSON (the ``CloudTrailEvent`` detail), shifted to look recent."""
    return shift_records(load_records(CLOUDTRAIL_FILE, settings), now)


def synthetic_auth_records(now: datetime | str | None = None, settings: Settings | None = None) -> list[dict]:
    """App auth log records (INC-002, benign-arjun and background), shifted to look recent."""
    return shift_records(load_records(AUTH_FILE, settings), now)


def app_auth_simulation_records(now: datetime | str | None = None, settings: Settings | None = None) -> list[dict]:
    """INC-002 + arjun records for ``simulate_app_auth.py``; the last one lands a minute before ``now``."""
    recs = [r for r in load_records(AUTH_FILE, settings) if r.get("scenario") in SIMULATION_SCENARIOS]
    if not recs:
        return []
    latest = max(parse_ts(r["ts"]) for r in recs)
    shifted = shift_records(recs, now, anchor=latest, lead_minutes=1, fields=("ts",))
    for r in shifted:
        r["simulated"] = True
    return sorted(shifted, key=lambda r: r["ts"])


def load_users(settings: Settings | None = None) -> list[dict]:
    """Identity directory from ``data/identity/users.json``."""
    return load_records(USERS_FILE, settings)


# --- backend selection for the MCP servers ------------------------------------------------------

def backend_choice(settings: Settings) -> tuple[str, str | None]:
    """``("aws", None)`` when ``SENTINEL_BACKEND=aws`` is allowed, else ``("offline", reason|None)``."""
    requested = (os.environ.get("SENTINEL_BACKEND") or "offline").strip().lower()
    if requested != "aws":
        return "offline", None
    if settings.offline_only:
        return "offline", "SENTINEL_MODE=offline"
    return "aws", None
