"""Shared data model. Plain dataclasses, JSON-friendly via ``to_dict()``.

Timestamps are ISO-8601 strings in UTC with a trailing ``Z``
(see :func:`iso`), so they sort lexicographically.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

SEVERITIES = ("critical", "high", "medium", "low", "info")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime | str | None = None) -> str:
    """Normalise a datetime (or ISO string) to ``YYYY-MM-DDTHH:MM:SSZ``."""
    if dt is None:
        dt = utcnow()
    if isinstance(dt, str):
        dt = parse_ts(dt)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_ts(v: str | datetime | int | float) -> datetime:
    """Parse ISO strings (with or without Z / offset), datetimes and epoch seconds/ms."""
    if isinstance(v, datetime):
        return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
    if isinstance(v, (int, float)):
        secs = v / 1000.0 if v > 1e11 else float(v)
        return datetime.fromtimestamp(secs, tz=timezone.utc)
    s = str(v).strip().replace("Z", "+00:00")
    dt = datetime.fromisoformat(s)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


class _Dict:
    def to_dict(self) -> dict[str, Any]:
        return asdict(self)  # type: ignore[arg-type]


@dataclass
class Event(_Dict):
    """One normalised security-relevant event from any source."""

    id: str
    ts: str
    source: str  # "cloudtrail" | "github" | "app-auth" | "logs"
    kind: str  # e.g. "AttachUserPolicy", "login_failed", "secret_scanning_alert"
    actor: str = ""  # IAM user name / app user / repo
    ip: str = ""
    outcome: str = "success"  # "success" | "denied" | "failure" | "info"
    region: str = ""
    summary: str = ""
    access_key_id: str = ""
    error_code: str = ""
    live: bool = False  # True when it came from real AWS (CloudTrail/CloudWatch/S3)
    simulated: bool = False  # True for simulated app traffic written by our scripts
    tags: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class SecretAlert(_Dict):
    """GitHub secret-scanning alert (always synthetic in this project)."""

    number: int
    state: str  # "open" | "resolved"
    secret_type: str  # "aws_access_key_id"
    access_key_id: str
    repository: str
    path: str
    commit_sha: str
    created_at: str
    html_url: str
    pusher: str = ""
    live: bool = False


@dataclass
class Incident(_Dict):
    id: str  # "INC-001"
    title: str
    severity: str
    status: str  # "open" | "mitigated" | "resolved"
    summary: str
    created_at: str
    updated_at: str
    rule_ids: list[str] = field(default_factory=list)
    entities: dict[str, Any] = field(default_factory=dict)
    events: list[Event] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    recommended_actions: list[str] = field(default_factory=list)  # action type ids
    data_mode: str = "synthetic"  # "live" | "synthetic" | "mixed"
    counts: dict[str, int] = field(default_factory=dict)

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "Incident":
        d = dict(d)
        d["events"] = [Event(**e) for e in d.get("events", [])]
        return Incident(**d)


@dataclass
class Action(_Dict):
    id: str  # "ACT-0001"
    incident_id: str
    type: str  # key in actions.ACTION_CATALOG
    title: str
    description: str
    target: dict[str, Any] = field(default_factory=dict)
    status: str = "proposed"  # proposed|rejected|executed|simulated|failed|superseded
    real_capable: bool = False
    proposed_by: str = "rules"  # "rules" | "agent"
    reason: str = ""
    created_at: str = ""
    decided_by: str = ""
    decided_at: str = ""
    result: dict[str, Any] = field(default_factory=dict)
    # Non-secret fingerprint of what the incident was about when this was proposed (actions.incident_subject);
    # "" for actions stored before subjects existed.
    subject: str = ""


@dataclass
class AuditEntry(_Dict):
    seq: int
    ts: str
    actor: str
    action: str
    incident_id: str
    details: dict[str, Any]
    prev_hash: str
    hash: str


@dataclass
class TraceEntry(_Dict):
    """One tool call made while answering / detecting, shown in the UI trace."""

    server: str  # "CloudTrail MCP", "Identity MCP", "Logs MCP", "GitHub MCP", "Bedrock", "S3", "IAM"
    tool: str  # "lookup_events", "converse", ...
    target: str  # "aws" | "offline" | "local"
    backend: str = ""  # "awslabs.cloudtrail-mcp-server", "boto3", "mock", "cloudwatch-logs", ...
    ok: bool = True
    ms: int = 0
    summary: str = ""  # "7 events"
    region: str = ""
    error: str = ""
