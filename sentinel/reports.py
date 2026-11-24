"""Incident reports: masked Markdown + JSON, stored in S3 (SSE-S3) with a local fallback.

Keys: ``<s3_reports_prefix><INC>/<UTC-ts>.md|.json`` (default prefix ``reports/``). When AWS is not
live, no bucket is configured, or the upload fails, both files go to ``var/reports/<INC>/`` and
the result carries ``fallback_reason``.
"""
from __future__ import annotations

import importlib
import json
import re
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Iterable

from . import trace
from .aws.session import safe_reason
from .masking import mask_obj, mask_text
from .models import Action, AuditEntry, Incident, iso, parse_ts, utcnow

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .aws.session import AwsSessionFactory
    from .config import Settings

SCHEMA = "sentinelai.report/v1"
MAX_TIMELINE_ROWS = 60
MAX_AUDIT_ROWS = 25


def provenance(incident: Incident) -> dict[str, Any]:
    """Describe where the incident's data came from ("live AWS" vs "synthetic")."""
    live_events = sum(1 for e in incident.events if e.live)
    label = "live AWS" if incident.data_mode in {"live", "mixed"} else "synthetic"
    notes = []
    if label == "live AWS":
        notes.append(f"{live_events} of {len(incident.events)} events came from live AWS.")
    if "alert_number" in incident.entities:
        notes.append("GitHub secret-scanning alert: synthetic (mock GitHub MCP).")
    if label == "synthetic":
        notes.append("All evidence is synthetic demo data; no AWS data was used.")
    return {"label": label, "data_mode": incident.data_mode, "live_events": live_events, "total_events": len(incident.events), "notes": notes}


_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f\u0085\u2028\u2029]+")


def _line(v: Any) -> str:
    """One Markdown line of data: no control characters (no forged headings/rows), no raw HTML tags."""
    text = _CONTROL_RE.sub(" ", str(v if v is not None else "")).strip()
    return text.replace("<", "&lt;").replace(">", "&gt;")


def _cell(v: Any) -> str:
    text = ", ".join(map(str, v)) if isinstance(v, (list, tuple)) else str(v if v is not None else "")
    return _line(text).replace("|", "\\|") or "—"


def _table(headers: list[str], rows: Iterable[list[Any]]) -> list[str]:
    out = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    out += ["| " + " | ".join(_cell(c) for c in row) + " |" for row in rows]
    return out


def render_markdown(
    incident: Incident, actions: list[Action], audit: list[AuditEntry], *, trigger: str, generated_at: str
) -> str:
    """Human-readable report. The caller masks the result."""
    prov = provenance(incident)
    lines = [
        f"# {incident.id}: {_line(incident.title)}",
        "",
        f"- **Severity:** {incident.severity}",
        f"- **Status:** {incident.status}",
        f"- **Data provenance:** {prov['label']}",
        f"- **Rules:** {', '.join(incident.rule_ids) or '—'}",
        f"- **Opened:** {incident.created_at} · **Updated:** {incident.updated_at}",
        f"- **Report generated:** {generated_at} (trigger: {trigger})",
        "",
        "## Summary",
        "",
        _line(incident.summary) or "—",
        "",
        "## Entities",
        "",
        *_table(["Entity", "Value"], [[k, v] for k, v in incident.entities.items()]),
        "",
        "## Timeline",
        "",
    ]
    events = sorted(incident.events, key=lambda e: e.ts)
    lines += _table(
        ["Time (UTC)", "Source", "Event", "Actor", "IP", "Region", "Outcome", "Origin"],
        [
            [e.ts, e.source, e.summary or e.kind, e.actor, e.ip, e.region, e.outcome, "live" if e.live else "synthetic"]
            for e in events[:MAX_TIMELINE_ROWS]
        ],
    )
    if len(events) > MAX_TIMELINE_ROWS:
        lines.append(f"\n_{len(events) - MAX_TIMELINE_ROWS} more events omitted._")
    lines += ["", "## Evidence", ""]
    lines += [f"- {_line(item)}" for item in incident.evidence] or ["- —"]
    lines += ["", "## Actions and decisions", ""]
    lines += _table(
        ["Action", "Type", "Status", "Mode", "Proposed by", "Decided by", "Decided at", "Notes"],
        [
            [
                a.id,
                a.type,
                a.status,
                a.result.get("mode", "—"),
                a.proposed_by,
                a.decided_by,
                a.decided_at,
                "; ".join(a.result.get("simulated_reasons", [])) or a.result.get("summary") or a.result.get("reason") or a.reason,
            ]
            for a in actions
        ],
    )
    lines += ["", "## Audit excerpt", ""]
    lines += _table(
        ["Seq", "Time (UTC)", "Actor", "Action", "Hash", "Prev hash"],
        [[e.seq, e.ts, e.actor, e.action, f"`{e.hash[:16]}…`", f"`{e.prev_hash[:16]}…`"] for e in audit[-MAX_AUDIT_ROWS:]],
    )
    lines += ["", "Audit entries are SHA-256 hash-chained; full hashes are in the JSON report.", "", "## Data provenance", ""]
    lines += [f"- **{prov['label']}** (data_mode `{prov['data_mode']}`)"] + [f"- {n}" for n in prov["notes"]]
    return "\n".join(lines) + "\n"


def build_json(
    incident: Incident, actions: list[Action], audit: list[AuditEntry], *, trigger: str, generated_at: str
) -> dict[str, Any]:
    """Machine-readable report (unmasked; the caller masks it)."""
    return {
        "schema": SCHEMA,
        "generated_at": generated_at,
        "trigger": trigger,
        "provenance": provenance(incident),
        "incident": incident.to_dict(),
        "actions": [a.to_dict() for a in actions],
        "audit": [e.to_dict() for e in audit[-MAX_AUDIT_ROWS:]],
    }


def _stamp(dt: datetime) -> str:
    """Sortable UTC timestamp with milliseconds, e.g. ``20261124T120000.123Z``."""
    return dt.strftime("%Y%m%dT%H%M%S.%f")[:-3] + "Z"


class ReportWriter:
    def __init__(self, settings: Settings, aws: AwsSessionFactory | None):
        self.settings = settings
        self.aws = aws

    @property
    def _prefix(self) -> str:
        p = self.settings.s3_reports_prefix.strip("/")
        return f"{p}/" if p else ""

    def _s3_reason(self, live: bool) -> str | None:
        """Why S3 cannot be used, or None when it can."""
        if self.settings.offline_only:
            return "SENTINEL_MODE=offline"
        if not live or self.aws is None:
            return "AWS not connected"
        if not self.settings.s3_bucket:
            return "S3_BUCKET is not set"
        return None

    def write(self, incident: Incident, actions: list[Action], audit: list[AuditEntry], *, trigger: str, live: bool) -> dict[str, Any]:
        """Write masked ``.md`` + ``.json``. Returns ``{"uri","markdown_key","json_key","live", ...}``."""
        now = utcnow()
        generated_at = iso(now)
        # Oldest first by seq whatever order the caller passed (store.list_audit is newest first), so the
        # excerpt keeps the newest MAX_AUDIT_ROWS entries in chain order.
        incident_audit = sorted((e for e in audit if e.incident_id == incident.id), key=lambda e: e.seq)
        markdown = mask_text(render_markdown(incident, actions, incident_audit, trigger=trigger, generated_at=generated_at))
        payload = json.dumps(
            mask_obj(build_json(incident, actions, incident_audit, trigger=trigger, generated_at=generated_at)), indent=2, default=str, ensure_ascii=False
        )
        base = f"{self._prefix}{incident.id}/{_stamp(now)}"
        md_key, json_key = f"{base}.md", f"{base}.json"

        reason = self._s3_reason(live)
        if reason is None:
            try:
                uri = self._put_s3(md_key, markdown, "text/markdown; charset=utf-8")
                self._put_s3(json_key, payload, "application/json")
                return {"uri": uri, "markdown_key": md_key, "json_key": json_key, "live": True, "location": "s3"}
            except Exception as exc:  # noqa: BLE001 - fall back to local disk
                if self.aws is not None:
                    self.aws.mark_failure(exc)
                reason = f"S3 upload failed: {safe_reason(exc)}"
                # A .md that reached S3 before the .json failed stays there (the policy grants no
                # s3:DeleteObject); the full pair is written locally and list() shows each key once.
        path = self._write_local(md_key, markdown, json_key, payload)
        return {
            "uri": path.as_uri(),
            "markdown_key": md_key,
            "json_key": json_key,
            "live": False,
            "location": "local",
            "fallback_reason": reason,
        }

    def _put_s3(self, key: str, body: str, content_type: str) -> str:
        s3 = importlib.import_module("sentinel.aws.s3")  # owned by SOURCES; imported lazily
        with trace.span("S3", "put_object", target="aws", backend="boto3") as sp:
            uri = s3.put_text(self.aws, self.settings.s3_bucket, key, body, content_type=content_type)
            sp.summary = f"{key} ({len(body.encode())} B, SSE-S3)"
        return str(uri)

    def _local_path(self, key: str) -> Path:
        return self.settings.local_reports_dir / key.removeprefix(self._prefix)

    def _write_local(self, md_key: str, markdown: str, json_key: str, payload: str) -> Path:
        md_path = self._local_path(md_key)
        with trace.span("Reports", "write_local", target="local", backend="filesystem") as sp:
            md_path.parent.mkdir(parents=True, exist_ok=True)
            md_path.write_text(markdown, encoding="utf-8")
            self._local_path(json_key).write_text(payload, encoding="utf-8")
            sp.summary = f"{md_path.parent.name}/{md_path.name} (+ .json)"
        return md_path

    def list(self, live: bool) -> list[dict[str, Any]]:
        """Reports newest first: S3 objects (when live) plus local files (always)."""
        items: list[dict[str, Any]] = []
        if self._s3_reason(live) is None:
            try:
                items += self._list_s3()
            except Exception as exc:  # noqa: BLE001 - local listing still works
                if self.aws is not None:
                    self.aws.mark_failure(exc)
        # One entry per key: a report whose S3 upload half-failed also exists locally; prefer the S3 copy.
        seen = {r["key"] for r in items}
        items += [r for r in self._list_local() if r["key"] not in seen]
        return sorted(items, key=lambda r: r["key"].rsplit("/", 1)[-1], reverse=True)

    def _list_s3(self) -> list[dict[str, Any]]:
        s3 = importlib.import_module("sentinel.aws.s3")
        bucket = self.settings.s3_bucket
        with trace.span("S3", "list_objects_v2", target="aws", backend="boto3") as sp:
            objs = s3.list_keys(self.aws, bucket, self._prefix)
            sp.summary = f"{len(objs)} objects"
        out = []
        for o in objs:
            key = str(o["key"])
            fmt = key.rsplit(".", 1)[-1]
            if fmt not in {"md", "json"}:
                continue
            out.append(
                {
                    "key": key,
                    "incident_id": key.removeprefix(self._prefix).split("/", 1)[0],
                    "format": fmt,
                    "size": o.get("size", 0),
                    "last_modified": iso(o["last_modified"]) if o.get("last_modified") else "",
                    "uri": f"s3://{bucket}/{key}",
                    "location": "s3",
                }
            )
        return out

    def _list_local(self) -> list[dict[str, Any]]:
        root = self.settings.local_reports_dir
        if not root.is_dir():
            return []
        out = []
        for path in root.glob("*/*"):
            if path.suffix not in {".md", ".json"} or not path.is_file():
                continue
            st = path.stat()
            out.append(
                {
                    "key": f"{self._prefix}{path.parent.name}/{path.name}",
                    "incident_id": path.parent.name,
                    "format": path.suffix[1:],
                    "size": st.st_size,
                    "last_modified": iso(parse_ts(st.st_mtime)),
                    "uri": path.as_uri(),
                    "location": "local",
                }
            )
        return out
