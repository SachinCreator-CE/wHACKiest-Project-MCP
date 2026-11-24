"""Tools the SOC copilot can call (Bedrock Converse ``toolSpec`` + executors).

Every tool result is masked with :func:`mask_obj` and capped to ~8 KB of JSON
before it is handed to a model. Data tools delegate to :class:`DataSources`
(which traces its own MCP/AWS calls); store-backed tools get a ``local`` span.
``propose_remediation`` only ever creates a *proposed* action: execution is
reserved for the human approve endpoint.
"""
from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from typing import Any, Awaitable, Callable

from .. import trace
from ..config import Settings
from ..masking import mask_obj
from ..models import Event, Incident

MAX_RESULT_CHARS = 8000
MAX_EVENTS = 30
ACTION_TYPES = (
    "deactivate_access_key",
    "resolve_github_alert",
    "notify_owner",
    "force_password_reset",
    "block_ip",
    "revoke_sessions",
)
CLOUDTRAIL_ATTRIBUTES = (
    "AccessKeyId",
    "Username",
    "EventName",
    "EventSource",
    "EventId",
    "ResourceName",
    "ResourceType",
    "ReadOnly",
)
PROPOSAL_NOTE = "Proposed only. Nothing has run: a human must approve it in the SentinelAI UI."


@dataclass
class AgentContext:
    """Everything a tool needs. ``sources``/``aws``/``store`` follow the contract interfaces."""

    settings: Settings
    store: Any
    sources: Any
    aws: Any


class ToolError(ValueError):
    """Bad tool arguments or a missing entity; reported back to the model as an error result."""


def _spec(name: str, description: str, properties: dict[str, Any], required: list[str] | None = None) -> dict:
    schema: dict[str, Any] = {"type": "object", "properties": properties}
    if required:
        schema["required"] = required
    return {"toolSpec": {"name": name, "description": description, "inputSchema": {"json": schema}}}


_INT = {"type": "integer"}
TOOL_SPECS: list[dict[str, Any]] = [
    _spec("list_incidents", "List all SentinelAI incidents with severity, status, data provenance and pending actions.", {}),
    _spec(
        "get_incident",
        "Full detail for one incident: entities, evidence, counts, events (timestamps, IPs, outcomes) and its actions.",
        {"incident_id": {"type": "string", "description": "Incident id, e.g. INC-001."}},
        ["incident_id"],
    ),
    _spec(
        "get_github_secret_alerts",
        "GitHub secret-scanning alerts (synthetic, served by the GitHub MCP mock).",
        {"state": {"type": "string", "enum": ["open", "resolved", "all"], "description": "Alert state filter."}},
    ),
    _spec(
        "lookup_cloudtrail_events",
        "Query CloudTrail Event history (live AWS via the AWS Labs CloudTrail MCP server, or the offline mock). "
        "Masked access key ids such as AKIA…WXYZ are accepted.",
        {
            "attribute_key": {"type": "string", "enum": list(CLOUDTRAIL_ATTRIBUTES)},
            "attribute_value": {"type": "string"},
            "hours_back": {**_INT, "description": "Lookback window in hours (1-168)."},
        },
        ["attribute_key", "attribute_value"],
    ),
    _spec(
        "get_auth_events",
        "Application login/MFA events (simulated app traffic, from CloudWatch Logs when live).",
        {
            "user": {"type": "string", "description": "App user name, e.g. priya."},
            "hours_back": {**_INT, "description": "Lookback window in hours (1-168)."},
            "outcome": {"type": "string", "enum": ["success", "failure"]},
        },
    ),
    _spec(
        "get_user_profile",
        "Directory profile for an app or IAM user (role, usual locations, devices).",
        {"username": {"type": "string"}},
        ["username"],
    ),
    _spec(
        "read_dataset",
        "Read raw records from a log dataset (S3 raw/ when live, local data/ otherwise).",
        {
            "name": {"type": "string", "description": "Dataset path, e.g. cloudtrail/events.json."},
            "contains": {"type": "string", "description": "Only records whose JSON contains this text."},
            "limit": {**_INT, "description": "Max records (1-50)."},
        },
        ["name"],
    ),
    _spec(
        "propose_remediation",
        "PROPOSE a remediation for an incident. This never executes anything; a human must approve it in the UI. "
        "action_type must be one of the incident's recommended_actions.",
        {
            "incident_id": {"type": "string"},
            "action_type": {"type": "string", "enum": list(ACTION_TYPES)},
            "reason": {"type": "string", "description": "One-sentence justification grounded in evidence."},
        },
        ["incident_id", "action_type", "reason"],
    ),
    _spec(
        "get_audit_log",
        "Recent entries of the hash-chained audit log and whether the chain verifies.",
        {"limit": {**_INT, "description": "Max entries (1-50)."}},
    ),
]
TOOL_CONFIG: dict[str, Any] = {"tools": TOOL_SPECS}


# --------------------------------------------------------------------- helpers
def _actions():
    """The ACTIONS module (imported lazily; it is owned by another component)."""
    from .. import actions

    return actions


def _str(args: dict, key: str, *, required: bool = False, max_len: int = 200) -> str | None:
    value = args.get(key)
    if value is None or str(value).strip() == "":
        if required:
            raise ToolError(f"'{key}' is required")
        return None
    return str(value).strip()[:max_len]


def _int(args: dict, key: str, default: int | None, lo: int, hi: int) -> int | None:
    value = args.get(key)
    if value is None or value == "":
        return default
    try:
        return max(lo, min(hi, int(value)))
    except (TypeError, ValueError) as exc:
        raise ToolError(f"'{key}' must be an integer") from exc


def compact_event(e: Event) -> dict[str, Any]:
    """Model-friendly event: drop raw payloads and empty fields."""
    d = {
        "ts": e.ts,
        "kind": e.kind,
        "actor": e.actor,
        "ip": e.ip,
        "outcome": e.outcome,
        "region": e.region,
        "summary": e.summary[:160],
        "access_key_id": e.access_key_id,
        "error_code": e.error_code,
        "live": e.live,
        "simulated": e.simulated,
    }
    return {k: v for k, v in d.items() if v not in ("", None)}


def _events_block(events: list[Event]) -> dict[str, Any]:
    ordered = sorted(events, key=lambda e: e.ts)
    return {
        "count": len(ordered),
        "first_seen": ordered[0].ts if ordered else None,
        "last_seen": ordered[-1].ts if ordered else None,
        "by_kind": dict(Counter(e.kind for e in ordered)),
        "by_outcome": dict(Counter(e.outcome for e in ordered)),
        "events": [compact_event(e) for e in ordered[-MAX_EVENTS:]],  # the newest, i.e. what just happened
    }


def _cloudtrail_provenance(meta: dict) -> str:
    if meta.get("live"):
        regions = ", ".join(meta.get("regions") or [])
        return f"live AWS CloudTrail Event history via {meta.get('backend', 'aws')} ({regions})"
    return "synthetic CloudTrail records (offline mock)"


def _auth_provenance(meta: dict) -> str:
    if meta.get("live"):
        return f"simulated app traffic stored in live CloudWatch Logs ({meta.get('log_group', '')})"
    return "synthetic app auth log (offline dataset)"


def incident_provenance(inc: Incident) -> str:
    if "R-LEAKED-KEY" in inc.rule_ids:
        return {
            "live": "CloudTrail evidence from live AWS; the GitHub alert is synthetic",
            "mixed": "CloudTrail evidence from live AWS; the GitHub alert is synthetic",
        }.get(inc.data_mode, "synthetic demo data (GitHub alert and CloudTrail records)")
    if inc.data_mode in {"live", "mixed"}:
        return "simulated app traffic read from live AWS CloudWatch Logs"
    return "synthetic demo data"


def _trim(obj: Any, max_items: int, max_str: int) -> Any:
    if isinstance(obj, str):
        return obj if len(obj) <= max_str else obj[:max_str] + "…"
    if isinstance(obj, dict):
        return {k: _trim(v, max_items, max_str) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_trim(v, max_items, max_str) for v in obj[:max_items]]
    return obj


def cap_result(result: dict[str, Any], limit: int = MAX_RESULT_CHARS) -> dict[str, Any]:
    """Shrink lists/strings until the JSON fits ``limit`` chars; flag ``truncated``."""
    if len(json.dumps(result, default=str)) <= limit:
        return result
    for items, chars in ((20, 400), (10, 200), (5, 120), (2, 80)):
        trimmed = {**_trim(result, items, chars), "truncated": True}
        if len(json.dumps(trimmed, default=str)) <= limit:
            return trimmed
    text = json.dumps(result, default=str)
    return {"truncated": True, "preview": text[: limit - 100]}


def _known_key_ids(ctx: AgentContext) -> set[str]:
    keys = {ctx.settings.demo_leaked_access_key_id} if ctx.settings.demo_leaked_access_key_id else set()
    for inc in ctx.store.list_incidents():
        key = inc.entities.get("access_key_id")
        if key:
            keys.add(str(key))
    return keys


def resolve_masked_key(value: str, ctx: AgentContext) -> str:
    """Map a masked key id (``AKIA…WXYZ``) the model saw back to the full id we hold."""
    if "…" not in value and "..." not in value:
        return value
    head, _, tail = value.replace("...", "…").partition("…")
    matches = [k for k in _known_key_ids(ctx) if k.startswith(head) and k.endswith(tail)]
    if len(matches) != 1:
        raise ToolError(f"cannot resolve masked access key id {value!r} to a known key")
    return matches[0]


def _require_incident(ctx: AgentContext, incident_id: str) -> Incident:
    inc = ctx.store.get_incident(incident_id.upper())
    if inc is None:
        raise ToolError(f"incident {incident_id} not found")
    return inc


# -------------------------------------------------------------------- executors
async def _list_incidents(args: dict, ctx: AgentContext) -> dict:
    with trace.span("SentinelAI", "list_incidents", target="local", backend="sqlite") as sp:
        pending = Counter(a.incident_id for a in ctx.store.list_actions() if a.status == "proposed")
        incidents = [
            {
                "id": inc.id,
                "title": inc.title,
                "severity": inc.severity,
                "status": inc.status,
                "rule_ids": inc.rule_ids,
                "summary": inc.summary,
                "created_at": inc.created_at,
                "data_mode": inc.data_mode,
                "provenance": incident_provenance(inc),
                "counts": inc.counts,
                "recommended_actions": inc.recommended_actions,
                "pending_actions": pending.get(inc.id, 0),
            }
            for inc in ctx.store.list_incidents()
        ]
        sp.summary = f"{len(incidents)} incidents"
    return {"incidents": incidents, "count": len(incidents)}


async def _get_incident(args: dict, ctx: AgentContext) -> dict:
    incident_id = _str(args, "incident_id", required=True, max_len=20)
    with trace.span("SentinelAI", "get_incident", target="local", backend="sqlite") as sp:
        inc = _require_incident(ctx, incident_id)
        actions = ctx.store.list_actions(inc.id)
        sp.summary = f"{inc.id} · {len(inc.events)} events"
    body = inc.to_dict()
    body.pop("events")
    return {
        "incident": body,
        "provenance": incident_provenance(inc),
        "timeline": _events_block(inc.events),
        "actions": [
            {
                "id": a.id,
                "type": a.type,
                "title": a.title,
                "status": a.status,
                "proposed_by": a.proposed_by,
                "decided_by": a.decided_by,
                "result": a.result.get("summary") or a.result.get("reason") or "",
            }
            for a in actions
        ],
    }


async def _get_github_secret_alerts(args: dict, ctx: AgentContext) -> dict:
    state = _str(args, "state") or "open"
    alerts = await ctx.sources.github_alerts(state=state)
    return {
        "alerts": [a.to_dict() for a in alerts],
        "count": len(alerts),
        "provenance": "synthetic GitHub secret-scanning alerts (GitHub MCP mock)",
    }


async def _lookup_cloudtrail_events(args: dict, ctx: AgentContext) -> dict:
    key = _str(args, "attribute_key", required=True)
    if key not in CLOUDTRAIL_ATTRIBUTES:
        raise ToolError(f"attribute_key must be one of {', '.join(CLOUDTRAIL_ATTRIBUTES)}")
    value = _str(args, "attribute_value", required=True)
    if key == "AccessKeyId":
        value = resolve_masked_key(value, ctx)
    hours = _int(args, "hours_back", None, 1, 168)
    events, meta = await ctx.sources.cloudtrail_lookup(key, value, hours_back=hours)
    return {**_events_block(events), "provenance": _cloudtrail_provenance(meta), "meta": meta}


async def _get_auth_events(args: dict, ctx: AgentContext) -> dict:
    outcome = _str(args, "outcome")
    if outcome not in (None, "success", "failure"):
        raise ToolError("outcome must be 'success' or 'failure'")
    events, meta = await ctx.sources.auth_events(
        user=_str(args, "user", max_len=80), hours_back=_int(args, "hours_back", None, 1, 168), outcome=outcome
    )
    return {**_events_block(events), "provenance": _auth_provenance(meta), "meta": meta}


async def _get_user_profile(args: dict, ctx: AgentContext) -> dict:
    username = _str(args, "username", required=True, max_len=80)
    user = await ctx.sources.get_user(username)
    return {"user": user, "found": user is not None}


async def _read_dataset(args: dict, ctx: AgentContext) -> dict:
    name = _str(args, "name", required=True)
    records, meta = await ctx.sources.read_dataset(
        name, limit=_int(args, "limit", 20, 1, 50), contains=_str(args, "contains")
    )
    return {"records": records, "count": len(records), "meta": meta}


async def _propose_remediation(args: dict, ctx: AgentContext) -> dict:
    incident_id = _str(args, "incident_id", required=True, max_len=20)
    action_type = _str(args, "action_type", required=True, max_len=60)
    reason = _str(args, "reason", max_len=500) or "Proposed by the SentinelAI copilot."
    actions = _actions()
    if action_type not in actions.ACTION_CATALOG:
        raise ToolError(f"unknown action_type {action_type!r}")
    with trace.span("SentinelAI", "propose_remediation", target="local", backend="sqlite") as sp:
        inc = _require_incident(ctx, incident_id)
        if action_type not in inc.recommended_actions:
            allowed = ", ".join(inc.recommended_actions) or "none"
            raise ToolError(f"{action_type} is not a recommended action for {inc.id}; recommended: {allowed}")
        try:
            action = actions.propose(ctx.store, inc, action_type, proposed_by="agent", reason=reason)
        except ValueError as exc:
            raise ToolError(str(exc)) from None
        sp.summary = f"{action.id} {action.status} (not executed)"
    return {
        "action": {"id": action.id, "type": action.type, "title": action.title, "status": action.status},
        "incident_id": inc.id,
        "executed": False,
        "note": PROPOSAL_NOTE
        if action.status == "proposed"
        else f"Not proposed again: {action.id} was already decided ({action.status}) by {action.decided_by or 'a human'}.",
    }


async def _get_audit_log(args: dict, ctx: AgentContext) -> dict:
    limit = _int(args, "limit", 15, 1, 50)
    with trace.span("SentinelAI", "get_audit_log", target="local", backend="sqlite") as sp:
        entries = ctx.store.list_audit(limit)
        chain_ok = ctx.store.verify_audit_chain()
        sp.summary = f"{len(entries)} entries · chain {'ok' if chain_ok else 'BROKEN'}"
    return {
        "entries": [
            {"seq": e.seq, "ts": e.ts, "actor": e.actor, "action": e.action, "incident_id": e.incident_id, "details": e.details}
            for e in entries
        ],
        "chain_ok": chain_ok,
    }


_EXECUTORS: dict[str, Callable[[dict, AgentContext], Awaitable[dict]]] = {
    "list_incidents": _list_incidents,
    "get_incident": _get_incident,
    "get_github_secret_alerts": _get_github_secret_alerts,
    "lookup_cloudtrail_events": _lookup_cloudtrail_events,
    "get_auth_events": _get_auth_events,
    "get_user_profile": _get_user_profile,
    "read_dataset": _read_dataset,
    "propose_remediation": _propose_remediation,
    "get_audit_log": _get_audit_log,
}
assert set(_EXECUTORS) == {s["toolSpec"]["name"] for s in TOOL_SPECS}


async def run_tool(name: str, args: dict | None, ctx: AgentContext) -> dict:
    """Run one tool. Always returns a masked, size-capped dict; failures carry an ``error`` key."""
    executor = _EXECUTORS.get(name)
    if executor is None:
        return {"error": f"unknown tool {name!r}"}
    try:
        result = await executor(dict(args or {}), ctx)
    except ToolError as exc:
        result = {"error": str(exc)}
    except Exception as exc:  # noqa: BLE001 - surfaced to the model, never crashes the loop
        result = {"error": f"{type(exc).__name__}: {str(exc)[:200]}"}
    return cap_result(mask_obj(result))
