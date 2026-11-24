"""Remediation actions: catalog, proposals, the real-action safety gate, and human approval.

The agent and the rule engine can only *propose* actions. :func:`approve` is the one place
that executes anything, and it runs a real AWS write (``iam:UpdateAccessKey``) only when
:func:`real_action_gate` passes; otherwise it simulates and records every reason why.
The execution target (IAM user + key) is always read from ``incident.entities``, never
from the proposal, so an agent cannot redirect a real write.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import re
import threading
import unicodedata
from typing import TYPE_CHECKING, Any

from . import trace
from .aws.iam_actions import set_access_key_status
from .aws.session import safe_reason
from .masking import ACCESS_KEY_RE, mask_access_key, mask_obj, mask_text
from .models import Action, Incident, iso

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .aws.session import AwsSessionFactory
    from .config import Settings
    from .reports import ReportWriter
    from .store import SQLiteStore

# AWS's documented example key, used for the offline scenario. Never a real write target.
SYNTHETIC_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
# Approver names that identify the app, the rule engine or a model, never a human. Names are
# normalised (lowercase, letters/digits only) and refused when they equal or start with a prefix.
NON_HUMAN_APPROVERS = frozenset({"agent", "bedrock", "system", "rules", "sentinel"})
NON_HUMAN_APPROVER_PREFIXES = ("agent", "bedrock", "system", "rules", "sentinel", "copilot", "amazonnova")
NON_HUMAN_APPROVER_NAMES = frozenset({"ai", "bot", "llm", "nova", "model", "auto", "automation", "preview", "root"})
MAX_APPROVER_LEN = 64
SYSTEM_ACTOR = "sentinel"

ACTION_CATALOG: dict[str, dict[str, Any]] = {
    "deactivate_access_key": {
        "title": "Deactivate leaked access key",
        "description": "Set the leaked IAM access key to Inactive (iam:UpdateAccessKey), then verify with ListAccessKeys.",
        "real_capable": True,
        "mitigates": True,
        "entities": ("iam_user", "access_key_id"),
    },
    "resolve_github_alert": {
        "title": "Resolve GitHub secret-scanning alert",
        "description": "Close the secret-scanning alert as 'revoked' once the key is disabled.",
        "real_capable": False,
        "mitigates": False,
        "entities": ("repository", "alert_number"),
    },
    "notify_owner": {
        "title": "Notify the owner",
        "description": "Tell the key / account owner what happened and what was done.",
        "real_capable": False,
        "mitigates": False,
        "entities": ("iam_user", "app_user", "repository"),
    },
    "force_password_reset": {
        "title": "Force password reset",
        "description": "Require the targeted app user to set a new password at next login.",
        "real_capable": False,
        "mitigates": True,
        "entities": ("app_user",),
    },
    "block_ip": {
        "title": "Block attacker IPs",
        "description": "Add the attacking source IPs to the app's deny list.",
        "real_capable": False,
        "mitigates": True,
        "entities": ("attacker_ips",),
    },
    "revoke_sessions": {
        "title": "Revoke active sessions",
        "description": "Invalidate the targeted app user's sessions and refresh tokens.",
        "real_capable": False,
        "mitigates": True,
        "entities": ("app_user",),
    },
}


class ActionNotFound(LookupError):
    """Unknown action id, or the action's incident no longer exists."""


# Action ids currently being approved in this process (guards against concurrent double-approval).
_inflight: set[str] = set()
_inflight_lock = threading.Lock()


def _spec(action_type: str) -> dict[str, Any]:
    try:
        return ACTION_CATALOG[action_type]
    except KeyError:
        raise ValueError(f"unknown action type {action_type!r}; expected one of {sorted(ACTION_CATALOG)}") from None


def _entity_target(incident: Incident, spec: dict[str, Any]) -> dict[str, Any]:
    return {k: incident.entities[k] for k in spec["entities"] if incident.entities.get(k) not in (None, "", [])}


def proposal_problem(incident: Incident, action_type: str) -> str | None:
    """Why ``action_type`` cannot be proposed for ``incident``, or None when it can.

    Only action types the detection rules recommend for this incident may be proposed, and only
    when the incident carries the entities the action needs; anything else (e.g. an agent
    following an injected instruction) would be an empty, misleading action.
    """
    spec = _spec(action_type)
    if action_type not in incident.recommended_actions:
        allowed = ", ".join(incident.recommended_actions) or "none"
        return f"{action_type} is not a recommended action for {incident.id} (recommended: {allowed})"
    if not _entity_target(incident, spec):
        return f"{incident.id} has none of the entities {action_type} needs ({', '.join(spec['entities'])})"
    return None


def incident_subject(incident: Incident) -> str:
    """Non-secret fingerprint of what an incident is about: its rule, target entities and whether it is live.

    One incident id can change subject between runs (the synthetic INC-001 twin becomes the live INC-001
    with a different key; synthetic data turns live). Actions remember the subject they were proposed for,
    so a decision about the old subject neither blocks nor mitigates the new one, and a stale proposal
    can never be approved against a different key.
    """
    ent = incident.entities or {}
    canon = json.dumps([
        incident.rule_ids[0] if incident.rule_ids else "",
        str(ent.get("access_key_id") or ""),
        str(ent.get("iam_user") or ""),
        str(ent.get("app_user") or "").strip().casefold(),
        incident.data_mode == "live",
    ])
    return hashlib.sha256(canon.encode()).hexdigest()[:16]


def _for_subject(action: Action, subject: str) -> bool:
    return not action.subject or action.subject == subject


def _live_change_pending(action: Action) -> bool:
    """True for a real-capable action that was only simulated on a live incident (the real resource is unchanged)."""
    return action.status == "simulated" and bool((action.result or {}).get("live_change_pending"))


def _settled(action: Action) -> bool:
    """True when the action already achieved its effect (simulated, or executed and verified).

    A real-capable action that was only simulated on a live incident did not: the real key is still Active.
    """
    if action.status == "simulated":
        return not _live_change_pending(action)
    return action.status == "executed" and bool((action.result or {}).get("verification", {}).get("verified"))


def _retryable(action: Action) -> bool:
    """A failed, executed-but-unverified, or live-but-simulated action may be proposed again (UpdateAccessKey is idempotent)."""
    return (
        action.status == "failed"
        or (action.status == "executed" and not _settled(action))
        or _live_change_pending(action)
    )


def propose(
    store: SQLiteStore,
    incident: Incident,
    action_type: str,
    *,
    proposed_by: str = "rules",
    reason: str = "",
    target: dict[str, Any] | None = None,
) -> Action:
    """Create a proposed action, or return the existing one for (incident, type).

    An existing ``proposed`` action is returned as is, and so is the latest action of that type
    when it already took effect (simulated, or executed and verified), so nobody can queue a
    duplicate on a mitigated incident. A failed, unverified or rejected one may be proposed again.
    Entity-derived target fields override anything in ``target``; the stored target is masked
    and informational only (execution re-reads ``incident.entities``).
    Raises ``ValueError`` for an unknown type, a type not in ``incident.recommended_actions``,
    or an incident without the entities the action targets (see :func:`proposal_problem`).
    """
    spec = _spec(action_type)
    problem = proposal_problem(incident, action_type)
    if problem:
        raise ValueError(problem)
    subject = incident_subject(incident)
    same = [a for a in store.list_actions(incident.id)  # ordered by id
            if a.type == action_type and _for_subject(a, subject)]
    for existing in same:
        if existing.status == "proposed":
            return existing
    if same and _settled(same[-1]):
        return same[-1]
    action = store.add_action(
        Action(
            id="",
            incident_id=incident.id,
            type=action_type,
            title=spec["title"],
            description=spec["description"],
            target=mask_obj({**(target or {}), **_entity_target(incident, spec)}),
            real_capable=spec["real_capable"],
            proposed_by=proposed_by,
            reason=reason,
            subject=subject,
        )
    )
    store.append_audit(
        proposed_by,
        "action_proposed",
        incident.id,
        {"action_id": action.id, "type": action_type, "reason": reason},
    )
    return action


def ensure_recommended(store: SQLiteStore, incident: Incident) -> list[Action]:
    """Propose each recommended action type once per incident.

    A type whose latest action is proposed, settled (simulated / executed and verified) or
    rejected is not re-proposed, so re-running detection never resurrects an approved or
    rejected action. A failed or unverified real execution is re-proposed so it can be retried.
    Only actions proposed for the incident's current subject count (see :func:`incident_subject`);
    pending proposals for an earlier subject are superseded first.
    """
    supersede_stale(store, incident)
    subject = incident_subject(incident)
    by_type: dict[str, Action] = {}
    for a in store.list_actions(incident.id):
        if _for_subject(a, subject):
            by_type[a.type] = a  # list is ordered by id, so the latest wins
    out: list[Action] = []
    for action_type in incident.recommended_actions:
        if action_type not in ACTION_CATALOG or proposal_problem(incident, action_type):
            continue
        if action_type not in by_type or _retryable(by_type[action_type]):
            rules = ", ".join(incident.rule_ids) or "detection rules"
            by_type[action_type] = propose(store, incident, action_type, reason=f"Recommended by {rules}")
        out.append(by_type[action_type])
    _reconcile_status(store, incident)
    return out


def _reconcile_status(store: SQLiteStore, incident: Incident) -> None:
    """Keep the stored status in line with the actions taken for the incident's *current* subject.

    When an incident changes subject (the synthetic INC-001 twin becomes live with the real key) a
    simulated deactivation of the old key must not leave the live incident 'mitigated'; and when it
    changes back, the earlier verified mitigation counts again.
    """
    stored = store.get_incident(incident.id)
    if stored is None or stored.status not in {"open", "mitigated"}:
        return
    status = "mitigated" if mitigated_for_subject(store, incident) else "open"
    if status == stored.status:
        return
    store.set_incident_status(incident.id, status)
    store.append_audit(SYSTEM_ACTOR, "incident_reopened" if status == "open" else "incident_mitigated", incident.id, {
        "from": stored.status,
        "to": status,
        "data_mode": incident.data_mode,
        "reason": "status follows the actions taken for the incident's current target",
    })


def supersede_stale(store: SQLiteStore, incident: Incident) -> list[Action]:
    """Mark proposed actions whose subject is no longer the incident's as ``superseded`` (never approvable)."""
    subject = incident_subject(incident)
    out: list[Action] = []
    for a in store.list_actions(incident.id):
        if a.status != "proposed" or _for_subject(a, subject):
            continue
        with _inflight_lock:
            if a.id in _inflight:
                continue  # being approved right now; the gate refuses a real run for a changed subject
            current = store.get_action(a.id)
            if current is None or current.status != "proposed":
                continue
            current.status = "superseded"
            current.decided_by = SYSTEM_ACTOR
            current.decided_at = iso()
            current.result = {"mode": "none", "reason": f"{incident.id} now shows a different target; superseded by a new proposal."}
            store.update_action(current)
        store.append_audit(SYSTEM_ACTOR, "action_superseded", incident.id, {"action_id": a.id, "type": a.type})
        out.append(current)
    return out


def mitigated_for_subject(store: SQLiteStore, incident: Incident) -> bool:
    """True when an action that mitigates this incident already took effect for its current subject."""
    subject = incident_subject(incident)
    return any(
        _for_subject(a, subject) and _settled(a) and ACTION_CATALOG.get(a.type, {}).get("mitigates")
        and a.type in incident.recommended_actions
        for a in store.list_actions(incident.id)
    )


_INVISIBLE_CATEGORIES = ("Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp")


def clean_approver(approver: str | None) -> str:
    """Display form of an approver name: no control/bidi/format characters, collapsed spaces, capped length."""
    text = "".join(" " if unicodedata.category(ch) in _INVISIBLE_CATEGORIES else ch for ch in str(approver or ""))
    return re.sub(r"\s+", " ", text).strip()[:MAX_APPROVER_LEN].strip()


def approver_problem(approver: str | None) -> str | None:
    """Why ``approver`` cannot be recorded as a human approver, or None when it can."""
    name = clean_approver(approver)
    if not name:
        return "An approver name is required"
    if not is_human_approver(name):
        return f"{name!r} is a reserved system/agent name; enter the name of the human approving this"
    return None


def is_human_approver(approver: str) -> bool:
    norm = re.sub(r"[^a-z0-9]", "", clean_approver(approver).lower())
    if not norm:
        return False
    return not (
        norm in NON_HUMAN_APPROVERS
        or norm in NON_HUMAN_APPROVER_NAMES
        or norm.startswith(NON_HUMAN_APPROVER_PREFIXES)
    )


def real_action_gate(
    action: Action, incident: Incident, settings: Settings, aws_connected: bool, approver: str
) -> tuple[bool, list[str]]:
    """Decide whether ``action`` may run against real AWS. Returns ``(run_real, reasons_if_not)``.

    Every failing condition is reported (not just the first), so the UI can explain the simulation.
    """
    reasons: list[str] = []
    if not ACTION_CATALOG.get(action.type, {}).get("real_capable"):
        return False, [f"'{action.type}' has no real AWS implementation; it is always simulated"]
    if action.incident_id != incident.id:
        reasons.append(f"action belongs to {action.incident_id}, not {incident.id}")
    if action.subject and action.subject != incident_subject(incident):
        reasons.append(f"action was proposed for an earlier target of {incident.id}; the incident now shows a different key")
    if not is_human_approver(approver):
        reasons.append(f"approver {approver!r} is not a human (agent/system approvals never run real actions)")
    if not settings.allow_real_actions:
        reasons.append("ALLOW_REAL_ACTIONS is off")
    if incident.data_mode != "live":
        reasons.append(f"incident data is {incident.data_mode!r}, not live AWS")
    if not aws_connected:
        reasons.append("AWS is not connected")
    user = str(incident.entities.get("iam_user") or "")
    if not user:
        reasons.append("incident has no iam_user entity")
    elif user not in settings.real_action_user_allowlist:
        reasons.append(f"IAM user {user!r} is not in REAL_ACTION_USER_ALLOWLIST")
    key = str(incident.entities.get("access_key_id") or "")
    if not key:
        reasons.append("incident has no access_key_id entity")
    elif key == SYNTHETIC_ACCESS_KEY:
        reasons.append("target key is the synthetic example key AKIAIOSFODNN7EXAMPLE")
    elif not ACCESS_KEY_RE.fullmatch(key):
        reasons.append("target key is not a valid AWS access key ID")
    return not reasons, reasons


async def _aws_connected(aws: AwsSessionFactory | None) -> bool:
    if aws is None:
        return False
    try:
        status = await asyncio.to_thread(aws.status)
    except Exception:  # noqa: BLE001 - a broken status check simply means "not connected"
        return False
    return bool(status.connected)


async def _run_real_deactivation(aws: AwsSessionFactory, incident: Incident) -> tuple[str, dict[str, Any]]:
    """Run UpdateAccessKey(Status=Inactive) + verification. Returns (status, partial result)."""
    user = str(incident.entities["iam_user"])
    key = str(incident.entities["access_key_id"])
    with trace.span("IAM", "update_access_key", target="aws", backend="boto3") as sp:
        try:
            outcome = await asyncio.to_thread(set_access_key_status, aws, user, key, "Inactive")
        except Exception as exc:  # noqa: BLE001 - recorded on the action, never raised to the approver
            aws.mark_failure(exc)
            sp.ok, sp.error = False, safe_reason(exc)
            return "failed", {
                "error": safe_reason(exc),
                "verification": {"method": "iam:ListAccessKeys", "verified": False, "observed_status": "unknown"},
                "summary": f"UpdateAccessKey failed: {safe_reason(exc)}",
            }
        verified = bool(outcome["verified"])
        sp.summary = f"{mask_access_key(key)} → {outcome['status']}" + (" (verified)" if verified else " (NOT verified)")
    result: dict[str, Any] = {
        "verification": {"method": "iam:ListAccessKeys", "verified": verified, "observed_status": outcome["status"]},
        "summary": f"Access key {mask_access_key(key)} of {user} set to Inactive"
        + ("; ListAccessKeys confirms Inactive." if verified else f"; ListAccessKeys shows {outcome['status']}."),
    }
    if not verified:
        result["warning"] = "UpdateAccessKey succeeded but verification did not show Inactive"
    return "executed", result


def _simulate(action: Action, incident: Incident, reasons: list[str]) -> dict[str, Any]:
    server, tool = ("IAM", "update_access_key") if action.type == "deactivate_access_key" else ("Remediation", action.type)
    with trace.span(server, tool, target="offline", backend="simulated") as sp:
        sp.summary = "simulated: " + "; ".join(reasons)
    expected = {"expected_status": "Inactive"} if action.type == "deactivate_access_key" else {}
    return {
        "verification": {"method": "simulated", "verified": False, **expected},
        "summary": f"Simulated '{ACTION_CATALOG[action.type]['title']}' for {incident.id}; no external change was made.",
    }


async def approve(
    action_id: str,
    approver: str,
    *,
    store: SQLiteStore,
    settings: Settings,
    aws: AwsSessionFactory | None,
    reports: ReportWriter | None,
) -> Action:
    """Human approval: audit, execute (real or simulated), audit the outcome, write a report.

    Raises :class:`ActionNotFound` for unknown actions/incidents and ``ValueError`` for an empty
    approver or an action that is not in ``proposed`` state (double approval).
    """
    approver = mask_text(clean_approver(approver))
    if not approver:
        raise ValueError("approver is required")
    with _inflight_lock:
        action = store.get_action(action_id)
        if action is None:
            raise ActionNotFound(f"unknown action {action_id}")
        if action_id in _inflight:
            raise ValueError(f"{action_id} is already being approved")
        if action.status != "proposed":
            raise ValueError(f"{action_id} was already decided ({action.status}); it cannot be approved again")
        incident = store.get_incident(action.incident_id)
        if incident is None:
            raise ActionNotFound(f"incident {action.incident_id} for {action_id} not found")
        if not _for_subject(action, incident_subject(incident)):
            raise ValueError(f"{action_id} was proposed for an earlier target of {incident.id}; run detection and "
                             "approve the new proposal")
        _inflight.add(action_id)
    try:
        return await _approve_claimed(action, incident, approver, store, settings, aws, reports)
    finally:
        with _inflight_lock:
            _inflight.discard(action_id)


async def _approve_claimed(
    action: Action,
    incident: Incident,
    approver: str,
    store: SQLiteStore,
    settings: Settings,
    aws: AwsSessionFactory | None,
    reports: ReportWriter | None,
) -> Action:
    store.append_audit(approver, "action_approved", incident.id, {"action_id": action.id, "type": action.type, "proposed_by": action.proposed_by})
    connected = await _aws_connected(aws)
    run_real, reasons = real_action_gate(action, incident, settings, connected, approver)
    started = iso()
    if run_real and aws is not None:
        status, outcome = await _run_real_deactivation(aws, incident)
        mode = "real"
    else:
        status, outcome, mode = "simulated", _simulate(action, incident, reasons), "simulated"
    spec = ACTION_CATALOG[action.type]
    if mode == "simulated" and spec["real_capable"] and incident.data_mode == "live":
        # The leaked key is real and still Active: a simulation must not close a live incident.
        outcome["live_change_pending"] = True
        outcome["summary"] += f" The live AWS resource was not changed, so {incident.id} stays open."
    action.status = status
    action.decided_by = approver
    action.decided_at = iso()
    action.result = mask_obj(
        {
            "mode": mode,
            "started_at": started,
            "ended_at": iso(),
            "approved_by": approver,
            "target": _entity_target(incident, spec),
            "simulated_reasons": reasons if mode == "simulated" else [],
            **outcome,
        }
    )
    store.update_action(action)
    store.append_audit(
        SYSTEM_ACTOR,
        f"action_{status}",
        incident.id,
        {
            "action_id": action.id,
            "type": action.type,
            "mode": mode,
            "approved_by": approver,
            "reasons": action.result["simulated_reasons"],
            "verification": action.result.get("verification", {}),
            "error": action.result.get("error", ""),
        },
    )
    succeeded = _settled(action)
    # Only an action that fits the incident (recommended type, real entity target) can mitigate it.
    fits = action.type in incident.recommended_actions and bool(action.result["target"])
    if succeeded and spec["mitigates"] and fits:
        store.set_incident_status(incident.id, "mitigated")
    if reports is not None:
        # Off the event loop: an S3 upload (timeouts + retries) must not freeze every other request.
        await asyncio.to_thread(_write_report, action, store, reports, live=connected)
    return action


def _write_report(action: Action, store: SQLiteStore, reports: ReportWriter, *, live: bool) -> None:
    """Write the post-approval report and audit it; a report failure never undoes the action."""
    incident = store.get_incident(action.incident_id)
    if incident is None:
        return
    audit = [e for e in reversed(store.list_audit(500)) if e.incident_id == incident.id]
    try:
        info = reports.write(incident, store.list_actions(incident.id), audit, trigger="action_approved", live=live)
    except Exception as exc:  # noqa: BLE001 - recorded in audit + action result
        store.append_audit(SYSTEM_ACTOR, "report_failed", incident.id, {"action_id": action.id, "error": safe_reason(exc)})
        action.result = {**action.result, "report": {"error": safe_reason(exc)}}
    else:
        store.append_audit(SYSTEM_ACTOR, "report_written", incident.id, {"action_id": action.id, **info})
        action.result = {**action.result, "report": mask_obj(info)}
    store.update_action(action)


def reject(action_id: str, approver: str, *, store: SQLiteStore, reason: str = "") -> Action:
    """Human rejection of a proposed action. ``ValueError`` if already decided or no approver."""
    approver = mask_text(clean_approver(approver))
    if not approver:
        raise ValueError("approver is required")
    with _inflight_lock:
        action = store.get_action(action_id)
        if action is None:
            raise ActionNotFound(f"unknown action {action_id}")
        if action_id in _inflight:
            raise ValueError(f"{action_id} is being approved; it cannot be rejected")
        if action.status != "proposed":
            raise ValueError(f"{action_id} was already decided ({action.status}); it cannot be rejected")
        action.status = "rejected"
        action.decided_by = approver
        action.decided_at = iso()
        action.result = mask_obj({"mode": "none", "reason": reason})
        store.update_action(action)
    store.append_audit(approver, "action_rejected", action.incident_id, {"action_id": action.id, "type": action.type, "reason": reason})
    return action
