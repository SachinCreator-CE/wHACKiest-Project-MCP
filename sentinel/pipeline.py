"""Detection pipeline: fetch data through ``DataSources``, run the rule engine,
persist incidents, propose the recommended actions and audit new incidents.

AWS is the primary path. When the live demo key has no CloudTrail events yet
(Event history lags ~15 min) INC-001 is rebuilt from the offline alert and mock
CloudTrail, and the reason is recorded as a ``cloudtrail`` fallback so the UI
banner explains it.
"""
from __future__ import annotations

import asyncio
import logging
import re
from datetime import datetime
from typing import Any, Awaitable, TypeVar

from . import trace
from .config import Settings
from .engine import DetectionResult, detect
from .masking import mask_access_key, mask_text
from .models import Event, Incident, SecretAlert, utcnow
from .store import Store

log = logging.getLogger(__name__)
T = TypeVar("T")

RULES_ACTOR = "sentinel-rules"


async def _guarded(sources: Any, component: str, call: Awaitable[T], default: T) -> T:
    """Await a source call; an exception that escaped the source's own fallback becomes a noted fallback."""
    try:
        return await call
    except Exception as exc:  # noqa: BLE001 - detection must never crash the app
        log.warning("%s source failed: %s", component, type(exc).__name__)
        sources.note_fallback(component, f"{component} lookup failed ({type(exc).__name__}); continuing without it.")
        return default


def _is_live(events: list[Event]) -> bool:
    return any(e.live for e in events)


def _lookup_failure(sources: Any, meta: dict[str, Any]) -> str | None:
    """Why the live lookup did not reach AWS, or None when AWS answered (an empty answer means lag)."""
    if meta.get("live"):
        return None
    reason = meta.get("fallback_reason") or (sources.fallbacks.get("cloudtrail") or {}).get("reason")
    reason = re.sub(r"\s+", " ", str(reason or "AWS did not answer")).strip()
    return reason[:300]


async def _synthetic_inc001(sources: Any, live_alert: SecretAlert, hours: int, regions: list[str]
                            ) -> tuple[SecretAlert, list[Event]] | None:
    """Offline twin of the live INC-001 alert (same alert number) plus its mock CloudTrail events."""
    offline = await _guarded(sources, "github", sources.github_alerts(state="open", force_offline=True), [])
    if not offline:
        return None
    alert = next((a for a in offline if a.number == live_alert.number), offline[0])
    events, _ = await _guarded(
        sources, "cloudtrail",
        sources.cloudtrail_lookup("AccessKeyId", alert.access_key_id, hours_back=hours, regions=regions,
                                  force_offline=True),
        ([], {}),
    )
    return alert, events


async def _gather(sources: Any, settings: Settings
                  ) -> tuple[list[SecretAlert], dict[str, list[Event]], dict[str, str], list[Event]]:
    """Alerts, CloudTrail events per key, data mode per key, and app-auth events."""
    hours = settings.cloudtrail_lookback_hours
    regions = list(settings.cloudtrail_regions)
    demo_key = settings.demo_leaked_access_key_id
    # Snapshot before any lookup: a failed live call (e.g. expired session token) marks AWS as not connected
    # mid-run, and that must not stop the synthetic INC-001 twin from replacing the live alert.
    live_at_start = await asyncio.to_thread(lambda: bool(sources.live))
    alerts_in = await _guarded(sources, "github", sources.github_alerts(state="open"), [])

    alerts: list[SecretAlert] = []
    events_by_key: dict[str, list[Event]] = {}
    data_modes: dict[str, str] = {}
    for alert in alerts_in:
        if alert.state != "open" or alert.access_key_id in events_by_key:
            continue
        events, meta = await _guarded(
            sources, "cloudtrail",
            sources.cloudtrail_lookup("AccessKeyId", alert.access_key_id, hours_back=hours, regions=regions),
            ([], {}),
        )
        live_demo_key = bool(demo_key) and alert.access_key_id == demo_key and (live_at_start or sources.live)
        if live_demo_key and not _is_live(events):
            failure = _lookup_failure(sources, meta)
            twin = await _synthetic_inc001(sources, alert, hours, regions)
            if twin is not None:
                if failure is None:
                    reason = (f"No live CloudTrail events for {mask_access_key(demo_key)} in the last {hours} h yet; "
                              "Event history can lag ~15 min. Showing synthetic INC-001.")
                else:
                    reason = f"Live CloudTrail lookup failed ({failure}). Showing synthetic INC-001."
                sources.note_fallback("cloudtrail", mask_text(reason))
                alert, events = twin
        alerts.append(alert)
        events_by_key[alert.access_key_id] = events
        data_modes[alert.access_key_id] = "live" if _is_live(events) else "synthetic"

    auth, _ = await _guarded(sources, "identity", sources.auth_events(hours_back=hours), ([], {}))
    return alerts, events_by_key, data_modes, auth


def _identity(inc: Incident) -> tuple[str, str]:
    """What an incident is about: its rule plus the alert number (leaked key) or app user (brute force).

    The alert number, not the key, identifies a leaked-key incident, so the live INC-001 and its
    synthetic twin (same alert number, different key) share one id.
    """
    rule = inc.rule_ids[0] if inc.rule_ids else ""
    ent = inc.entities or {}
    entity = ent.get("alert_number") if ent.get("alert_number") is not None else ent.get("app_user") or ent.get("access_key_id")
    return rule, str(entity or "").strip().casefold()


def _stable_ids(store: Store, incidents: list[Incident]) -> None:
    """Keep incident ids stable across runs.

    ``detect`` numbers incidents by position, so when one disappears (say INC-001 is not produced) the
    next one would take its number and be upserted onto a different incident with that incident's
    actions. Reuse the stored id of the same (rule, entity); give a new entity a fresh number when its
    positional id already belongs to a different incident.
    """
    stored = {inc.id: _identity(inc) for inc in store.list_incidents()}
    by_identity = {ident: inc_id for inc_id, ident in stored.items()}
    taken = set(stored)
    claimed: set[str] = set()
    pending: list[Incident] = []
    for inc in incidents:
        ident = _identity(inc)
        known = by_identity.get(ident)
        if known is not None and known not in claimed:
            inc.id = known
        elif stored.get(inc.id, ident) != ident or inc.id in claimed:
            pending.append(inc)
            continue
        claimed.add(inc.id)
    for inc in pending:
        n = 1
        while f"INC-{n:03d}" in taken or f"INC-{n:03d}" in claimed:
            n += 1
        inc.id = f"INC-{n:03d}"
        claimed.add(inc.id)


def _persist(store: Store, incidents: list[Incident]) -> None:
    """Upsert incidents (keeping the first-seen created_at), audit new incidents once, propose actions."""
    from . import actions  # lazy: pulls in the IAM/report stack, which the pure engine does not need

    _stable_ids(store, incidents)
    for inc in incidents:
        existing = store.get_incident(inc.id)
        if existing is not None:
            inc.created_at = existing.created_at
        created = store.upsert_incident(inc)  # atomic, so a concurrent writer cannot audit it a second time
        if created:
            store.append_audit(RULES_ACTOR, "incident_opened", inc.id, {
                "title": inc.title,
                "severity": inc.severity,
                "rule_ids": inc.rule_ids,
                "data_mode": inc.data_mode,
            })
        actions.ensure_recommended(store, inc)


async def run_detection(sources: Any, store: Store, settings: Settings, *, now: datetime | None = None
                        ) -> dict[str, Any]:
    """Run all rules end to end. Returns unmasked dicts; the API masks at the edge.

    -> {"incidents", "suppressed", "fallbacks", "trace", "mode": "aws"|"offline"}
    """
    now = now or utcnow()
    with trace.collect() as entries:
        alerts, events_by_key, data_modes, auth = await _gather(sources, settings)
        with trace.span("Rule engine", "detect", target="local", backend="sentinel.engine") as sp:
            result: DetectionResult = detect(alerts, events_by_key, auth, now=now, data_modes=data_modes)
            sp.summary = f"{len(result.incidents)} incidents, {len(result.suppressed)} suppressed"
        _persist(store, result.incidents)

    return {
        "incidents": [inc.to_dict() for inc in result.incidents],
        "suppressed": list(result.suppressed),
        "fallbacks": list(sources.fallbacks.values()),
        "trace": [e.to_dict() for e in entries],
        "mode": "aws" if sources.live else "offline",
    }
