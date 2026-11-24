"""Pipeline tests with fake DataSources and a fake ``sentinel.actions`` module."""
from __future__ import annotations

import asyncio
import sys
import types
from dataclasses import replace
from datetime import timedelta

import pytest

import sentinel
from sentinel.config import load_settings
from sentinel.models import Event, SecretAlert
from sentinel.pipeline import run_detection
from sentinel.store import SQLiteStore
from tests.test_engine import KEY, NOW, alert, arjun, inc001_events, priya_burst

LIVE_KEY = "AKIAEXAMPLEZZZZD1234"  # synthetic placeholder, not a real key


class FakeSources:
    """Implements the slice of ``DataSources`` that the pipeline uses."""

    def __init__(self, *, live: bool, alerts: list[SecretAlert], ct: dict[str, list[Event]],
                 offline_alerts: list[SecretAlert] | None = None, offline_ct: dict[str, list[Event]] | None = None,
                 auth: list[Event] | None = None, fail_auth: bool = False):
        self.live = live
        self.fallbacks: dict[str, dict] = {}
        self._alerts, self._ct = alerts, ct
        self._offline_alerts, self._offline_ct = offline_alerts or [], offline_ct or {}
        self._auth, self._fail_auth = auth or [], fail_auth
        self.lookups: list[tuple[str, bool]] = []

    def note_fallback(self, component: str, reason: str) -> None:
        self.fallbacks[component] = {"component": component, "reason": reason, "ts": "2026-11-20T13:00:00Z"}

    async def github_alerts(self, state: str = "open", force_offline: bool = False) -> list[SecretAlert]:
        return list(self._offline_alerts if force_offline else self._alerts)

    async def cloudtrail_lookup(self, attribute_key, attribute_value, hours_back=None, regions=None,
                                max_events=200, force_offline=False):
        assert attribute_key == "AccessKeyId"
        self.lookups.append((attribute_value, force_offline))
        events = (self._offline_ct if force_offline else self._ct).get(attribute_value, [])
        live = self.live and not force_offline
        return list(events), {"live": live, "backend": "boto3" if live else "mock", "count": len(events)}

    async def auth_events(self, user=None, hours_back=None, outcome=None, force_offline=False):
        if self._fail_auth:
            raise RuntimeError("identity server crashed")
        return list(self._auth), {"live": False}


@pytest.fixture
def ensured(monkeypatch) -> list[str]:
    """Replace sentinel.actions with a fake that records ensure_recommended calls."""
    calls: list[str] = []
    fake = types.ModuleType("sentinel.actions")
    fake.ensure_recommended = lambda store, incident: calls.append(incident.id) or []
    monkeypatch.setitem(sys.modules, "sentinel.actions", fake)
    monkeypatch.setattr(sentinel, "actions", fake, raising=False)
    return calls


def run(sources, store, settings):
    return asyncio.run(run_detection(sources, store, settings, now=NOW))


def offline_sources() -> FakeSources:
    return FakeSources(live=False, alerts=[alert()], ct={KEY: inc001_events()}, auth=priya_burst() + arjun())


def test_offline_run_detects_persists_and_traces(ensured):
    store, settings = SQLiteStore(), load_settings()
    out = run(offline_sources(), store, settings)
    assert out["mode"] == "offline" and out["fallbacks"] == []
    assert [(i["id"], i["severity"], i["data_mode"]) for i in out["incidents"]] == [
        ("INC-001", "critical", "synthetic"), ("INC-002", "high", "synthetic")]
    assert [s["entity"] for s in out["suppressed"]] == ["arjun"]
    assert any(t["server"] == "Rule engine" and t["summary"] == "2 incidents, 1 suppressed" for t in out["trace"])
    assert [i.id for i in store.list_incidents()] == ["INC-001", "INC-002"]
    assert ensured == ["INC-001", "INC-002"]


def test_incident_opened_audit_is_idempotent_and_created_at_kept(ensured):
    store, settings = SQLiteStore(), load_settings()
    run(offline_sources(), store, settings)
    first_created = store.get_incident("INC-001").created_at
    store.set_incident_status("INC-002", "mitigated")
    asyncio.run(run_detection(offline_sources(), store, settings, now=NOW + timedelta(minutes=5)))
    opened = [a for a in store.list_audit() if a.action == "incident_opened"]
    assert sorted(a.incident_id for a in opened) == ["INC-001", "INC-002"]
    assert store.verify_audit_chain()
    assert store.get_incident("INC-001").created_at == first_created
    assert store.get_incident("INC-002").status == "mitigated"  # a human's decision is never reopened
    assert ensured == ["INC-001", "INC-002"] * 2


def test_live_demo_key_without_events_falls_back_to_synthetic_inc001(ensured):
    settings = load_settings(demo_leaked_access_key_id=LIVE_KEY, cloudtrail_regions=["ap-south-1", "us-east-1"])
    sources = FakeSources(
        live=True, alerts=[alert(key=LIVE_KEY)], ct={},
        offline_alerts=[alert(key=KEY)], offline_ct={KEY: inc001_events()},
    )
    out = run(sources, SQLiteStore(), settings)
    inc = out["incidents"][0]
    assert inc["id"] == "INC-001" and inc["severity"] == "critical"
    assert inc["entities"]["access_key_id"] == KEY and inc["data_mode"] == "synthetic"
    assert sources.lookups == [(LIVE_KEY, False), (KEY, True)]
    reason = sources.fallbacks["cloudtrail"]["reason"]
    assert reason == ("No live CloudTrail events for AKIA…1234 in the last 24 h yet; "
                      "Event history can lag ~15 min. Showing synthetic INC-001.")
    assert LIVE_KEY not in reason
    assert out["mode"] == "aws" and out["fallbacks"][0]["component"] == "cloudtrail"


def test_live_demo_key_with_live_events_is_live(ensured):
    settings = load_settings(demo_leaked_access_key_id=LIVE_KEY)
    live_events = [replace(e, access_key_id=LIVE_KEY) for e in inc001_events(live=True)]
    sources = FakeSources(live=True, alerts=[alert(key=LIVE_KEY)], ct={LIVE_KEY: live_events})
    out = run(sources, SQLiteStore(), settings)
    inc = out["incidents"][0]
    assert inc["data_mode"] == "live" and inc["entities"]["access_key_id"] == LIVE_KEY
    assert "GitHub alert is synthetic" in inc["evidence"][-1]
    assert sources.fallbacks == {} and sources.lookups == [(LIVE_KEY, False)]


def test_source_exception_becomes_fallback_not_crash(ensured):
    sources = FakeSources(live=False, alerts=[alert()], ct={KEY: inc001_events()}, fail_auth=True)
    out = run(sources, SQLiteStore(), load_settings())
    assert [i["id"] for i in out["incidents"]] == ["INC-001"]
    assert "identity lookup failed (RuntimeError)" in sources.fallbacks["identity"]["reason"]


class ExpiringSources(FakeSources):
    """Live at the start; the live CloudTrail lookup fails (expired token) and flips ``live`` to False."""

    async def cloudtrail_lookup(self, attribute_key, attribute_value, hours_back=None, regions=None,
                                max_events=200, force_offline=False):
        if force_offline:
            return await super().cloudtrail_lookup(attribute_key, attribute_value, hours_back, regions,
                                                   max_events, force_offline)
        self.lookups.append((attribute_value, False))
        self.live = False  # what AwsSessionFactory.mark_failure does
        reason = f"boto3 LookupEvents failed (ExpiredTokenException for {attribute_value})"
        self.note_fallback("cloudtrail", reason)
        return [], {"live": False, "backend": "mock", "fallback_reason": reason, "count": 0}


def test_credentials_expiring_mid_run_still_shows_synthetic_inc001_with_the_real_reason(ensured):
    settings = load_settings(demo_leaked_access_key_id=LIVE_KEY)
    sources = ExpiringSources(
        live=True, alerts=[alert(key=LIVE_KEY)], ct={},
        offline_alerts=[alert(key=KEY)], offline_ct={KEY: inc001_events()}, auth=priya_burst(),
    )
    out = run(sources, SQLiteStore(), settings)
    inc = out["incidents"][0]
    assert inc["id"] == "INC-001" and "R-LEAKED-KEY" in inc["rule_ids"] and inc["entities"]["access_key_id"] == KEY
    assert out["suppressed"] == []
    reason = sources.fallbacks["cloudtrail"]["reason"]
    assert reason.startswith("Live CloudTrail lookup failed (boto3 LookupEvents failed (ExpiredTokenException")
    assert reason.endswith("Showing synthetic INC-001.") and "lag" not in reason
    assert LIVE_KEY not in reason  # masked


def test_live_lookup_failure_is_not_reported_as_event_history_lag(ensured):
    settings = load_settings(demo_leaked_access_key_id=LIVE_KEY)

    class DeniedSources(FakeSources):
        async def cloudtrail_lookup(self, attribute_key, attribute_value, hours_back=None, regions=None,
                                    max_events=200, force_offline=False):
            if not force_offline:
                return [], {"live": False, "backend": "mock", "count": 0,
                            "fallback_reason": "AWS Labs CloudTrail MCP failed (AccessDeniedException)"}
            return await super().cloudtrail_lookup(attribute_key, attribute_value, hours_back, regions,
                                                   max_events, force_offline)

    sources = DeniedSources(live=True, alerts=[alert(key=LIVE_KEY)], ct={},
                            offline_alerts=[alert(key=KEY)], offline_ct={KEY: inc001_events()})
    run(sources, SQLiteStore(), settings)
    assert sources.fallbacks["cloudtrail"]["reason"] == (
        "Live CloudTrail lookup failed (AWS Labs CloudTrail MCP failed (AccessDeniedException)). Showing synthetic INC-001.")


def test_incident_ids_stay_stable_when_the_leaked_key_incident_disappears(ensured):
    store, settings = SQLiteStore(), load_settings()
    run(offline_sources(), store, settings)
    assert [(i.id, i.rule_ids) for i in store.list_incidents()] == [
        ("INC-001", ["R-LEAKED-KEY"]), ("INC-002", ["R-BRUTE-FORCE"])]
    # Second run: no leaked-key incident; detect() numbers the brute force INC-001 by position.
    out = run(FakeSources(live=False, alerts=[], ct={}, auth=priya_burst()), store, settings)
    assert [i["id"] for i in out["incidents"]] == ["INC-002"]
    stored = {i.id: i.rule_ids for i in store.list_incidents()}
    assert stored == {"INC-001": ["R-LEAKED-KEY"], "INC-002": ["R-BRUTE-FORCE"]}  # INC-001 not overwritten, no duplicate
    # A brand-new entity whose positional id is taken gets the next free number.
    other = [replace(e, actor="meera", raw={**e.raw, "user": "meera"}) for e in priya_burst()]
    out = run(FakeSources(live=False, alerts=[], ct={}, auth=other), store, settings)
    assert [(i["id"], i["entities"]["app_user"]) for i in out["incidents"]] == [("INC-003", "meera")]
    assert ensured == ["INC-001", "INC-002", "INC-002", "INC-003"]


def test_live_inc001_and_its_synthetic_twin_share_an_id(ensured):
    store = SQLiteStore()
    settings = load_settings(demo_leaked_access_key_id=LIVE_KEY)
    live_events = [replace(e, access_key_id=LIVE_KEY) for e in inc001_events(live=True)]
    run(FakeSources(live=True, alerts=[alert(key=LIVE_KEY)], ct={LIVE_KEY: live_events}, auth=priya_burst()),
        store, settings)
    out = run(FakeSources(live=True, alerts=[alert(key=LIVE_KEY)], ct={}, offline_alerts=[alert(key=KEY)],
                          offline_ct={KEY: inc001_events()}, auth=priya_burst()), store, settings)
    assert [(i["id"], i["data_mode"]) for i in out["incidents"]] == [("INC-001", "synthetic"), ("INC-002", "synthetic")]


def test_two_stores_on_one_file_keep_one_audit_chain_and_one_incident_opened(tmp_path):
    """Two servers on one var dir: the chain head read + append and 'is it new?' must be atomic across connections."""
    import threading

    from sentinel import store as store_mod

    path = tmp_path / "sentinel.db"
    stores = [SQLiteStore(path), SQLiteStore(path)]
    # Widen the race window: pause between reading the chain head and inserting the new entry.
    real_hash = store_mod.SQLiteStore._entry_hash
    def slow_hash(*a):
        threading.Event().wait(0.01)
        return real_hash(*a)
    barrier = threading.Barrier(2)
    errors: list[BaseException] = []

    def worker(st: SQLiteStore) -> None:
        try:
            barrier.wait()
            for i in range(10):
                st.append_audit("rules", "tick", "INC-001", {"i": i})
            created = st.upsert_incident(__import__("sentinel.models", fromlist=["Incident"]).Incident(
                id="INC-009", title="t", severity="low", status="open", summary="s",
                created_at="2026-01-01T00:00:00Z", updated_at="2026-01-01T00:00:00Z"))
            if created:
                st.append_audit("rules", "incident_opened", "INC-009", {})
        except BaseException as exc:  # pragma: no cover - reported below
            errors.append(exc)

    store_mod.SQLiteStore._entry_hash = staticmethod(slow_hash)
    try:
        threads = [threading.Thread(target=worker, args=(st,)) for st in stores]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
    finally:
        store_mod.SQLiteStore._entry_hash = staticmethod(real_hash)
    assert not errors
    audit = stores[0].list_audit(1000)
    assert stores[0].verify_audit_chain()
    assert len(audit) == 21
    assert sum(e.action == "incident_opened" for e in audit) == 1
