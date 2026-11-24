"""Actions + IAM remediation tests. IAM is exercised with botocore Stubber (no AWS credentials needed)."""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any

import boto3
import pytest
from botocore.stub import Stubber

from sentinel import actions, trace
from sentinel.aws import iam_actions
from sentinel.aws.iam_actions import list_access_keys, set_access_key_status
from sentinel.aws.session import AwsStatus
from sentinel.config import load_settings
from sentinel.models import Action, Event, Incident
from sentinel.store import SQLiteStore

LIVE_KEY = "AKIAEXAMPLETESTTLIVE"  # fake but well-formed; not a real key
USER = "sentinel-demo-victim"


class FakeAws:
    """Stand-in for AwsSessionFactory backed by a Stubber-wrapped IAM client."""

    def __init__(self, connected: bool = True):
        self.iam = boto3.client("iam", region_name="us-east-1", aws_access_key_id="testing", aws_secret_access_key="testing")
        self.stub = Stubber(self.iam)
        self.stub.activate()
        self.connected = connected
        self.failures: list[BaseException] = []

    def client(self, service: str, region: str | None = None) -> Any:
        assert service == "iam"
        return self.iam

    def status(self, refresh: bool = False) -> AwsStatus:
        return AwsStatus(self.connected, account_suffix="1234", region="ap-south-1")

    def mark_failure(self, exc: BaseException) -> None:
        self.failures.append(exc)


class FakeReports:
    def __init__(self, fail: bool = False):
        self.calls: list[dict[str, Any]] = []
        self.fail = fail

    def write(self, incident, actions_, audit, *, trigger: str, live: bool) -> dict[str, Any]:
        if self.fail:
            raise RuntimeError("disk full")
        self.calls.append({"incident": incident, "actions": actions_, "audit": audit, "trigger": trigger, "live": live})
        return {"uri": "s3://bucket/reports/INC-001/x.md", "markdown_key": "reports/INC-001/x.md", "json_key": "reports/INC-001/x.json", "live": live}


def make_incident(**overrides: Any) -> Incident:
    base: dict[str, Any] = dict(
        id="INC-001",
        title="Leaked AWS key used after exposure",
        severity="critical",
        status="open",
        summary="Key flagged on GitHub then used.",
        created_at="2026-11-24T10:00:00Z",
        updated_at="2026-11-24T10:00:00Z",
        rule_ids=["R-LEAKED-KEY"],
        entities={"access_key_id": LIVE_KEY, "iam_user": USER, "repository": "acme-payments/billing-service", "alert_number": 7},
        events=[Event(id="e1", ts="2026-11-24T10:01:00Z", source="cloudtrail", kind="GetCallerIdentity", live=True)],
        recommended_actions=["deactivate_access_key", "notify_owner"],
        data_mode="live",
    )
    base.update(overrides)
    return Incident(**base)


@pytest.fixture
def settings(tmp_path):
    return load_settings(mode="auto", allow_real_actions=True, real_action_user_allowlist=[USER], var_dir=tmp_path, s3_bucket="")


@pytest.fixture
def store():
    return SQLiteStore(":memory:")


def _setup(store: SQLiteStore, incident: Incident, action_type: str = "deactivate_access_key", **kw: Any):
    store.upsert_incident(incident)
    return actions.propose(store, incident, action_type, **kw)


def _approve(action_id: str, approver: str, store, settings, aws, reports=None):
    return asyncio.run(actions.approve(action_id, approver, store=store, settings=settings, aws=aws, reports=reports or FakeReports()))


def _expect_real_calls(aws: FakeAws, *, user: str = USER, key: str = LIVE_KEY, observed: str = "Inactive") -> None:
    aws.stub.add_response("update_access_key", {}, {"UserName": user, "AccessKeyId": key, "Status": "Inactive"})
    aws.stub.add_response(
        "list_access_keys",
        {"AccessKeyMetadata": [{"UserName": user, "AccessKeyId": key, "Status": observed, "CreateDate": datetime(2026, 11, 1, tzinfo=timezone.utc)}]},
        {"UserName": user},
    )


# --------------------------------------------------------------------- real path
def test_real_path_calls_update_access_key_inactive_and_verifies(store, settings):
    aws, reports = FakeAws(), FakeReports()
    act = _setup(store, make_incident())
    _expect_real_calls(aws)
    with trace.collect() as spans:
        done = _approve(act.id, "alice", store, settings, aws, reports)
    aws.stub.assert_no_pending_responses()

    assert done.status == "executed"
    r = done.result
    assert r["mode"] == "real" and r["simulated_reasons"] == []
    assert r["verification"] == {"method": "iam:ListAccessKeys", "verified": True, "observed_status": "Inactive"}
    assert r["started_at"] <= r["ended_at"]
    assert LIVE_KEY not in str(r) and "AKIA…LIVE" in str(r)  # masked
    assert store.get_incident("INC-001").status == "mitigated"
    assert [s.target for s in spans if s.server == "IAM"] == ["aws"]

    log = [e.action for e in reversed(store.list_audit())]
    assert log == ["action_proposed", "action_approved", "action_executed", "report_written"]
    assert store.verify_audit_chain()
    assert reports.calls[0]["trigger"] == "action_approved" and reports.calls[0]["live"] is True
    assert reports.calls[0]["incident"].status == "mitigated"
    assert store.get_action(act.id).result["report"]["markdown_key"] == "reports/INC-001/x.md"


def test_real_path_uses_incident_entities_not_agent_target(store, settings):
    aws = FakeAws()
    act = _setup(store, make_incident(), proposed_by="agent", target={"iam_user": "admin", "access_key_id": "AKIAEXAMPLEADMINMIN1"})
    assert act.target["iam_user"] == USER  # entity values override agent input
    _expect_real_calls(aws)  # Stubber fails the test if params differ from incident entities
    assert _approve(act.id, "alice", store, settings, aws).status == "executed"
    aws.stub.assert_no_pending_responses()


def test_real_path_failure_is_recorded(store, settings):
    aws = FakeAws()
    act = _setup(store, make_incident())
    aws.stub.add_client_error("update_access_key", "AccessDenied", "not authorized", 403)
    done = _approve(act.id, "alice", store, settings, aws)
    assert done.status == "failed" and done.result["mode"] == "real"
    assert "AccessDenied" in done.result["error"]
    assert done.result["verification"]["verified"] is False
    assert store.get_incident("INC-001").status == "open"
    assert "action_failed" in [e.action for e in store.list_audit()]
    assert aws.failures


def _expect_list(aws: FakeAws, observed: str) -> None:
    aws.stub.add_response(
        "list_access_keys",
        {"AccessKeyMetadata": [{"UserName": USER, "AccessKeyId": LIVE_KEY, "Status": observed, "CreateDate": datetime(2026, 11, 1, tzinfo=timezone.utc)}]},
        {"UserName": USER},
    )


@pytest.fixture
def no_verify_delay(monkeypatch):
    monkeypatch.setattr(iam_actions, "VERIFY_DELAY_S", 0.0)


def test_real_path_unverified_does_not_mitigate(store, settings, no_verify_delay):
    aws = FakeAws()
    act = _setup(store, make_incident())
    _expect_real_calls(aws, observed="Active")
    for _ in range(iam_actions.VERIFY_ATTEMPTS - 1):  # verification re-reads before giving up
        _expect_list(aws, "Active")
    done = _approve(act.id, "alice", store, settings, aws)
    aws.stub.assert_no_pending_responses()
    assert done.status == "executed"
    assert done.result["verification"]["verified"] is False and "warning" in done.result
    assert store.get_incident("INC-001").status == "open"


def test_verification_rides_out_iam_eventual_consistency(store, settings, no_verify_delay):
    aws = FakeAws()
    act = _setup(store, make_incident())
    _expect_real_calls(aws, observed="Active")  # first read still shows the old status
    _expect_list(aws, "Inactive")
    done = _approve(act.id, "alice", store, settings, aws)
    aws.stub.assert_no_pending_responses()
    assert done.status == "executed" and done.result["verification"]["verified"] is True
    assert store.get_incident("INC-001").status == "mitigated"


def test_verification_reread_error_keeps_last_observation(store, settings, no_verify_delay):
    aws = FakeAws()
    act = _setup(store, make_incident())
    _expect_real_calls(aws, observed="Active")
    aws.stub.add_client_error("list_access_keys", "Throttling", "Rate exceeded", 400)
    done = _approve(act.id, "alice", store, settings, aws)
    aws.stub.assert_no_pending_responses()
    assert done.status == "executed" and done.result["verification"] == {
        "method": "iam:ListAccessKeys", "verified": False, "observed_status": "Active"}


@pytest.mark.parametrize("first", ["failed", "unverified"])
def test_failed_or_unverified_real_action_can_be_retried(store, settings, no_verify_delay, first):
    inc = make_incident()
    store.upsert_incident(inc)
    aws = FakeAws()
    (act,) = actions.ensure_recommended(store, make_incident(recommended_actions=["deactivate_access_key"]))
    if first == "failed":
        aws.stub.add_client_error("update_access_key", "Throttling", "Rate exceeded", 400)
    else:
        _expect_real_calls(aws, observed="Active")
        for _ in range(iam_actions.VERIFY_ATTEMPTS - 1):
            _expect_list(aws, "Active")
    done = _approve(act.id, "alice", store, settings, aws)
    assert done.status == ("failed" if first == "failed" else "executed")
    assert store.get_incident("INC-001").status == "open"

    # Re-running detection re-proposes the step; a second approval retries and succeeds.
    (retry,) = actions.ensure_recommended(store, make_incident(recommended_actions=["deactivate_access_key"]))
    assert retry.id != act.id and retry.status == "proposed"
    assert actions.propose(store, inc, "deactivate_access_key", proposed_by="agent").id == retry.id
    _expect_real_calls(aws)
    assert _approve(retry.id, "alice", store, settings, aws).status == "executed"
    aws.stub.assert_no_pending_responses()
    assert store.get_incident("INC-001").status == "mitigated"
    assert len(store.list_actions("INC-001")) == 2
    assert [a.id for a in actions.ensure_recommended(store, inc) if a.type == "deactivate_access_key"] == [retry.id]


# ------------------------------------------------------------------- safety gate
GATE_CASES = {
    "agent approver": dict(approver="agent"),
    "bedrock approver": dict(approver="Bedrock"),
    "system approver": dict(approver="system"),
    "rule-engine actor approver": dict(approver="sentinel-rules"),
    "app name approver": dict(approver="SentinelAI"),
    "spaced agent approver": dict(approver="Bedrock agent"),
    "model name approver": dict(approver="Nova"),
    "bidi-padded agent approver": dict(approver="\u202eagent\n"),
    "real actions off": dict(settings={"allow_real_actions": False}),
    "user not allowlisted": dict(incident={"entities": {"access_key_id": LIVE_KEY, "iam_user": "prod-admin"}}),
    "synthetic data": dict(incident={"data_mode": "synthetic"}),
    "mixed data": dict(incident={"data_mode": "mixed"}),
    "aws disconnected": dict(connected=False),
    "example key": dict(incident={"entities": {"access_key_id": "AKIAIOSFODNN7EXAMPLE", "iam_user": USER}}),
    "missing key": dict(incident={"entities": {"iam_user": USER}}),
}


@pytest.mark.parametrize("case", GATE_CASES.values(), ids=GATE_CASES.keys())
def test_each_gate_condition_forces_simulation(store, settings, case):
    for k, v in case.get("settings", {}).items():
        setattr(settings, k, v)
    aws = FakeAws(connected=case.get("connected", True))  # no stubbed responses: any IAM call would raise
    act = _setup(store, make_incident(**case.get("incident", {})))
    done = _approve(act.id, case.get("approver", "alice"), store, settings, aws)

    aws.stub.assert_no_pending_responses()
    assert done.status == "simulated"
    r = done.result
    assert r["mode"] == "simulated" and len(r["simulated_reasons"]) == 1, r["simulated_reasons"]
    assert r["verification"]["method"] == "simulated" and r["started_at"] and r["ended_at"]
    audit = next(e for e in store.list_audit() if e.action == "action_simulated")
    assert audit.details["reasons"] == r["simulated_reasons"]
    # A simulation only mitigates offline/synthetic data; on a live incident the real key is still Active.
    live = store.get_incident("INC-001").data_mode == "live"
    assert store.get_incident("INC-001").status == ("open" if live else "mitigated")
    assert bool(r.get("live_change_pending")) is live


def test_gate_baseline_allows_real_and_reports_all_reasons(settings):
    inc = make_incident()
    act = actions.Action(id="ACT-1", incident_id="INC-001", type="deactivate_access_key", title="", description="")
    assert actions.real_action_gate(act, inc, settings, True, "alice") == (True, [])
    ok, reasons = actions.real_action_gate(act, inc, settings, True, "")
    assert not ok and "not a human" in reasons[0]
    settings.allow_real_actions = False
    ok, reasons = actions.real_action_gate(act, make_incident(data_mode="synthetic"), settings, False, "agent")
    assert not ok and len(reasons) == 4


def test_non_real_capable_action_is_always_simulated(store, settings):
    aws = FakeAws()
    act = _setup(store, make_incident(), "notify_owner")
    done = _approve(act.id, "alice", store, settings, aws)
    assert done.status == "simulated" and "no real AWS implementation" in done.result["simulated_reasons"][0]
    assert store.get_incident("INC-001").status == "open"  # notifying does not mitigate


# ------------------------------------------------------------ decisions / proposals
def test_double_approval_and_decided_actions_are_rejected(store, settings):
    aws = FakeAws(connected=False)
    act = _setup(store, make_incident())
    _approve(act.id, "alice", store, settings, aws)
    with pytest.raises(ValueError):
        _approve(act.id, "bob", store, settings, aws)
    with pytest.raises(ValueError):
        actions.reject(act.id, "bob", store=store)

    other = _setup(store, make_incident(), "notify_owner")
    rejected = actions.reject(other.id, "bob", store=store, reason="owner already knows")
    assert rejected.status == "rejected" and rejected.decided_by == "bob"
    with pytest.raises(ValueError):
        _approve(other.id, "alice", store, settings, aws)
    assert "action_rejected" in [e.action for e in store.list_audit()]


def test_approve_validation(store, settings):
    act = _setup(store, make_incident())
    with pytest.raises(ValueError):
        _approve(act.id, "  ", store, settings, FakeAws())
    with pytest.raises(actions.ActionNotFound):
        _approve("ACT-9999", "alice", store, settings, FakeAws())
    assert store.get_action(act.id).status == "proposed"


def test_report_failure_does_not_undo_action(store, settings):
    act = _setup(store, make_incident())
    done = _approve(act.id, "alice", store, settings, FakeAws(connected=False), FakeReports(fail=True))
    assert done.status == "simulated" and "error" in done.result["report"]
    assert "report_failed" in [e.action for e in store.list_audit()]


def test_propose_is_idempotent_and_validates_type(store):
    inc = make_incident()
    store.upsert_incident(inc)
    a1 = actions.propose(store, inc, "deactivate_access_key")
    a2 = actions.propose(store, inc, "deactivate_access_key", proposed_by="agent")
    assert a1.id == a2.id and a1.real_capable
    with pytest.raises(ValueError):
        actions.propose(store, inc, "rm_rf")


def test_propose_returns_settled_action_instead_of_duplicating(store, settings):
    inc = make_incident(data_mode="synthetic")
    store.upsert_incident(inc)
    act = actions.propose(store, inc, "deactivate_access_key")
    _approve(act.id, "alice", store, settings, FakeAws(connected=False))
    again = actions.propose(store, inc, "deactivate_access_key", proposed_by="agent", reason="please propose it again")
    assert again.id == act.id and again.status == "simulated"
    assert len(store.list_actions("INC-001")) == 1
    # A rejected step can still be proposed again on explicit request.
    other = actions.propose(store, inc, "notify_owner")
    actions.reject(other.id, "bob", store=store)
    assert actions.propose(store, inc, "notify_owner", proposed_by="agent").status == "proposed"


def test_human_approver_normalisation():
    for name in ("alice", "Sachin B", "Agnes", "Systa Jones", "Ainsley", "o'brien"):
        assert actions.is_human_approver(name), name
        assert actions.approver_problem(name) is None
    for name in ("", "   ", "agent", "AGENT ", "sentinel-rules", "SentinelAI", "Bedrock agent", "system", "rules", "nova", "AI", "\u202e\n"):
        assert not actions.is_human_approver(name), name
        assert actions.approver_problem(name)
    assert actions.clean_approver("ev\nil\u202e") == "ev il"
    assert len(actions.clean_approver("x" * 5000)) == actions.MAX_APPROVER_LEN


def test_approver_is_cleaned_and_masked_everywhere(store, settings):
    act = _setup(store, make_incident())
    done = _approve(act.id, "AKIAIOSFODNN7EXAMPLE\u202e", store, settings, FakeAws(connected=False))
    assert done.decided_by == "AKIA…MPLE" and store.get_action(act.id).decided_by == "AKIA…MPLE"
    other = _setup(store, make_incident(), "notify_owner")
    assert actions.reject(other.id, "x" * 5000, store=store).decided_by == "x" * actions.MAX_APPROVER_LEN
    actors = [e.actor for e in store.list_audit()]
    assert "AKIA…MPLE" in actors and not any("AKIAIOSFODNN7EXAMPLE" in a or len(a) > 128 for a in actors)
    assert store.verify_audit_chain()


def test_post_approval_report_is_written_off_the_event_loop(store, settings):
    import threading

    threads: list[str] = []

    class ThreadReports(FakeReports):
        def write(self, *a, **kw):
            threads.append(threading.current_thread().name)
            return super().write(*a, **kw)

    act = _setup(store, make_incident())
    loop_thread = threading.current_thread().name
    done = _approve(act.id, "alice", store, settings, FakeAws(connected=False), ThreadReports())
    assert threads and threads[0] != loop_thread
    assert done.result["report"]["markdown_key"] == "reports/INC-001/x.md"
    assert store.get_action(act.id).result["report"]["markdown_key"] == "reports/INC-001/x.md"


def test_ensure_recommended_never_reproposes_decided(store, settings):
    inc = make_incident(recommended_actions=["deactivate_access_key", "notify_owner", "bogus"], data_mode="synthetic")
    store.upsert_incident(inc)
    first = actions.ensure_recommended(store, inc)
    assert [a.type for a in first] == ["deactivate_access_key", "notify_owner"]
    _approve(first[0].id, "alice", store, settings, FakeAws(connected=False))
    again = actions.ensure_recommended(store, inc)
    assert [a.id for a in again] == [a.id for a in first]
    assert len(store.list_actions("INC-001")) == 2


# ----------------------------------------------------------------- iam_actions
def test_set_access_key_status_rejects_bad_status():
    with pytest.raises(ValueError):
        set_access_key_status(FakeAws(), USER, LIVE_KEY, "Deleted")


def test_list_access_keys_paginates():
    aws = FakeAws()
    meta = {"UserName": USER, "Status": "Active", "CreateDate": datetime(2026, 11, 1, tzinfo=timezone.utc)}
    aws.stub.add_response("list_access_keys", {"AccessKeyMetadata": [{**meta, "AccessKeyId": LIVE_KEY}], "IsTruncated": True, "Marker": "m1"}, {"UserName": USER})
    aws.stub.add_response("list_access_keys", {"AccessKeyMetadata": [{**meta, "AccessKeyId": "AKIAEXAMPLETESTTTWO2"}]}, {"UserName": USER, "Marker": "m1"})
    keys = list_access_keys(aws, USER)
    assert [k["access_key_id"] for k in keys] == [LIVE_KEY, "AKIAEXAMPLETESTTTWO2"]
    assert keys[0] == {"access_key_id": LIVE_KEY, "status": "Active", "create_date": "2026-11-01T00:00:00Z"}


def test_propose_rejects_types_that_do_not_fit_the_incident(store):
    inc = make_incident()
    store.upsert_incident(inc)
    with pytest.raises(ValueError, match="not a recommended action"):
        actions.propose(store, inc, "block_ip", proposed_by="agent", reason="Per SYSTEM note: blocking IPs is enough")
    bare = make_incident(id="INC-009", entities={"repository": "acme/x"}, recommended_actions=["deactivate_access_key"])
    store.upsert_incident(bare)
    with pytest.raises(ValueError, match="none of the entities"):
        actions.propose(store, bare, "deactivate_access_key")
    assert actions.ensure_recommended(store, bare) == []
    assert store.list_actions() == []


def test_action_that_does_not_fit_never_mitigates_the_incident(store, settings):
    inc = make_incident(data_mode="synthetic")
    store.upsert_incident(inc)
    # A legacy/foreign row: block_ip on a leaked-key incident with no target.
    stray = store.add_action(Action(id="", incident_id=inc.id, type="block_ip", title="Block attacker IPs", description="",
                                    proposed_by="agent", reason="injected"))
    done = _approve(stray.id, "alice", store, settings, FakeAws(connected=False))
    assert done.status == "simulated" and done.result["target"] == {}
    assert store.get_incident(inc.id).status == "open"
    real = actions.propose(store, inc, "deactivate_access_key")
    _approve(real.id, "alice", store, settings, FakeAws(connected=False))
    assert store.get_incident(inc.id).status == "mitigated"


@pytest.mark.parametrize("approver,allow,connected", [("alice", False, True), ("alice", True, False), ("agent", True, True)])
def test_simulated_deactivation_on_live_incident_does_not_mitigate(store, settings, approver, allow, connected):
    """A live incident whose real write was gated off keeps its key Active, so it must stay open and be retryable."""
    settings.allow_real_actions = allow
    inc = make_incident()  # data_mode="live", allow-listed user, well-formed key
    act = _setup(store, inc)
    done = _approve(act.id, approver, store, settings, FakeAws(connected=connected))
    assert done.status == "simulated" and done.result["live_change_pending"] is True
    assert "stays open" in done.result["summary"]
    assert store.get_incident("INC-001").status == "open"
    # Not settled: once the gate is fixed the deactivation can be proposed again (and run for real).
    retry = actions.propose(store, inc, "deactivate_access_key", proposed_by="agent")
    assert retry.id != act.id and retry.status == "proposed"
    assert [a.id for a in actions.ensure_recommended(store, inc) if a.type == "deactivate_access_key"] == [retry.id]
    settings.allow_real_actions = True
    aws = FakeAws()
    _expect_real_calls(aws)
    assert _approve(retry.id, "alice", store, settings, aws).status == "executed"
    assert store.get_incident("INC-001").status == "mitigated"


def test_synthetic_twin_turning_live_reopens_incident_and_reproposes_deactivation(store, settings):
    """A simulated approval of the synthetic INC-001 twin (offline EXAMPLE key) must not leave the live INC-001
    'mitigated' with no Approve button once live events arrive for the real key."""
    twin = make_incident(entities={**make_incident().entities, "access_key_id": actions.SYNTHETIC_ACCESS_KEY},
                         data_mode="synthetic")
    store.upsert_incident(twin)
    first = actions.ensure_recommended(store, twin)
    deact = next(a for a in first if a.type == "deactivate_access_key")
    notify = next(a for a in first if a.type == "notify_owner")
    assert _approve(deact.id, "alice", store, settings, FakeAws(connected=False)).status == "simulated"
    assert store.get_incident("INC-001").status == "mitigated"

    live = make_incident()  # same id and alert number, real key, data_mode="live"
    store.upsert_incident(live)  # upsert alone keeps "mitigated"
    now = actions.ensure_recommended(store, live)
    assert store.get_incident("INC-001").status == "open"
    fresh = next(a for a in now if a.type == "deactivate_access_key")
    assert fresh.id != deact.id and fresh.status == "proposed" and fresh.target["access_key_id"].endswith("LIVE")
    # The undecided proposal for the old key can no longer be approved (it would act on the new key).
    stale = store.get_action(notify.id)
    assert stale.status == "superseded"
    with pytest.raises(ValueError):
        _approve(stale.id, "alice", store, settings, FakeAws())
    assert any(e.action == "incident_reopened" for e in store.list_audit())
    # The fresh proposal runs for real and mitigates the live incident.
    aws = FakeAws()
    _expect_real_calls(aws)
    assert _approve(fresh.id, "alice", store, settings, aws).status == "executed"
    assert store.get_incident("INC-001").status == "mitigated"
    # Detection re-run on the same subject keeps it mitigated and proposes nothing new.
    count = len(store.list_actions("INC-001"))
    actions.ensure_recommended(store, live)
    assert store.get_incident("INC-001").status == "mitigated" and len(store.list_actions("INC-001")) == count


def test_gate_refuses_real_run_for_action_proposed_for_another_key(store, settings):
    old = make_incident(entities={**make_incident().entities, "access_key_id": "AKIAEXAMPLETESTTOLD1"})
    act = _setup(store, old)
    new = make_incident()
    run_real, reasons = actions.real_action_gate(act, new, settings, True, "alice")
    assert run_real is False and any("earlier target" in r for r in reasons)
    assert actions.real_action_gate(act, old, settings, True, "alice") == (True, [])
