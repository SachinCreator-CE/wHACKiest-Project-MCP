"""Risk scoring: pure function plus API attachment."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from sentinel.models import Incident
from sentinel.risk import compute_risk, risk_label
from tests.test_api import build


def leaked(**counts) -> Incident:
    base = {"post_flag_uses": 5, "pre_flag_uses": 0, "denied": 4, "escalation_attempts": 3,
            "admin_attach_attempts": 1, "escalations_succeeded": 0, "recon_calls": 3, "distinct_ips": 1, "regions": 2}
    base.update(counts)
    return Incident(id="INC-001", title="t", severity="critical", status="open", summary="", created_at="", updated_at="",
                    rule_ids=["R-LEAKED-KEY"], counts=base)


def brute(**counts) -> Incident:
    base = {"failed_logins": 18, "total_failed_logins": 18, "attacker_successes": 1, "takeovers_blocked": 1, "distinct_ips": 1}
    base.update(counts)
    return Incident(id="INC-002", title="t", severity="high", status="open", summary="", created_at="", updated_at="",
                    rule_ids=["R-BRUTE-FORCE"], counts=base)


def test_leaked_key_is_critical_with_factors() -> None:
    r = compute_risk(leaked())
    labels = {f["label"]: f["points"] for f in r["factors"]}
    assert labels["Key used after GitHub exposure"] == 35
    assert labels["Denied privilege-escalation attempts"] == 20  # capped
    assert labels["AdministratorAccess attach attempt"] == 15
    assert labels["Reconnaissance calls"] == 9
    assert labels["Multiple regions"] == 5
    assert r["score"] == sum(f["points"] for f in r["factors"]) == 84
    assert r["label"] == "CRITICAL" and r["method"]
    assert all(set(f) == {"label", "points", "detail"} for f in r["factors"])


def test_succeeded_escalation_adds_25() -> None:
    r = compute_risk(leaked(escalations_succeeded=1, escalation_attempts=1, admin_attach_attempts=0))
    assert {f["label"]: f["points"] for f in r["factors"]}["Privilege escalation succeeded"] == 25


def test_brute_force_blocked_by_mfa_is_high() -> None:
    r = compute_risk(brute())
    labels = {f["label"]: f["points"] for f in r["factors"]}
    assert labels["Attacker login succeeded"] == 20 and labels["MFA blocked the takeover"] == -15
    assert r["score"] == 62 and r["label"] == "HIGH"


def test_brute_force_without_mfa_block_is_critical() -> None:
    r = compute_risk(brute(takeovers_blocked=0))
    assert r["score"] > compute_risk(brute())["score"] and r["label"] == "CRITICAL"


@pytest.mark.parametrize("make", [leaked, brute])
def test_mitigated_lowers_score(make) -> None:
    done = make()
    done.status = "mitigated"
    a, b = compute_risk(make()), compute_risk(done)
    assert b["score"] == a["score"] - 30
    assert b["factors"][-1]["label"] == "Mitigated by approved action" and b["factors"][-1]["points"] == -30


def test_bounds() -> None:
    huge = compute_risk(leaked(escalations_succeeded=9, escalation_attempts=99, recon_calls=99, regions=9))
    assert huge["score"] == 100
    low = Incident(id="X", title="t", severity="low", status="resolved", summary="", created_at="", updated_at="",
                   rule_ids=["R-BRUTE-FORCE"], counts={"failed_logins": 0})
    assert compute_risk(low)["score"] == 0
    empty = Incident(id="X", title="t", severity="info", status="resolved", summary="", created_at="", updated_at="")
    assert 0 <= compute_risk(empty)["score"] <= 100


@pytest.mark.parametrize("score,label", [(100, "CRITICAL"), (80, "CRITICAL"), (79, "HIGH"), (60, "HIGH"),
                                         (59, "MEDIUM"), (35, "MEDIUM"), (34, "LOW"), (0, "LOW")])
def test_label_thresholds(score: int, label: str) -> None:
    assert risk_label(score) == label


def test_deterministic() -> None:
    assert compute_risk(leaked()) == compute_risk(leaked())


def test_pre_flag_only_key_is_medium() -> None:
    r = compute_risk(leaked(post_flag_uses=0, pre_flag_uses=2, denied=0, escalation_attempts=0,
                            admin_attach_attempts=0, recon_calls=0, regions=1))
    assert r["label"] == "MEDIUM"


def test_api_includes_risk_and_tracks_status() -> None:
    app, harness = build()
    with TestClient(app) as client:
        client.post("/api/detect")
        listed = client.get("/api/incidents").json()["incidents"][0]
        detail = client.get("/api/incidents/INC-001").json()["incident"]
        for inc in (listed, detail):
            r = inc["risk"]
            assert 0 <= r["score"] <= 100 and r["label"] in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
            assert isinstance(r["factors"], list) and r["method"]
        before = detail["risk"]["score"]
        stored = harness.store.get_incident("INC-001")
        stored.status = "mitigated"
        harness.store.upsert_incident(stored)
        after = client.get("/api/incidents/INC-001").json()["incident"]["risk"]
        assert after["score"] == max(0, before - 30)
        assert "risk" not in harness.store.get_incident("INC-001").to_dict()
