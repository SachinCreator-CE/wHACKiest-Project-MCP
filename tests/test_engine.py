"""Rule engine tests. Events are built directly; no data files or other modules needed."""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from sentinel.engine import (
    BRUTE_FORCE_ACTIONS,
    LEAKED_KEY_ACTIONS,
    detect,
    detect_bruteforce,
    detect_leaked_key,
)
from sentinel.models import Event, SecretAlert, iso

KEY = "AKIAIOSFODNN7EXAMPLE"
MASKED = "AKIA…MPLE"
T0 = datetime(2026, 11, 20, 12, 0, tzinfo=timezone.utc)
NOW = T0 + timedelta(hours=1)
ATTACKER = "185.220.101.47"


def at(minutes: float) -> str:
    return iso(T0 + timedelta(minutes=minutes))


def alert(number: int = 1, key: str = KEY, state: str = "open", created: float = 0) -> SecretAlert:
    return SecretAlert(
        number=number, state=state, secret_type="aws_access_key_id", access_key_id=key,
        repository="acme-payments/billing-service", path="config/settings.py", commit_sha="abc123",
        created_at=at(created), html_url="https://github.com/acme-payments/billing-service/security/1",
        pusher="dev-bob",
    )


def ct(i: int, name: str, minutes: float, *, source: str, outcome: str = "denied", region: str = "us-east-1",
       params: dict | None = None, key: str = KEY, live: bool = False) -> Event:
    raw = {"eventSource": f"{source}.amazonaws.com", "eventName": name}
    if params is not None:
        raw["requestParameters"] = params
    return Event(
        id=f"ct-{i}", ts=at(minutes), source="cloudtrail", kind=name, actor="sentinel-demo-victim",
        ip="203.0.113.50", outcome=outcome, region=region, access_key_id=key,
        error_code="AccessDenied" if outcome == "denied" else "", live=live, raw=raw,
    )


def inc001_events(live: bool = False) -> list[Event]:
    admin = {"userName": "sentinel-demo-victim", "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}
    return [
        ct(5, "AttachUserPolicy", 9, source="iam", params=admin, live=live),
        ct(1, "GetCallerIdentity", 5, source="sts", outcome="success", live=live),
        ct(2, "ListBuckets", 6, source="s3", region="ap-south-1", live=live),
        ct(3, "ListAttachedUserPolicies", 7, source="iam", live=live),
        ct(4, "CreateAccessKey", 8, source="iam", params={"userName": "sentinel-demo-victim"}, live=live),
    ]


def auth(i: int, kind: str, minutes: float, *, user: str = "priya", ip: str = ATTACKER, live: bool = False) -> Event:
    outcome = "failure" if kind in {"login_failed", "mfa_failed"} else "success"
    return Event(
        id=f"{user}-{i}", ts=at(minutes), source="app-auth", kind=kind, actor=user, ip=ip, outcome=outcome,
        live=live, simulated=True, raw={"event": kind, "user": user, "ip": ip, "geo": "Frankfurt, DE"},
    )


def priya_burst(n: int = 18, *, then: tuple[str, ...] = ("login_success", "mfa_challenge", "mfa_failed")) -> list[Event]:
    events = [auth(i, "login_failed", 10 + i * 0.22) for i in range(n)]
    events += [auth(100 + j, kind, 15 + j * 0.2) for j, kind in enumerate(then)]
    return events


def arjun() -> list[Event]:
    ip = "49.205.33.10"
    return [auth(1, "login_failed", 20, user="arjun", ip=ip), auth(2, "login_success", 20.5, user="arjun", ip=ip),
            auth(3, "mfa_success", 21, user="arjun", ip=ip)]


# ------------------------------------------------------------- leaked key
def test_leaked_key_post_flag_use_is_critical_with_counts_and_entities():
    inc = detect_leaked_key(alert(), inc001_events(), flagged_at=T0, data_mode="synthetic", now=NOW)
    assert inc is not None
    assert inc.id == "INC-001" and inc.severity == "critical" and inc.status == "open"
    assert inc.title == f"Leaked AWS access key {MASKED} used after GitHub exposure"
    assert inc.counts == {
        "post_flag_uses": 5, "pre_flag_uses": 0, "denied": 4, "escalation_attempts": 2, "admin_attach_attempts": 1,
        "escalations_succeeded": 0, "recon_calls": 3, "distinct_ips": 1, "regions": 2,
    }
    assert inc.entities["access_key_id"] == KEY  # full key; masking happens at the edge
    assert inc.entities["iam_user"] == "sentinel-demo-victim"
    assert inc.entities["repository"] == "acme-payments/billing-service"
    assert inc.entities["alert_number"] == 1
    assert inc.entities["regions"] == ["ap-south-1", "us-east-1"]
    assert inc.recommended_actions == LEAKED_KEY_ACTIONS
    assert inc.rule_ids == ["R-LEAKED-KEY"] and inc.data_mode == "synthetic"


def test_leaked_key_evidence_is_masked_and_explains_the_attack():
    inc = detect_leaked_key(alert(), inc001_events(), flagged_at=T0, data_mode="synthetic", now=NOW)
    text = "\n".join([inc.title, inc.summary, *inc.evidence])
    assert KEY not in text and MASKED in text
    assert any("used 5 times after it was flagged" in e for e in inc.evidence)
    assert any("IAM denied 4 of those 5 calls" in e for e in inc.evidence)
    assert any("iam:AttachUserPolicy (AdministratorAccess on sentinel-demo-victim)" in e and "all denied" in e
               for e in inc.evidence)
    assert any("attach AdministratorAccess to sentinel-demo-victim; IAM denied it" in e for e in inc.evidence)
    assert any(e.startswith("3 reconnaissance calls: sts:GetCallerIdentity, s3:ListBuckets") for e in inc.evidence)
    assert inc.evidence[-1].startswith("Synthetic demo data")


def test_leaked_key_timeline_starts_with_github_alert_and_is_sorted():
    inc = detect_leaked_key(alert(), inc001_events(), flagged_at=T0, data_mode="live", now=NOW)
    first = inc.events[0]
    assert (first.source, first.kind, first.access_key_id) == ("github", "secret_scanning_alert", KEY)
    assert [e.ts for e in inc.events] == sorted(e.ts for e in inc.events)
    admin = next(e for e in inc.events if e.kind == "AttachUserPolicy")
    assert {"post_flag", "escalation", "admin_attach"} <= set(admin.tags)
    assert "GitHub alert is synthetic" in inc.evidence[-1]


def test_leaked_key_does_not_mutate_input_events():
    events = inc001_events()
    detect_leaked_key(alert(), events, flagged_at=T0, data_mode="synthetic", now=NOW)
    assert all(e.tags == [] for e in events)


def test_admin_attach_detected_from_summary_when_request_parameters_missing():
    e = ct(1, "AttachUserPolicy", 5, source="iam")
    e.summary = "iam:AttachUserPolicy (AdministratorAccess) → AccessDenied"
    inc = detect_leaked_key(alert(), [e], flagged_at=T0, data_mode="synthetic", now=NOW)
    assert inc.counts["admin_attach_attempts"] == 1


def test_successful_escalation_is_called_out():
    e = ct(1, "CreateAccessKey", 5, source="iam", outcome="success")
    inc = detect_leaked_key(alert(), [e], flagged_at=T0, data_mode="synthetic", now=NOW)
    assert inc.counts["escalations_succeeded"] == 1
    assert any(x.startswith("Warning: 1 escalation call succeeded") for x in inc.evidence)


def test_only_pre_flag_use_is_medium_and_unused_key_is_none():
    pre = [ct(1, "GetCallerIdentity", -30, source="sts", outcome="success")]
    inc = detect_leaked_key(alert(), pre, flagged_at=T0, data_mode="synthetic", now=NOW)
    assert inc.severity == "medium" and inc.counts["post_flag_uses"] == 0 and inc.counts["pre_flag_uses"] == 1
    other_key = [ct(1, "GetCallerIdentity", 5, source="sts", key="AKIAEXAMPLEZZZZZZZZZ")]
    assert detect_leaked_key(alert(), other_key, flagged_at=T0, data_mode="synthetic", now=NOW) is None


# ------------------------------------------------------------- brute force
def test_bruteforce_blocked_by_mfa_is_high():
    incidents, suppressed = detect_bruteforce(priya_burst(), now=NOW)
    assert suppressed == [] and len(incidents) == 1
    inc = incidents[0]
    assert inc.severity == "high"
    assert inc.entities == {"app_user": "priya", "attacker_ips": [ATTACKER], "attacker_geo": ["Frankfurt, DE"]}
    assert inc.counts["failed_logins"] == 18 and inc.counts["attacker_successes"] == 1
    assert inc.counts["takeovers_blocked"] == 1
    assert inc.title == "Brute-force attack on app user priya: 18 failed logins in 4 min"
    assert any("The MFA challenge failed at 12:15 UTC, so the account takeover was blocked" in e for e in inc.evidence)
    assert inc.recommended_actions == BRUTE_FORCE_ACTIONS
    assert [e.ts for e in inc.events] == sorted(e.ts for e in inc.events)


def test_bruteforce_success_without_mfa_block_is_critical():
    inc = detect_bruteforce(priya_burst(then=("login_success", "mfa_challenge", "mfa_success")), now=NOW)[0][0]
    assert inc.severity == "critical"
    assert any("treat the account as compromised" in e for e in inc.evidence)


def test_bruteforce_uses_sliding_window_not_total():
    spread = [auth(i, "login_failed", i * 2) for i in range(12)]  # 12 failures, 2 min apart -> max 6 in 10 min
    incidents, suppressed = detect_bruteforce(spread, now=NOW)
    assert incidents == []
    assert suppressed[0]["entity"] == "priya" and suppressed[0]["reason"].startswith("6 failed logins for priya")


@pytest.mark.parametrize("n, expected", [(9, 0), (10, 1)])
def test_bruteforce_threshold_boundary(n, expected):
    assert len(detect_bruteforce(priya_burst(n, then=()), now=NOW)[0]) == expected


def test_arjun_typo_is_suppressed_with_reason():
    incidents, suppressed = detect_bruteforce(arjun(), now=NOW)
    assert incidents == []
    assert suppressed == [{
        "rule": "R-BRUTE-FORCE",
        "entity": "arjun",
        "reason": "1 failed login for arjun within 10 min (threshold 10); below the brute-force threshold. "
                  "Followed by a successful login and MFA from 49.205.33.10 (Frankfurt, DE): consistent with a typo.",
    }]


def test_bruteforce_live_data_mode():
    inc = detect_bruteforce([auth(i, "login_failed", i * 0.1, live=True) for i in range(10)], now=NOW)[0][0]
    assert inc.data_mode == "live" and "CloudWatch Logs" in inc.evidence[-1]


# ------------------------------------------------------------------- detect
def test_detect_numbers_incidents_deterministically_and_suppresses():
    alerts = [alert(1), alert(2, key="AKIAEXAMPLEABCDEWXYZ"), alert(3, key="AKIAEXAMPLEQQQQQ1234", state="resolved")]
    attacker_bob = [auth(i, "login_failed", 30 + i * 0.1, user="bob", ip="198.51.100.7") for i in range(11)]
    result = detect(alerts, {KEY: inc001_events(live=True)}, priya_burst() + arjun() + attacker_bob,
                    now=NOW, data_modes={KEY: "live"})
    assert [(i.id, i.rule_ids[0], i.severity) for i in result.incidents] == [
        ("INC-001", "R-LEAKED-KEY", "critical"),
        ("INC-002", "R-BRUTE-FORCE", "high"),  # bob: no successful login
        ("INC-003", "R-BRUTE-FORCE", "high"),  # priya: MFA blocked the takeover
    ]
    assert [i.entities.get("app_user") for i in result.incidents[1:]] == ["bob", "priya"]
    assert any("No successful login from 198.51.100.7" in e for e in result.incidents[1].evidence)
    assert result.incidents[0].data_mode == "live"
    reasons = {s["entity"]: s["reason"] for s in result.suppressed}
    assert reasons["AKIA…WXYZ"] == "Alert #2 open, key AKIA…WXYZ unused in window."
    assert "resolved" in reasons["AKIA…1234"]
    assert "arjun" in reasons
    again = detect(alerts, {KEY: inc001_events(live=True)}, priya_burst() + arjun() + attacker_bob,
                   now=NOW, data_modes={KEY: "live"})
    assert again.to_dict() == result.to_dict()


def test_denied_evidence_names_the_actual_error_codes():
    ec2 = replace(ct(6, "DescribeInstances", 10, source="ec2", region="ap-south-1"),
                  error_code="Client.UnauthorizedOperation")
    inc = detect_leaked_key(alert(), inc001_events() + [ec2], flagged_at=T0, data_mode="synthetic", now=NOW)
    assert "IAM denied 5 of those 6 calls (AccessDenied, Client.UnauthorizedOperation)." in inc.evidence


def test_bruteforce_groups_users_case_and_whitespace_insensitively():
    """Alternating 'Alice'/'alice '/'alice' must not split one attack below threshold."""
    spellings = ["Alice", "alice ", "alice"]
    events = [auth(i, "login_failed", i * 0.1, user=spellings[i % 3]) for i in range(12)]
    incidents, suppressed = detect_bruteforce(events, now=NOW)
    assert suppressed == [] and len(incidents) == 1
    inc = incidents[0]
    assert inc.counts["failed_logins"] == 12
    assert inc.entities["app_user"] == "alice"  # most common spelling after stripping ("alice " + "alice")
    assert detect_bruteforce(list(reversed(events)), now=NOW)[0][0].entities["app_user"] == "alice"


def test_bruteforce_reports_the_latest_burst_after_a_rehearsal():
    """A rehearsal 3 h earlier ties with the on-stage burst; the on-stage (latest) one must be highlighted."""
    rehearsal = priya_burst()
    on_stage = [replace(e, id=f"stage-{e.id}", ts=iso(datetime.fromisoformat(e.ts.replace("Z", "+00:00")) + timedelta(hours=3)))
                for e in priya_burst()]
    inc = detect_bruteforce(rehearsal + on_stage, now=NOW + timedelta(hours=3))[0][0]
    burst = [e for e in inc.events if "burst" in e.tags]
    assert len(burst) == 18 and all(e.id.startswith("stage-") for e in burst)
    assert all(e.id.startswith("stage-") for e in inc.events)  # the rehearsal is not part of this attack's timeline
    assert inc.counts["attacker_successes"] == 1
    assert sum("logged in successfully" in line for line in inc.evidence) == 1
