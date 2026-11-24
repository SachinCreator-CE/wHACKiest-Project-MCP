"""Tests for the synthetic dataset (sentinel/datasets.py + data/)."""
from __future__ import annotations

import json
import re
from collections import Counter
from datetime import datetime, timedelta, timezone

import pytest

from sentinel import datasets as ds
from sentinel.config import load_settings
from sentinel.masking import ACCESS_KEY_RE
from sentinel.models import parse_ts

NOW = datetime(2026, 12, 3, 8, 0, tzinfo=timezone.utc)
ATTACKER_IP = "185.220.101.47"
INC001_EVENTS = ["GetCallerIdentity", "ListBuckets", "ListAttachedUserPolicies", "CreateAccessKey", "AttachUserPolicy"]
DOC_NETS = ("192.0.2.", "198.51.100.", "203.0.113.")


# --- paths / loading ---------------------------------------------------------------------------

def test_list_dataset_names_covers_contract_files():
    names = ds.list_dataset_names()
    for rel in (ds.ALERTS_FILE, ds.CLOUDTRAIL_FILE, ds.AUTH_FILE, ds.USERS_FILE):
        assert rel in names


@pytest.mark.parametrize("bad", ["../secrets.json", "/etc/passwd", "a/../../b.json", "", "C:\\x.json", "a\\b.json"])
def test_data_path_rejects_traversal(bad):
    with pytest.raises(ValueError):
        ds.data_path(bad)


def test_data_path_respects_settings_data_dir(tmp_path):
    (tmp_path / "x").mkdir()
    (tmp_path / "x" / "r.jsonl").write_text('{"a": 1}\n\n{"a": 2}\n')
    settings = load_settings(data_dir=tmp_path)
    assert ds.load_records("x/r.jsonl", settings) == [{"a": 1}, {"a": 2}]
    assert ds.list_dataset_names(settings) == ["x/r.jsonl"]


def test_parse_records_formats():
    assert ds.parse_records('{"Records": [{"a": 1}]}', "ct.json") == [{"a": 1}]
    assert ds.parse_records('[{"a": 1}]', "x.json") == [{"a": 1}]
    with pytest.raises(ValueError):
        ds.parse_records('{"a": 1}', "x.json")


# --- time handling -----------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("expr", "expected"),
    [
        ("now", NOW),
        ("1 day ago", NOW - timedelta(days=1)),
        ("24 hours ago", NOW - timedelta(hours=24)),
        ("90 minutes ago", NOW - timedelta(minutes=90)),
        ("2 weeks ago", NOW - timedelta(weeks=2)),
        ("2026-11-20T12:00:00Z", datetime(2026, 11, 20, 12, tzinfo=timezone.utc)),
        ("2026-11-20T17:30:00+05:30", datetime(2026, 11, 20, 12, tzinfo=timezone.utc)),
    ],
)
def test_parse_time_expr(expr, expected):
    assert ds.parse_time_expr(expr, NOW) == expected


def test_parse_time_expr_empty_and_invalid():
    assert ds.parse_time_expr(None, NOW) is None
    assert ds.parse_time_expr("  ", NOW) is None
    with pytest.raises(ValueError):
        ds.parse_time_expr("last tuesday", NOW)


def test_shift_records_moves_anchor_to_now_minus_lead_and_deep_copies():
    recs = [{"ts": ds.ANCHOR, "nested": {"created_at": "2026-11-20T11:00:00Z"}, "ts_note": "x"}, {"ts": None}]
    out = ds.shift_records(recs, NOW, lead_minutes=30)
    assert out[0]["ts"] == "2026-12-03T07:30:00Z"
    assert out[0]["nested"]["created_at"] == "2026-12-03T06:30:00Z"
    assert out[1]["ts"] is None
    assert recs[0]["ts"] == ds.ANCHOR  # original untouched


# --- GitHub alerts -----------------------------------------------------------------------------

def test_alert_file_keeps_placeholder_and_no_real_keys():
    raw = ds.load_records(ds.ALERTS_FILE)
    inc = [a for a in raw if a["access_key_id"] == ds.KEY_PLACEHOLDER]
    assert len(inc) == 1 and inc[0]["repository"] == "acme-payments/billing-service"
    assert inc[0]["path"] == "config/settings.py"


def test_synthetic_alerts_offline_key_and_recent_times():
    alerts = ds.synthetic_alerts(NOW)
    by_state = {a["state"]: a for a in alerts}
    assert set(by_state) == {"open", "resolved"}
    inc = by_state["open"]
    assert inc["access_key_id"] == ds.OFFLINE_LEAKED_KEY
    assert parse_ts(inc["created_at"]) < NOW - timedelta(minutes=30)
    assert NOW - parse_ts(inc["created_at"]) < timedelta(hours=2)
    assert by_state["resolved"]["access_key_id"] != ds.OFFLINE_LEAKED_KEY
    assert ds.KEY_PLACEHOLDER not in json.dumps(alerts)


def test_synthetic_alerts_live_key_and_flagged_at():
    live = "AKIA" + "Z" * 12 + "TEST"
    alerts = ds.synthetic_alerts(NOW, live_key=live, flagged_at="2026-12-02T08:00:00Z")
    inc = next(a for a in alerts if a["state"] == "open")
    assert inc["access_key_id"] == live
    assert inc["created_at"] == "2026-12-02T08:00:00Z"


# --- CloudTrail --------------------------------------------------------------------------------

REQUIRED_CT_FIELDS = {
    "eventVersion", "userIdentity", "eventTime", "eventSource", "eventName", "awsRegion", "sourceIPAddress",
    "userAgent", "requestParameters", "responseElements", "requestID", "eventID", "readOnly", "eventType",
    "managementEvent", "recipientAccountId",
}
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")


def test_cloudtrail_records_are_shaped_like_real_records():
    recs = ds.synthetic_cloudtrail_records(NOW)
    assert len({r["eventID"] for r in recs}) == len(recs)
    for r in recs:
        assert REQUIRED_CT_FIELDS <= r.keys(), r["eventName"]
        ident = r["userIdentity"]
        assert ident["type"] == "IAMUser" and ident["accountId"] == "123456789012"
        assert ident["arn"] == f"arn:aws:iam::123456789012:user/{ident['userName']}"
        assert UUID_RE.match(r["eventID"])
        assert parse_ts(r["eventTime"]) <= NOW - timedelta(minutes=30)


def test_cloudtrail_inc001_scenario():
    recs = ds.synthetic_cloudtrail_records(NOW)
    inc = [r for r in recs if r["userIdentity"]["accessKeyId"] == ds.OFFLINE_LEAKED_KEY]
    inc.sort(key=lambda r: r["eventTime"])
    assert [r["eventName"] for r in inc] == INC001_EVENTS
    assert {r["userIdentity"]["userName"] for r in inc} == {"sentinel-demo-victim"}
    assert all(r["sourceIPAddress"].startswith(DOC_NETS) for r in inc)
    assert "errorCode" not in inc[0]
    assert all(r["errorCode"] == "AccessDenied" for r in inc[1:])
    regions = {r["eventName"]: r["awsRegion"] for r in inc}
    assert regions.pop("ListBuckets") == "ap-south-1"
    assert set(regions.values()) == {"us-east-1"}
    attach = inc[-1]["requestParameters"]
    assert attach == {"userName": "sentinel-demo-victim", "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}
    flagged = next(a for a in ds.synthetic_alerts(NOW) if a["state"] == "open")["created_at"]
    assert all(r["eventTime"] > flagged for r in inc)


def test_cloudtrail_has_benign_background():
    recs = ds.synthetic_cloudtrail_records(NOW)
    users = Counter(r["userIdentity"]["userName"] for r in recs)
    assert users["ci-deployer"] >= 3 and users["priya"] >= 1
    assert all(r["sourceIPAddress"] != ATTACKER_IP for r in recs)


def test_no_real_looking_access_keys_in_data():
    allowed_markers = ("EXAMPLE",)
    for name in ds.list_dataset_names():
        text = ds.data_path(name).read_text()
        for m in ACCESS_KEY_RE.finditer(text):
            assert any(x in m.group(0) for x in allowed_markers), f"{name}: {m.group(0)}"


# --- app auth ----------------------------------------------------------------------------------

AUTH_FIELDS = {"ts", "event", "user", "ip", "geo", "user_agent", "app", "reason", "simulated", "scenario", "source"}


def test_auth_records_schema():
    recs = ds.synthetic_auth_records(NOW)
    for r in recs:
        assert set(r) == AUTH_FIELDS
        assert r["app"] == "sentinel-demo-app" and r["source"] == "simulated-app-traffic" and r["simulated"] is True
        assert r["scenario"] in {"INC-002", "benign-arjun", "background"}


def test_inc002_bruteforce_scenario():
    recs = [r for r in ds.synthetic_auth_records(NOW) if r["scenario"] == "INC-002"]
    recs.sort(key=lambda r: r["ts"])
    failed = [r for r in recs if r["event"] == "login_failed"]
    assert len(failed) == 18
    assert {r["user"] for r in recs} == {"priya"} and {r["ip"] for r in recs} == {ATTACKER_IP}
    span = parse_ts(failed[-1]["ts"]) - parse_ts(failed[0]["ts"])
    assert timedelta(minutes=3) <= span <= timedelta(minutes=5)
    assert [r["event"] for r in recs[18:]] == ["login_success", "mfa_challenge", "mfa_failed"]


def test_benign_arjun_scenario():
    recs = sorted((r for r in ds.synthetic_auth_records(NOW) if r["scenario"] == "benign-arjun"), key=lambda r: r["ts"])
    assert [r["event"] for r in recs] == ["login_failed", "login_success", "mfa_challenge", "mfa_success"]
    assert all(r["geo"].endswith(", IN") for r in recs)
    ist = timezone(timedelta(hours=5, minutes=30))
    authored = [r for r in ds.load_records(ds.AUTH_FILE) if r["scenario"] == "benign-arjun"]
    assert all(9 <= parse_ts(r["ts"]).astimezone(ist).hour < 18 for r in authored)  # IST work hours


def test_app_auth_simulation_records_end_just_before_now():
    recs = ds.app_auth_simulation_records(NOW)
    assert {r["scenario"] for r in recs} == {"INC-002", "benign-arjun"}
    assert all(r["simulated"] is True for r in recs)
    assert recs == sorted(recs, key=lambda r: r["ts"])
    assert parse_ts(recs[-1]["ts"]) == NOW - timedelta(minutes=1)
    assert Counter(r["event"] for r in recs if r["user"] == "priya")["login_failed"] == 18


# --- identity directory ------------------------------------------------------------------------

def test_users_directory():
    users = {u["username"]: u for u in ds.load_users()}
    assert {"priya", "arjun", "sentinel-demo-victim", "ci-deployer"} <= set(users)
    for u in users.values():
        assert {"username", "display_name", "email", "team", "mfa_enabled", "usual_geo", "usual_ips"} <= u.keys()
        assert u["email"].endswith("@example.com")
    victim = users["sentinel-demo-victim"]
    assert victim["key_owner"] is True and victim["owner"] in users and victim["team"]


# --- backend selection -------------------------------------------------------------------------

def test_backend_choice(monkeypatch):
    monkeypatch.delenv("SENTINEL_BACKEND", raising=False)
    assert ds.backend_choice(load_settings(mode="auto")) == ("offline", None)
    monkeypatch.setenv("SENTINEL_BACKEND", "aws")
    assert ds.backend_choice(load_settings(mode="auto")) == ("aws", None)
    assert ds.backend_choice(load_settings(mode="offline")) == ("offline", "SENTINEL_MODE=offline")
