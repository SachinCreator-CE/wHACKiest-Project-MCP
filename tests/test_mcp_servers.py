"""Tests for the four stdio MCP servers (pure tool functions + real stdio round-trips)."""
from __future__ import annotations

import asyncio
import json
import os
import sys
import types
from datetime import timedelta
from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from sentinel import datasets as ds
from sentinel.mcp_servers import cloudtrail_mock, github_mock, identity, logs
from sentinel.models import parse_ts, utcnow

ROOT = Path(__file__).resolve().parent.parent
KEY = ds.OFFLINE_LEAKED_KEY
LIVE_KEY = "AKIA" + "Q" * 12 + "LIVE"


@pytest.fixture
def aws_backend(monkeypatch):
    """Pretend the hub started the servers with SENTINEL_BACKEND=aws (no real AWS is touched)."""
    monkeypatch.setenv("SENTINEL_BACKEND", "aws")
    monkeypatch.setenv("SENTINEL_MODE", "auto")
    monkeypatch.setattr(identity, "_aws", None)
    monkeypatch.setattr(logs, "_aws", None)


def _fake_module(monkeypatch, name: str, **attrs) -> None:
    monkeypatch.setitem(sys.modules, name, types.SimpleNamespace(**attrs))


# --- github_mock -------------------------------------------------------------------------------

def test_github_offline_backend_uses_example_key(monkeypatch):
    monkeypatch.setenv("DEMO_LEAKED_ACCESS_KEY_ID", LIVE_KEY)  # ignored without the aws backend
    res = github_mock.list_secret_scanning_alerts()
    assert res["backend"] == "mock" and res["key_source"] == "offline"
    assert [a["access_key_id"] for a in res["alerts"]] == [KEY]
    assert len(github_mock.list_secret_scanning_alerts(state="all")["alerts"]) == 2
    assert [a["state"] for a in github_mock.list_secret_scanning_alerts(state="resolved")["alerts"]] == ["resolved"]


def test_github_aws_backend_uses_live_key_and_lookback(monkeypatch, aws_backend):
    monkeypatch.setenv("DEMO_LEAKED_ACCESS_KEY_ID", LIVE_KEY)
    monkeypatch.setenv("CLOUDTRAIL_LOOKBACK_HOURS", "6")
    monkeypatch.delenv("DEMO_LEAK_FLAGGED_AT", raising=False)
    res = github_mock.list_secret_scanning_alerts()
    assert res["key_source"] == "env"
    alert = res["alerts"][0]
    assert alert["access_key_id"] == LIVE_KEY
    age = utcnow() - parse_ts(alert["created_at"])
    assert timedelta(hours=5, minutes=59) < age < timedelta(hours=6, minutes=1)

    monkeypatch.setenv("DEMO_LEAK_FLAGGED_AT", "2026-11-23T10:00:00Z")
    assert github_mock.list_secret_scanning_alerts()["alerts"][0]["created_at"] == "2026-11-23T10:00:00Z"
    forced = github_mock.list_secret_scanning_alerts(offline=True)
    assert forced["key_source"] == "offline" and forced["alerts"][0]["access_key_id"] == KEY


def test_github_explicit_offline_false_overrides_frozen_offline_backend(monkeypatch):
    """The hub fixes SENTINEL_BACKEND at startup; DataSources decides live/offline per call."""
    monkeypatch.setenv("SENTINEL_BACKEND", "offline")  # hub built while AWS was unreachable
    monkeypatch.setenv("SENTINEL_MODE", "auto")
    monkeypatch.setenv("DEMO_LEAKED_ACCESS_KEY_ID", LIVE_KEY)
    res = github_mock.list_secret_scanning_alerts(offline=False)
    assert res["key_source"] == "env" and res["alerts"][0]["access_key_id"] == LIVE_KEY
    assert github_mock.list_secret_scanning_alerts()["alerts"][0]["access_key_id"] == KEY  # not told: backend decides
    monkeypatch.setenv("SENTINEL_MODE", "offline")  # offline mode always wins
    assert github_mock.list_secret_scanning_alerts(offline=False)["alerts"][0]["access_key_id"] == KEY


def test_github_rejects_bad_state():
    with pytest.raises(ValueError):
        github_mock.list_secret_scanning_alerts(state="closed")


# --- cloudtrail_mock ---------------------------------------------------------------------------

def test_lookup_events_shape_and_filters():
    res = cloudtrail_mock.lookup_events(attribute_key="AccessKeyId", attribute_value=KEY, max_results=50)
    assert set(res) == {"events", "next_token", "query_params"}
    assert res["next_token"] is None
    assert res["query_params"]["region"] == "us-east-1" and res["query_params"]["attribute_value"] == KEY
    names = [e["EventName"] for e in res["events"]]
    assert names == ["AttachUserPolicy", "CreateAccessKey", "ListAttachedUserPolicies", "GetCallerIdentity"]  # newest first
    ev = res["events"][0]
    assert set(ev) == {"EventId", "EventName", "ReadOnly", "AccessKeyId", "EventTime", "EventSource", "Username",
                       "Resources", "CloudTrailEvent"}
    assert ev["ReadOnly"] == "false" and ev["Username"] == "sentinel-demo-victim" and ev["AccessKeyId"] == KEY
    detail = json.loads(ev["CloudTrailEvent"])
    assert detail["eventID"] == ev["EventId"] and detail["errorCode"] == "AccessDenied"
    assert {"ResourceType": "AWS::IAM::Policy", "ResourceName": "arn:aws:iam::aws:policy/AdministratorAccess"} in ev["Resources"]

    s3 = cloudtrail_mock.lookup_events(attribute_key="AccessKeyId", attribute_value=KEY, region="ap-south-1")
    assert [e["EventName"] for e in s3["events"]] == ["ListBuckets"]


def test_lookup_events_excludes_data_events_and_filters_other_attributes():
    res = cloudtrail_mock.lookup_events(attribute_key="Username", attribute_value="ci-deployer", region="ap-south-1",
                                        max_results=50)
    names = {e["EventName"] for e in res["events"]}
    assert "DescribeInstances" in names and "PutObject" not in names
    by_res = cloudtrail_mock.lookup_events(attribute_key="ResourceName", attribute_value="sentinel-demo-victim")
    assert len(by_res["events"]) == 3


def test_lookup_events_time_window_and_pagination():
    assert cloudtrail_mock.lookup_events(start_time="10 minutes ago", end_time="now")["events"] == []
    full = cloudtrail_mock.lookup_events(start_time="24 hours ago", max_results=50)["events"]
    page1 = cloudtrail_mock.lookup_events(start_time="24 hours ago", max_results=2)
    assert len(page1["events"]) == 2 and page1["next_token"]
    page2 = cloudtrail_mock.lookup_events(start_time="24 hours ago", max_results=2, next_token=page1["next_token"])
    assert page1["events"] + page2["events"] == full[:4]
    iso_start = (utcnow() - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    assert len(cloudtrail_mock.lookup_events(start_time=iso_start, max_results=50)["events"]) == len(full)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"attribute_key": "SourceIp", "attribute_value": "x"},
        {"attribute_key": "EventName"},
        {"start_time": "yesterday-ish"},
        {"start_time": "now", "end_time": "1 day ago"},
        {"next_token": "garbage"},
    ],
)
def test_lookup_events_rejects_bad_input(kwargs):
    with pytest.raises(ValueError):
        cloudtrail_mock.lookup_events(**kwargs)


# --- identity ----------------------------------------------------------------------------------

def test_identity_offline_filters():
    res = identity.filter_auth_events(user="PRIYA", outcome="failure")
    assert res["backend"] == "offline" and res["live"] is False and res["fallback_reason"] is None
    assert res["log_group"] == "/sentinelai/app-auth"
    assert len(res["events"]) == 19  # 18 login_failed + 1 mfa_failed
    assert identity.filter_auth_events(user="arjun", outcome="login_failed")["events"][0]["scenario"] == "benign-arjun"
    assert len(identity.filter_auth_events(limit=3)["events"]) == 3
    assert identity.filter_auth_events(start_time="5 minutes ago")["events"] == []
    with pytest.raises(ValueError):
        identity.filter_auth_events(outcome="maybe")


def test_identity_aws_backend_uses_cloudwatch(monkeypatch, aws_backend):
    calls = {}
    live_recs = [
        {"ts": (utcnow() - timedelta(minutes=m)).strftime("%Y-%m-%dT%H:%M:%SZ"), "event": ev, "user": "priya"}
        for m, ev in ((3, "login_failed"), (2, "login_success"))
    ]

    def fake_filter(aws, log_group, start_ms, end_ms, user=None, limit=500):
        calls.update(log_group=log_group, user=user, span_h=(end_ms - start_ms) / 3_600_000, limit=limit)
        return live_recs

    _fake_module(monkeypatch, "sentinel.aws.cloudwatch", filter_auth_events=fake_filter)
    res = identity.filter_auth_events(user="priya", outcome="failure")
    assert res["backend"] == "cloudwatch-logs" and res["live"] is True and res["fallback_reason"] is None
    assert [e["event"] for e in res["events"]] == ["login_failed"]
    assert calls["log_group"] == "/sentinelai/app-auth" and calls["user"] == "priya"
    assert round(calls["span_h"]) == 24


@pytest.mark.parametrize("module", [None, "raises"])
def test_identity_aws_failure_falls_back(monkeypatch, aws_backend, module):
    if module is None:
        monkeypatch.setitem(sys.modules, "sentinel.aws.cloudwatch", None)  # -> ImportError
    else:
        def boom(*_a, **_k):
            raise RuntimeError("log group not found")
        _fake_module(monkeypatch, "sentinel.aws.cloudwatch", filter_auth_events=boom)
    res = identity.filter_auth_events(user="priya")
    assert res["backend"] == "offline" and res["live"] is False
    assert res["fallback_reason"]
    assert any(e["scenario"] == "INC-002" for e in res["events"])


def test_identity_directory():
    assert identity.get_user("Sentinel-Demo-Victim")["user"]["owner"] == "priya"
    assert identity.get_user("nobody") == {"user": None}
    assert len(identity.list_users()["users"]) >= 4


# --- logs --------------------------------------------------------------------------------------

def test_logs_offline():
    res = logs.list_datasets()
    assert res["backend"] == "offline" and "cloudtrail/events.json" in res["datasets"]
    data = logs.read_dataset("cloudtrail/events.json", limit=2, contains="ATTACHUSERPOLICY")
    assert data["total"] == 1 and data["records"][0]["eventName"] == "AttachUserPolicy"
    assert parse_ts(data["records"][0]["eventTime"]) > utcnow() - timedelta(days=1)  # time-shifted like other tools
    alerts = logs.read_dataset("github/secret_scanning_alerts.json")["records"]
    assert ds.KEY_PLACEHOLDER not in json.dumps(alerts)
    assert len(logs.read_dataset("auth/app_auth.jsonl", limit=5)["records"]) == 5


@pytest.mark.parametrize("name", ["../config.py", "/etc/passwd", "auth/../../x.json", "identity/users.txt"])
def test_logs_rejects_bad_names(name):
    with pytest.raises(ValueError):
        logs.read_dataset(name)


def test_logs_unknown_dataset_is_a_result_not_an_error():
    """A hallucinated name must not raise (that reads as 'Logs MCP unavailable') or leak the local data/ path."""
    res = logs.read_dataset("cloudtrail/cloudtrail_events.json")
    assert res["records"] == [] and res["total"] == 0 and "list_datasets" in res["error"]
    assert res["live"] is False and res["fallback_reason"] is None
    assert str(ROOT) not in json.dumps(res)


def test_logs_aws_unknown_dataset_keeps_s3_live(monkeypatch, aws_backend):
    monkeypatch.setenv("S3_BUCKET", "sentinel-demo-bucket")

    class NoSuchKey(Exception):
        response = {"Error": {"Code": "NoSuchKey", "Message": "The specified key does not exist."}}

    def get_text(*_a):
        raise NoSuchKey("NoSuchKey")

    _fake_module(monkeypatch, "sentinel.aws.s3", get_text=get_text)
    res = logs.read_dataset("cloudtrail/cloudtrail_events.json")
    assert res["records"] == [] and "unknown dataset" in res["error"]
    assert res["live"] is True and res["backend"] == "s3" and res["fallback_reason"] is None


def test_logs_aws_without_bucket_falls_back(monkeypatch, aws_backend):
    monkeypatch.delenv("S3_BUCKET", raising=False)
    res = logs.list_datasets()
    assert res["backend"] == "offline" and res["fallback_reason"] == "S3_BUCKET is not set"


def test_logs_aws_reads_s3(monkeypatch, aws_backend):
    monkeypatch.setenv("S3_BUCKET", "sentinel-demo-bucket")
    seen = []

    def get_text(aws, bucket, key):
        seen.append((bucket, key))
        return '{"ts": "2026-11-20T00:00:00Z", "msg": "hello"}\n{"ts": "2026-11-20T00:00:01Z", "msg": "bye"}\n'

    def list_keys(aws, bucket, prefix):
        return [{"key": f"{prefix}auth/app_auth.jsonl", "size": 10, "last_modified": ""},
                {"key": f"{prefix}README.txt", "size": 1, "last_modified": ""}]

    _fake_module(monkeypatch, "sentinel.aws.s3", get_text=get_text, list_keys=list_keys)
    assert logs.list_datasets() == {"datasets": ["auth/app_auth.jsonl"], "backend": "s3", "live": True,
                                    "fallback_reason": None}
    res = logs.read_dataset("auth/app_auth.jsonl", contains="hello")
    assert seen == [("sentinel-demo-bucket", "raw/auth/app_auth.jsonl")]
    assert res["backend"] == "s3" and res["live"] is True and res["records"] == [
        {"ts": "2026-11-20T00:00:00Z", "msg": "hello"}]


def test_logs_aws_read_failure_falls_back(monkeypatch, aws_backend):
    monkeypatch.setenv("S3_BUCKET", "sentinel-demo-bucket")

    def get_text(*_a):
        raise KeyError("NoSuchKey")

    _fake_module(monkeypatch, "sentinel.aws.s3", get_text=get_text)
    res = logs.read_dataset("identity/users.json")
    assert res["backend"] == "offline" and "NoSuchKey" in res["fallback_reason"] and res["total"] >= 4


# --- real stdio round-trips --------------------------------------------------------------------

async def _roundtrip(module: str, tool: str, args: dict) -> tuple[list[str], dict]:
    env = {
        **os.environ,
        "PYTHONPATH": str(ROOT),
        "SENTINEL_BACKEND": "offline",
        "SENTINEL_MODE": "offline",
        "SENTINEL_NO_DOTENV": "1",
    }
    params = StdioServerParameters(command=sys.executable, args=["-m", f"sentinel.mcp_servers.{module}"], env=env, cwd=ROOT)
    async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        tools = (await session.list_tools()).tools
        res = await session.call_tool(tool, args)
        assert not res.is_error, res.content
        return [t.name for t in tools], json.loads(res.content[0].text)


@pytest.mark.parametrize(
    ("module", "tool", "args", "expected_tools"),
    [
        ("cloudtrail_mock", "lookup_events", {"attribute_key": "AccessKeyId", "attribute_value": KEY,
                                              "start_time": "1 day ago"}, {"lookup_events"}),
        ("github_mock", "list_secret_scanning_alerts", {"state": "open"}, {"list_secret_scanning_alerts"}),
        ("identity", "filter_auth_events", {"user": "priya", "outcome": "failure"},
         {"filter_auth_events", "get_user", "list_users"}),
        ("logs", "list_datasets", {}, {"list_datasets", "read_dataset"}),
    ],
)
def test_stdio_roundtrip(module, tool, args, expected_tools):
    names, payload = asyncio.run(asyncio.wait_for(_roundtrip(module, tool, args), timeout=60))
    assert set(names) == expected_tools
    if module == "cloudtrail_mock":
        assert len(payload["events"]) == 4 and payload["events"][0]["EventName"] == "AttachUserPolicy"
    elif module == "github_mock":
        assert payload["alerts"][0]["access_key_id"] == KEY and payload["key_source"] == "offline"
    elif module == "identity":
        assert payload["backend"] == "offline" and len(payload["events"]) == 19
    else:
        assert "auth/app_auth.jsonl" in payload["datasets"]


def test_stdio_cloudtrail_schema_matches_awslabs_parameters():
    async def schema() -> dict:
        env = {**os.environ, "PYTHONPATH": str(ROOT), "SENTINEL_NO_DOTENV": "1", "SENTINEL_MODE": "offline"}
        params = StdioServerParameters(command=sys.executable, args=["-m", "sentinel.mcp_servers.cloudtrail_mock"],
                                       env=env, cwd=ROOT)
        async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
            await session.initialize()
            return (await session.list_tools()).tools[0].input_schema

    props = asyncio.run(asyncio.wait_for(schema(), timeout=60))["properties"]
    assert list(props) == ["start_time", "end_time", "attribute_key", "attribute_value", "max_results", "next_token",
                           "region"]
