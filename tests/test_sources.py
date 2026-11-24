"""DataSources with a fake hub, a fake AWS factory (Stubber) and a fake datasets module."""
from __future__ import annotations

import asyncio
import json
import sys
import time
import types
from datetime import timedelta
from collections.abc import Callable
from typing import Any

import boto3
import pytest
from botocore import UNSIGNED
from botocore.config import Config
from botocore.exceptions import ClientError
from botocore.stub import ANY, Stubber

from sentinel import trace
from sentinel.aws.session import AwsStatus
from sentinel.config import load_settings
from sentinel.mcp_hub import AWSLABS_CLOUDTRAIL, MCPError
from sentinel.models import iso, parse_ts, utcnow
from sentinel.sources import EXTRA_PAGES, DataSources, TokenBucket, is_throttling
from sentinel.store import SQLiteStore

KEY = "AKIAIOSFODNN7EXAMPLE"
Handler = Callable[[dict[str, Any]], dict[str, Any]]


# ------------------------------------------------------------------ fakes
class FakeHub:
    """Records calls; a missing handler behaves like a server that can't start."""

    def __init__(self, handlers: dict[tuple[str, str], Handler] | None = None, registered: set[str] | None = None):
        self.handlers = handlers or {}
        self.registered = registered if registered is not None else {"github", "cloudtrail_mock", "identity", "logs"}
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    def is_registered(self, name: str) -> bool:
        return name in self.registered

    async def call(self, name: str, tool: str, args: dict[str, Any], timeout: float = 45) -> dict[str, Any]:
        self.calls.append((name, tool, dict(args)))
        handler = self.handlers.get((name, tool))
        if handler is None:
            raise MCPError(f"{name} failed to start")
        return handler(args)

    def count(self, name: str) -> int:
        return sum(1 for c in self.calls if c[0] == name)


class FakeAws:
    def __init__(self, connected: bool = True, reason: str = ""):
        self._status = AwsStatus(connected, account_suffix="1234" if connected else "", region="ap-south-1", reason=reason)
        self.failures: list[BaseException] = []
        self.stubs: dict[str, Stubber] = {}

    def status(self, refresh: bool = False) -> AwsStatus:
        return self._status

    def mark_failure(self, exc: BaseException) -> None:
        self.failures.append(exc)

    def stub(self, region: str) -> Stubber:
        client = boto3.client("cloudtrail", region_name=region, config=Config(signature_version=UNSIGNED))
        self.stubs[region] = Stubber(client)
        self.stubs[region].activate()
        return self.stubs[region]

    def client(self, service: str, region: str | None = None) -> Any:
        assert service == "cloudtrail", service
        return self.stubs[region or "ap-south-1"].client


def ct_record(eid: str, name: str, minutes_ago: int, region: str, key: str = KEY, error: str = "") -> dict[str, Any]:
    rec = {
        "eventID": eid, "eventName": name, "eventTime": iso(utcnow() - timedelta(minutes=minutes_ago)),
        "eventSource": "iam.amazonaws.com", "awsRegion": region, "sourceIPAddress": "203.0.113.50",
        "userIdentity": {"type": "IAMUser", "userName": "sentinel-demo-victim", "accessKeyId": key},
    }
    if error:
        rec["errorCode"] = error
    return rec


def ct_raw(eid: str, name: str, minutes_ago: int, region: str, error: str = "") -> dict[str, Any]:
    rec = ct_record(eid, name, minutes_ago, region, error=error)
    return {"EventId": eid, "EventName": name, "AccessKeyId": KEY, "EventTime": rec["eventTime"],
            "EventSource": rec["eventSource"], "Username": "sentinel-demo-victim", "Resources": [],
            "CloudTrailEvent": json.dumps(rec)}


def auth_rec(user: str, event: str, minutes_ago: int, ip: str = "185.220.101.47") -> dict[str, Any]:
    return {"ts": iso(utcnow() - timedelta(minutes=minutes_ago)), "event": event, "user": user, "ip": ip, "geo": "DE",
            "app": "sentinel-demo-app", "simulated": True, "scenario": "INC-002", "source": "simulated-app-traffic"}


@pytest.fixture
def fake_datasets(monkeypatch: pytest.MonkeyPatch) -> types.ModuleType:
    mod = types.ModuleType("sentinel.datasets")
    mod.calls = []  # type: ignore[attr-defined]

    def synthetic_alerts(now=None, live_key=None, flagged_at=None):
        mod.calls.append(("synthetic_alerts", live_key, flagged_at))
        return [
            {"number": 2, "state": "resolved", "access_key_id": "AKIAI44QH8DHBEXAMPLE", "repository": "acme/old",
             "path": "x", "commit_sha": "1", "created_at": "2026-11-01T00:00:00Z", "html_url": ""},
            {"number": 1, "state": "open", "access_key_id": live_key or KEY, "repository": "acme-payments/billing-service",
             "path": "config/settings.py", "commit_sha": "2", "created_at": flagged_at or iso(), "html_url": ""},
        ]

    mod.synthetic_alerts = synthetic_alerts  # type: ignore[attr-defined]
    mod.synthetic_cloudtrail_records = lambda now=None: [  # type: ignore[attr-defined]
        ct_record("l1", "GetCallerIdentity", 20, "us-east-1"),
        ct_record("l2", "ListBuckets", 15, "ap-south-1"),
        ct_record("l3", "CreateAccessKey", 10, "us-east-1", error="AccessDenied"),
        ct_record("l4", "ListUsers", 5, "us-east-1", key="AKIAEXAMPLEOTHER0000"),
        ct_record("l5", "GetUser", 60 * 48, "us-east-1"),  # outside the window
    ]
    mod.synthetic_auth_records = lambda now=None: [  # type: ignore[attr-defined]
        auth_rec("priya", "login_failed", 9), auth_rec("priya", "login_success", 8),
        auth_rec("arjun", "login_failed", 7, ip="49.36.0.1"),
    ]
    mod.load_records = lambda rel, settings=None: (  # type: ignore[attr-defined]
        [{"username": "priya", "mfa": True}] if rel == "identity/users.json"
        else [{"msg": "hello priya"}, {"msg": "hello arjun"}, {"msg": "bye priya"}]
    )
    mod.list_dataset_names = lambda settings=None: ["auth/app_auth.jsonl", "cloudtrail/events.json"]  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "sentinel.datasets", mod)
    return mod


def make(hub: FakeHub, aws: FakeAws, **settings: Any) -> DataSources:
    opts: dict[str, Any] = {"mode": "auto", "cloudtrail_regions": ["ap-south-1", "us-east-1"]}
    opts.update(settings)
    ds = DataSources(load_settings(**opts), hub, aws, SQLiteStore(":memory:"))  # type: ignore[arg-type]
    ds.backoff_base_s = 0
    return ds


def run(coro):
    with trace.collect() as spans:
        result = asyncio.run(coro)
    return result, spans


# ----------------------------------------------------------- CloudTrail
def test_live_awslabs_paginates_dedupes_sorts_and_caches() -> None:
    def lookup(args: dict[str, Any]) -> dict[str, Any]:
        qp = {**args, "start_time": "2026-11-23T00:00:00+00:00"}  # server-normalised window
        qp.pop("next_token", None)
        if args["region"] == "ap-south-1":
            if "next_token" not in args:
                return {"events": [ct_raw("a", "ListBuckets", 30, "ap-south-1")], "next_token": "tok", "query_params": qp}
            assert args["next_token"] == "tok" and args["start_time"] == "2026-11-23T00:00:00+00:00"
            return {"events": [ct_raw("shared", "GetCallerIdentity", 40, "us-east-1")], "next_token": None, "query_params": qp}
        assert args["max_results"] == 50 and args["attribute_key"] == "AccessKeyId" and args["attribute_value"] == KEY
        return {"events": [ct_raw("shared", "GetCallerIdentity", 40, "us-east-1"),
                           ct_raw("b", "AttachUserPolicy", 10, "us-east-1", error="AccessDenied")], "next_token": None}

    hub = FakeHub({(AWSLABS_CLOUDTRAIL, "lookup_events"): lookup}, registered={AWSLABS_CLOUDTRAIL})
    ds = make(hub, FakeAws())
    (events, meta), spans = run(ds.cloudtrail_lookup("AccessKeyId", KEY))

    assert [e.id for e in events] == ["shared", "a", "b"]  # deduped and sorted by ts
    assert all(e.live for e in events) and events[-1].outcome == "denied"
    assert meta["live"] is True and meta["backend"] == "awslabs.cloudtrail-mcp-server" and meta["count"] == 3
    assert meta["regions"] == ["ap-south-1", "us-east-1"] and meta["fallback_reason"] is None
    assert hub.count(AWSLABS_CLOUDTRAIL) == 3
    assert {(s.server, s.target, s.backend) for s in spans} == {("CloudTrail MCP", "aws", "awslabs.cloudtrail-mcp-server")}
    assert any("2 pages" in s.summary for s in spans)

    (again, meta2), spans2 = run(ds.cloudtrail_lookup("AccessKeyId", KEY))
    assert [e.id for e in again] == ["shared", "a", "b"] and meta2["live"] is True
    assert hub.count(AWSLABS_CLOUDTRAIL) == 3  # served from the store cache
    assert all("(cached)" in s.summary for s in spans2)
    assert ds.fallbacks == {}


def test_throttling_is_retried_with_backoff() -> None:
    attempts = {"n": 0}

    def lookup(args: dict[str, Any]) -> dict[str, Any]:
        attempts["n"] += 1
        if attempts["n"] < 3:
            raise MCPError("CloudTrail MCP (AWS Labs) lookup_events failed: ThrottlingException: Rate exceeded")
        return {"events": [ct_raw("a", "ListBuckets", 5, "us-east-1")], "next_token": None}

    hub = FakeHub({(AWSLABS_CLOUDTRAIL, "lookup_events"): lookup}, registered={AWSLABS_CLOUDTRAIL})
    (events, meta), _ = run(make(hub, FakeAws()).cloudtrail_lookup("AccessKeyId", KEY, regions=["us-east-1"]))
    assert attempts["n"] == 3 and [e.id for e in events] == ["a"] and meta["backend"] == "awslabs.cloudtrail-mcp-server"


def test_awslabs_generic_error_with_server_log_is_retried() -> None:
    """What MCPHub raises for a real AWS Labs throttle: FastMCP's generic text plus the server's ctx.error() log."""
    attempts = {"n": 0}

    def lookup(args: dict[str, Any]) -> dict[str, Any]:
        attempts["n"] += 1
        if attempts["n"] < 2:
            raise MCPError("CloudTrail MCP (AWS Labs) lookup_events failed: Error executing tool lookup_events (Error looking "
                           "up CloudTrail events: An error occurred (ThrottlingException) when calling the LookupEvents "
                           "operation: Rate exceeded)")
        return {"events": [ct_raw("a", "ListBuckets", 5, "us-east-1")], "next_token": None}

    hub = FakeHub({(AWSLABS_CLOUDTRAIL, "lookup_events"): lookup}, registered={AWSLABS_CLOUDTRAIL})
    (events, meta), _ = run(make(hub, FakeAws()).cloudtrail_lookup("AccessKeyId", KEY, regions=["us-east-1"]))
    assert attempts["n"] == 2 and [e.id for e in events] == ["a"] and meta["backend"] == "awslabs.cloudtrail-mcp-server"


def test_pagination_stops_on_repeated_token_and_page_cap() -> None:
    calls = {"n": 0}

    def same_token(args: dict[str, Any]) -> dict[str, Any]:
        calls["n"] += 1
        return {"events": [], "next_token": "SAME"}

    hub = FakeHub({(AWSLABS_CLOUDTRAIL, "lookup_events"): same_token}, registered={AWSLABS_CLOUDTRAIL})
    ds = make(hub, FakeAws())
    ds.lookup_bucket("us-east-1").rate = 1000  # keep the test fast
    (events, meta), _ = run(asyncio.wait_for(ds.cloudtrail_lookup("AccessKeyId", KEY, regions=["us-east-1"]), 10))
    assert calls["n"] == 2 and events == [] and meta["live"] is True
    assert "repeated" in meta["partial"]["us-east-1"]

    calls["n"] = 0

    def fresh_tokens(args: dict[str, Any]) -> dict[str, Any]:
        calls["n"] += 1
        return {"events": [], "next_token": f"t{calls['n']}"}

    hub = FakeHub({(AWSLABS_CLOUDTRAIL, "lookup_events"): fresh_tokens}, registered={AWSLABS_CLOUDTRAIL})
    ds = make(hub, FakeAws())
    ds.lookup_bucket("us-east-1").rate = 1000
    (events, meta), _ = run(asyncio.wait_for(ds.cloudtrail_lookup("AccessKeyId", KEY, regions=["us-east-1"], max_events=100), 10))
    assert calls["n"] == 2 + EXTRA_PAGES and "page cap" in meta["partial"]["us-east-1"]

    aws = FakeAws()
    stub = aws.stub("us-east-1")
    for _ in range(5):
        stub.add_response("lookup_events", {"Events": [], "NextToken": "SAME"}, None)
    ds = make(FakeHub({}, registered=set()), aws)
    ds.lookup_bucket("us-east-1").rate = 1000
    (events, meta), _ = run(asyncio.wait_for(ds.cloudtrail_lookup("AccessKeyId", KEY, regions=["us-east-1"]), 10))
    assert meta["backend"] == "boto3" and "repeated" in meta["partial"]["us-east-1"] and len(stub._queue) == 3


def test_mid_pagination_failure_keeps_live_pages_and_skips_cache() -> None:
    def lookup(args: dict[str, Any]) -> dict[str, Any]:
        if args.get("next_token") == "p2":
            raise MCPError("CloudTrail MCP (AWS Labs) lookup_events failed: Error executing tool lookup_events")
        n = int((args.get("next_token") or "p0")[1:])
        return {"events": [ct_raw(f"e{n}-{i}", "ListBuckets", n * 50 + i, "us-east-1") for i in range(50)],
                "next_token": f"p{n + 1}"}

    mock = lambda args: {"events": [ct_raw("mock1", "ListBuckets", 3, "us-east-1")]}  # noqa: E731
    hub = FakeHub({(AWSLABS_CLOUDTRAIL, "lookup_events"): lookup, ("cloudtrail_mock", "lookup_events"): mock},
                  registered={AWSLABS_CLOUDTRAIL, "cloudtrail_mock"})
    aws = FakeAws()
    aws.stub("us-east-1")  # boto3 must not be called: no responses queued
    ds = make(hub, aws)
    ds.lookup_bucket("us-east-1").rate = 1000
    (events, meta), spans = run(ds.cloudtrail_lookup("AccessKeyId", KEY, regions=["us-east-1"]))

    assert len(events) == 100 and all(e.live for e in events) and "mock1" not in {e.id for e in events}
    assert meta["live"] is True and meta["backend"] == "awslabs.cloudtrail-mcp-server" and meta["fallback_reason"] is None
    assert "page 3 failed" in meta["partial"]["us-east-1"] and "kept 100 events" in meta["partial"]["us-east-1"]
    assert ds.fallbacks == {} and hub.count("cloudtrail_mock") == 0
    assert any("(partial)" in s.summary for s in spans)
    run(ds.cloudtrail_lookup("AccessKeyId", KEY, regions=["us-east-1"]))
    assert hub.count(AWSLABS_CLOUDTRAIL) == 6  # partial result was not cached


def test_lookup_buckets_are_per_region_and_strict() -> None:
    ds = make(FakeHub({}), FakeAws())
    a, b = ds.lookup_bucket("us-east-1"), ds.lookup_bucket("ap-south-1")
    assert a is ds.lookup_bucket("us-east-1") and a is not b
    assert a.rate == 2 and a.capacity == 1  # 0.5 s spacing: never 3 calls in one second


def test_awslabs_server_is_started_before_a_rate_limit_slot_is_taken() -> None:
    order: list[str] = []

    class StartingHub(FakeHub):
        async def start(self, name: str, timeout: float = 45) -> None:
            order.append(f"start:{name}")

    hub = StartingHub({(AWSLABS_CLOUDTRAIL, "lookup_events"): lambda a: order.append("call") or {"events": []}},
                      registered={AWSLABS_CLOUDTRAIL})
    ds = make(hub, FakeAws())
    bucket = ds.lookup_bucket("us-east-1")
    real_acquire = bucket.acquire

    async def acquire() -> None:
        order.append("acquire")
        await real_acquire()

    bucket.acquire = acquire  # type: ignore[method-assign]
    run(ds.cloudtrail_lookup("AccessKeyId", KEY, regions=["us-east-1"]))
    assert order == [f"start:{AWSLABS_CLOUDTRAIL}", "acquire", "call"]


def test_awslabs_failure_falls_back_to_boto3_direct() -> None:
    aws = FakeAws()
    for region, eid in (("ap-south-1", "s3-1"), ("us-east-1", "iam-1")):
        stub = aws.stub(region)
        params = {"StartTime": ANY, "EndTime": ANY, "MaxResults": 50,
                  "LookupAttributes": [{"AttributeKey": "AccessKeyId", "AttributeValue": KEY}]}
        raw = ct_raw(eid, "ListBuckets", 5, region)
        raw["EventTime"] = utcnow()
        stub.add_response("lookup_events", {"Events": [raw], "NextToken": "n"}, params)
        stub.add_response("lookup_events", {"Events": []}, {**params, "NextToken": "n"})
    hub = FakeHub({}, registered={AWSLABS_CLOUDTRAIL})  # registered but cannot start
    ds = make(hub, aws)
    (events, meta), spans = run(ds.cloudtrail_lookup("AccessKeyId", KEY, hours_back=2))

    assert sorted(e.id for e in events) == ["iam-1", "s3-1"] and all(e.live for e in events)
    assert meta["live"] is True and meta["backend"] == "boto3" and meta["fallback_reason"] is None
    assert ds.fallbacks == {}  # boto3 is still real AWS: no offline banner
    ok_spans = [s for s in spans if s.ok]
    assert {(s.target, s.backend) for s in ok_spans} == {("aws", "boto3")}
    assert any(not s.ok and s.backend == "awslabs.cloudtrail-mcp-server" for s in spans)
    for stub in aws.stubs.values():
        stub.assert_no_pending_responses()


def test_all_live_paths_fail_falls_back_to_mock_and_notes_reason() -> None:
    aws = FakeAws()
    aws.stub("us-east-1").add_client_error("lookup_events", "AccessDeniedException", "not authorized")
    mock = lambda args: {"events": [ct_raw("m1", "ListBuckets", 5, "us-east-1")], "next_token": None}  # noqa: E731
    hub = FakeHub({("cloudtrail_mock", "lookup_events"): mock})  # AWS Labs not registered
    ds = make(hub, aws)
    (events, meta), spans = run(ds.cloudtrail_lookup("AccessKeyId", KEY, regions=["us-east-1"]))

    assert [e.id for e in events] == ["m1"] and not events[0].live
    assert meta["live"] is False and meta["backend"] == "mock"
    assert "AccessDeniedException" in meta["fallback_reason"]
    assert "AccessDeniedException" in ds.fallbacks["cloudtrail"]["reason"]
    assert isinstance(aws.failures[0], ClientError)
    assert spans[-1].target == "offline" and spans[-1].backend == "mock"


def test_not_connected_uses_mock_and_force_offline_does_not_note() -> None:
    seen: list[dict[str, Any]] = []
    mock = lambda args: seen.append(args) or {"events": [ct_raw("m-" + args["region"], "ListBuckets", 5, args["region"])]}  # noqa: E731
    hub = FakeHub({("cloudtrail_mock", "lookup_events"): mock})
    ds = make(hub, FakeAws(connected=False, reason="No AWS credentials found"))
    (events, meta), _ = run(ds.cloudtrail_lookup("AccessKeyId", KEY))
    assert meta["live"] is False and meta["backend"] == "mock" and len(events) == 2
    assert "No AWS credentials found" in ds.fallbacks["cloudtrail"]["reason"]
    assert {a["region"] for a in seen} == {"ap-south-1", "us-east-1"}

    ds.fallbacks.clear()
    (_, meta), _ = run(ds.cloudtrail_lookup("AccessKeyId", KEY, force_offline=True))
    assert meta["fallback_reason"].endswith("forced offline") and ds.fallbacks == {}


def test_offline_mode_with_mock_server_down_uses_local_synthetic_data(fake_datasets: types.ModuleType) -> None:
    ds = make(FakeHub({}), FakeAws(connected=False, reason="SENTINEL_MODE=offline"), mode="offline")
    (events, meta), spans = run(ds.cloudtrail_lookup("AccessKeyId", KEY))
    assert [e.id for e in events] == ["l1", "l2", "l3"]  # other key and out-of-window records dropped
    assert {e.region for e in events} == {"us-east-1", "ap-south-1"}
    assert meta["backend"] == "local-data" and meta["live"] is False
    assert "mock CloudTrail MCP failed" in ds.fallbacks["cloudtrail"]["reason"]
    assert all(s.target == "offline" for s in spans)


def test_attribute_filter_on_local_data(fake_datasets: types.ModuleType) -> None:
    ds = make(FakeHub({}), FakeAws(connected=False), mode="offline")
    (events, _), _ = run(ds.cloudtrail_lookup("EventName", "CreateAccessKey"))
    assert [e.id for e in events] == ["l3"]


# --------------------------------------------------------------- GitHub
def test_github_alerts_via_hub() -> None:
    alerts = lambda args: {"alerts": [{"number": 1, "state": "open", "access_key_id": KEY,  # noqa: E731
                                       "repository": "acme-payments/billing-service", "created_at": iso()}],
                           "backend": "mock", "key_source": "offline" if args["offline"] else "env"}
    hub = FakeHub({("github", "list_secret_scanning_alerts"): alerts})
    result, spans = run(make(hub, FakeAws(connected=False)).github_alerts())
    assert result[0].access_key_id == KEY and result[0].repository == "acme-payments/billing-service"
    assert hub.calls[0][2] == {"state": "open", "offline": True}
    assert spans[0].server == "GitHub MCP" and spans[0].summary == "1 alerts" and spans[0].target == "offline"

    run(make(hub, FakeAws(connected=True)).github_alerts())
    assert hub.calls[-1][2]["offline"] is False


def test_github_alerts_local_fallback_uses_live_key(fake_datasets: types.ModuleType) -> None:
    live_key = "AKIAEXAMPLEABCDEMNOP"
    ds = make(FakeHub({}), FakeAws(connected=True), demo_leaked_access_key_id=live_key, demo_leak_flagged_at="2026-11-24T00:00:00Z")
    result, _ = run(ds.github_alerts(state="open"))
    assert [a.number for a in result] == [1] and result[0].access_key_id == live_key
    assert fake_datasets.calls[-1] == ("synthetic_alerts", live_key, "2026-11-24T00:00:00Z")
    assert "github" in ds.fallbacks

    result, _ = run(ds.github_alerts(state="all", force_offline=True))
    assert [a.number for a in result] == [1, 2] and result[0].access_key_id == KEY


def test_github_alerts_local_fallback_survives_invalid_flagged_at(fake_datasets: types.ModuleType) -> None:
    live_key = "AKIAEXAMPLEABCDEMNOP"
    ds = make(FakeHub({}), FakeAws(connected=True), demo_leaked_access_key_id=live_key,
              demo_leak_flagged_at="24/11/2026 10:00", cloudtrail_lookback_hours=24)
    result, _ = run(ds.github_alerts(state="open"))
    assert [a.number for a in result] == [1] and result[0].access_key_id == live_key
    flagged = parse_ts(fake_datasets.calls[-1][2])
    assert abs((utcnow() - flagged).total_seconds() - 24 * 3600) < 120  # lookback start, like the GitHub MCP


# ------------------------------------------------------------- auth logs
def test_auth_events_live_then_server_fallback_is_noted() -> None:
    state = {"live": True}

    def identity(args: dict[str, Any]) -> dict[str, Any]:
        assert args["user"] == "priya" and args["limit"] == 500
        return {"events": [auth_rec("priya", "login_success", 1), auth_rec("priya", "login_failed", 2)],
                "backend": "cloudwatch-logs" if state["live"] else "offline", "live": state["live"],
                "log_group": "/sentinelai/app-auth", "fallback_reason": None if state["live"] else "AccessDeniedException"}

    hub = FakeHub({("identity", "filter_auth_events"): identity})
    ds = make(hub, FakeAws())
    (events, meta), spans = run(ds.auth_events(user="priya"))
    assert [e.kind for e in events] == ["login_failed", "login_success"] and all(e.live for e in events)
    assert meta["live"] is True and meta["backend"] == "cloudwatch-logs" and meta["count"] == 2
    assert spans[0].target == "aws" and spans[0].backend == "cloudwatch-logs"

    state["live"] = False
    (events, meta), spans = run(ds.auth_events(user="priya"))
    assert not events[0].live and meta["fallback_reason"] == "AccessDeniedException"
    assert ds.fallbacks["auth"]["reason"] == "AccessDeniedException" and spans[0].target == "offline"

    state["live"] = True
    run(ds.auth_events(user="priya"))
    assert "auth" not in ds.fallbacks


def test_auth_events_force_offline_filters_locally(fake_datasets: types.ModuleType) -> None:
    hub = FakeHub({})
    ds = make(hub, FakeAws())
    (events, meta), _ = run(ds.auth_events(user="priya", outcome="failure", force_offline=True))
    assert [(e.actor, e.kind) for e in events] == [("priya", "login_failed")]
    assert hub.calls == [] and meta["live"] is False and ds.fallbacks == {}


def test_auth_events_hub_down_falls_back_and_notes(fake_datasets: types.ModuleType) -> None:
    ds = make(FakeHub({}), FakeAws(connected=False), mode="offline")
    (events, meta), _ = run(ds.auth_events())
    assert len(events) == 3 and "Identity MCP unavailable" in meta["fallback_reason"]
    assert "auth" in ds.fallbacks


# ------------------------------------------------------- identity + logs
def test_get_user_via_hub_and_local_fallback(fake_datasets: types.ModuleType) -> None:
    hub = FakeHub({("identity", "get_user"): lambda a: {"user": {"username": a["username"]} if a["username"] == "priya" else None}})
    ds = make(hub, FakeAws(connected=False))
    assert run(ds.get_user("priya"))[0] == {"username": "priya"}
    assert run(ds.get_user("nobody"))[0] is None

    ds = make(FakeHub({}), FakeAws(connected=False))
    assert run(ds.get_user("priya"))[0] == {"username": "priya", "mfa": True}
    assert "identity" in ds.fallbacks


def test_datasets_via_hub_and_local_fallback(fake_datasets: types.ModuleType) -> None:
    hub = FakeHub({
        ("logs", "list_datasets"): lambda a: {"datasets": ["cloudtrail/events.json"], "backend": "s3", "live": True, "fallback_reason": None},
        ("logs", "read_dataset"): lambda a: {"records": [{"n": 1}], "backend": "s3", "live": True, "fallback_reason": None},
    })
    ds = make(hub, FakeAws())
    (names, meta), spans = run(ds.list_datasets())
    assert names == ["cloudtrail/events.json"] and meta["live"] is True and spans[0].target == "aws"
    (records, meta), _ = run(ds.read_dataset("cloudtrail/events.json", limit=5, contains="x"))
    assert records == [{"n": 1}] and hub.calls[-1][2] == {"name": "cloudtrail/events.json", "limit": 5, "contains": "x"}

    ds = make(FakeHub({}), FakeAws())
    (names, meta), _ = run(ds.list_datasets())
    assert names == ["auth/app_auth.jsonl", "cloudtrail/events.json"] and "Logs MCP unavailable" in meta["fallback_reason"]
    (records, meta), _ = run(ds.read_dataset("auth/app_auth.jsonl", limit=1, contains="PRIYA"))
    assert records == [{"msg": "hello priya"}] and meta["count"] == 1 and "logs" in ds.fallbacks


def test_unknown_dataset_is_a_tool_error_not_a_logs_outage(fake_datasets: types.ModuleType) -> None:
    """A hallucinated dataset name from the agent must not raise the 'Logs MCP unavailable' banner or leak paths."""
    hub = FakeHub({("logs", "read_dataset"): lambda a: {
        "name": a["name"], "records": [], "total": 0, "error": f"unknown dataset {a['name']!r}; call list_datasets",
        "backend": "s3", "live": True, "fallback_reason": None}})
    ds = make(hub, FakeAws())
    with pytest.raises(ValueError, match="call list_datasets"):
        run(ds.read_dataset("cloudtrail/cloudtrail_events.json"))
    assert "logs" not in ds.fallbacks

    def missing(rel, settings=None):
        raise FileNotFoundError(f"/Users/someone/sentinelai/data/{rel}")

    fake_datasets.load_records = missing  # type: ignore[attr-defined]
    ds = make(FakeHub({}), FakeAws())  # Logs MCP down: local fallback
    with pytest.raises(ValueError) as err:
        run(ds.read_dataset("cloudtrail/cloudtrail_events.json"))
    assert "call list_datasets" in str(err.value) and "/Users/" not in str(err.value)


@pytest.mark.parametrize("name", ["../secrets.json", "/etc/passwd", "a/../../b", "", "C:\\x", "s3://bucket/x"])
def test_read_dataset_rejects_path_traversal(name: str) -> None:
    ds = make(FakeHub({}), FakeAws())
    with pytest.raises(ValueError):
        asyncio.run(ds.read_dataset(name))


# ------------------------------------------------------------ primitives
def test_token_bucket_limits_rate() -> None:
    bucket = TokenBucket(rate=20, capacity=1)

    async def burst() -> float:
        t0 = time.perf_counter()
        await asyncio.gather(*(bucket.acquire() for _ in range(5)))
        return time.perf_counter() - t0

    assert asyncio.run(burst()) >= 0.18  # 4 extra tokens at 20/s


def test_is_throttling() -> None:
    err = ClientError({"Error": {"Code": "ThrottlingException", "Message": "Rate exceeded"}}, "LookupEvents")
    assert is_throttling(err)
    assert is_throttling(MCPError("lookup_events failed: Rate exceeded"))
    assert not is_throttling(ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}}, "LookupEvents"))


def test_hub_follows_aws_connecting_after_an_offline_start(monkeypatch: pytest.MonkeyPatch) -> None:
    """Offline start, then AWS connects: the MCP children are rewired to the aws backend on the next live check."""
    from sentinel.mcp_hub import build_hub

    settings = load_settings(mode="auto", cloudtrail_mcp_command=f"{sys.executable} -m awslabs.cloudtrail_mcp_server.server")
    hub = build_hub(settings, aws_live=False)
    aws = FakeAws(connected=False, reason="ConnectTimeoutError")
    ds = DataSources(settings, hub, aws, SQLiteStore(":memory:"))  # type: ignore[arg-type]
    assert asyncio.run(ds._is_live()) is False and hub.aws_live is False
    aws._status = AwsStatus(True, account_suffix="1234", region="ap-south-1")  # network came back
    assert asyncio.run(ds._is_live()) is True
    assert hub.aws_live is True and hub.is_registered(AWSLABS_CLOUDTRAIL)
    assert hub._child_env(hub._servers["identity"])["SENTINEL_BACKEND"] == "aws"
