"""boto3 adapters (CloudTrail, CloudWatch Logs, S3) against botocore Stubber; no AWS needed."""
from __future__ import annotations

import io
import json
from datetime import datetime, timedelta, timezone
from typing import Any

import boto3
import pytest
from botocore import UNSIGNED
from botocore.config import Config
from botocore.response import StreamingBody
from botocore.stub import ANY, Stubber

from sentinel.aws import cloudtrail_direct, cloudwatch, s3

KEY = "AKIAIOSFODNN7EXAMPLE"
START = datetime(2026, 11, 20, 0, 0, tzinfo=timezone.utc)
END = START + timedelta(hours=24)


class FakeAws:
    """Stand-in for AwsSessionFactory: unsigned clients, one per service, stubbed."""

    def __init__(self) -> None:
        self.clients: dict[str, Any] = {}
        self.regions: list[str | None] = []

    def client(self, service: str, region: str | None = None) -> Any:
        self.regions.append(region)
        if service not in self.clients:
            self.clients[service] = boto3.client(
                service, region_name=region or "ap-south-1", config=Config(signature_version=UNSIGNED)
            )
        return self.clients[service]

    def stub(self, service: str) -> Stubber:
        stubber = Stubber(self.client(service))
        stubber.activate()
        return stubber


def _ct_event(i: int) -> dict[str, Any]:
    return {
        "EventId": f"e{i}",
        "EventName": "ListBuckets",
        "ReadOnly": "true",
        "AccessKeyId": KEY,
        "EventTime": START + timedelta(minutes=i),
        "EventSource": "s3.amazonaws.com",
        "Username": "sentinel-demo-victim",
        "Resources": [],
        "CloudTrailEvent": json.dumps({"eventID": f"e{i}"}),
    }


# ------------------------------------------------------------------ CloudTrail
def test_lookup_events_direct_paginates_and_serializes_times() -> None:
    aws = FakeAws()
    stub = aws.stub("cloudtrail")
    base = {"StartTime": START, "EndTime": END, "LookupAttributes": [{"AttributeKey": "AccessKeyId", "AttributeValue": KEY}]}
    stub.add_response("lookup_events", {"Events": [_ct_event(0), _ct_event(1)], "NextToken": "t1"}, {**base, "MaxResults": 50})
    stub.add_response("lookup_events", {"Events": [_ct_event(2)]}, {**base, "MaxResults": 50, "NextToken": "t1"})

    events = cloudtrail_direct.lookup_events_direct(aws, "us-east-1", "AccessKeyId", KEY, START, END)

    stub.assert_no_pending_responses()
    assert [e["EventId"] for e in events] == ["e0", "e1", "e2"]
    assert events[1]["EventTime"] == "2026-11-20T00:01:00Z"
    assert aws.regions[-1] == "us-east-1"


def test_lookup_events_direct_respects_max_events() -> None:
    aws = FakeAws()
    stub = aws.stub("cloudtrail")
    stub.add_response("lookup_events", {"Events": [_ct_event(0), _ct_event(1)], "NextToken": "more"},
                      {"StartTime": START, "EndTime": END, "MaxResults": 2})
    assert len(cloudtrail_direct.lookup_events_direct(aws, "us-east-1", None, None, START, END, max_events=2)) == 2
    stub.assert_no_pending_responses()


def test_lookup_events_page_rejects_unknown_attribute() -> None:
    with pytest.raises(ValueError):
        cloudtrail_direct.lookup_events_page(FakeAws(), "us-east-1", "SourceIp", "1.2.3.4", START, END)


# ------------------------------------------------------------- CloudWatch Logs
def _log_event(rec: dict[str, Any] | str, ts_ms: int = 1_700_000_000_000) -> dict[str, Any]:
    message = rec if isinstance(rec, str) else json.dumps(rec)
    return {"logStreamName": "s", "timestamp": ts_ms, "message": message, "ingestionTime": ts_ms, "eventId": "1"}


def test_filter_auth_events_uses_json_pattern_paginates_and_parses() -> None:
    aws = FakeAws()
    stub = aws.stub("logs")
    expected = {"logGroupName": "/g", "startTime": 1, "endTime": 2, "filterPattern": '{ $.user = "priya" || $.user = "Priya" }'}
    stub.add_response(
        "filter_log_events",
        {"events": [_log_event({"ts": "2026-11-20T11:02:00Z", "user": "priya", "event": "login_failed"}),
                    _log_event("not json")], "nextToken": "n1"},
        expected,
    )
    stub.add_response(
        "filter_log_events",
        {"events": [_log_event({"ts": "2026-11-20T11:01:00Z", "user": "priya", "event": "login_failed"}),
                    _log_event({"ts": "2026-11-20T11:03:00Z", "user": "arjun", "event": "login_success"})]},
        {**expected, "nextToken": "n1"},
    )
    recs = cloudwatch.filter_auth_events(aws, "/g", 1, 2, user="priya")
    stub.assert_no_pending_responses()
    assert [r["ts"] for r in recs] == ["2026-11-20T11:01:00Z", "2026-11-20T11:02:00Z"]  # sorted, arjun dropped


def test_filter_auth_events_user_match_is_case_insensitive() -> None:
    """The model may pass 'Priya'; the live path must match the lower-case record like the offline path does."""
    aws = FakeAws()
    stub = aws.stub("logs")
    stub.add_response(
        "filter_log_events",
        {"events": [_log_event({"ts": "2026-11-20T11:02:00Z", "user": "priya", "event": "login_failed"}),
                    _log_event({"ts": "2026-11-20T11:03:00Z", "user": "arjun", "event": "login_failed"})]},
        {"logGroupName": "/g", "startTime": 1, "endTime": 2,
         "filterPattern": '{ $.user = "PRIYA" || $.user = "priya" || $.user = "Priya" }'},
    )
    recs = cloudwatch.filter_auth_events(aws, "/g", 1, 2, user=" PRIYA ")
    stub.assert_no_pending_responses()
    assert [r["user"] for r in recs] == ["priya"]


def test_filter_auth_events_limit_and_unsafe_user_skips_pattern() -> None:
    aws = FakeAws()
    stub = aws.stub("logs")
    stub.add_response(
        "filter_log_events",
        {"events": [_log_event({"user": 'x" || 1', "event": "login_failed"}, 1_700_000_000_000 + i) for i in range(3)]},
        {"logGroupName": "/g", "startTime": 1, "endTime": 2},  # no filterPattern for an unsafe user
    )
    recs = cloudwatch.filter_auth_events(aws, "/g", 1, 2, user='x" || 1', limit=2)
    assert len(recs) == 2 and recs[0]["ts"].endswith("Z")  # ts filled from the log event timestamp


def test_ensure_log_group_handles_existing_group() -> None:
    aws = FakeAws()
    stub = aws.stub("logs")
    stub.add_client_error("create_log_group", "ResourceAlreadyExistsException", expected_params={"logGroupName": "/g"})
    stub.add_response("put_retention_policy", {}, {"logGroupName": "/g", "retentionInDays": 7})
    assert cloudwatch.ensure_log_group(aws, "/g") is False
    stub.add_response("create_log_group", {}, {"logGroupName": "/h"})
    stub.add_response("put_retention_policy", {}, {"logGroupName": "/h", "retentionInDays": 3})
    assert cloudwatch.ensure_log_group(aws, "/h", retention_days=3) is True
    stub.add_client_error("create_log_group", "AccessDeniedException")
    with pytest.raises(Exception, match="AccessDenied"):
        cloudwatch.ensure_log_group(aws, "/i")


def test_put_auth_events_sorts_and_batches(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cloudwatch, "MAX_BATCH_EVENTS", 2)
    aws = FakeAws()
    stub = aws.stub("logs")
    stub.add_client_error("create_log_stream", "ResourceAlreadyExistsException")
    recs = [{"ts": f"2026-11-20T11:0{i}:00Z", "user": "priya", "event": "login_failed"} for i in (3, 1, 2)]
    sent_batches: list[list[dict[str, Any]]] = []
    for _ in range(2):
        stub.add_response("put_log_events", {"nextSequenceToken": "x"},
                          {"logGroupName": "/g", "logStreamName": "s", "logEvents": ANY})
    client = aws.client("logs")
    client.meta.events.register("provide-client-params.logs.PutLogEvents",
                                lambda params, **_: sent_batches.append(params["logEvents"]))
    assert cloudwatch.put_auth_events(aws, "/g", "s", recs) == 3
    stub.assert_no_pending_responses()
    assert [len(b) for b in sent_batches] == [2, 1]
    flat = [json.loads(e["message"])["ts"] for b in sent_batches for e in b]
    assert flat == sorted(flat)


def test_batches_split_on_bytes_and_24h_span() -> None:
    big = "x" * 600_000
    evs = [{"timestamp": 0, "message": big}, {"timestamp": 1, "message": big}]
    assert [len(b) for b in cloudwatch._batches(evs)] == [1, 1]
    day = 24 * 3600 * 1000
    evs = [{"timestamp": 0, "message": "a"}, {"timestamp": day + 1, "message": "b"}]
    assert [len(b) for b in cloudwatch._batches(evs)] == [1, 1]


# ------------------------------------------------------------------------- S3
def test_s3_put_get_list() -> None:
    aws = FakeAws()
    stub = aws.stub("s3")
    stub.add_response("put_object", {}, {"Bucket": "b", "Key": "reports/INC-001/a.md", "Body": "# hi".encode(),
                                         "ContentType": "text/markdown", "ServerSideEncryption": "AES256"})
    assert s3.put_text(aws, "b", "reports/INC-001/a.md", "# hi", "text/markdown") == "s3://b/reports/INC-001/a.md"

    body = "line1\nline2".encode()
    stub.add_response("get_object", {"Body": StreamingBody(io.BytesIO(body), len(body))}, {"Bucket": "b", "Key": "raw/x.json"})
    assert s3.get_text(aws, "b", "raw/x.json") == "line1\nline2"

    stub.add_response("list_objects_v2", {"Contents": [{"Key": "raw/a.json", "Size": 10, "LastModified": START}],
                                          "IsTruncated": True, "NextContinuationToken": "c"},
                      {"Bucket": "b", "Prefix": "raw/"})
    stub.add_response("list_objects_v2", {"Contents": [{"Key": "raw/b.jsonl", "Size": 5, "LastModified": END}]},
                      {"Bucket": "b", "Prefix": "raw/", "ContinuationToken": "c"})
    keys = s3.list_keys(aws, "b", "raw/")
    stub.assert_no_pending_responses()
    assert keys == [
        {"key": "raw/a.json", "size": 10, "last_modified": "2026-11-20T00:00:00Z"},
        {"key": "raw/b.jsonl", "size": 5, "last_modified": "2026-11-21T00:00:00Z"},
    ]


def test_filter_auth_events_limit_keeps_the_newest_across_pages() -> None:
    """FilterLogEvents pages oldest first; a limit must keep what just happened (the on-stage burst)."""
    aws = FakeAws()
    stub = aws.stub("logs")
    expected = {"logGroupName": "/g", "startTime": 1, "endTime": 2, "filterPattern": '{ $.user = "priya" || $.user = "Priya" }'}
    rec = lambda m: _log_event({"ts": f"2026-11-20T11:0{m}:00Z", "user": "priya", "event": "login_failed"})  # noqa: E731
    stub.add_response("filter_log_events", {"events": [rec(1), rec(2), rec(3)], "nextToken": "n1"}, expected)
    stub.add_response("filter_log_events", {"events": [rec(4), rec(5)]}, {**expected, "nextToken": "n1"})
    recs = cloudwatch.filter_auth_events(aws, "/g", 1, 2, user="priya", limit=3)
    stub.assert_no_pending_responses()
    assert [r["ts"][14:16] for r in recs] == ["03", "04", "05"]


def test_cloudtrail_client_has_no_botocore_retries() -> None:
    """DataSources owns LookupEvents retries (per-region bucket + backoff); botocore retries would bypass the bucket."""
    from sentinel.aws.session import client_config

    assert client_config("cloudtrail")["retries"] == {"total_max_attempts": 1, "mode": "standard"}
    assert client_config("iam")["retries"]["max_attempts"] == 4  # other services keep adaptive retries


def test_sts_probe_is_bounded_so_a_blackholed_network_fails_fast() -> None:
    """GetCallerIdentity gates startup and /api/status: 2 attempts x 2 s connect, not 4 adaptive x 5 s (~25 s)."""
    from sentinel.aws.session import client_config

    cfg = client_config("sts")
    assert cfg["connect_timeout"] <= 2 and cfg["read_timeout"] <= 5
    assert cfg["retries"]["total_max_attempts"] <= 2

