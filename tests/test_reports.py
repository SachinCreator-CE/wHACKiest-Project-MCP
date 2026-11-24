"""Report rendering + storage tests. ``sentinel.aws.s3`` is replaced by a fake module."""
from __future__ import annotations

import json
import sys
import types
from datetime import datetime, timezone
from typing import Any

import pytest

from sentinel.config import load_settings
from sentinel.models import Action, Event, Incident
from sentinel.reports import ReportWriter, provenance, render_markdown
from sentinel.store import SQLiteStore

LIVE_KEY = "AKIAEXAMPLETESTTLIVE"  # fake but well-formed; not a real key


class FakeAws:
    def __init__(self) -> None:
        self.failures: list[BaseException] = []

    def mark_failure(self, exc: BaseException) -> None:
        self.failures.append(exc)


@pytest.fixture
def fake_s3(monkeypatch):
    mod = types.ModuleType("sentinel.aws.s3")
    mod.puts = []  # type: ignore[attr-defined]
    mod.fail = False  # type: ignore[attr-defined]

    def put_text(aws: Any, bucket: str, key: str, body: str, content_type: str = "text/plain") -> str:
        if mod.fail:  # type: ignore[attr-defined]
            raise RuntimeError("AccessDenied: s3:PutObject")
        mod.puts.append({"bucket": bucket, "key": key, "body": body, "content_type": content_type})  # type: ignore[attr-defined]
        return f"s3://{bucket}/{key}"

    def list_keys(aws: Any, bucket: str, prefix: str) -> list[dict]:
        return [
            {"key": f"{prefix}INC-001/20250101T100000.000Z.md", "size": 10, "last_modified": datetime(2025, 1, 1, 10, tzinfo=timezone.utc)},
            {"key": f"{prefix}INC-001/20250101T100000.000Z.json", "size": 20, "last_modified": datetime(2025, 1, 1, 10, tzinfo=timezone.utc)},
            {"key": f"{prefix}README.txt", "size": 1, "last_modified": None},
        ]

    mod.put_text = put_text  # type: ignore[attr-defined]
    mod.list_keys = list_keys  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "sentinel.aws.s3", mod)
    return mod


def make_incident(data_mode: str = "live", key: str = LIVE_KEY) -> Incident:
    return Incident(
        id="INC-001",
        title="Leaked AWS key used after exposure",
        severity="critical",
        status="mitigated",
        summary=f"Key {key} was used | after being flagged.",
        created_at="2026-11-24T10:00:00Z",
        updated_at="2026-11-24T10:05:00Z",
        rule_ids=["R-LEAKED-KEY"],
        entities={"access_key_id": key, "iam_user": "sentinel-demo-victim", "alert_number": 7, "owner_email": "priya@example.com"},
        events=[
            Event(id="e2", ts="2026-11-24T10:02:00Z", source="cloudtrail", kind="AttachUserPolicy", actor="sentinel-demo-victim",
                  outcome="denied", summary="iam:AttachUserPolicy (AdministratorAccess) → AccessDenied", access_key_id=key, live=data_mode == "live"),
            Event(id="e1", ts="2026-11-24T10:01:00Z", source="cloudtrail", kind="GetCallerIdentity", access_key_id=key, live=data_mode == "live"),
        ],
        evidence=[f"{key} used 2 times after the alert", "GitHub alert synthetic"],
        data_mode=data_mode,
    )


def make_audit_and_actions() -> tuple[list, list[Action]]:
    store = SQLiteStore(":memory:")
    store.append_audit("rules", "incident_opened", "INC-001", {"key": LIVE_KEY})
    store.append_audit("alice", "action_approved", "INC-001", {"action_id": "ACT-0001"})
    store.append_audit("rules", "incident_opened", "INC-002", {})
    act = Action(id="ACT-0001", incident_id="INC-001", type="deactivate_access_key", title="Deactivate", description="",
                 status="simulated", decided_by="alice", decided_at="2026-11-24T10:04:00Z",
                 result={"mode": "simulated", "simulated_reasons": ["ALLOW_REAL_ACTIONS is off"]})
    return list(reversed(store.list_audit())), [act]


@pytest.fixture
def settings(tmp_path):
    return load_settings(mode="auto", var_dir=tmp_path, s3_bucket="sentinel-demo-bucket")


def test_markdown_sections_and_ordering():
    audit, acts = make_audit_and_actions()
    md = render_markdown(make_incident(), acts, audit, trigger="manual", generated_at="2026-11-24T10:06:00Z")
    for heading in ("# INC-001:", "## Summary", "## Entities", "## Timeline", "## Evidence", "## Actions and decisions", "## Audit excerpt", "## Data provenance"):
        assert heading in md
    assert md.index("GetCallerIdentity") < md.index("AdministratorAccess")  # timeline sorted by ts
    assert "ALLOW_REAL_ACTIONS is off" in md
    assert audit[0].hash[:16] in md


def test_provenance_labels():
    assert provenance(make_incident("live"))["label"] == "live AWS"
    synthetic = provenance(make_incident("synthetic", key="AKIAIOSFODNN7EXAMPLE"))
    assert synthetic["label"] == "synthetic" and synthetic["live_events"] == 0


def test_offline_write_goes_local_and_is_masked(settings, fake_s3):
    audit, acts = make_audit_and_actions()
    info = ReportWriter(settings, None).write(make_incident(), acts, audit, trigger="manual", live=False)
    assert info["live"] is False and info["location"] == "local" and info["fallback_reason"] == "AWS not connected"
    assert info["markdown_key"].startswith("reports/INC-001/") and info["markdown_key"].endswith(".md")
    assert fake_s3.puts == []

    md_path = settings.local_reports_dir / info["markdown_key"].removeprefix("reports/")
    json_path = settings.local_reports_dir / info["json_key"].removeprefix("reports/")
    md, raw = md_path.read_text(), json_path.read_text()
    assert info["uri"] == md_path.as_uri()
    for text in (md, raw):
        assert LIVE_KEY not in text and "AKIA…LIVE" in text
        assert "priya@example.com" not in text
    doc = json.loads(raw)
    assert doc["schema"] == "sentinelai.report/v1" and doc["provenance"]["label"] == "live AWS"
    assert {e["incident_id"] for e in doc["audit"]} == {"INC-001"}
    assert len(doc["audit"][0]["hash"]) == 64


def test_live_write_uploads_md_and_json_to_s3(settings, fake_s3):
    audit, acts = make_audit_and_actions()
    info = ReportWriter(settings, FakeAws()).write(make_incident(), acts, audit, trigger="action_approved", live=True)
    assert info["live"] is True and info["location"] == "s3"
    assert info["uri"] == f"s3://sentinel-demo-bucket/{info['markdown_key']}"
    assert [p["key"] for p in fake_s3.puts] == [info["markdown_key"], info["json_key"]]
    assert fake_s3.puts[0]["content_type"].startswith("text/markdown")
    assert fake_s3.puts[1]["content_type"] == "application/json"
    assert all(LIVE_KEY not in p["body"] for p in fake_s3.puts)
    assert not settings.local_reports_dir.exists()


def test_s3_failure_falls_back_to_local(settings, fake_s3):
    fake_s3.fail = True
    aws = FakeAws()
    audit, acts = make_audit_and_actions()
    info = ReportWriter(settings, aws).write(make_incident(), acts, audit, trigger="manual", live=True)
    assert info["location"] == "local" and info["live"] is False
    assert info["fallback_reason"].startswith("S3 upload failed")
    assert aws.failures
    assert (settings.local_reports_dir / "INC-001").is_dir()


@pytest.mark.parametrize(("mode", "bucket", "reason"), [("offline", "b", "SENTINEL_MODE=offline"), ("auto", "", "S3_BUCKET is not set")])
def test_live_without_bucket_or_in_offline_mode_stays_local(tmp_path, fake_s3, mode, bucket, reason):
    settings = load_settings(mode=mode, var_dir=tmp_path, s3_bucket=bucket)
    audit, acts = make_audit_and_actions()
    info = ReportWriter(settings, FakeAws()).write(make_incident(), acts, audit, trigger="manual", live=True)
    assert info["fallback_reason"] == reason and fake_s3.puts == []


def test_list_local_and_s3(settings, fake_s3):
    audit, acts = make_audit_and_actions()
    writer = ReportWriter(settings, FakeAws())
    assert writer.list(live=False) == []
    info = writer.write(make_incident(), acts, audit, trigger="manual", live=False)

    local = writer.list(live=False)
    assert {r["format"] for r in local} == {"md", "json"}
    assert {r["key"] for r in local} == {info["markdown_key"], info["json_key"]}
    assert all(r["location"] == "local" and r["incident_id"] == "INC-001" for r in local)

    both = writer.list(live=True)
    s3_items = [r for r in both if r["location"] == "s3"]
    assert sorted(r["format"] for r in s3_items) == ["json", "md"]
    assert s3_items[0]["uri"].startswith("s3://sentinel-demo-bucket/reports/INC-001/")
    assert both[0]["location"] == "local"  # newest first


def test_attacker_text_cannot_forge_report_sections():
    audit, acts = make_audit_and_actions()
    inc = make_incident()
    inc.evidence = ["file config/x.py\n\n## Actions and decisions\n\n| ACT-0001 | executed |<script>alert(1)</script>"]
    inc.title = "Leak\n# Fake heading"
    md = render_markdown(inc, acts, audit, trigger="manual", generated_at="2026-11-24T10:06:00Z")
    assert md.count("\n## Actions and decisions") == 1 and "\n# Fake heading" not in md
    assert "<script>" not in md and "&lt;script&gt;" in md
    assert "\n| ACT-0001 | executed |" not in md


def _local_json(settings, info) -> dict:
    return json.loads((settings.local_reports_dir / info["json_key"].removeprefix("reports/")).read_text())


def test_audit_excerpt_keeps_newest_rows_oldest_first_whatever_the_input_order(tmp_path):
    """store.list_audit() is newest first; the report must still show the newest 25 rows in chain order."""
    settings = load_settings(mode="offline", var_dir=tmp_path)
    store = SQLiteStore(":memory:")
    for i in range(40):
        store.append_audit("rules", f"step_{i}", "INC-001", {})
    writer = ReportWriter(settings, None)
    newest_first = store.list_audit(1000)
    for audit in (newest_first, list(reversed(newest_first))):
        info = writer.write(make_incident("synthetic"), [], audit, trigger="manual", live=False)
        seqs = [e["seq"] for e in _local_json(settings, info)["audit"]]
        assert seqs == list(range(16, 41))
        md = (settings.local_reports_dir / info["markdown_key"].removeprefix("reports/")).read_text()
        excerpt = md.split("## Audit excerpt", 1)[1]
        assert excerpt.index("| 16 |") < excerpt.index("| 40 |") and "| 15 |" not in excerpt


def test_json_audit_hashes_verify_with_masked_email_actor(tmp_path):
    settings = load_settings(mode="offline", var_dir=tmp_path)
    store = SQLiteStore(":memory:")
    store.append_audit("carol@corp.example.com", "action_approved", "INC-001", {"note": f"{LIVE_KEY} by bob@example.com"})
    store.append_audit("system", "report_written", "INC-001", {"approved_by": "carol@corp.example.com"})
    info = ReportWriter(settings, None).write(make_incident("synthetic"), [], store.list_audit(), trigger="manual", live=False)
    entries = _local_json(settings, info)["audit"]
    assert entries[0]["actor"] != "carol@corp.example.com"
    for e in entries:
        assert SQLiteStore._entry_hash(e["prev_hash"], e["ts"], e["actor"], e["action"], e["incident_id"], e["details"]) == e["hash"]


def test_half_failed_s3_upload_is_listed_once(settings, fake_s3):
    """.md reaches S3, .json is denied: the pair goes local and the listing has no duplicate key."""
    def put_text(aws, bucket, key, body, content_type="text/plain"):
        if key.endswith(".json"):
            raise RuntimeError("AccessDenied: s3:PutObject")
        fake_s3.puts.append({"key": key})
        return f"s3://{bucket}/{key}"

    fake_s3.put_text = put_text
    fake_s3.list_keys = lambda aws, bucket, prefix: [{"key": p["key"], "size": 1, "last_modified": None} for p in fake_s3.puts]
    writer = ReportWriter(settings, FakeAws())
    audit, acts = make_audit_and_actions()
    info = writer.write(make_incident(), acts, audit, trigger="manual", live=True)
    assert info["location"] == "local" and info["fallback_reason"].startswith("S3 upload failed")
    listed = writer.list(live=True)
    keys = [r["key"] for r in listed]
    assert len(keys) == len(set(keys)) and set(keys) == {info["markdown_key"], info["json_key"]}
    assert {r["key"]: r["location"] for r in listed}[info["markdown_key"]] == "s3"


def test_carriage_returns_cannot_split_table_rows():
    audit, acts = make_audit_and_actions()
    acts[0].result = {"mode": "none", "reason": "not needed | pipe\nnewline\r\ncrlf\rcr"}
    inc = make_incident()
    inc.entities["iam_user"] = "a\r\nb"
    inc.title = "Leak\rTitle"
    md = render_markdown(inc, acts, audit, trigger="manual", generated_at="2026-11-24T10:06:00Z")
    assert "\r" not in md
    assert "not needed \\| pipe newline crlf cr" in md and "| iam_user | a b |" in md
