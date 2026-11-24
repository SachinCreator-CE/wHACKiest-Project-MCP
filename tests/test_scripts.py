"""Tests for the ops scripts. AWS is never contacted: clients are wrapped in botocore Stubbers."""
from __future__ import annotations

import io
import json
import re
import sys
import types
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import boto3
import httpx
import pytest
from botocore.stub import Stubber

from scripts import (
    _common,
    aws_check,
    aws_setup,
    aws_teardown,
    list_bedrock_models,
    render_iam_policy,
    reset_demo_victim,
    simulate_app_auth,
    simulate_leaked_key,
)
from sentinel.config import load_settings

KEY = "AKIAIOSFODNN7EXAMPLE"  # AWS's documented example key; never a real one
OTHER_KEY = "AKIA" + "I44QH8DHBEXAMPLE"  # second documented example, split so the repo key scan ignores it
ACCOUNT = "123456789012"
VICTIM_ARN = f"arn:aws:iam::{ACCOUNT}:user/sentinel-demo-victim"
NOW = datetime(2026, 11, 20, 12, 0, tzinfo=timezone.utc)


def make_client(service: str, region: str = "ap-south-1") -> Any:
    return boto3.Session(aws_access_key_id=KEY, aws_secret_access_key="testing", region_name=region).client(service)


def denied(stubber: Stubber, method: str, code: str = "AccessDenied") -> None:
    stubber.add_client_error(method, service_error_code=code, service_message="not authorized", http_status_code=403)


class FakeAws:
    """Stands in for AwsSessionFactory: hands out pre-stubbed clients by service name."""

    def __init__(self, **clients: Any):
        self.clients = clients

    def client(self, service: str, region: str | None = None) -> Any:
        return self.clients[service.replace("-", "_")]


@pytest.fixture
def settings(tmp_path: Path):
    return load_settings(
        mode="aws",
        s3_bucket="sentinelai-0badc0de",
        demo_leaked_access_key_id=KEY,
        data_dir=tmp_path / "data",
        var_dir=tmp_path / "var",
    )


# --------------------------------------------------------------------------- _common


def test_redact_masks_keys_and_account_ids() -> None:
    text = _common.redact(f"User: arn:aws:iam::{ACCOUNT}:user/x used {KEY}")
    assert ACCOUNT not in text and "…9012" in text
    assert KEY not in text and "AKIA…MPLE" in text


def test_out_respects_no_color(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.setenv("FORCE_COLOR", "1")
    buf = io.StringIO()
    out = _common.Out(buf)
    out.ok("fine")
    out.fail(f"key {KEY}")
    assert "\033[" not in buf.getvalue()
    assert "✓ fine" in buf.getvalue() and "AKIA…MPLE" in buf.getvalue() and KEY not in buf.getvalue()


def test_upsert_env_var_replaces_or_appends(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("S3_BUCKET", "")
    monkeypatch.setenv("NEW_VAR", "")
    env = tmp_path / ".env"
    env.write_text("# comment\nS3_BUCKET=old\nAWS_REGION=ap-south-1\n")
    _common.upsert_env_var("S3_BUCKET", "sentinelai-12345678", env)
    _common.upsert_env_var("NEW_VAR", "x", env)
    assert env.read_text() == "# comment\nS3_BUCKET=sentinelai-12345678\nAWS_REGION=ap-south-1\nNEW_VAR=x\n"


def test_resolve_bucket_generates_and_persists(tmp_path: Path, settings, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("S3_BUCKET", "")
    settings.s3_bucket = ""
    env = tmp_path / ".env"
    bucket, saved = _common.resolve_bucket(settings, env_path=env)
    assert saved and re.fullmatch(r"sentinelai-[0-9a-f]{8}", bucket)
    assert f"S3_BUCKET={bucket}" in env.read_text()
    assert _common.resolve_bucket(settings, env_path=env) == (bucket, False)
    with pytest.raises(ValueError):
        _common.resolve_bucket(settings, "Bad_Bucket", env_path=env)


def test_bedrock_probe_detects_tool_use() -> None:
    client = make_client("bedrock-runtime")
    with Stubber(client) as stub:
        stub.add_response("converse", {
            "output": {"message": {"role": "assistant", "content": [{"toolUse": {"toolUseId": "t1", "name": "report_status", "input": {"status": "ready"}}}]}},
            "stopReason": "tool_use",
            "usage": {"inputTokens": 10, "outputTokens": 5, "totalTokens": 15},
            "metrics": {"latencyMs": 100},
        })
        probe = _common.bedrock_probe(client, "apac.amazon.nova-lite-v1:0", with_tool=True)
    assert probe.tool_used and probe.stop_reason == "tool_use"


# --------------------------------------------------------------------------- render_iam_policy


def _template() -> dict:
    return json.loads(render_iam_policy.TEMPLATE.read_text())


def test_policy_template_is_valid_least_privilege_json() -> None:
    sids = [s["Sid"] for s in _template()["Statement"]]
    assert sids == [
        "BedrockInvoke", "BedrockDiscovery", "CloudTrailLookup", "LogsAppAuth", "S3Bucket",
        "S3Objects", "IamDemoVictimKeyOnly", "STS", "SecretsManagerElevenLabs",
    ]
    for st in _template()["Statement"]:
        assert "*" not in st["Action"], "no wildcard actions"


def test_render_policy_fills_every_placeholder() -> None:
    policy = render_iam_policy.render_policy(_template(), account_id=ACCOUNT, bucket="sentinelai-0badc0de", region="ap-south-1")
    text = json.dumps(policy)
    assert not render_iam_policy.PLACEHOLDER_RE.search(text)
    assert json.loads(text) == policy
    assert f"arn:aws:iam::{ACCOUNT}:user/sentinel-demo-victim" in text
    assert "arn:aws:s3:::sentinelai-0badc0de/*" in text
    assert f"arn:aws:logs:ap-south-1:{ACCOUNT}:log-group:/sentinelai/app-auth" in text
    assert render_iam_policy.policy_size(policy) <= render_iam_policy.MANAGED_POLICY_LIMIT


def test_render_policy_extras_and_options() -> None:
    policy = render_iam_policy.render_policy(
        _template(), account_id=ACCOUNT, bucket="sentinelai-0badc0de", region="ap-south-1", bedrock_region="us-east-1",
        models=["apac.amazon.nova-lite-v1:0", "us.meta.llama3-1-70b-instruct-v1:0"],
        guardrail_id="gr123", include_secrets_manager=False,
    )
    by_sid = {s["Sid"]: s for s in policy["Statement"]}
    invoke = by_sid["BedrockInvoke"]["Resource"]
    assert f"arn:aws:bedrock:us-east-1:{ACCOUNT}:inference-profile/us.amazon.nova-*" in invoke
    assert "arn:aws:bedrock:*::foundation-model/meta.llama3-1-70b-instruct-v1:0" in invoke
    assert f"arn:aws:bedrock:us-east-1:{ACCOUNT}:inference-profile/us.meta.llama3-1-70b-instruct-v1:0" in invoke
    assert not any("nova-lite-v1:0" in r for r in invoke), "Nova ids are covered by the wildcard"
    assert by_sid["BedrockGuardrail"]["Action"] == "bedrock:ApplyGuardrail"
    assert "SecretsManagerElevenLabs" not in by_sid


def _profile_allowed(policy: dict, arn: str) -> bool:
    from fnmatch import fnmatchcase
    invoke = next(s for s in policy["Statement"] if s["Sid"] == "BedrockInvoke")
    return any(fnmatchcase(arn, pattern) for pattern in invoke["Resource"])


@pytest.mark.parametrize("region,model", [
    ("eu-west-1", "eu.amazon.nova-lite-v1:0"),
    ("ap-northeast-1", "jp.amazon.nova-2-lite-v1:0"),
    ("us-east-1", "global.amazon.nova-2-lite-v1:0"),
    ("ap-south-1", "apac.amazon.nova-lite-v1:0"),
])
def test_render_policy_allows_nova_profiles_in_every_geo(region: str, model: str) -> None:
    from scripts.list_bedrock_models import base_model_id
    policy = render_iam_policy.render_policy(_template(), account_id=ACCOUNT, bucket="b-bucket", region=region, bedrock_region=region, models=[model])
    assert _profile_allowed(policy, f"arn:aws:bedrock:{region}:{ACCOUNT}:inference-profile/{model}")
    assert _profile_allowed(policy, f"arn:aws:bedrock:{region}::foundation-model/{base_model_id(model)}")


def test_render_policy_accepts_model_and_guardrail_arns() -> None:
    profile = f"arn:aws:bedrock:ap-south-1:{ACCOUNT}:inference-profile/apac.amazon.nova-pro-v1:0"
    guardrail = f"arn:aws:bedrock:ap-south-1:{ACCOUNT}:guardrail/abc123"
    policy = render_iam_policy.render_policy(
        _template(), account_id=ACCOUNT, bucket="b-bucket", region="ap-south-1", models=[profile], guardrail_id=guardrail,
    )
    text = json.dumps(policy)
    assert "/arn:" not in text, "no ARN nested inside another ARN"
    assert _profile_allowed(policy, profile)
    assert _profile_allowed(policy, "arn:aws:bedrock:us-east-1::foundation-model/amazon.nova-pro-v1:0")
    assert next(s for s in policy["Statement"] if s["Sid"] == "BedrockGuardrail")["Resource"] == [guardrail]
    with pytest.raises(ValueError, match="unsupported Bedrock model ARN"):
        render_iam_policy.render_policy(_template(), account_id=ACCOUNT, bucket="b-bucket", region="ap-south-1",
                                        models=[f"arn:aws:bedrock:ap-south-1:{ACCOUNT}:application-inference-profile/x1"])
    with pytest.raises(ValueError, match="BEDROCK_GUARDRAIL_ID"):
        render_iam_policy.render_policy(_template(), account_id=ACCOUNT, bucket="b-bucket", region="ap-south-1", guardrail_id="arn:aws:bedrock:x")


def test_render_policy_uses_configured_resource_names() -> None:
    policy = render_iam_policy.render_policy(
        _template(), account_id=ACCOUNT, bucket="b-bucket", region="ap-south-1",
        auth_log_group="/acme/auth", victim_user="demo-victim-2", elevenlabs_secret_id="prod/elevenlabs",
    )
    by_sid = {s["Sid"]: s for s in policy["Statement"]}
    assert f"arn:aws:logs:ap-south-1:{ACCOUNT}:log-group:/acme/auth:log-stream:*" in by_sid["LogsAppAuth"]["Resource"]
    assert by_sid["IamDemoVictimKeyOnly"]["Resource"] == f"arn:aws:iam::{ACCOUNT}:user/demo-victim-2"
    assert by_sid["SecretsManagerElevenLabs"]["Resource"] == f"arn:aws:secretsmanager:ap-south-1:{ACCOUNT}:secret:prod/elevenlabs-*"
    text = json.dumps(policy)
    assert "app-auth" not in text and "sentinel-demo-victim" not in text and "sentinelai/elevenlabs" not in text
    secret_arn = f"arn:aws:secretsmanager:ap-south-1:{ACCOUNT}:secret:prod/elevenlabs-AbCdEf"
    policy = render_iam_policy.render_policy(_template(), account_id=ACCOUNT, bucket="b-bucket", region="ap-south-1", elevenlabs_secret_id=secret_arn)
    assert next(s for s in policy["Statement"] if s["Sid"] == "SecretsManagerElevenLabs")["Resource"] == secret_arn + "*"
    for bad in ({"victim_user": 'a"b'}, {"auth_log_group": ""}, {"elevenlabs_secret_id": "bad name"}):
        with pytest.raises(ValueError):
            render_iam_policy.render_policy(_template(), account_id=ACCOUNT, bucket="b-bucket", region="ap-south-1", **bad)


def test_render_main_uses_settings_and_warns_on_allowlist(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture) -> None:
    for key, value in {"AUTH_LOG_GROUP": "/acme/auth", "DEMO_VICTIM_USER": "demo-victim-2", "ELEVENLABS_SECRET_ID": "prod/elevenlabs",
                       "REAL_ACTION_USER_ALLOWLIST": "demo-victim-2,other-user", "S3_BUCKET": "sentinelai-test1234",
                       "BEDROCK_MODEL_ID": "eu.amazon.nova-lite-v1:0", "AWS_REGION": "eu-west-1", "BEDROCK_REGION": "eu-west-1"}.items():
        monkeypatch.setenv(key, value)
    out = tmp_path / "rendered.json"
    assert render_iam_policy.main(["--account-id", ACCOUNT, "--output", str(out)]) == 0
    text = out.read_text()
    assert "/acme/auth" in text and "user/demo-victim-2" in text and "secret:prod/elevenlabs-*" in text
    assert _profile_allowed(json.loads(text), f"arn:aws:bedrock:eu-west-1:{ACCOUNT}:inference-profile/eu.amazon.nova-lite-v1:0")
    printed = capsys.readouterr().out
    assert "other-user" in printed and "demo-victim-2' is not" not in printed


def test_policy_grants_only_actions_the_code_calls() -> None:
    actions = {a for st in _template()["Statement"] for a in ([st["Action"]] if isinstance(st["Action"], str) else st["Action"])}
    for unused in ("bedrock:InvokeModelWithResponseStream", "bedrock:GetInferenceProfile", "bedrock:GetFoundationModel",
                   "logs:GetLogEvents", "s3:GetEncryptionConfiguration"):
        assert unused not in actions


@pytest.mark.parametrize("kwargs", [{"account_id": "12345"}, {"region": "nowhere"}])
def test_render_policy_rejects_bad_input(kwargs: dict) -> None:
    args = {"account_id": ACCOUNT, "bucket": "sentinelai-0badc0de", "region": "ap-south-1", **kwargs}
    with pytest.raises(ValueError):
        render_iam_policy.render_policy(_template(), **args)


def test_render_policy_reports_unknown_placeholders() -> None:
    template = _template()
    template["Statement"][1]["Resource"] = "arn:aws:bedrock:<OTHER>:x"
    with pytest.raises(ValueError, match="<OTHER>"):
        render_iam_policy.render_policy(template, account_id=ACCOUNT, bucket="b-bucket", region="ap-south-1")


# --------------------------------------------------------------------------- simulate_leaked_key


@pytest.mark.parametrize("arn", [
    f"arn:aws:iam::{ACCOUNT}:user/sentinel-app",
    f"arn:aws:iam::{ACCOUNT}:user/ops/sentinel-demo-victim",
    f"arn:aws:iam::{ACCOUNT}:user/sentinel-demo-victim-2",
    f"arn:aws:sts::{ACCOUNT}:assumed-role/Admin/sentinel-demo-victim",
    f"arn:aws:iam::{ACCOUNT}:root",
    "",
])
def test_check_victim_arn_refuses_non_victims(arn: str) -> None:
    with pytest.raises(simulate_leaked_key.SafetyError):
        simulate_leaked_key.check_victim_arn(arn, "sentinel-demo-victim")


def test_check_victim_arn_accepts_exact_user() -> None:
    assert simulate_leaked_key.check_victim_arn(VICTIM_ARN, "sentinel-demo-victim") == "sentinel-demo-victim"


class Clients:
    """Client factory that records which services were requested."""

    def __init__(self, **clients: Any):
        self.clients, self.requested = clients, []

    def __call__(self, service: str) -> Any:
        self.requested.append(service)
        return self.clients[service]


def _sts(arn: str) -> tuple[Any, Stubber]:
    sts = make_client("sts")
    stub = Stubber(sts)
    stub.add_response("get_caller_identity", {"UserId": "AIDAEXAMPLE", "Account": ACCOUNT, "Arn": arn})
    return sts, stub


def test_simulation_aborts_before_any_other_call_for_wrong_user() -> None:
    sts, stub = _sts(f"arn:aws:iam::{ACCOUNT}:user/sentinel-app")
    clients = Clients(sts=sts)
    with stub:
        report = simulate_leaked_key.run_simulation(clients, "sentinel-demo-victim")
    assert clients.requested == ["sts"]
    assert report.exit_code == simulate_leaked_key.EXIT_ABORTED and "refusing" in report.aborted


def test_simulation_all_denied() -> None:
    sts, sts_stub = _sts(VICTIM_ARN)
    s3, iam = make_client("s3"), make_client("iam")
    with sts_stub, Stubber(s3) as s3_stub, Stubber(iam) as iam_stub:
        denied(s3_stub, "list_buckets")
        for method in ("list_attached_user_policies", "create_access_key", "attach_user_policy"):
            denied(iam_stub, method)
        report = simulate_leaked_key.run_simulation(Clients(sts=sts, s3=s3, iam=iam), "sentinel-demo-victim")
        iam_stub.assert_no_pending_responses()
    assert report.exit_code == simulate_leaked_key.EXIT_OK
    assert [c.result for c in report.calls] == ["OK"] + ["AccessDenied"] * 4
    assert all(c.as_expected for c in report.calls)


def test_simulation_deletes_unexpectedly_created_key_and_stops() -> None:
    sts, sts_stub = _sts(VICTIM_ARN)
    s3, iam = make_client("s3"), make_client("iam")
    new_key = OTHER_KEY
    with sts_stub, Stubber(s3) as s3_stub, Stubber(iam) as iam_stub:
        denied(s3_stub, "list_buckets")
        denied(iam_stub, "list_attached_user_policies")
        iam_stub.add_response("create_access_key", {"AccessKey": {
            "UserName": "sentinel-demo-victim", "AccessKeyId": new_key, "Status": "Active",
            "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        }})
        iam_stub.add_response("delete_access_key", {}, {"UserName": "sentinel-demo-victim", "AccessKeyId": new_key})
        report = simulate_leaked_key.run_simulation(Clients(sts=sts, s3=s3, iam=iam), "sentinel-demo-victim")
        iam_stub.assert_no_pending_responses()  # attach_user_policy was never attempted
    assert report.exit_code == simulate_leaked_key.EXIT_UNEXPECTED_SUCCESS
    assert "deleted" in report.calls[-1].note and new_key not in report.calls[-1].note


def test_simulation_detaches_unexpectedly_attached_policy() -> None:
    sts, sts_stub = _sts(VICTIM_ARN)
    s3, iam = make_client("s3"), make_client("iam")
    with sts_stub, Stubber(s3) as s3_stub, Stubber(iam) as iam_stub:
        denied(s3_stub, "list_buckets")
        denied(iam_stub, "list_attached_user_policies")
        denied(iam_stub, "create_access_key")
        iam_stub.add_response("attach_user_policy", {})
        iam_stub.add_response("detach_user_policy", {}, {"UserName": "sentinel-demo-victim", "PolicyArn": _common.ADMIN_POLICY_ARN})
        report = simulate_leaked_key.run_simulation(Clients(sts=sts, s3=s3, iam=iam), "sentinel-demo-victim")
        iam_stub.assert_no_pending_responses()
    assert report.exit_code == simulate_leaked_key.EXIT_UNEXPECTED_SUCCESS
    assert "detached" in report.calls[-1].note


def test_key_match_line_never_shows_full_key() -> None:
    other = OTHER_KEY
    lines = [
        simulate_leaked_key.key_match_line(KEY, KEY),
        simulate_leaked_key.key_match_line(KEY, other),
        simulate_leaked_key.key_match_line(KEY, ""),
    ]
    assert "matches" in lines[0] and "does NOT match" in lines[1] and "not set" in lines[2]
    for line in lines:
        assert KEY not in line and other not in line and "AKIA…MPLE" in line


# --------------------------------------------------------------------------- reset_demo_victim


def _keys(status: str) -> dict:
    return {"AccessKeyMetadata": [{"UserName": "sentinel-demo-victim", "AccessKeyId": KEY, "Status": status}], "IsTruncated": False}


def test_reset_refuses_users_outside_allowlist() -> None:
    with pytest.raises(reset_demo_victim.ResetRefused):
        reset_demo_victim.check_allowed("sentinel-app", ["sentinel-demo-victim"], KEY)
    with pytest.raises(reset_demo_victim.ResetRefused):
        reset_demo_victim.check_allowed("sentinel-demo-victim", ["sentinel-demo-victim"], "")


@pytest.mark.parametrize("use_iam_actions", [True, False])
def test_reset_reactivates_key(use_iam_actions: bool, monkeypatch: pytest.MonkeyPatch) -> None:
    if not use_iam_actions:
        monkeypatch.setitem(sys.modules, "sentinel.aws.iam_actions", None)  # forces the boto3 fallback
    iam = make_client("iam")
    with Stubber(iam) as stub:
        stub.add_response("list_access_keys", _keys("Inactive"))
        stub.add_response("update_access_key", {}, {"UserName": "sentinel-demo-victim", "AccessKeyId": KEY, "Status": "Active"})
        if use_iam_actions:
            stub.add_response("list_access_keys", _keys("Active"))  # set_access_key_status verifies
        stub.add_response("list_access_keys", _keys("Active"))
        before, after = reset_demo_victim.reset(FakeAws(iam=iam), "sentinel-demo-victim", KEY)
        stub.assert_no_pending_responses()
    assert (before, after) == ("Inactive", "Active")


def test_reset_local_only_clears_rehearsed_store_without_aws(tmp_path, monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    """A rehearsed approval lives in var/sentinel.db; the reset must clear it so INC-001 is proposable again."""
    from sentinel.models import Action, Incident
    from sentinel.store import SQLiteStore

    var = tmp_path / "var"
    monkeypatch.setenv("SENTINEL_NO_DOTENV", "1")
    monkeypatch.setenv("SENTINEL_VAR_DIR", str(var))
    db = var / "sentinel.db"
    store = SQLiteStore(db)
    store.upsert_incident(Incident(id="INC-001", title="Leaked key", severity="critical", status="mitigated", summary="s", created_at="2026-01-01T00:00:00Z", updated_at="2026-01-01T00:00:00Z"))
    store.add_action(Action(id="", incident_id="INC-001", type="deactivate_access_key", title="t", description="d", status="simulated"))
    store._db.close()

    def no_aws(*a: Any, **k: Any) -> Any:
        raise AssertionError("--local-only must not touch AWS")

    monkeypatch.setattr(reset_demo_victim, "AwsSessionFactory", no_aws)
    monkeypatch.setattr(reset_demo_victim, "use_profile", no_aws)
    assert reset_demo_victim.main(["--local-only"]) == 0
    assert not db.exists() and list(var.glob("sentinel.db.bak-*"))
    fresh = SQLiteStore(db)
    assert fresh.get_incident("INC-001") is None and fresh.list_actions("INC-001") == []
    fresh._db.close()
    assert reset_demo_victim.main(["--local-only"]) == 0  # moved again, never overwriting the first backup
    assert len(list(var.glob("sentinel.db.bak-*"))) == 2


def test_reset_keep_local_leaves_store(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    var = tmp_path / "var"
    var.mkdir()
    (var / "sentinel.db").write_bytes(b"x")
    monkeypatch.setenv("SENTINEL_NO_DOTENV", "1")
    monkeypatch.setenv("SENTINEL_VAR_DIR", str(var))
    with pytest.raises(SystemExit):
        reset_demo_victim.parse_args(["--keep-local", "--local-only"])
    assert reset_demo_victim.clear_local_store(var / "missing.db") == []
    assert (var / "sentinel.db").exists()


def test_reset_rejects_key_of_another_user() -> None:
    iam = make_client("iam")
    with Stubber(iam) as stub:
        stub.add_response("list_access_keys", {"AccessKeyMetadata": [], "IsTruncated": False})
        with pytest.raises(reset_demo_victim.ResetRefused, match="AKIA…MPLE"):
            reset_demo_victim.reset(FakeAws(iam=iam), "sentinel-demo-victim", KEY)


# --------------------------------------------------------------------------- simulate_app_auth


@pytest.fixture
def fake_datasets(monkeypatch: pytest.MonkeyPatch) -> list[dict]:
    records = [
        {"ts": "2026-11-20T11:30:00Z", "event": "login_failed", "user": "priya", "scenario": "INC-002"},
        {"ts": "2026-11-20T11:31:00Z", "event": "login_success", "user": "arjun", "scenario": "benign-arjun"},
    ]
    mod = types.ModuleType("sentinel.datasets")
    mod.app_auth_simulation_records = lambda now: [dict(r) for r in records]  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "sentinel.datasets", mod)
    return records


def test_simulate_app_auth_dry_run_never_touches_aws(fake_datasets, settings, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "sentinel.aws.cloudwatch", None)  # any import would fail the test
    res = simulate_app_auth.run(settings, aws=None, now=NOW, dry_run=True)
    assert res["records"] == 2 and res["written"] == 0
    assert res["stream"] == "simulated-app-traffic-2026-11-20"
    assert res["summary"] == ["INC-002: 1 events (login_failed=1)", "benign-arjun: 1 events (login_success=1)"]


def test_simulate_app_auth_writes_tagged_records(fake_datasets, settings, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: dict[str, Any] = {}
    cw = types.ModuleType("sentinel.aws.cloudwatch")
    cw.ensure_log_group = lambda aws, group, retention_days=7: calls.update(group=group, retention=retention_days)  # type: ignore[attr-defined]

    def put(aws: Any, group: str, stream: str, records: list[dict]) -> int:
        calls.update(stream=stream, records=records)
        return len(records)

    cw.put_auth_events = put  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "sentinel.aws.cloudwatch", cw)
    res = simulate_app_auth.run(settings, aws=object(), now=NOW)
    assert res["written"] == 2
    assert calls["group"] == "/sentinelai/app-auth" and calls["retention"] == 7
    assert calls["stream"] == "simulated-app-traffic-2026-11-20"
    assert all(r["simulated"] is True and r["source"] == "simulated-app-traffic" for r in calls["records"])


# --------------------------------------------------------------------------- aws_setup


def test_bucket_create_kwargs_location_constraint() -> None:
    assert aws_setup.bucket_create_kwargs("b", "us-east-1") == {"Bucket": "b"}
    assert aws_setup.bucket_create_kwargs("b", "ap-south-1")["CreateBucketConfiguration"] == {"LocationConstraint": "ap-south-1"}


def test_ensure_bucket_creates_when_missing_and_is_idempotent() -> None:
    s3 = make_client("s3")
    with Stubber(s3) as stub:
        stub.add_client_error("head_bucket", service_error_code="404", http_status_code=404)
        stub.add_response("create_bucket", {}, {"Bucket": "b-bucket", "CreateBucketConfiguration": {"LocationConstraint": "ap-south-1"}})
        stub.add_response("head_bucket", {"ResponseMetadata": {"HTTPStatusCode": 200}})  # bucket_exists waiter
        stub.add_response("head_bucket", {})  # second run
        assert aws_setup.ensure_bucket(s3, "b-bucket", "ap-south-1") == "created"
        assert aws_setup.ensure_bucket(s3, "b-bucket", "ap-south-1") == "exists"


def test_ensure_bucket_rejects_foreign_bucket() -> None:
    s3 = make_client("s3")
    with Stubber(s3) as stub:
        stub.add_client_error("head_bucket", service_error_code="403", http_status_code=403)
        with pytest.raises(aws_setup.SetupError, match="another account"):
            aws_setup.ensure_bucket(s3, "b-bucket", "ap-south-1")


def test_harden_bucket_blocks_public_access_and_encrypts() -> None:
    s3 = make_client("s3")
    with Stubber(s3) as stub:
        stub.add_response("put_public_access_block", {}, {"Bucket": "b-bucket", "PublicAccessBlockConfiguration": aws_setup.PUBLIC_ACCESS_BLOCK})
        stub.add_response("put_bucket_encryption", {}, {
            "Bucket": "b-bucket",
            "ServerSideEncryptionConfiguration": {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]},
        })
        aws_setup.harden_bucket(s3, "b-bucket")
        stub.assert_no_pending_responses()
    assert all(aws_setup.PUBLIC_ACCESS_BLOCK.values()) and len(aws_setup.PUBLIC_ACCESS_BLOCK) == 4


def test_upload_tree_keeps_relative_paths(tmp_path: Path) -> None:
    (tmp_path / "cloudtrail").mkdir()
    (tmp_path / "cloudtrail" / "events.json").write_text("[]")
    (tmp_path / "auth").mkdir()
    (tmp_path / "auth" / "app_auth.jsonl").write_text("{}\n")
    (tmp_path / ".DS_Store").write_text("x")
    s3 = make_client("s3")
    with Stubber(s3) as stub:
        for key, ctype, body in (("raw/auth/app_auth.jsonl", "application/x-ndjson", b"{}\n"), ("raw/cloudtrail/events.json", "application/json", b"[]")):
            stub.add_response("put_object", {}, {"Bucket": "b-bucket", "Key": key, "Body": body, "ContentType": ctype, "ServerSideEncryption": "AES256"})
        keys = aws_setup.upload_tree(s3, "b-bucket", tmp_path, "raw/")
        stub.assert_no_pending_responses()
    assert keys == ["raw/auth/app_auth.jsonl", "raw/cloudtrail/events.json"]


def test_aws_setup_main_runs_every_step(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_datasets, capsys) -> None:
    data = tmp_path / "data"
    (data / "github").mkdir(parents=True)
    (data / "github" / "alerts.json").write_text("[]")
    for var, value in {"SENTINEL_NO_DOTENV": "1", "S3_BUCKET": "sentinelai-0badc0de", "SENTINEL_DATA_DIR": str(data),
                       "AWS_REGION": "ap-south-1", "NO_COLOR": "1"}.items():
        monkeypatch.setenv(var, value)
    monkeypatch.setattr(aws_setup, "use_profile", lambda profile: None)  # keep AWS_PROFILE untouched
    cw_calls: list[str] = []
    cw = types.ModuleType("sentinel.aws.cloudwatch")
    cw.ensure_log_group = lambda aws, group, retention_days=7: cw_calls.append("ensure")  # type: ignore[attr-defined]
    cw.put_auth_events = lambda aws, group, stream, records: len(records)  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "sentinel.aws.cloudwatch", cw)

    sts, s3, rt = make_client("sts"), make_client("s3"), make_client("bedrock-runtime")
    with Stubber(sts) as sts_stub, Stubber(s3) as s3_stub, Stubber(rt) as rt_stub:
        sts_stub.add_response("get_caller_identity", {"UserId": "AIDAEXAMPLE", "Account": ACCOUNT, "Arn": f"arn:aws:iam::{ACCOUNT}:user/sentinel-app"})
        s3_stub.add_response("head_bucket", {})
        s3_stub.add_response("put_public_access_block", {})
        s3_stub.add_response("put_bucket_encryption", {})
        s3_stub.add_response("put_object", {}, {"Bucket": "sentinelai-0badc0de", "Key": "raw/github/alerts.json", "Body": b"[]",
                                                "ContentType": "application/json", "ServerSideEncryption": "AES256"})
        s3_stub.add_response("put_object", {}, {"Bucket": "sentinelai-0badc0de", "Key": "reports/", "Body": b"", "ServerSideEncryption": "AES256"})
        rt_stub.add_response("converse", {
            "output": {"message": {"role": "assistant", "content": [{"text": "SentinelAI ready"}]}},
            "stopReason": "end_turn", "usage": {"inputTokens": 1, "outputTokens": 1, "totalTokens": 2}, "metrics": {"latencyMs": 1},
        })
        monkeypatch.setattr(aws_setup, "AwsSessionFactory", lambda settings: FakeAws(sts=sts, s3=s3, bedrock_runtime=rt))
        assert aws_setup.main([]) == 0
        for stub in (sts_stub, s3_stub, rt_stub):
            stub.assert_no_pending_responses()
    out = capsys.readouterr().out
    assert cw_calls == ["ensure", "ensure"]
    assert "[9/9] Bedrock Converse test" in out and "'SentinelAI ready'" in out and ACCOUNT not in out
    assert "AWS setup complete" in out


# --------------------------------------------------------------------------- aws_check


def _ctx(settings, aws: Any, *, victim: Any = None, http: httpx.Client | None = None) -> aws_check.Ctx:
    return aws_check.Ctx(
        settings=settings, aws=aws, victim_session=lambda: victim,
        http=http or httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(500))),
        now=NOW, pause_s=0,
    )


def test_check_s3_pass_and_public_access_fail(settings) -> None:
    s3 = make_client("s3")
    with Stubber(s3) as stub:
        for pab in (True, False):
            stub.add_response("head_bucket", {})
            stub.add_response("list_objects_v2", {"KeyCount": 4, "IsTruncated": False})
            stub.add_response("get_public_access_block", {"PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": pab,
            }})
        ok = aws_check.check_s3(_ctx(settings, FakeAws(s3=s3)))
        bad = aws_check.check_s3(_ctx(settings, FakeAws(s3=s3)))
    assert ok.status == aws_check.PASS and "4 objects" in ok.detail
    assert bad.status == aws_check.FAIL and "RestrictPublicBuckets" in bad.detail


def test_check_cloudtrail_counts_pages_and_masks_key(settings) -> None:
    ct = make_client("cloudtrail")
    event = {"EventId": "e1", "EventName": "ListBuckets"}
    with Stubber(ct) as stub:
        stub.add_response("lookup_events", {"Events": [event, event], "NextToken": "t"})
        stub.add_response("lookup_events", {"Events": [event]})
        check = aws_check.check_cloudtrail(_ctx(settings, FakeAws(cloudtrail=ct)), "us-east-1")
    assert check.status == aws_check.PASS and check.detail.startswith("3 events for AKIA…MPLE")


def test_check_cloudtrail_zero_events_is_a_warning(settings) -> None:
    ct = make_client("cloudtrail")
    with Stubber(ct) as stub:
        stub.add_response("lookup_events", {"Events": []})
        check = aws_check.check_cloudtrail(_ctx(settings, FakeAws(cloudtrail=ct)), "ap-south-1")
    assert check.status == aws_check.WARN and "simulate_leaked_key" in check.detail


def test_check_logs_counts_simulated_events(settings) -> None:
    logs = make_client("logs")
    with Stubber(logs) as stub:
        stub.add_response("describe_log_streams", {"logStreams": []})
        stub.add_response("filter_log_events", {"events": [{"message": "{}"}] * 3, "nextToken": "n"})
        stub.add_response("filter_log_events", {"events": [{"message": "{}"}]})
        check = aws_check.check_logs(_ctx(settings, FakeAws(logs=logs)))
    assert check.status == aws_check.PASS and "4 simulated events" in check.detail


def test_check_logs_uses_the_app_lookback_window(settings) -> None:
    """Traffic older than CLOUDTRAIL_LOOKBACK_HOURS is invisible to the app, so it must not pass."""
    logs = make_client("logs")
    hours = settings.cloudtrail_lookback_hours
    expected = {
        "logGroupName": settings.auth_log_group,
        "filterPattern": aws_check.SIMULATED_FILTER,
        "startTime": int((NOW - timedelta(hours=hours)).timestamp() * 1000),
        "endTime": int(NOW.timestamp() * 1000),
    }
    with Stubber(logs) as stub:
        stub.add_response("describe_log_streams", {"logStreams": []})
        stub.add_response("filter_log_events", {"events": []}, expected)
        check = aws_check.check_logs(_ctx(settings, FakeAws(logs=logs)))
    assert check.status == aws_check.WARN
    assert f"last {hours} h" in check.detail and "simulate_app_auth" in check.detail and "INC-002" in check.detail


def test_check_victim_key_inactive_warns(settings) -> None:
    iam = make_client("iam")
    with Stubber(iam) as stub:
        stub.add_response("list_access_keys", _keys("Inactive"))
        check = aws_check.check_victim_key(_ctx(settings, FakeAws(iam=iam)))
    assert check.status == aws_check.WARN and "reset_demo_victim" in check.detail


class FakeVictimSession:
    def __init__(self, arn: str, key: str):
        self.sts = make_client("sts")
        self.stub = Stubber(self.sts)
        self.stub.add_response("get_caller_identity", {"UserId": "AIDAEXAMPLE", "Account": ACCOUNT, "Arn": arn})
        self.stub.activate()
        self.key = key

    def client(self, service: str) -> Any:
        return self.sts

    def get_credentials(self) -> Any:
        return types.SimpleNamespace(access_key=self.key)


def test_check_victim_profile_compares_key_without_printing_it(settings) -> None:
    other = OTHER_KEY
    ok = aws_check.check_victim_profile(_ctx(settings, FakeAws(), victim=FakeVictimSession(VICTIM_ARN, KEY)))
    bad = aws_check.check_victim_profile(_ctx(settings, FakeAws(), victim=FakeVictimSession(VICTIM_ARN, other)))
    wrong = aws_check.check_victim_profile(_ctx(settings, FakeAws(), victim=FakeVictimSession(f"arn:aws:iam::{ACCOUNT}:user/sentinel-app", KEY)))
    assert ok.status == aws_check.PASS and bad.status == aws_check.FAIL and wrong.status == aws_check.FAIL
    assert not bad.required
    for c in (ok, bad, wrong):
        assert KEY not in c.detail and other not in c.detail


def test_check_bedrock_requires_tool_use(settings) -> None:
    rt = make_client("bedrock-runtime")
    with Stubber(rt) as stub:
        stub.add_response("converse", {
            "output": {"message": {"role": "assistant", "content": [{"text": "ready"}]}},
            "stopReason": "end_turn",
            "usage": {"inputTokens": 1, "outputTokens": 1, "totalTokens": 2},
            "metrics": {"latencyMs": 1},
        })
        check = aws_check.check_bedrock(_ctx(settings, FakeAws(bedrock_runtime=rt)))
    assert check.status == aws_check.WARN and "without tool use" in check.detail


def test_check_elevenlabs(settings) -> None:
    settings.elevenlabs_api_key = ""
    assert aws_check.check_elevenlabs(_ctx(settings, FakeAws())).status == aws_check.SKIP
    settings.elevenlabs_api_key = "sk_" + "a" * 32
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["key"] = request.headers["xi-api-key"]
        return httpx.Response(200, json=[{"model_id": "eleven_flash_v2_5"}])

    check = aws_check.check_elevenlabs(_ctx(settings, FakeAws(), http=httpx.Client(transport=httpx.MockTransport(handler))))
    assert check.status == aws_check.PASS and seen["key"] == settings.elevenlabs_api_key
    assert settings.elevenlabs_api_key not in check.detail


def test_check_mcp_missing_executable_is_optional(settings) -> None:
    settings.cloudtrail_mcp_command = "definitely-not-installed-uvx awslabs.cloudtrail-mcp-server@latest"
    check = aws_check.check_mcp(_ctx(settings, FakeAws()))
    assert check.status == aws_check.FAIL and not check.required


FAKE_MCP_SERVER = """
from mcp.server.mcpserver import MCPServer
mcp = MCPServer("fake-cloudtrail")

@mcp.tool()
def lookup_events(attribute_key: str = "", attribute_value: str = "") -> dict:
    return {"events": []}

mcp.run()
"""


def test_check_mcp_lists_tools_of_a_stdio_server(settings, tmp_path: Path) -> None:
    server = tmp_path / "fake_cloudtrail_mcp.py"
    server.write_text(FAKE_MCP_SERVER)
    settings.cloudtrail_mcp_command = f"{sys.executable} {server}"
    ctx = _ctx(settings, FakeAws())
    ctx.mcp_timeout = 30
    check = aws_check.check_mcp(ctx)
    assert check.status == aws_check.PASS, check.detail
    assert "lookup_events" in check.detail


def test_isolated_turns_errors_into_failures_and_exit_code(settings) -> None:
    def boom(ctx: aws_check.Ctx) -> aws_check.Check:
        raise RuntimeError(f"bad key {KEY}")

    failed = aws_check.isolated("Boom", boom, _ctx(settings, FakeAws()))
    assert failed.status == aws_check.FAIL and KEY not in failed.detail
    optional = aws_check.Check("x", aws_check.FAIL, "", required=False)
    assert aws_check.exit_code([optional, aws_check.Check("y", aws_check.WARN, "")]) == 0
    assert aws_check.exit_code([optional, failed]) == 1


def test_run_checks_skips_aws_checks_without_credentials(settings) -> None:
    sts = make_client("sts")
    with Stubber(sts) as stub:
        stub.add_client_error("get_caller_identity", service_error_code="InvalidClientTokenId", http_status_code=403)
        checks = aws_check.run_checks(_ctx(settings, FakeAws(sts=sts), victim=None), skip_mcp=True)
    by_name = {c.name: c for c in checks}
    assert by_name["Credentials"].status == aws_check.FAIL and "invalid" in by_name["Credentials"].detail
    assert by_name["Region"].status == aws_check.PASS
    assert "not checked" in by_name["S3 bucket"].detail and "not checked" in by_name["CloudTrail us-east-1"].detail
    assert by_name["Victim profile"].status == aws_check.FAIL and not by_name["Victim profile"].required
    assert aws_check.exit_code(checks) == 1


def test_render_checklist_plain(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NO_COLOR", "1")
    buf = io.StringIO()
    aws_check.render([aws_check.Check("Credentials", aws_check.PASS, "account …9012"), aws_check.Check("S3 bucket", aws_check.FAIL, "missing")], _common.Out(buf))
    text = buf.getvalue()
    assert "\033[" not in text and "✓ Credentials" in text and "✗ S3 bucket" in text and "1 passed, 0 warnings, 1 failed" in text


# --------------------------------------------------------------------------- aws_teardown


def test_empty_bucket_deletes_versions_and_markers() -> None:
    s3 = make_client("s3")
    with Stubber(s3) as stub:
        stub.add_response("list_object_versions", {
            "Versions": [{"Key": "raw/a.json", "VersionId": "v1"}],
            "DeleteMarkers": [{"Key": "raw/a.json", "VersionId": "v2"}],
            "IsTruncated": False,
        })
        stub.add_response("delete_objects", {"Deleted": []}, {"Bucket": "b-bucket", "Delete": {
            "Objects": [{"Key": "raw/a.json", "VersionId": "v1"}, {"Key": "raw/a.json", "VersionId": "v2"}], "Quiet": True,
        }})
        stub.add_response("delete_bucket", {}, {"Bucket": "b-bucket"})
        assert aws_teardown.delete_bucket(s3, "b-bucket") == "deleted (2 object versions removed)"


def test_teardown_tolerates_missing_resources() -> None:
    s3, logs = make_client("s3"), make_client("logs")
    with Stubber(s3) as s3_stub, Stubber(logs) as logs_stub:
        s3_stub.add_client_error("list_object_versions", service_error_code="NoSuchBucket", http_status_code=404)
        logs_stub.add_client_error("delete_log_group", service_error_code="ResourceNotFoundException", http_status_code=400)
        assert aws_teardown.delete_bucket(s3, "b-bucket") == "already gone"
        assert aws_teardown.delete_log_group(logs, "/sentinelai/app-auth") == "already gone"


def test_teardown_requires_confirmation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "stdin", io.StringIO(""))  # not a TTY
    assert aws_teardown.confirmed("b-bucket", "/g", assume_yes=False) is False
    assert aws_teardown.confirmed("b-bucket", "/g", assume_yes=True) is True


# --------------------------------------------------------------------------- list_bedrock_models


@pytest.mark.parametrize("model_id,expected", [
    ("apac.amazon.nova-lite-v1:0", True),
    ("amazon.nova-pro-v1:0", True),
    ("us.amazon.nova-pro-v1:0", True),
    ("apac.amazon.nova-pro-v1:0", True),
    ("meta.llama3-1-70b-instruct-v1:0", True),
    ("meta.llama3-70b-instruct-v1:0", False),
    ("mistral.mistral-large-2402-v1:0", True),
    ("cohere.command-r-plus-v1:0", True),
    ("amazon.titan-text-express-v1", False),
])
def test_supports_tool_use(model_id: str, expected: bool) -> None:
    assert list_bedrock_models.supports_tool_use(model_id) is expected


def test_recommended_models() -> None:
    assert list_bedrock_models.recommended_model("ap-south-1") == "apac.amazon.nova-lite-v1:0"
    assert list_bedrock_models.recommended_model("us-east-1") == "us.amazon.nova-lite-v1:0"
    assert list_bedrock_models.recommended_model("ap-south-1", {"amazon.nova-lite-v1:0"}) == "amazon.nova-lite-v1:0"
    profiles = {"apac.amazon.nova-premier-v1:0", "apac.amazon.nova-pro-v1:0"}
    assert list_bedrock_models.stronger_model("ap-south-1", profiles) == "apac.amazon.nova-pro-v1:0"
    assert list_bedrock_models.stronger_model("us-east-1", set()) == "us.amazon.nova-pro-v1:0"


def test_list_models_filters_inactive_and_provisioned_only() -> None:
    bedrock = make_client("bedrock")

    def summary(model_id: str, types_: list[str], status: str = "ACTIVE") -> dict:
        return {"modelArn": f"arn:aws:bedrock:ap-south-1::foundation-model/{model_id}", "modelId": model_id,
                "inferenceTypesSupported": types_, "modelLifecycle": {"status": status}}

    with Stubber(bedrock) as stub:
        stub.add_response("list_foundation_models", {"modelSummaries": [
            summary("amazon.nova-lite-v1:0", ["INFERENCE_PROFILE"]),
            summary("amazon.titan-old", ["ON_DEMAND"], "LEGACY"),
            summary("meta.custom", ["PROVISIONED"]),
        ]})
        assert [m["modelId"] for m in list_bedrock_models.list_models(bedrock)] == ["amazon.nova-lite-v1:0"]


# --------------------------------------------------------------------------- repo hygiene


OWNED = ["scripts", "infra", "docs/AWS_SETUP.md", "README.md", "DEMO_SCRIPT.md", ".env.example", "Dockerfile",
         "docker-compose.yml", "Makefile", ".github", "tests/test_scripts.py"]


def test_no_real_access_keys_in_ops_files() -> None:
    root = Path(__file__).resolve().parent.parent
    pattern = re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}")
    allowed = {KEY}
    for rel in OWNED:
        target = root / rel
        files = [p for p in target.rglob("*") if p.is_file()] if target.is_dir() else [target] if target.exists() else []
        for path in files:
            if "__pycache__" in path.parts:
                continue
            found = set(pattern.findall(path.read_text(errors="ignore"))) - allowed
            assert not found, f"possible real access key id in {path}"


def test_cloudtrail_lookback_window(settings) -> None:
    ct = make_client("cloudtrail")
    with Stubber(ct) as stub:
        stub.add_response("lookup_events", {"Events": []}, {
            "LookupAttributes": [{"AttributeKey": "AccessKeyId", "AttributeValue": KEY}],
            "StartTime": NOW - timedelta(hours=24), "EndTime": NOW, "MaxResults": 50,
        })
        assert aws_check.count_key_events(ct, KEY, NOW - timedelta(hours=24), NOW, pause_s=0) == 0


def _probe_reply(stop: str, content: list) -> dict:
    return {"output": {"message": {"role": "assistant", "content": content}}, "stopReason": stop,
            "usage": {"inputTokens": 10, "outputTokens": 5, "totalTokens": 15}, "metrics": {"latencyMs": 100}}


def test_check_bedrock_sends_the_agents_request_shape(settings) -> None:
    from botocore.stub import ANY

    settings.bedrock_guardrail_id, settings.bedrock_guardrail_version = "abc123xyz", "2"
    guardrail = {"guardrailIdentifier": "abc123xyz", "guardrailVersion": "2", "trace": "enabled"}
    client = make_client("bedrock-runtime")
    use = {"toolUseId": "t1", "name": "report_status", "input": {"status": "ready"}}
    with Stubber(client) as stub:
        stub.add_response("converse", _probe_reply("tool_use", [{"toolUse": use}]), {
            "modelId": settings.bedrock_model_id, "messages": ANY, "inferenceConfig": ANY, "toolConfig": ANY,
            "system": ANY, "guardrailConfig": guardrail})
        stub.add_response("converse", _probe_reply("end_turn", [{"text": "ready"}]), {
            "modelId": settings.bedrock_model_id, "inferenceConfig": ANY, "toolConfig": ANY, "system": ANY,
            "guardrailConfig": guardrail, "messages": [
                ANY, {"role": "assistant", "content": [{"toolUse": use}]},
                {"role": "user", "content": [{"toolResult": {"toolUseId": "t1", "content": [{"json": {"status": "recorded"}}],
                                                             "status": "success"}}]}]})
        check = aws_check.check_bedrock(_ctx(settings, FakeAws(bedrock_runtime=client)))
        stub.assert_no_pending_responses()
    assert check.status == aws_check.PASS and "toolResult + guardrail" in check.detail


def test_check_bedrock_fails_on_guardrail_name(settings) -> None:
    settings.bedrock_guardrail_id = "sentinelai-pii"
    check = aws_check.check_bedrock(_ctx(settings, FakeAws()))
    assert check.status == aws_check.FAIL and "not the name" in check.detail
