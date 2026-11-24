"""Configuration edge cases: blank/invalid env values must never crash startup or silently go online."""
from __future__ import annotations

import logging
import os

import pytest
from botocore.exceptions import ProfileNotFound

from sentinel import __main__ as entry
from sentinel.aws.session import AwsSessionFactory, safe_reason
from sentinel.config import MAX_LOOKBACK_HOURS, leak_flagged_at, load_settings
from sentinel.models import iso, parse_ts, utcnow

NOW = parse_ts("2026-11-24T12:00:00Z")


@pytest.fixture(autouse=True)
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("CLOUDTRAIL_REGIONS", "CLOUDTRAIL_LOOKBACK_HOURS", "CLOUDTRAIL_CACHE_TTL_S", "BEDROCK_MAX_TOKENS",
                 "BEDROCK_MAX_TURNS", "DEMO_LEAK_FLAGGED_AT", "AWS_REGION", "AWS_DEFAULT_REGION", "SENTINEL_PORT"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("SENTINEL_NO_DOTENV", "1")
    monkeypatch.setenv("SENTINEL_MODE", "offline")


# ---------------------------------------------------------------- AWS_PROFILE


def test_empty_aws_profile_line_in_dotenv_is_treated_as_unset(monkeypatch, tmp_path) -> None:
    env = tmp_path / ".env"
    env.write_text("AWS_PROFILE=\nSENTINEL_MODE=auto\n")
    monkeypatch.delenv("SENTINEL_NO_DOTENV")
    monkeypatch.delenv("SENTINEL_MODE")
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    s = load_settings(env)
    assert s.mode == "auto"
    assert "AWS_PROFILE" not in os.environ  # boto3 (and MCP children) now use the default chain


def test_whitespace_aws_profile_env_is_dropped_but_real_profile_kept(monkeypatch) -> None:
    monkeypatch.setenv("AWS_PROFILE", "  ")
    load_settings()
    assert "AWS_PROFILE" not in os.environ
    monkeypatch.setenv("AWS_PROFILE", "sentinel-app")
    load_settings()
    assert os.environ["AWS_PROFILE"] == "sentinel-app"


def test_empty_profile_reason_explains_the_fix() -> None:
    assert "empty" in safe_reason(ProfileNotFound(profile=""))
    assert safe_reason(ProfileNotFound(profile="nope")) == "AWS profile not found: nope"


def test_empty_aws_default_profile_is_dropped_too(monkeypatch) -> None:
    monkeypatch.setenv("AWS_DEFAULT_PROFILE", "")
    load_settings()
    assert "AWS_DEFAULT_PROFILE" not in os.environ  # botocore reads it as the profile name as well


# ------------------------------------------------------------ AWS status probe


def test_credentials_added_after_an_offline_start_are_picked_up(monkeypatch, tmp_path) -> None:
    """No credentials at startup must not pin the cached session/STS client to credentials=None."""
    for var in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_PROFILE", "AWS_DEFAULT_PROFILE"):
        monkeypatch.delenv(var, raising=False)
    creds = tmp_path / "credentials"
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(creds))
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "config"))
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    for var in ("AWS_CONTAINER_CREDENTIALS_FULL_URI", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "AWS_WEB_IDENTITY_TOKEN_FILE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("SENTINEL_MODE", "auto")
    f = AwsSessionFactory(load_settings())
    st = f.status()
    assert not st.connected and st.reason.startswith("No AWS credentials found")
    creds.write_text("[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = fake\n")
    # The next probe builds a fresh session and STS client that see the new file (no network needed to check).
    assert f.session().get_credentials().access_key == "AKIAIOSFODNN7EXAMPLE"
    assert f.client("sts")._request_signer._credentials.access_key == "AKIAIOSFODNN7EXAMPLE"


def test_status_probe_is_single_flight_and_serves_stale_while_refreshing(monkeypatch) -> None:
    import threading
    import time as _time

    from sentinel.aws.session import AwsStatus

    monkeypatch.setenv("SENTINEL_MODE", "auto")
    f = AwsSessionFactory(load_settings())
    gate, entered, calls = threading.Event(), threading.Event(), []

    class SlowSts:
        def get_caller_identity(self):
            calls.append(1)
            entered.set()
            gate.wait(5)
            return {"Account": "123456789012", "Arn": "arn:aws:iam::123456789012:user/sentinel-app"}

    monkeypatch.setattr(f, "client", lambda *a, **k: SlowSts())
    f._status = AwsStatus(False, region="ap-south-1", reason="ConnectTimeoutError", checked_at=_time.time() - 400)
    t = threading.Thread(target=f.status)
    t.start()
    assert entered.wait(5)
    started = _time.time()
    stale = f.status()  # a second caller (e.g. /api/status poll) must not block on, or start, another probe
    assert _time.time() - started < 1 and stale.reason == "ConnectTimeoutError" and len(calls) == 1
    gate.set()
    t.join(5)
    assert f.status().connected and len(calls) == 1


# ------------------------------------------------------------------- integers


@pytest.mark.parametrize("raw,expected", [("24h", 24), ("abc", 24), ("1.5", 24), (" 48 ", 48), ("0", 24), ("-5", 24), ("1", 1),
                                          ("99999999999", MAX_LOOKBACK_HOURS), ("", 24)])
def test_lookback_hours_is_parsed_and_clamped(monkeypatch, raw: str, expected: int) -> None:
    monkeypatch.setenv("CLOUDTRAIL_LOOKBACK_HOURS", raw)
    assert load_settings().cloudtrail_lookback_hours == expected


def test_other_int_settings_never_crash(monkeypatch, caplog) -> None:
    monkeypatch.setenv("BEDROCK_MAX_TOKENS", "1,200")
    monkeypatch.setenv("BEDROCK_MAX_TURNS", "0")
    monkeypatch.setenv("CLOUDTRAIL_CACHE_TTL_S", "-1")
    with caplog.at_level(logging.WARNING, logger="sentinel.config"):
        s = load_settings()
    assert (s.bedrock_max_tokens, s.bedrock_max_turns, s.cloudtrail_cache_ttl_s) == (1200, 6, 60)
    assert "BEDROCK_MAX_TOKENS" in caplog.text


def test_main_port_env_is_parsed_safely(monkeypatch) -> None:
    monkeypatch.setenv("SENTINEL_PORT", "abc")
    assert entry._env_port() == 8000
    monkeypatch.setenv("SENTINEL_PORT", "70000")
    assert entry._env_port() == 8000
    monkeypatch.setenv("SENTINEL_PORT", " 8916 ")
    assert entry._env_port() == 8916


def test_main_reads_server_settings_after_loading_dotenv(monkeypatch, tmp_path) -> None:
    seen: dict = {}
    def fake_load():  # stands in for load_dotenv putting SENTINEL_PORT=8917 into the environment
        monkeypatch.setenv("SENTINEL_PORT", "8917")
        return load_settings()

    monkeypatch.setattr(entry, "load_settings", fake_load)
    monkeypatch.setattr(entry, "create_app", lambda settings: object())
    monkeypatch.setattr(entry.uvicorn, "run", lambda app, **kw: seen.update(kw))
    monkeypatch.setenv("SENTINEL_VAR_DIR", str(tmp_path))
    entry.main([])
    assert seen["port"] == 8917


# -------------------------------------------------------------------- regions


@pytest.mark.parametrize("raw,expected", [
    ("ap-south-1;us-east-1", ["ap-south-1", "us-east-1"]),
    ("ap-south-1 us-east-1", ["ap-south-1", "us-east-1"]),
    ("AP-SOUTH-1, ap-south-1 ,us-east-1", ["ap-south-1", "us-east-1"]),
    ("us-gov-west-1,eu-central-2", ["us-gov-west-1", "eu-central-2"]),
    ("bogus,ap-south-1", ["ap-south-1"]),
    ("bogus", ["ap-south-1", "us-east-1"]),
    ("", ["ap-south-1", "us-east-1"]),
])
def test_cloudtrail_regions_parsing(monkeypatch, raw: str, expected: list[str]) -> None:
    monkeypatch.setenv("CLOUDTRAIL_REGIONS", raw)
    assert load_settings().cloudtrail_regions == expected


def test_default_regions_deduplicated_in_us_east_1(monkeypatch) -> None:
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    assert load_settings().cloudtrail_regions == ["us-east-1"]


# ----------------------------------------------------------------------- mode


@pytest.mark.parametrize("raw,expected", [("off", "offline"), ("false", "offline"), ("demo", "offline"),
                                          ("weird", "offline"), ("LIVE", "aws"), ("true", "aws"), (" Auto ", "auto"),
                                          ("", "auto"), ("offline", "offline")])
def test_mode_aliases_and_unknown_fail_safe(monkeypatch, raw: str, expected: str) -> None:
    monkeypatch.setenv("SENTINEL_MODE", raw)
    assert load_settings().mode == expected


def test_unknown_mode_never_calls_sts(monkeypatch) -> None:
    monkeypatch.setenv("SENTINEL_MODE", "off")
    f = AwsSessionFactory(load_settings())
    monkeypatch.setattr(f, "client", lambda *a, **k: pytest.fail("STS must not be called"))
    assert f.status().reason == "SENTINEL_MODE=offline"


# ------------------------------------------------------------- flagged_at


@pytest.mark.parametrize("raw,expected", [
    ("2026-11-24T10:00:00Z", "2026-11-24T10:00:00Z"),
    ("2026-11-24T10:00:00+05:30", "2026-11-24T04:30:00Z"),
    ("2026-11-24 10:00", "2026-11-24T10:00:00Z"),
    ("24/11/2026 10:00", ""),
    ("yesterday", ""),
])
def test_demo_leak_flagged_at_is_normalised_or_blanked(monkeypatch, raw: str, expected: str) -> None:
    monkeypatch.setenv("DEMO_LEAK_FLAGGED_AT", raw)
    assert load_settings().demo_leak_flagged_at == expected


def test_demo_leak_flagged_at_relative(monkeypatch) -> None:
    monkeypatch.setenv("DEMO_LEAK_FLAGGED_AT", "2 hours ago")
    got = parse_ts(load_settings().demo_leak_flagged_at)
    assert abs((utcnow() - got).total_seconds() - 7200) < 120


def test_leak_flagged_at_tolerates_bad_override() -> None:
    s = load_settings(demo_leak_flagged_at="24/11/2026 10:00", cloudtrail_lookback_hours=24)
    assert iso(leak_flagged_at(s, NOW)) == "2026-11-23T12:00:00Z"


@pytest.mark.parametrize("raw,expected", [("", ""), ("draft", "DRAFT"), ("DRAFT", "DRAFT"), ("v3", "3"), ("12", "12")])
def test_guardrail_version_is_normalised(monkeypatch, raw: str, expected: str) -> None:
    monkeypatch.setenv("BEDROCK_GUARDRAIL_VERSION", raw)
    assert load_settings().bedrock_guardrail_version == expected


def test_guardrail_name_instead_of_id_is_warned(monkeypatch, caplog) -> None:
    from sentinel.config import GUARDRAIL_ID_RE

    monkeypatch.setenv("BEDROCK_GUARDRAIL_ID", "sentinelai-pii")
    with caplog.at_level("WARNING", logger="sentinel.config"):
        s = load_settings()
    assert "BEDROCK_GUARDRAIL_ID" in caplog.text and not GUARDRAIL_ID_RE.fullmatch(s.bedrock_guardrail_id)
    for ok in ("abc123xyz", "arn:aws:bedrock:ap-south-1:123456789012:guardrail/abc123xyz"):
        assert GUARDRAIL_ID_RE.fullmatch(ok)


def test_bedrock_deadline_is_bounded(monkeypatch) -> None:
    monkeypatch.setenv("BEDROCK_DEADLINE_S", "9999")
    assert load_settings().bedrock_deadline_s == 300


def test_future_leak_flagged_at_falls_back_to_lookback_start(caplog) -> None:
    """A presenter's local 09:00 IST written without an offset is read as 09:00Z, hours in the future:
    every post-leak call would look 'before the alert' and the live INC-001 would drop to medium."""
    s = load_settings(demo_leak_flagged_at="2026-11-24T17:00:00Z", cloudtrail_lookback_hours=24)
    with caplog.at_level(logging.WARNING, logger="sentinel.config"):
        assert iso(leak_flagged_at(s, NOW)) == "2026-11-23T12:00:00Z"
    assert "in the future" in caplog.text
    near = load_settings(demo_leak_flagged_at="2026-11-24T12:03:00Z")  # small clock skew is tolerated
    assert iso(leak_flagged_at(near, NOW)) == "2026-11-24T12:03:00Z"
    past = load_settings(demo_leak_flagged_at="2026-11-24T03:30:00Z")
    assert iso(leak_flagged_at(past, NOW)) == "2026-11-24T03:30:00Z"


def test_naive_leak_flagged_at_warns_that_it_is_utc(monkeypatch, caplog) -> None:
    monkeypatch.setenv("DEMO_LEAK_FLAGGED_AT", "2026-11-24T09:00")
    with caplog.at_level(logging.WARNING, logger="sentinel.config"):
        assert load_settings().demo_leak_flagged_at == "2026-11-24T09:00:00Z"
    assert "no UTC offset" in caplog.text
    caplog.clear()
    monkeypatch.setenv("DEMO_LEAK_FLAGGED_AT", "2026-11-24T09:00:00+05:30")
    with caplog.at_level(logging.WARNING, logger="sentinel.config"):
        load_settings()
    assert "no UTC offset" not in caplog.text


def test_short_lookback_warns_once(monkeypatch, caplog) -> None:
    from sentinel import config as config_mod

    monkeypatch.setattr(config_mod, "_warned_once", set())
    monkeypatch.setenv("CLOUDTRAIL_LOOKBACK_HOURS", "1")
    with caplog.at_level(logging.WARNING, logger="sentinel.config"):
        load_settings()
        load_settings()
    assert caplog.text.count("shorter than the offline demo scenario") == 1
    caplog.clear()
    monkeypatch.setattr(config_mod, "_warned_once", set())
    monkeypatch.setenv("CLOUDTRAIL_LOOKBACK_HOURS", "3")
    with caplog.at_level(logging.WARNING, logger="sentinel.config"):
        load_settings()
    assert "offline demo scenario" not in caplog.text


def test_second_server_on_the_same_var_dir_exits_before_startup(monkeypatch, tmp_path, capsys) -> None:
    first = entry.acquire_instance_lock(tmp_path)
    assert first is not None
    try:
        assert entry.acquire_instance_lock(tmp_path) is None
        started: list = []
        monkeypatch.setattr(entry, "create_app", lambda settings: started.append(1) or object())
        monkeypatch.setattr(entry.uvicorn, "run", lambda app, **kw: started.append(2))
        monkeypatch.setenv("SENTINEL_VAR_DIR", str(tmp_path))
        with pytest.raises(SystemExit):
            entry.main([])
        assert started == []  # no app, so no lifespan / initial detection against the shared store
        assert "already using" in capsys.readouterr().err
    finally:
        first.close()
    again = entry.acquire_instance_lock(tmp_path)
    assert again is not None
    again.close()
