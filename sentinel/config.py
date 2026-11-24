"""Runtime configuration for SentinelAI.

All settings come from environment variables (optionally loaded from a local
``.env`` file). Nothing in here ever reads or stores AWS credentials: boto3's
default credential chain (AWS_PROFILE=sentinel-app locally, an instance role on
EC2) is used everywhere.
"""
from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

try:  # python-dotenv is optional at import time (tests may not need it)
    from dotenv import load_dotenv
except Exception:  # pragma: no cover
    load_dotenv = None  # type: ignore

ROOT = Path(__file__).resolve().parent.parent
log = logging.getLogger("sentinel.config")

MODES = ("auto", "aws", "offline")
# Common spellings operators reach for. Anything unrecognised fails safe to offline.
_MODE_ALIASES = {
    "off": "offline", "false": "offline", "no": "offline", "0": "offline", "none": "offline",
    "local": "offline", "demo": "offline", "mock": "offline",
    "live": "aws", "on": "aws", "true": "aws", "yes": "aws", "1": "aws",
}
# CloudTrail Event history only keeps 90 days.
MAX_LOOKBACK_HOURS = 90 * 24
# The shifted offline scenario spans ~3 h before now (benign-arjun lands at now - 2 h 55 min).
OFFLINE_SCENARIO_HOURS = 3
_warned_once: set[str] = set()
_REGION_RE = re.compile(r"^[a-z]{2,4}(-gov|-iso[a-z]*)?-[a-z]+-\d+$")


def _bool(v: str | None, default: bool = False) -> bool:
    if v is None or v.strip() == "":
        return default
    return v.strip().lower() in {"1", "true", "yes", "on"}


def _list(v: str | None, default: list[str]) -> list[str]:
    if v is None or v.strip() == "":
        return list(default)
    return [x.strip() for x in v.split(",") if x.strip()]


def _int(name: str, default: int, lo: int, hi: int) -> int:
    """Integer env var: blank, unparsable or below ``lo`` -> default; above ``hi`` -> ``hi`` (warned)."""
    raw = (os.environ.get(name) or "").strip()
    if not raw:
        return default
    try:
        val = int(raw)
    except ValueError:
        log.warning("%s=%r is not an integer; using %d", name, raw, default)
        return default
    if val < lo:  # 0 / negative is never a meaningful choice here: use the default, not an empty window
        log.warning("%s=%d is below %d; using %d", name, val, lo, default)
        return default
    if val > hi:
        log.warning("%s=%d is above %d; using %d", name, val, hi, hi)
        return hi
    return val


# bedrock-runtime service-model patterns for guardrailConfig (Converse rejects anything else).
GUARDRAIL_ID_RE = re.compile(r"[a-z0-9]+|arn:aws(-[^:]+)?:bedrock:[a-z0-9-]{1,20}:[0-9]{12}:guardrail/[a-z0-9]+")
GUARDRAIL_VERSION_RE = re.compile(r"[1-9][0-9]{0,7}|DRAFT")


def _guardrail_id(raw: str | None) -> str:
    """BEDROCK_GUARDRAIL_ID; a value Converse would reject (e.g. the guardrail *name*) is warned about loudly."""
    text = (raw or "").strip()
    if text and not GUARDRAIL_ID_RE.fullmatch(text):
        log.warning("BEDROCK_GUARDRAIL_ID=%r is not a guardrail id (lowercase letters/digits) or guardrail ARN; "
                    "every Bedrock chat will fail and fall back offline. Use the id, not the name.", text)
    return text


def _guardrail_version(raw: str | None) -> str:
    """BEDROCK_GUARDRAIL_VERSION: '' (= DRAFT), DRAFT or 1-99999999; 'draft' and 'v3' are normalised."""
    text = (raw or "").strip()
    if text.lower() == "draft":
        return "DRAFT"
    if re.fullmatch(r"[vV][1-9][0-9]{0,7}", text):
        text = text[1:]
    if text and not GUARDRAIL_VERSION_RE.fullmatch(text):
        log.warning("BEDROCK_GUARDRAIL_VERSION=%r is not DRAFT or a version number; every Bedrock chat will fail "
                    "and fall back offline", text)
    return text


def _mode(raw: str | None) -> str:
    text = (raw or "").strip().lower()
    if not text:
        return "auto"
    if text in MODES:
        return text
    if text in _MODE_ALIASES:
        return _MODE_ALIASES[text]
    log.warning("SENTINEL_MODE=%r is not one of %s; using offline (never touches AWS)", raw, "/".join(MODES))
    return "offline"


def _regions(raw: str | None, default: list[str]) -> list[str]:
    """Comma/semicolon/space separated region names, lowercased, de-duplicated, validated."""
    out: list[str] = []
    for part in re.split(r"[\s,;]+", raw or ""):
        r = part.strip().lower()
        if not r:
            continue
        if not _REGION_RE.match(r):
            log.warning("CLOUDTRAIL_REGIONS entry %r is not an AWS region name; ignoring it", part)
            continue
        if r not in out:
            out.append(r)
    if not out:
        if (raw or "").strip():
            log.warning("CLOUDTRAIL_REGIONS=%r has no valid region; using %s", raw, ",".join(default))
        return list(dict.fromkeys(default))
    return out


# ISO date-time with no "Z"/offset: read as UTC, which is easy to get wrong on a non-UTC laptop.
_NAIVE_ISO = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?$")
# A DEMO_LEAK_FLAGGED_AT later than now + this is rejected (clock skew allowance).
FLAGGED_AT_SKEW_MINUTES = 5


def _flagged_at(raw: str | None) -> str:
    """``DEMO_LEAK_FLAGGED_AT`` normalised to UTC ISO-8601; invalid values are blanked (warned).

    Accepts ISO-8601 (naive = UTC), epoch seconds/ms and relative forms such as "2 hours ago".
    """
    text = (raw or "").strip()
    if not text:
        return ""
    from .datasets import parse_time_expr  # lazy: datasets imports this module
    from .models import iso

    try:
        dt = parse_time_expr(text)
    except (ValueError, OverflowError, OSError):
        dt = None
    if dt is None:
        log.warning("DEMO_LEAK_FLAGGED_AT=%r is not ISO-8601; using the lookback window start", raw)
        return ""
    if _NAIVE_ISO.match(text):
        log.warning("DEMO_LEAK_FLAGGED_AT=%r has no UTC offset; reading it as UTC (%s)", raw, iso(dt))
    return iso(dt)


def leak_flagged_at(settings: "Settings", now):
    """When the synthetic GitHub alert flagged the live key: ``DEMO_LEAK_FLAGGED_AT`` if valid,
    else the start of the CloudTrail lookback window. Shared by the GitHub MCP and its local fallback."""
    from datetime import timedelta

    from .models import parse_ts

    if settings.demo_leak_flagged_at:
        try:
            flagged = parse_ts(settings.demo_leak_flagged_at)
        except (ValueError, OverflowError):
            log.warning("DEMO_LEAK_FLAGGED_AT is not ISO-8601; using the lookback window start")
        else:
            if flagged <= now + timedelta(minutes=FLAGGED_AT_SKEW_MINUTES):
                return flagged
            # A future flag (typically a local time written without its offset, read as UTC) would turn
            # every post-leak call into "used before the alert" and downgrade the incident.
            log.warning(
                "DEMO_LEAK_FLAGGED_AT=%s is in the future (times without an offset are UTC); "
                "using the lookback window start", settings.demo_leak_flagged_at,
            )
    return now - timedelta(hours=settings.cloudtrail_lookback_hours)


# Exact, tested version of the third-party AWS Labs server (never @latest: a new upstream release
# could change lookup_events, and startup should not depend on resolving the newest PyPI release).
DEFAULT_CLOUDTRAIL_MCP_COMMAND = "uvx awslabs.cloudtrail-mcp-server@0.1.2"


@dataclass
class Settings:
    # --- mode -------------------------------------------------------------
    # "auto": use AWS when credentials work, otherwise offline fallback.
    # "aws": same as auto, but the UI flags a missing/broken AWS as an error.
    # "offline": never touch AWS (demo backup / CI).
    mode: str = "auto"

    # --- AWS core ---------------------------------------------------------
    aws_region: str = "ap-south-1"
    # IAM + global STS events land in us-east-1 Event history, so query it too.
    cloudtrail_regions: list[str] = field(default_factory=lambda: ["ap-south-1", "us-east-1"])
    cloudtrail_lookback_hours: int = 24
    cloudtrail_cache_ttl_s: int = 60
    cloudtrail_mcp_command: str = DEFAULT_CLOUDTRAIL_MCP_COMMAND

    # --- Bedrock ----------------------------------------------------------
    bedrock_region: str = "ap-south-1"
    # One-line switch for the demo, e.g. apac.amazon.nova-pro-v1:0.
    # Newer models need an inference profile ID.
    bedrock_model_id: str = "apac.amazon.nova-lite-v1:0"
    bedrock_max_tokens: int = 1200
    bedrock_max_turns: int = 6
    bedrock_guardrail_id: str = ""
    bedrock_guardrail_version: str = ""
    # Wall-clock budget for one copilot question on Bedrock (all Converse rounds + tools);
    # past it the answer comes from the offline agent instead.
    bedrock_deadline_s: int = 45

    # --- S3 / CloudWatch Logs --------------------------------------------
    s3_bucket: str = ""
    s3_raw_prefix: str = "raw/"
    s3_reports_prefix: str = "reports/"
    auth_log_group: str = "/sentinelai/app-auth"

    # --- live INC-001 -------------------------------------------------------
    demo_leaked_access_key_id: str = ""
    demo_victim_user: str = "sentinel-demo-victim"
    # ISO timestamp when the (synthetic) GitHub alert flagged the key. Empty =
    # start of the CloudTrail lookback window.
    demo_leak_flagged_at: str = ""

    # --- real remediation guard rails --------------------------------------
    allow_real_actions: bool = False
    real_action_user_allowlist: list[str] = field(default_factory=lambda: ["sentinel-demo-victim"])

    # --- ElevenLabs -----------------------------------------------------------
    elevenlabs_api_key: str = ""
    elevenlabs_secret_id: str = ""  # optional AWS Secrets Manager secret id
    elevenlabs_voice_id: str = "JBFqnCBsd6RMkjVDRZzb"
    elevenlabs_tts_model: str = "eleven_flash_v2_5"
    elevenlabs_stt_model: str = "scribe_v1"

    # --- local paths ----------------------------------------------------------
    data_dir: Path = ROOT / "data"
    var_dir: Path = ROOT / "var"
    web_dir: Path = ROOT / "web"

    @property
    def offline_only(self) -> bool:
        return self.mode == "offline"

    @property
    def db_path(self) -> Path:
        return self.var_dir / "sentinel.db"

    @property
    def local_reports_dir(self) -> Path:
        return self.var_dir / "reports"

    def public_dict(self) -> dict:
        """Settings that are safe to show in the UI (no secrets)."""
        return {
            "mode": self.mode,
            "aws_region": self.aws_region,
            "cloudtrail_regions": self.cloudtrail_regions,
            "bedrock_region": self.bedrock_region,
            "bedrock_model_id": self.bedrock_model_id,
            "guardrail": bool(self.bedrock_guardrail_id),
            "s3_bucket": self.s3_bucket,
            "auth_log_group": self.auth_log_group,
            "demo_victim_user": self.demo_victim_user,
            "allow_real_actions": self.allow_real_actions,
            "real_action_user_allowlist": self.real_action_user_allowlist,
            "elevenlabs_configured": bool(self.elevenlabs_api_key or self.elevenlabs_secret_id),
        }


def load_settings(env_file: str | os.PathLike | None = None, **overrides) -> Settings:
    """Build Settings from the environment (and ``.env`` unless disabled).

    ``SENTINEL_NO_DOTENV=1`` skips reading ``.env`` (used by tests).
    """
    if load_dotenv is not None and not _bool(os.environ.get("SENTINEL_NO_DOTENV")):
        load_dotenv(env_file or ROOT / ".env", override=False)
    for var in ("AWS_PROFILE", "AWS_DEFAULT_PROFILE"):
        if os.environ.get(var, None) is not None and not os.environ[var].strip():
            # An empty ``AWS_PROFILE=`` line makes botocore raise ProfileNotFound('') instead of using
            # the default chain (env creds / EC2 instance role). Treat it as unset, for MCP children too.
            del os.environ[var]
    e = os.environ.get
    region = e("AWS_REGION") or e("AWS_DEFAULT_REGION") or "ap-south-1"
    s = Settings(
        mode=_mode(e("SENTINEL_MODE")),
        aws_region=region,
        cloudtrail_regions=_regions(e("CLOUDTRAIL_REGIONS"), [region, "us-east-1"]),
        cloudtrail_lookback_hours=_int("CLOUDTRAIL_LOOKBACK_HOURS", 24, 1, MAX_LOOKBACK_HOURS),
        cloudtrail_cache_ttl_s=_int("CLOUDTRAIL_CACHE_TTL_S", 60, 0, 86400),
        cloudtrail_mcp_command=e("CLOUDTRAIL_MCP_COMMAND") or DEFAULT_CLOUDTRAIL_MCP_COMMAND,
        bedrock_region=e("BEDROCK_REGION") or region,
        bedrock_model_id=e("BEDROCK_MODEL_ID") or "apac.amazon.nova-lite-v1:0",
        bedrock_max_tokens=_int("BEDROCK_MAX_TOKENS", 1200, 1, 10000),
        bedrock_max_turns=_int("BEDROCK_MAX_TURNS", 6, 1, 20),
        bedrock_guardrail_id=_guardrail_id(e("BEDROCK_GUARDRAIL_ID")),
        bedrock_guardrail_version=_guardrail_version(e("BEDROCK_GUARDRAIL_VERSION")),
        bedrock_deadline_s=_int("BEDROCK_DEADLINE_S", 45, 5, 300),
        s3_bucket=e("S3_BUCKET") or "",
        auth_log_group=e("AUTH_LOG_GROUP") or "/sentinelai/app-auth",
        demo_leaked_access_key_id=(e("DEMO_LEAKED_ACCESS_KEY_ID") or "").strip(),
        demo_victim_user=e("DEMO_VICTIM_USER") or "sentinel-demo-victim",
        demo_leak_flagged_at=_flagged_at(e("DEMO_LEAK_FLAGGED_AT")),
        allow_real_actions=_bool(e("ALLOW_REAL_ACTIONS")),
        real_action_user_allowlist=_list(e("REAL_ACTION_USER_ALLOWLIST"), ["sentinel-demo-victim"]),
        elevenlabs_api_key=e("ELEVENLABS_API_KEY") or "",
        elevenlabs_secret_id=e("ELEVENLABS_SECRET_ID") or "",
        elevenlabs_voice_id=e("ELEVENLABS_VOICE_ID") or "JBFqnCBsd6RMkjVDRZzb",
        elevenlabs_tts_model=e("ELEVENLABS_TTS_MODEL") or "eleven_flash_v2_5",
        elevenlabs_stt_model=e("ELEVENLABS_STT_MODEL") or "scribe_v1",
    )
    if s.cloudtrail_lookback_hours < OFFLINE_SCENARIO_HOURS and "CLOUDTRAIL_LOOKBACK_HOURS" not in _warned_once:
        _warned_once.add("CLOUDTRAIL_LOOKBACK_HOURS")
        log.warning(
            "CLOUDTRAIL_LOOKBACK_HOURS=%d is shorter than the offline demo scenario (%d h): the synthetic "
            "INC-001/INC-002 events and the benign-arjun session fall outside the window",
            s.cloudtrail_lookback_hours, OFFLINE_SCENARIO_HOURS,
        )
    if e("SENTINEL_DATA_DIR"):
        s.data_dir = Path(e("SENTINEL_DATA_DIR"))
    if e("SENTINEL_VAR_DIR"):
        s.var_dir = Path(e("SENTINEL_VAR_DIR"))
    for k, v in overrides.items():
        setattr(s, k, v)
    return s
