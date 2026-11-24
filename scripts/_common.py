"""Shared helpers for the SentinelAI ops scripts.

Everything printed by a script goes through :func:`redact`, so access key IDs are
shown as ``AKIA…WXYZ``, secrets are removed and account IDs keep only their last
four digits. Credentials are never passed explicitly: boto3's default chain (an
AWS CLI profile locally, an instance role on EC2) is used.
"""
from __future__ import annotations

import os
import re
import secrets
import shutil
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence, TextIO

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import boto3  # noqa: E402
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError, ProfileNotFound  # noqa: E402

from sentinel.aws.session import safe_reason  # noqa: E402
from sentinel.config import Settings, load_settings  # noqa: E402
from sentinel.masking import mask_access_key, mask_text  # noqa: E402

DEFAULT_APP_PROFILE = "sentinel-app"
DEFAULT_VICTIM_PROFILE = "sentinel-victim"
ENV_FILE = ROOT / ".env"
ENV_EXAMPLE = ROOT / ".env.example"
ADMIN_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"

_ACCOUNT_RE = re.compile(r"(?<![\d…])\d{8}(\d{4})(?!\d)")
_BUCKET_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")

AWS_ERRORS: tuple[type[BaseException], ...] = (ClientError, BotoCoreError)


# --------------------------------------------------------------------------- output


def redact(text: object) -> str:
    """Mask keys/secrets/emails and shorten 12-digit account IDs to ``…1234``."""
    return _ACCOUNT_RE.sub(lambda m: "…" + m.group(1), mask_text(str(text)))


def _use_color(stream: TextIO) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return bool(getattr(stream, "isatty", lambda: False)())


class Out:
    """Tiny ✓/✗ console printer that honours ``NO_COLOR`` and non-TTY output."""

    COLORS = {"green": "32", "red": "31", "yellow": "33", "cyan": "36", "dim": "2", "bold": "1"}

    def __init__(self, stream: TextIO | None = None, color: bool | None = None):
        self.stream = stream or sys.stdout
        self.color = _use_color(self.stream) if color is None else color

    def paint(self, text: str, color: str) -> str:
        if not self.color:
            return text
        return f"\033[{self.COLORS[color]}m{text}\033[0m"

    def line(self, text: str = "") -> None:
        print(redact(text), file=self.stream, flush=True)

    def step(self, title: str) -> None:
        self.line()
        self.line(self.paint(f"▶ {title}", "bold"))

    def ok(self, msg: str) -> None:
        self.line(f"  {self.paint('✓', 'green')} {msg}")

    def fail(self, msg: str) -> None:
        self.line(f"  {self.paint('✗', 'red')} {msg}")

    def warn(self, msg: str) -> None:
        self.line(f"  {self.paint('!', 'yellow')} {msg}")

    def info(self, msg: str) -> None:
        self.line(f"  {self.paint('·', 'dim')} {msg}")


def table(headers: Sequence[str], rows: Iterable[Sequence[object]]) -> str:
    """Render a plain-text table (values are redacted)."""
    body = [[redact(c) for c in row] for row in rows]
    widths = [max(len(h), *(len(r[i]) for r in body)) if body else len(h) for i, h in enumerate(headers)]
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    lines = [fmt.format(*headers).rstrip(), fmt.format(*("-" * w for w in widths))]
    lines += [fmt.format(*r).rstrip() for r in body]
    return "\n".join(lines)


# --------------------------------------------------------------------------- errors


def error_code(exc: BaseException) -> str:
    """AWS error code (``AccessDenied``) or the exception class name."""
    if isinstance(exc, ClientError):
        return str(exc.response.get("Error", {}).get("Code") or "ClientError")
    return type(exc).__name__


_HINTS = {
    "AccessDenied": "the IAM policy does not allow this call; re-render infra/iam/sentinel-app-policy.json and update the user",
    "AccessDeniedException": "not allowed: Bedrock model access not granted, wrong model/profile id, or the IAM policy is missing it",
    "UnrecognizedClientException": "the access key in this profile is invalid, inactive or deleted",
    "InvalidClientTokenId": "the access key in this profile is invalid, inactive or deleted",
    "ExpiredToken": "the session token expired; refresh your credentials",
    "ThrottlingException": "throttled (CloudTrail LookupEvents allows ~2 requests/second); wait a moment and retry",
    "ValidationException": "check the model id; newer models need an inference profile id such as apac.amazon.nova-lite-v1:0",
    "ResourceNotFoundException": "the resource does not exist yet; run scripts/aws_setup.py",
    "NoSuchBucket": "the bucket does not exist yet; run scripts/aws_setup.py",
}


def describe_error(exc: BaseException) -> str:
    """Credential-free, redacted one-liner with a fix hint when we know one."""
    if isinstance(exc, NoCredentialsError):
        return "No AWS credentials found; run `aws configure --profile sentinel-app` (see docs/AWS_SETUP.md)"
    if isinstance(exc, ProfileNotFound):
        return f"{redact(exc)}; create it with `aws configure --profile <name>`"
    text = redact(safe_reason(exc))
    code = error_code(exc)
    hint = _HINTS.get(code)
    if code == "ValidationException" and "on-demand" not in text:
        hint = None  # only the "on-demand throughput isn't supported" variant has a known fix
    return f"{text} → {hint}" if hint else text


# --------------------------------------------------------------------------- settings / sessions


def init_settings(region: str | None = None) -> Settings:
    """Load ``.env`` + environment into Settings; ``--region`` wins over both."""
    if region:
        os.environ["AWS_REGION"] = region
    settings = load_settings()
    if os.environ.get("AWS_PROFILE") == "":
        del os.environ["AWS_PROFILE"]  # an empty AWS_PROFILE= line makes botocore raise ProfileNotFound('')
    return settings


def app_profile(cli_value: str | None) -> str | None:
    """Profile for the app identity: ``--profile`` > ``AWS_PROFILE`` > ``sentinel-app``.

    An explicit empty string means "boto3 default chain" (e.g. an EC2 instance role).
    """
    if cli_value is not None:
        return cli_value or None
    return os.environ.get("AWS_PROFILE") or DEFAULT_APP_PROFILE


def use_profile(profile: str | None) -> None:
    """Point boto3's default chain (and child processes) at ``profile``."""
    if profile:
        os.environ["AWS_PROFILE"] = profile
    else:
        os.environ.pop("AWS_PROFILE", None)


def boto_session(profile: str | None, region: str) -> boto3.Session:
    return boto3.Session(profile_name=profile or None, region_name=region)


def principal_of(arn: str) -> str:
    """``arn:aws:iam::123456789012:user/x`` -> ``user/x``."""
    return arn.split(":", 5)[-1] if arn.count(":") >= 5 else arn


def find_executable(name: str) -> str | None:
    """``shutil.which`` that also looks in the project's ``.venv/bin``."""
    found = shutil.which(name)
    if found:
        return found
    candidate = ROOT / ".venv" / "bin" / name
    return str(candidate) if candidate.exists() else None


def mask_key(key: str) -> str:
    return mask_access_key(key) if key else "(not set)"


# --------------------------------------------------------------------------- .env + bucket


def upsert_env_var(key: str, value: str, path: Path = ENV_FILE) -> None:
    """Set ``KEY=value`` in a .env file, creating it from .env.example if missing."""
    if not path.exists():
        path.write_text(ENV_EXAMPLE.read_text() if ENV_EXAMPLE.exists() else "")
    lines = path.read_text().splitlines()
    pattern = re.compile(rf"^\s*{re.escape(key)}\s*=")
    for i, line in enumerate(lines):
        if pattern.match(line):
            lines[i] = f"{key}={value}"
            break
    else:
        lines.append(f"{key}={value}")
    path.write_text("\n".join(lines) + "\n")
    os.environ[key] = value


def generate_bucket_name() -> str:
    return f"sentinelai-{secrets.token_hex(4)}"


def valid_bucket_name(name: str) -> bool:
    return bool(_BUCKET_RE.match(name)) and ".." not in name


def resolve_bucket(settings: Settings, cli_bucket: str | None = None, env_path: Path = ENV_FILE) -> tuple[str, bool]:
    """Bucket from ``--bucket`` > ``S3_BUCKET`` > a new ``sentinelai-<8 hex>``.

    A generated or ``--bucket`` name is saved to .env so the app uses the same bucket.
    Returns ``(bucket, saved_to_env)``.
    """
    bucket = (cli_bucket or settings.s3_bucket or "").strip() or generate_bucket_name()
    if not valid_bucket_name(bucket):
        raise ValueError(f"invalid S3 bucket name: {bucket!r}")
    saved = bucket != settings.s3_bucket
    if saved:
        upsert_env_var("S3_BUCKET", bucket, env_path)
        settings.s3_bucket = bucket
    return bucket, saved


# --------------------------------------------------------------------------- Bedrock


PROBE_TOOL_CONFIG: dict[str, Any] = {
    "tools": [
        {
            "toolSpec": {
                "name": "report_status",
                "description": "Report SentinelAI's connectivity status.",
                "inputSchema": {
                    "json": {
                        "type": "object",
                        "properties": {"status": {"type": "string", "description": "one word status"}},
                        "required": ["status"],
                    }
                },
            }
        }
    ]
}


@dataclass
class BedrockProbe:
    model_id: str
    ms: int
    reply: str
    stop_reason: str
    tool_used: bool


def bedrock_probe(
    client: Any,
    model_id: str,
    *,
    with_tool: bool,
    system: str | None = None,
    guardrail: dict[str, Any] | None = None,
    follow_up: bool = False,
) -> BedrockProbe:
    """One tiny Converse call (≈30 tokens). Raises botocore errors to the caller.

    ``system``/``guardrail`` add the agent's system block and ``guardrailConfig``; ``follow_up``
    answers a returned toolUse with a ``toolResult`` turn (built like the agent's), so the probe
    exercises the exact request shapes the copilot sends.
    """
    from sentinel.aws.bedrock import tool_result_block

    prompt = (
        "Call the report_status tool with status 'ready'."
        if with_tool
        else "Reply with exactly: SentinelAI ready"
    )
    messages: list[dict[str, Any]] = [{"role": "user", "content": [{"text": prompt}]}]
    kwargs: dict[str, Any] = {
        "modelId": model_id,
        "messages": messages,
        "inferenceConfig": {"maxTokens": 64, "temperature": 0},
    }
    if system:
        kwargs["system"] = [{"text": system}]
    if guardrail:
        kwargs["guardrailConfig"] = guardrail
    if with_tool:
        kwargs["toolConfig"] = PROBE_TOOL_CONFIG
    t0 = time.perf_counter()
    resp = client.converse(**kwargs)
    content = resp.get("output", {}).get("message", {}).get("content", [])
    tool_used = any("toolUse" in c for c in content)
    if follow_up and tool_used:
        uses = [c["toolUse"] for c in content if "toolUse" in c]
        messages.append(resp["output"]["message"])
        messages.append({"role": "user", "content": [
            tool_result_block(model_id, u["toolUseId"], {"status": "recorded"}, False) for u in uses
        ]})
        resp = client.converse(**kwargs)
        content = resp.get("output", {}).get("message", {}).get("content", [])
    ms = int((time.perf_counter() - t0) * 1000)
    reply = " ".join(str(c["text"]).strip() for c in content if "text" in c)
    return BedrockProbe(model_id, ms, reply[:200], str(resp.get("stopReason", "")), tool_used)
