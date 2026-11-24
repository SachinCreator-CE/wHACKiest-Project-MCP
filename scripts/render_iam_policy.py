#!/usr/bin/env python3
"""Render infra/iam/sentinel-app-policy.json into a ready-to-attach policy.

Fills <ACCOUNT_ID> (STS or --account-id), <BUCKET_NAME> (S3_BUCKET, --bucket or a
generated name saved to .env), <REGION>, <AUTH_LOG_GROUP> (AUTH_LOG_GROUP),
<VICTIM_USER> (DEMO_VICTIM_USER) and <ELEVENLABS_SECRET> (ELEVENLABS_SECRET_ID);
adds the foundation-model and inference-profile ARNs (in AWS_REGION and
BEDROCK_REGION) for BEDROCK_MODEL_ID / --model that the template wildcards do not
already cover (ids or full ARNs), plus bedrock:ApplyGuardrail when
BEDROCK_GUARDRAIL_ID (id or ARN) is set. Output (gitignored):
infra/iam/sentinel-app-policy.rendered.json
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any, Iterable

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts._common import (  # noqa: E402
    AWS_ERRORS,
    ROOT,
    Out,
    app_profile,
    describe_error,
    init_settings,
    resolve_bucket,
    use_profile,
)
from scripts.list_bedrock_models import base_model_id  # noqa: E402
from sentinel.aws.session import AwsSessionFactory  # noqa: E402

TEMPLATE = ROOT / "infra" / "iam" / "sentinel-app-policy.json"
RENDERED = ROOT / "infra" / "iam" / "sentinel-app-policy.rendered.json"
PLACEHOLDER_RE = re.compile(r"<[A-Z_]+>")
MANAGED_POLICY_LIMIT = 6144  # characters, whitespace excluded
DEFAULT_AUTH_LOG_GROUP = "/sentinelai/app-auth"
DEFAULT_VICTIM_USER = "sentinel-demo-victim"
DEFAULT_ELEVENLABS_SECRET = "sentinelai/elevenlabs"
# Resource names substituted into ARNs (AWS naming rules; also keeps the JSON well-formed).
_NAME_RULES = {
    "AUTH_LOG_GROUP": re.compile(r"[\w.#/-]{1,512}", re.ASCII),
    "DEMO_VICTIM_USER": re.compile(r"[\w+=,.@-]{1,64}", re.ASCII),
    "ELEVENLABS_SECRET_ID": re.compile(r"[\w/+=.@-]{1,512}", re.ASCII),
}
_MODEL_ARN_RE = re.compile(r"arn:aws(?:-[a-z]+)*:bedrock:[a-z0-9-]*:(?:\d{12})?:([a-z-]+)/(.+)")
_GUARDRAIL_RE = re.compile(r"[a-z0-9]+|arn:aws(?:-[^:]+)?:bedrock:[a-z0-9-]{1,20}:\d{12}:guardrail/[a-z0-9]+")
_SECRET_ARN_RE = re.compile(r"arn:aws(?:-[a-z]+)*:secretsmanager:[a-z0-9-]+:\d{12}:secret:[\w/+=.@-]+", re.ASCII)


def _statement(policy: dict[str, Any], sid: str) -> dict[str, Any] | None:
    return next((s for s in policy["Statement"] if s.get("Sid") == sid), None)


def _as_list(value: str | list[str]) -> list[str]:
    return [value] if isinstance(value, str) else list(value)


def _covered(arn: str, resources: Iterable[str]) -> bool:
    return any(fnmatchcase(arn, pattern) for pattern in resources)


def _model_arns(model_id: str, account_id: str, bedrock_regions: list[str]) -> list[str]:
    """ARNs Converse needs for a model/profile id or ARN (the profile in each region + the destination models)."""
    arns: list[str] = []
    if model_id.startswith("arn:"):
        m = _MODEL_ARN_RE.fullmatch(model_id)
        if not m or m.group(1) not in {"inference-profile", "foundation-model"}:
            raise ValueError(f"unsupported Bedrock model ARN {model_id!r}: use a foundation-model or inference-profile id")
        arns.append(model_id)
        model_id = m.group(2)
    base = base_model_id(model_id)
    arns.append(f"arn:aws:bedrock:*::foundation-model/{base}")
    if base != model_id:  # a cross-region inference profile (apac./us./eu./jp./global. …)
        arns += [f"arn:aws:bedrock:{r}:{account_id}:inference-profile/{model_id}" for r in bedrock_regions]
    return arns


def render_policy(
    template: dict[str, Any],
    *,
    account_id: str,
    bucket: str,
    region: str,
    bedrock_region: str | None = None,
    models: Iterable[str] = (),
    guardrail_id: str = "",
    include_secrets_manager: bool = True,
    auth_log_group: str = DEFAULT_AUTH_LOG_GROUP,
    victim_user: str = DEFAULT_VICTIM_USER,
    elevenlabs_secret_id: str = "",
) -> dict[str, Any]:
    """Return the rendered policy; raises ValueError on bad input or leftover placeholders."""
    if not re.fullmatch(r"\d{12}", account_id):
        raise ValueError("account id must be 12 digits")
    if not re.fullmatch(r"[a-z]{2}(-[a-z]+)+-\d", region):
        raise ValueError(f"invalid region {region!r}")
    secret_arn = elevenlabs_secret_id if elevenlabs_secret_id.startswith("arn:") else ""
    if secret_arn and not _SECRET_ARN_RE.fullmatch(secret_arn):
        raise ValueError(f"invalid ELEVENLABS_SECRET_ID ARN {secret_arn!r}")
    secret_name = "" if secret_arn else (elevenlabs_secret_id or DEFAULT_ELEVENLABS_SECRET)
    names = {"AUTH_LOG_GROUP": auth_log_group, "DEMO_VICTIM_USER": victim_user, "ELEVENLABS_SECRET_ID": secret_name}
    for setting, value in names.items():
        if (value or not secret_arn or setting != "ELEVENLABS_SECRET_ID") and not _NAME_RULES[setting].fullmatch(value):
            raise ValueError(f"invalid {setting} {value!r}")
    values = {
        "<ACCOUNT_ID>": account_id, "<BUCKET_NAME>": bucket, "<REGION>": region,
        "<AUTH_LOG_GROUP>": auth_log_group, "<VICTIM_USER>": victim_user, "<ELEVENLABS_SECRET>": secret_name,
    }
    text = json.dumps(template)
    for placeholder, value in values.items():
        text = text.replace(placeholder, json.dumps(value)[1:-1])
    policy = json.loads(text)
    secret = _statement(policy, "SecretsManagerElevenLabs")
    if secret is not None and secret_arn:
        secret["Resource"] = secret_arn + "*"  # a full ARN already carries the random suffix; a partial one does not

    invoke = _statement(policy, "BedrockInvoke")
    if invoke is None:
        raise ValueError("template has no BedrockInvoke statement")
    resources = _as_list(invoke["Resource"])
    bedrock_regions = list(dict.fromkeys([region, bedrock_region or region]))
    if bedrock_region and bedrock_region != region:  # the Bedrock client may run in another region
        prefix = f"arn:aws:bedrock:{region}:"
        resources += [r.replace(prefix, f"arn:aws:bedrock:{bedrock_region}:") for r in resources if r.startswith(prefix)]
    for model_id in models:
        resources += [arn for arn in _model_arns(model_id, account_id, bedrock_regions) if not _covered(arn, resources)]
    invoke["Resource"] = list(dict.fromkeys(resources))

    if guardrail_id:
        if not _GUARDRAIL_RE.fullmatch(guardrail_id):
            raise ValueError(f"invalid BEDROCK_GUARDRAIL_ID {guardrail_id!r}: use the guardrail id or its ARN")
        policy["Statement"].append({
            "Sid": "BedrockGuardrail",
            "Effect": "Allow",
            "Action": "bedrock:ApplyGuardrail",
            "Resource": [guardrail_id] if guardrail_id.startswith("arn:") else [
                f"arn:aws:bedrock:{r}:{account_id}:guardrail/{guardrail_id}" for r in bedrock_regions
            ],
        })
    if not include_secrets_manager:
        policy["Statement"] = [s for s in policy["Statement"] if s.get("Sid") != "SecretsManagerElevenLabs"]

    leftover = sorted(set(PLACEHOLDER_RE.findall(json.dumps(policy))))
    if leftover:
        raise ValueError(f"unfilled placeholders: {', '.join(leftover)}")
    return policy


def unwritable_allowlist(allowlist: Iterable[str], victim_user: str) -> list[str]:
    """Allow-listed users the policy grants no key actions on (only DEMO_VICTIM_USER is granted)."""
    return [u for u in dict.fromkeys(allowlist) if u != victim_user]


def policy_size(policy: dict[str, Any]) -> int:
    """Size as IAM counts it (no whitespace)."""
    return len(json.dumps(policy, separators=(",", ":")))


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0], formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    p.add_argument("--profile", default=None, help="profile used for STS when --account-id is absent (default: AWS_PROFILE or sentinel-app)")
    p.add_argument("--account-id", default=None, help="12-digit AWS account id (skips the STS call)")
    p.add_argument("--bucket", default=None, help="bucket name (default: S3_BUCKET or a generated one saved to .env)")
    p.add_argument("--region", default=None, help="AWS region (default: AWS_REGION or ap-south-1)")
    p.add_argument("--model", action="append", default=[], help="extra Bedrock model/profile id to allow (repeatable)")
    p.add_argument("--no-secrets-manager", action="store_true", help="drop the optional SecretsManagerElevenLabs statement")
    p.add_argument("--output", type=Path, default=RENDERED, help="output path (default: %(default)s)")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    settings = init_settings(args.region)
    out = Out()
    try:
        account_id = args.account_id
        if not account_id:
            use_profile(app_profile(args.profile))
            account_id = str(AwsSessionFactory(settings).client("sts").get_caller_identity()["Account"])
        bucket, saved = resolve_bucket(settings, args.bucket)
        policy = render_policy(
            json.loads(TEMPLATE.read_text()),
            account_id=account_id,
            bucket=bucket,
            region=settings.aws_region,
            bedrock_region=settings.bedrock_region,
            models=[settings.bedrock_model_id, *args.model],
            guardrail_id=settings.bedrock_guardrail_id,
            include_secrets_manager=not args.no_secrets_manager,
            auth_log_group=settings.auth_log_group,
            victim_user=settings.demo_victim_user,
            elevenlabs_secret_id=settings.elevenlabs_secret_id,
        )
    except AWS_ERRORS as exc:
        out.fail(f"{describe_error(exc)} (pass --account-id to skip STS)")
        return 1
    except ValueError as exc:
        out.fail(str(exc))
        return 1
    args.output.write_text(json.dumps(policy, indent=2) + "\n")
    out.ok(f"wrote {args.output} (account …{account_id[-4:]}, bucket {bucket}{' (saved to .env)' if saved else ''}, region {settings.aws_region})")
    for user in unwritable_allowlist(settings.real_action_user_allowlist, settings.demo_victim_user):
        out.warn(f"REAL_ACTION_USER_ALLOWLIST user {user!r} is not DEMO_VICTIM_USER; this policy denies iam:UpdateAccessKey on it")
    size = policy_size(policy)
    (out.info if size <= MANAGED_POLICY_LIMIT else out.warn)(f"{size}/{MANAGED_POLICY_LIMIT} characters (managed policy limit)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
