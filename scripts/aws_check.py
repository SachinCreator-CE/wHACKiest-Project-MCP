#!/usr/bin/env python3
"""Green/red readiness checklist for the live AWS demo.

Every check is isolated: one failure never hides the others. Exits 1 when any
required check fails. Colors follow the terminal (set NO_COLOR=1 to disable).
"""
from __future__ import annotations

import argparse
import asyncio
import shlex
import sys
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import boto3  # noqa: E402
import httpx  # noqa: E402
from botocore.loaders import create_loader  # noqa: E402
from botocore.regions import EndpointResolver  # noqa: E402

from scripts._common import (  # noqa: E402
    DEFAULT_VICTIM_PROFILE,
    Out,
    app_profile,
    bedrock_probe,
    describe_error,
    error_code,
    find_executable,
    init_settings,
    mask_key,
    principal_of,
    use_profile,
)
from scripts.simulate_leaked_key import SafetyError, check_victim_arn  # noqa: E402
from sentinel.agent.prompts import build_system_prompt  # noqa: E402
from sentinel.aws.bedrock import guardrail_config  # noqa: E402
from sentinel.config import GUARDRAIL_ID_RE, GUARDRAIL_VERSION_RE  # noqa: E402
from sentinel.aws.session import AwsSessionFactory  # noqa: E402
from sentinel.mcp_hub import third_party_env  # noqa: E402
from sentinel.config import Settings  # noqa: E402
from sentinel.models import utcnow  # noqa: E402

PASS, FAIL, WARN, SKIP = "pass", "fail", "warn", "skip"
ELEVENLABS_MODELS_URL = "https://api.elevenlabs.io/v1/models"
SIMULATED_FILTER = "{ $.simulated IS TRUE }"
MAX_PAGES = 10
LOOKUP_PAUSE_S = 0.5  # CloudTrail LookupEvents is limited to 2 requests/second per account+region


@dataclass
class Check:
    name: str
    status: str
    detail: str
    required: bool = True


@dataclass
class Ctx:
    """What the checks need; tests swap in stubbed clients and fakes."""

    settings: Settings
    aws: Any  # anything with .client(service, region=None)
    victim_session: Callable[[], Any]  # -> boto3.Session-like for the victim profile
    http: httpx.Client
    now: datetime = field(default_factory=utcnow)
    mcp_timeout: float = 60.0
    pause_s: float = LOOKUP_PAUSE_S


# --------------------------------------------------------------------------- individual checks


def check_credentials(ctx: Ctx) -> Check:
    ident = ctx.aws.client("sts").get_caller_identity()
    return Check("Credentials", PASS, f"account …{str(ident['Account'])[-4:]}, principal {principal_of(ident['Arn'])}")


def _known_regions(service: str) -> set[str]:
    """Regions botocore's bundled endpoint data lists for ``service`` (no network, no profile)."""
    return set(EndpointResolver(create_loader().load_data("endpoints")).get_available_endpoints(service))


def check_region(ctx: Ctx) -> Check:
    s = ctx.settings
    detail = f"AWS_REGION {s.aws_region}, BEDROCK_REGION {s.bedrock_region}, CloudTrail {', '.join(s.cloudtrail_regions)}"
    wanted = {"bedrock": [s.bedrock_region], "cloudtrail": s.cloudtrail_regions, "logs": [s.aws_region]}
    unknown = [f"{svc} in {r}" for svc, regions in wanted.items() for r in regions if r not in _known_regions(svc)]
    if unknown:
        return Check("Region", FAIL, f"{detail}; not available: {', '.join(unknown)}")
    return Check("Region", PASS, detail)


def check_bedrock(ctx: Ctx) -> Check:
    s = ctx.settings
    if s.bedrock_guardrail_id and not GUARDRAIL_ID_RE.fullmatch(s.bedrock_guardrail_id):
        return Check("Bedrock model", FAIL, f"BEDROCK_GUARDRAIL_ID {s.bedrock_guardrail_id!r} is not a guardrail id or ARN "
                     "(use the id from `aws bedrock list-guardrails`, not the name)")
    if s.bedrock_guardrail_version and not GUARDRAIL_VERSION_RE.fullmatch(s.bedrock_guardrail_version):
        return Check("Bedrock model", FAIL, f"BEDROCK_GUARDRAIL_VERSION {s.bedrock_guardrail_version!r} must be DRAFT or a number")
    # Same request shape as the copilot: real system prompt, guardrailConfig, then a toolResult turn.
    probe = bedrock_probe(
        ctx.aws.client("bedrock-runtime", s.bedrock_region), s.bedrock_model_id, with_tool=True,
        system=build_system_prompt(), guardrail=guardrail_config(s), follow_up=True,
    )
    if probe.tool_used:
        extra = " + guardrail" if s.bedrock_guardrail_id else ""
        return Check("Bedrock model", PASS,
                     f"{s.bedrock_model_id} answered with toolUse and accepted the toolResult{extra} in {probe.ms} ms")
    return Check(
        "Bedrock model", WARN,
        f"{s.bedrock_model_id} replied without tool use (stopReason {probe.stop_reason}); the agent may fall back",
    )


def count_key_events(ct: Any, key_id: str, start: datetime, end: datetime, pause_s: float = LOOKUP_PAUSE_S) -> int:
    """CloudTrail events for one access key id in [start, end] (at most MAX_PAGES pages)."""
    count, token = 0, None
    for page in range(MAX_PAGES):
        kwargs: dict[str, Any] = {
            "LookupAttributes": [{"AttributeKey": "AccessKeyId", "AttributeValue": key_id}],
            "StartTime": start,
            "EndTime": end,
            "MaxResults": 50,
        }
        if token:
            kwargs["NextToken"] = token
        if page and pause_s:
            time.sleep(pause_s)
        resp = ct.lookup_events(**kwargs)
        count += len(resp.get("Events", []))
        token = resp.get("NextToken")
        if not token:
            break
    return count


def check_cloudtrail(ctx: Ctx, region: str) -> Check:
    s = ctx.settings
    name = f"CloudTrail {region}"
    ct = ctx.aws.client("cloudtrail", region)
    hours = s.cloudtrail_lookback_hours
    if not s.demo_leaked_access_key_id:
        ct.lookup_events(MaxResults=1)
        return Check(name, WARN, "LookupEvents works, but DEMO_LEAKED_ACCESS_KEY_ID is not set in .env")
    key = mask_key(s.demo_leaked_access_key_id)
    n = count_key_events(ct, s.demo_leaked_access_key_id, ctx.now - timedelta(hours=hours), ctx.now, ctx.pause_s)
    if n:
        return Check(name, PASS, f"{n} events for {key} in the last {hours} h")
    return Check(
        name, WARN,
        f"0 events for {key} in the last {hours} h; run scripts/simulate_leaked_key.py and wait 5–15 min",
    )


async def _mcp_tool_names(command: list[str], env: dict[str, str], errlog: Any) -> list[str]:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    params = StdioServerParameters(command=command[0], args=command[1:], env=env)
    async with stdio_client(params, errlog=errlog) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            return [t.name for t in (await session.list_tools()).tools]


def check_mcp(ctx: Ctx) -> Check:
    s = ctx.settings
    name = "CloudTrail MCP (AWS Labs)"
    command = shlex.split(s.cloudtrail_mcp_command)
    exe = find_executable(command[0]) if command else None
    if not exe:
        return Check(name, FAIL, f"{command[0] if command else '(empty)'} not found; `brew install uv` (app falls back to boto3)", required=False)
    env = {**third_party_env(), "AWS_REGION": s.aws_region, "FASTMCP_LOG_LEVEL": "ERROR"}  # same env as the app gives it
    t0 = time.perf_counter()
    with tempfile.TemporaryFile("w+") as errlog:
        try:
            names = asyncio.run(asyncio.wait_for(_mcp_tool_names([exe, *command[1:]], env, errlog), ctx.mcp_timeout))
        except (TimeoutError, asyncio.TimeoutError):
            return Check(name, FAIL, f"no answer within {ctx.mcp_timeout:.0f} s (first uvx run downloads the server; retry)", required=False)
        except Exception as exc:  # noqa: BLE001 - spawn/protocol errors of any kind
            errlog.seek(0)
            tail = errlog.read().strip().splitlines()[-1:] or [str(exc)]
            return Check(name, FAIL, f"{type(exc).__name__}: {tail[0][:160]} (app falls back to boto3)", required=False)
    secs = time.perf_counter() - t0
    if "lookup_events" in names:
        return Check(name, PASS, f"{len(names)} tools incl. lookup_events ({secs:.1f} s)", required=False)
    return Check(name, FAIL, f"lookup_events missing from tools {names} (app falls back to boto3)", required=False)


def check_logs(ctx: Ctx) -> Check:
    s = ctx.settings
    logs = ctx.aws.client("logs")
    name = "CloudWatch Logs"
    try:
        logs.describe_log_streams(logGroupName=s.auth_log_group, limit=1)
    except Exception as exc:
        if error_code(exc) == "ResourceNotFoundException":
            return Check(name, FAIL, f"{s.auth_log_group} does not exist; run scripts/aws_setup.py")
        raise
    # Count over the same window the app reads (identity MCP / sources.auth_events): older traffic
    # is invisible to detection, and an empty live answer shows no INC-002 and no fallback banner.
    hours = s.cloudtrail_lookback_hours
    start_ms = int((ctx.now - timedelta(hours=hours)).timestamp() * 1000)
    end_ms = int(ctx.now.timestamp() * 1000)
    count, token = 0, None
    for _ in range(MAX_PAGES):
        kwargs: dict[str, Any] = {
            "logGroupName": s.auth_log_group,
            "filterPattern": SIMULATED_FILTER,
            "startTime": start_ms,
            "endTime": end_ms,
        }
        if token:
            kwargs["nextToken"] = token
        resp = logs.filter_log_events(**kwargs)
        count += len(resp.get("events", []))
        token = resp.get("nextToken")
        if not token:
            break
    if count:
        return Check(name, PASS, f"{s.auth_log_group} readable, {count} simulated events in the last {hours} h (the app's window)")
    return Check(
        name,
        WARN,
        f"{s.auth_log_group} has no simulated events in the last {hours} h (CLOUDTRAIL_LOOKBACK_HOURS), "
        "so INC-002 will not appear; run scripts/simulate_app_auth.py",
    )


def check_s3(ctx: Ctx) -> Check:
    s = ctx.settings
    name = "S3 bucket"
    if not s.s3_bucket:
        return Check(name, FAIL, "S3_BUCKET is not set; run scripts/aws_setup.py")
    s3 = ctx.aws.client("s3")
    s3.head_bucket(Bucket=s.s3_bucket)
    raw = sum(page.get("KeyCount", 0) for page in s3.get_paginator("list_objects_v2").paginate(Bucket=s.s3_bucket, Prefix=s.s3_raw_prefix))
    pab = s3.get_public_access_block(Bucket=s.s3_bucket)["PublicAccessBlockConfiguration"]
    off = [k for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets") if not pab.get(k)]
    if off:
        return Check(name, FAIL, f"s3://{s.s3_bucket} Block Public Access is OFF for {', '.join(off)}")
    detail = f"s3://{s.s3_bucket}, {raw} objects under {s.s3_raw_prefix}, Block Public Access on"
    return Check(name, PASS if raw else WARN, detail if raw else detail + "; run scripts/aws_setup.py to upload data/")


def check_victim_profile(ctx: Ctx) -> Check:
    s = ctx.settings
    name = "Victim profile"
    session = ctx.victim_session()
    arn = session.client("sts").get_caller_identity()["Arn"]
    try:
        check_victim_arn(arn, s.demo_victim_user)
    except SafetyError:
        return Check(name, FAIL, f"profile is {principal_of(arn)}, expected user/{s.demo_victim_user}", required=False)
    creds = session.get_credentials()
    key_id = creds.access_key if creds else ""  # compared only, never printed unmasked
    if not s.demo_leaked_access_key_id:
        return Check(
            name, WARN,
            f"user/{s.demo_victim_user}; set DEMO_LEAKED_ACCESS_KEY_ID in .env to this profile's key ID ({mask_key(key_id)})",
            required=False,
        )
    if key_id != s.demo_leaked_access_key_id:
        return Check(
            name, FAIL,
            f"profile key {mask_key(key_id)} ≠ DEMO_LEAKED_ACCESS_KEY_ID {mask_key(s.demo_leaked_access_key_id)}",
            required=False,
        )
    return Check(name, PASS, f"user/{s.demo_victim_user}, key {mask_key(key_id)} matches DEMO_LEAKED_ACCESS_KEY_ID", required=False)


def check_victim_key(ctx: Ctx) -> Check:
    s = ctx.settings
    name = "Victim key status"
    if not s.demo_leaked_access_key_id:
        return Check(name, WARN, "DEMO_LEAKED_ACCESS_KEY_ID is not set")
    iam = ctx.aws.client("iam")
    for page in iam.get_paginator("list_access_keys").paginate(UserName=s.demo_victim_user):
        for meta in page.get("AccessKeyMetadata", []):
            if meta.get("AccessKeyId") == s.demo_leaked_access_key_id:
                key = mask_key(s.demo_leaked_access_key_id)
                if meta.get("Status") == "Active":
                    return Check(name, PASS, f"{key} is Active (ready to be deactivated in the demo)")
                return Check(name, WARN, f"{key} is {meta.get('Status')}; run scripts/reset_demo_victim.py")
    return Check(name, FAIL, f"{mask_key(s.demo_leaked_access_key_id)} not found on {s.demo_victim_user}")


def check_allow_real_actions(ctx: Ctx) -> Check:
    s = ctx.settings
    if s.allow_real_actions:
        return Check("ALLOW_REAL_ACTIONS", PASS, f"true: approved key deactivation is REAL for {', '.join(s.real_action_user_allowlist)}", required=False)
    return Check("ALLOW_REAL_ACTIONS", WARN, "false: approved actions are simulated", required=False)


def check_elevenlabs(ctx: Ctx) -> Check:
    s = ctx.settings
    name = "ElevenLabs"
    if not s.elevenlabs_api_key:
        if s.elevenlabs_secret_id:
            return Check(name, SKIP, f"key comes from Secrets Manager {s.elevenlabs_secret_id} at runtime (not checked here)", required=False)
        return Check(name, SKIP, "ELEVENLABS_API_KEY not set; the UI uses browser speech instead", required=False)
    resp = ctx.http.get(ELEVENLABS_MODELS_URL, headers={"xi-api-key": s.elevenlabs_api_key}, timeout=10)
    if resp.status_code == 200:
        models = resp.json()
        return Check(name, PASS, f"API reachable, {len(models) if isinstance(models, list) else '?'} models", required=False)
    return Check(name, FAIL, f"GET /v1/models returned HTTP {resp.status_code}", required=False)


# --------------------------------------------------------------------------- runner


CheckFn = Callable[[Ctx], Check]


def isolated(name: str, fn: CheckFn, ctx: Ctx, required: bool = True) -> Check:
    """Run one check; any exception becomes a FAIL with a credential-free reason."""
    try:
        return fn(ctx)
    except Exception as exc:  # noqa: BLE001 - each check must be isolated
        return Check(name, FAIL, describe_error(exc), required=required)


def run_checks(ctx: Ctx, *, skip_mcp: bool = False) -> list[Check]:
    """Credentials first; checks that need the app credentials are not attempted when they fail."""
    # (name, check, required, needs app credentials)
    plan: list[tuple[str, CheckFn, bool, bool]] = [
        ("Region", check_region, True, False),
        ("Bedrock model", check_bedrock, True, True),
    ]
    plan += [(f"CloudTrail {r}", (lambda c, r=r: check_cloudtrail(c, r)), True, True) for r in ctx.settings.cloudtrail_regions]
    if not skip_mcp:
        plan.append(("CloudTrail MCP (AWS Labs)", check_mcp, False, True))
    plan += [
        ("CloudWatch Logs", check_logs, True, True),
        ("S3 bucket", check_s3, True, True),
        ("Victim profile", check_victim_profile, False, False),
        ("Victim key status", check_victim_key, True, True),
        ("ALLOW_REAL_ACTIONS", check_allow_real_actions, False, False),
        ("ElevenLabs", check_elevenlabs, False, False),
    ]
    results = [isolated("Credentials", check_credentials, ctx)]
    creds_ok = results[0].status == PASS
    for name, fn, required, needs_creds in plan:
        if needs_creds and not creds_ok:
            results.append(Check(name, FAIL, "not checked: the app credentials above do not work", required))
        else:
            results.append(isolated(name, fn, ctx, required))
    return results


def exit_code(checks: list[Check]) -> int:
    return 1 if any(c.status == FAIL and c.required for c in checks) else 0


def render(checks: list[Check], out: Out) -> None:
    marks = {PASS: ("✓", "green"), FAIL: ("✗", "red"), WARN: ("!", "yellow"), SKIP: ("-", "yellow")}
    width = max(len(c.name) for c in checks)
    for c in checks:
        sym, color = marks[c.status]
        optional = "" if c.required or c.status == PASS else out.paint(" (optional)", "dim")
        out.line(f"  {out.paint(sym, color)} {c.name.ljust(width)}  {c.detail}{optional}")
    counts = {s: sum(c.status == s for c in checks) for s in marks}
    out.line()
    out.line(f"{counts[PASS]} passed, {counts[WARN] + counts[SKIP]} warnings, {counts[FAIL]} failed")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--profile", default=None, help="app AWS CLI profile (default: AWS_PROFILE or sentinel-app; '' = default chain)")
    p.add_argument("--victim-profile", default=DEFAULT_VICTIM_PROFILE, help="victim AWS CLI profile (default: %(default)s)")
    p.add_argument("--region", default=None, help="AWS region (default: AWS_REGION or ap-south-1)")
    p.add_argument("--skip-mcp", action="store_true", help="skip spawning the AWS Labs CloudTrail MCP server")
    p.add_argument("--mcp-timeout", type=float, default=60.0, help="seconds to wait for the MCP server (default: %(default)s)")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    settings = init_settings(args.region)
    use_profile(app_profile(args.profile))
    out = Out()
    out.line(out.paint("SentinelAI AWS readiness check", "bold"))
    if settings.offline_only:
        out.line(out.paint("  note: SENTINEL_MODE=offline, so the app itself will not use AWS", "yellow"))
    with httpx.Client() as http:
        ctx = Ctx(
            settings=settings,
            aws=AwsSessionFactory(settings),
            victim_session=lambda: boto3.Session(profile_name=args.victim_profile, region_name=settings.aws_region),
            http=http,
            mcp_timeout=args.mcp_timeout,
        )
        checks = run_checks(ctx, skip_mcp=args.skip_mcp)
    render(checks, out)
    return exit_code(checks)


if __name__ == "__main__":
    sys.exit(main())
