#!/usr/bin/env python3
"""Create REAL, denied CloudTrail events with the deliberately "leaked" demo key.

Runs as the zero-permission IAM user ``sentinel-demo-victim`` (profile
``sentinel-victim``): GetCallerIdentity (allowed), then ListBuckets,
ListAttachedUserPolicies, CreateAccessKey and AttachUserPolicy(AdministratorAccess)
on itself, which should all fail with AccessDenied and show up in CloudTrail
Event history for INC-001.

Safety: nothing but GetCallerIdentity runs unless the caller ARN is exactly
``user/<DEMO_VICTIM_USER>``. If any call unexpectedly succeeds, the script stops,
undoes it (deletes a created key / detaches the policy) and exits non-zero.
"""
from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts._common import (  # noqa: E402
    ADMIN_POLICY_ARN,
    AWS_ERRORS,
    DEFAULT_VICTIM_PROFILE,
    Out,
    boto_session,
    describe_error,
    error_code,
    init_settings,
    mask_key,
    principal_of,
    table,
)

EXIT_OK, EXIT_ABORTED, EXIT_UNEXPECTED_SUCCESS = 0, 2, 3
DENIED = "AccessDenied"
ClientFactory = Callable[[str], Any]


class SafetyError(RuntimeError):
    """The current credentials are not the demo victim's."""


def check_victim_arn(arn: str, expected_user: str) -> str:
    """Return the user name when ``arn`` is exactly ``arn:aws:iam::<acct>:user/<expected_user>``."""
    m = re.fullmatch(r"arn:aws[a-z-]*:iam::\d{12}:user/([\w+=,.@-]+)", arn or "")
    if not m or m.group(1) != expected_user:
        raise SafetyError(
            f"refusing to continue: these credentials are {principal_of(arn) or 'unknown'}, "
            f"expected user/{expected_user} (DEMO_VICTIM_USER)"
        )
    return m.group(1)


@dataclass
class CallResult:
    call: str
    result: str  # "OK" or the AWS errorCode
    expected: str
    note: str = ""

    @property
    def as_expected(self) -> bool:
        return self.result == self.expected


@dataclass
class SimulationReport:
    calls: list[CallResult] = field(default_factory=list)
    aborted: str = ""  # reason the run stopped before the denied calls
    unexpected_success: bool = False

    @property
    def exit_code(self) -> int:
        if self.unexpected_success:
            return EXIT_UNEXPECTED_SUCCESS
        return EXIT_ABORTED if self.aborted else EXIT_OK


def _attempt(fn: Callable[[], Any]) -> tuple[str, Any]:
    """Run one AWS call; return ("OK", response) or (errorCode, None)."""
    try:
        return "OK", fn()
    except AWS_ERRORS as exc:
        return error_code(exc), None


def _undo(report: SimulationReport, call: CallResult, undo: Callable[[], Any], what: str) -> None:
    report.unexpected_success = True
    try:
        undo()
        call.note = f"UNEXPECTED SUCCESS: {what} undone"
    except AWS_ERRORS as exc:
        call.note = f"UNEXPECTED SUCCESS and undo FAILED ({describe_error(exc)}): fix it in the IAM console NOW"


def run_simulation(clients: ClientFactory, victim_user: str) -> SimulationReport:
    """Make the five demo calls in order, stopping at the first unexpected success."""
    report = SimulationReport()
    sts = clients("sts")
    try:
        arn = str(sts.get_caller_identity().get("Arn", ""))
    except AWS_ERRORS as exc:
        report.calls.append(CallResult("sts:GetCallerIdentity", error_code(exc), "OK"))
        report.aborted = describe_error(exc)
        return report
    report.calls.append(CallResult("sts:GetCallerIdentity", "OK", "OK", principal_of(arn)))
    try:
        user = check_victim_arn(arn, victim_user)
    except SafetyError as exc:
        report.aborted = str(exc)
        return report

    s3, iam = clients("s3"), clients("iam")
    read_only = [
        ("s3:ListBuckets", lambda: s3.list_buckets()),
        ("iam:ListAttachedUserPolicies", lambda: iam.list_attached_user_policies(UserName=user)),
    ]
    for name, fn in read_only:
        result, _ = _attempt(fn)
        call = CallResult(name, result, DENIED)
        report.calls.append(call)
        if result == "OK":
            call.note = "UNEXPECTED SUCCESS: the victim user has permissions; remove them"
            report.unexpected_success = True
            return report

    result, resp = _attempt(lambda: iam.create_access_key(UserName=user))
    call = CallResult("iam:CreateAccessKey", result, DENIED)
    report.calls.append(call)
    if result == "OK":
        new_key = str(resp["AccessKey"]["AccessKeyId"])
        del resp  # drop the secret immediately; it is never printed
        _undo(report, call, lambda: iam.delete_access_key(UserName=user, AccessKeyId=new_key), f"key {mask_key(new_key)} deleted")
        return report

    result, _ = _attempt(lambda: iam.attach_user_policy(UserName=user, PolicyArn=ADMIN_POLICY_ARN))
    call = CallResult("iam:AttachUserPolicy (AdministratorAccess)", result, DENIED)
    report.calls.append(call)
    if result == "OK":
        _undo(report, call, lambda: iam.detach_user_policy(UserName=user, PolicyArn=ADMIN_POLICY_ARN), "policy detached")
    return report


def key_match_line(key_id: str | None, expected: str) -> str:
    """Masked key id + whether it matches DEMO_LEAKED_ACCESS_KEY_ID (never the full value)."""
    if not key_id:
        return "Access key id: unavailable (no static credentials in this profile)"
    shown = mask_key(key_id)
    if not expected:
        return f"Access key id: {shown}. DEMO_LEAKED_ACCESS_KEY_ID is not set in .env; set it to this key's ID"
    if key_id == expected:
        return f"Access key id: {shown} (matches DEMO_LEAKED_ACCESS_KEY_ID ✓)"
    return f"Access key id: {shown} does NOT match DEMO_LEAKED_ACCESS_KEY_ID ({mask_key(expected)}) ✗"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--profile", default=DEFAULT_VICTIM_PROFILE, help="victim AWS CLI profile (default: %(default)s)")
    p.add_argument("--region", default=None, help="region for the S3 call (default: AWS_REGION or ap-south-1)")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    settings = init_settings(args.region)
    region = settings.aws_region
    out = Out()
    out.step(f"Simulating leaked-key usage as profile {args.profile!r} in {region}")
    try:
        session = boto_session(args.profile, region)
        creds = session.get_credentials()
        key_id = creds.access_key if creds else None
    except AWS_ERRORS + (ValueError,) as exc:
        out.fail(describe_error(exc))
        return EXIT_ABORTED

    report = run_simulation(lambda svc: session.client(svc, region_name=region), settings.demo_victim_user)

    out.line()
    out.line(table(["call", "result", "expected", "note"], [(c.call, c.result, c.expected, c.note) for c in report.calls]))
    out.line()
    out.line(key_match_line(key_id, settings.demo_leaked_access_key_id))
    if report.unexpected_success:
        out.line(out.paint("!!! WARNING: a call that must be denied SUCCEEDED. The victim user has permissions. !!!", "red"))
        out.line(out.paint("!!! Remove every policy from the victim user before running this demo again.     !!!", "red"))
    elif report.aborted:
        out.fail(f"Aborted: {report.aborted}")
    else:
        unexpected = [c for c in report.calls if not c.as_expected]
        for c in unexpected:
            out.warn(f"{c.call} returned {c.result} (expected {c.expected}); the event may still be recorded")
        out.ok("Done. These are real CloudTrail events from the leaked key.")
        out.info("CloudTrail Event history can take ~5–15 min to show them; then run scripts/aws_check.py.")
    return report.exit_code


if __name__ == "__main__":
    sys.exit(main())
