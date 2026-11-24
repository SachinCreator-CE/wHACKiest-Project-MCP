#!/usr/bin/env python3
"""Delete the SentinelAI demo resources: the S3 bucket (every object version) and the log group.

IAM users are NOT touched; the script prints the manual steps for those.
Requires --yes or an interactive confirmation (typing the bucket name).
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts._common import (  # noqa: E402
    AWS_ERRORS,
    Out,
    app_profile,
    describe_error,
    error_code,
    init_settings,
    use_profile,
)
from sentinel.aws.session import AwsSessionFactory  # noqa: E402

GONE_CODES = {"NoSuchBucket", "404", "NotFound", "ResourceNotFoundException"}
MANUAL_IAM_STEPS = """\
IAM users were left alone on purpose. To remove them (as an admin, not sentinel-app):
  aws iam list-access-keys --user-name sentinel-demo-victim
  aws iam delete-access-key --user-name sentinel-demo-victim --access-key-id <KEY_ID>
  aws iam delete-user --user-name sentinel-demo-victim
  aws iam list-access-keys --user-name sentinel-app
  aws iam delete-access-key --user-name sentinel-app --access-key-id <KEY_ID>
  aws iam detach-user-policy --user-name sentinel-app --policy-arn arn:aws:iam::<ACCOUNT_ID>:policy/SentinelAIApp
  aws iam delete-policy --policy-arn arn:aws:iam::<ACCOUNT_ID>:policy/SentinelAIApp
  aws iam delete-user --user-name sentinel-app
Then remove the [sentinel-app] and [sentinel-victim] sections from ~/.aws/credentials."""


def empty_bucket(s3: Any, bucket: str) -> int:
    """Delete every object version and delete marker. Returns how many were removed."""
    removed = 0
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
        batch = [
            {"Key": v["Key"], "VersionId": v["VersionId"]}
            for v in page.get("Versions", []) + page.get("DeleteMarkers", [])
        ]
        for i in range(0, len(batch), 1000):
            chunk = batch[i : i + 1000]
            resp = s3.delete_objects(Bucket=bucket, Delete={"Objects": chunk, "Quiet": True})
            if resp.get("Errors"):
                first = resp["Errors"][0]
                raise RuntimeError(f"could not delete {first.get('Key')}: {first.get('Code')}")
            removed += len(chunk)
    return removed


def delete_bucket(s3: Any, bucket: str) -> str:
    """Empty and delete ``bucket``; returns a short human result."""
    try:
        removed = empty_bucket(s3, bucket)
        s3.delete_bucket(Bucket=bucket)
    except AWS_ERRORS as exc:
        if error_code(exc) in GONE_CODES:
            return "already gone"
        raise
    return f"deleted ({removed} object versions removed)"


def delete_log_group(logs: Any, group: str) -> str:
    try:
        logs.delete_log_group(logGroupName=group)
    except AWS_ERRORS as exc:
        if error_code(exc) in GONE_CODES:
            return "already gone"
        raise
    return "deleted"


def confirmed(bucket: str, group: str, assume_yes: bool) -> bool:
    """--yes, or an interactive prompt where the operator types the bucket name (or "delete")."""
    if assume_yes:
        return True
    if not sys.stdin.isatty():
        return False
    token = bucket or "delete"
    target = f"s3://{bucket} (all versions) and {group}" if bucket else group
    answer = input(f"This permanently deletes {target}.\nType {token!r} to confirm: ")
    return answer.strip() == token


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--profile", default=None, help="app AWS CLI profile (default: AWS_PROFILE or sentinel-app; '' = default chain)")
    p.add_argument("--region", default=None, help="AWS region (default: AWS_REGION or ap-south-1)")
    p.add_argument("--yes", action="store_true", help="do not ask for confirmation")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    settings = init_settings(args.region)
    use_profile(app_profile(args.profile))
    out = Out()
    bucket, group = settings.s3_bucket, settings.auth_log_group
    if not confirmed(bucket, group, args.yes):
        out.fail("Not confirmed; nothing deleted. Re-run with --yes to skip the prompt.")
        return 2
    aws = AwsSessionFactory(settings)
    failed = False

    out.step("S3 bucket")
    if not bucket:
        out.warn("S3_BUCKET is not set; skipping")
    else:
        try:
            out.ok(f"s3://{bucket} {delete_bucket(aws.client('s3'), bucket)}")
        except (RuntimeError, *AWS_ERRORS) as exc:
            out.fail(describe_error(exc) if isinstance(exc, AWS_ERRORS) else str(exc))
            failed = True

    out.step("CloudWatch Logs group")
    try:
        out.ok(f"{group} {delete_log_group(aws.client('logs'), group)}")
    except AWS_ERRORS as exc:
        out.fail(describe_error(exc))
        failed = True

    out.step("IAM (manual)")
    for line in MANUAL_IAM_STEPS.splitlines():
        out.info(line)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
