#!/usr/bin/env python3
"""Idempotent AWS setup for SentinelAI (safe to run more than once).

1. verify credentials (STS)            5. upload data/ -> s3://<bucket>/raw/
2. resolve S3_BUCKET (persist to .env) 6. create the reports/ prefix marker
3. create the bucket                   7. CloudWatch log group (7-day retention)
4. Block Public Access + SSE-S3        8. write simulated app-auth traffic
                                       9. one tiny Bedrock Converse test call
"""
from __future__ import annotations

import argparse
import mimetypes
import sys
from pathlib import Path
from typing import Any, Callable, TypeVar

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from botocore.exceptions import ClientError  # noqa: E402

from scripts._common import (  # noqa: E402
    AWS_ERRORS,
    Out,
    app_profile,
    bedrock_probe,
    describe_error,
    error_code,
    init_settings,
    principal_of,
    resolve_bucket,
    use_profile,
)
from scripts.simulate_app_auth import LOG_RETENTION_DAYS, run as simulate_run  # noqa: E402
from sentinel.aws.session import AwsSessionFactory  # noqa: E402

T = TypeVar("T")
SSE = "AES256"
PUBLIC_ACCESS_BLOCK = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}


class SetupError(RuntimeError):
    """A setup step failed in a way the operator must fix."""


def bucket_create_kwargs(bucket: str, region: str) -> dict[str, Any]:
    """us-east-1 must not send a LocationConstraint; every other region must."""
    kwargs: dict[str, Any] = {"Bucket": bucket}
    if region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": region}
    return kwargs


def ensure_bucket(s3: Any, bucket: str, region: str) -> str:
    """Create the bucket unless we already own it. Returns "created" or "exists"."""
    try:
        s3.head_bucket(Bucket=bucket)
        return "exists"
    except ClientError as exc:
        if error_code(exc) in {"403", "AccessDenied", "Forbidden"}:
            raise SetupError(f"bucket {bucket} exists but is not accessible (owned by another account?); choose another S3_BUCKET") from exc
        if error_code(exc) not in {"404", "NoSuchBucket", "NotFound"}:
            raise
    try:
        s3.create_bucket(**bucket_create_kwargs(bucket, region))
    except ClientError as exc:
        if error_code(exc) == "BucketAlreadyOwnedByYou":
            return "exists"
        if error_code(exc) == "BucketAlreadyExists":
            raise SetupError(f"bucket name {bucket} is taken globally; set a different S3_BUCKET in .env") from exc
        raise
    s3.get_waiter("bucket_exists").wait(Bucket=bucket, WaiterConfig={"Delay": 2, "MaxAttempts": 15})
    return "created"


def harden_bucket(s3: Any, bucket: str) -> None:
    """Block all public access and enable default SSE-S3 encryption."""
    s3.put_public_access_block(Bucket=bucket, PublicAccessBlockConfiguration=PUBLIC_ACCESS_BLOCK)
    s3.put_bucket_encryption(
        Bucket=bucket,
        ServerSideEncryptionConfiguration={"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": SSE}}]},
    )


def iter_data_files(data_dir: Path) -> list[Path]:
    """Dataset files under data/ (hidden files and caches skipped), sorted."""
    return sorted(
        p
        for p in data_dir.rglob("*")
        if p.is_file() and not any(part.startswith((".", "__")) for part in p.relative_to(data_dir).parts)
    )


def upload_tree(s3: Any, bucket: str, data_dir: Path, prefix: str) -> list[str]:
    """Upload every dataset file to ``prefix`` + its path relative to data_dir. Returns keys."""
    keys: list[str] = []
    for path in iter_data_files(data_dir):
        key = prefix + path.relative_to(data_dir).as_posix()
        content_type = "application/x-ndjson" if path.suffix == ".jsonl" else (mimetypes.guess_type(path.name)[0] or "application/octet-stream")
        s3.put_object(Bucket=bucket, Key=key, Body=path.read_bytes(), ContentType=content_type, ServerSideEncryption=SSE)
        keys.append(key)
    return keys


class Runner:
    """Runs numbered steps, printing ✓/✗ and remembering failures."""

    def __init__(self, out: Out, total: int):
        self.out, self.total, self.n = out, total, 0
        self.failures: list[str] = []

    def run(self, title: str, fn: Callable[[], T]) -> T | None:
        self.n += 1
        self.out.step(f"[{self.n}/{self.total}] {title}")
        try:
            return fn()
        except (SetupError, ValueError, ImportError) as exc:
            self.out.fail(str(exc))
        except AWS_ERRORS as exc:
            self.out.fail(describe_error(exc))
        self.failures.append(title)
        return None

    def skip(self, title: str, reason: str) -> None:
        self.n += 1
        self.out.step(f"[{self.n}/{self.total}] {title}")
        self.out.warn(f"skipped: {reason}")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0], formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    p.add_argument("--profile", default=None, help="app AWS CLI profile (default: AWS_PROFILE or sentinel-app; '' = default chain)")
    p.add_argument("--region", default=None, help="AWS region (default: AWS_REGION or ap-south-1)")
    p.add_argument("--bucket", default=None, help="bucket name (default: S3_BUCKET or a generated sentinelai-<8 hex>)")
    p.add_argument("--skip-simulation", action="store_true", help="do not write simulated app-auth traffic")
    p.add_argument("--skip-bedrock", action="store_true", help="do not make the Bedrock test call")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    settings = init_settings(args.region)
    use_profile(app_profile(args.profile))
    aws = AwsSessionFactory(settings)
    out = Out()
    r = Runner(out, total=9)
    out.line(out.paint(f"SentinelAI AWS setup (region {settings.aws_region})", "bold"))

    def identity() -> None:
        ident = aws.client("sts").get_caller_identity()
        out.ok(f"account …{str(ident['Account'])[-4:]}, principal {principal_of(ident['Arn'])}")

    r.run("Credentials (sts:GetCallerIdentity)", identity)
    if r.failures:
        out.line()
        out.fail("Cannot continue without working credentials. See docs/AWS_SETUP.md.")
        return 1

    def bucket_name() -> str:
        bucket, saved = resolve_bucket(settings, args.bucket)
        out.ok(bucket + (" (saved to .env as S3_BUCKET)" if saved else ""))
        return bucket

    bucket = r.run("Resolve S3 bucket name", bucket_name)

    def create() -> str:
        state = ensure_bucket(aws.client("s3"), bucket, settings.aws_region)
        out.ok(f"s3://{bucket} {state}")
        return state

    def harden() -> None:
        harden_bucket(aws.client("s3"), bucket)
        out.ok("all four Block Public Access settings on; default encryption SSE-S3 (AES256)")

    def upload() -> None:
        keys = upload_tree(aws.client("s3"), bucket, settings.data_dir, settings.s3_raw_prefix)
        (out.ok if keys else out.warn)(f"{len(keys)} files → s3://{bucket}/{settings.s3_raw_prefix}")

    def marker() -> None:
        aws.client("s3").put_object(Bucket=bucket, Key=settings.s3_reports_prefix, Body=b"", ServerSideEncryption=SSE)
        out.ok(f"s3://{bucket}/{settings.s3_reports_prefix}")

    bucket_steps = [("Block Public Access + SSE-S3 encryption", harden), ("Upload data/ → raw/", upload), ("Create reports/ prefix", marker)]
    if bucket and r.run("Create bucket", create):
        for title, fn in bucket_steps:
            r.run(title, fn)
    else:
        if not bucket:
            r.skip("Create bucket", "no bucket name")
        for title, _ in bucket_steps:
            r.skip(title, "bucket not available")

    def log_group() -> None:
        from sentinel.aws.cloudwatch import ensure_log_group

        ensure_log_group(aws, settings.auth_log_group, retention_days=LOG_RETENTION_DAYS)
        out.ok(f"{settings.auth_log_group} ({LOG_RETENTION_DAYS}-day retention)")

    r.run("CloudWatch Logs group", log_group)

    if args.skip_simulation:
        r.skip("Simulated app-auth traffic", "--skip-simulation")
    else:
        def simulate() -> None:
            res = simulate_run(settings, aws)
            for line in res["summary"]:
                out.info(line)
            out.ok(f"wrote {res['written']} events to {res['stream']}")

        r.run("Simulated app-auth traffic", simulate)

    if args.skip_bedrock:
        r.skip("Bedrock Converse test", "--skip-bedrock")
    else:
        def bedrock() -> None:
            probe = bedrock_probe(aws.client("bedrock-runtime", settings.bedrock_region), settings.bedrock_model_id, with_tool=False)
            out.ok(f"{probe.model_id} in {settings.bedrock_region}: {probe.reply!r} ({probe.ms} ms)")

        r.run("Bedrock Converse test", bedrock)

    out.line()
    if r.failures:
        out.fail(f"{len(r.failures)} step(s) failed: {', '.join(r.failures)}")
        return 1
    out.ok("AWS setup complete. Next: python scripts/aws_check.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
