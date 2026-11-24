"""Small S3 helpers for raw datasets and incident reports (SSE-S3 on every write)."""
from __future__ import annotations

from typing import Any

from ..models import iso


def put_text(aws: Any, bucket: str, key: str, body: str, content_type: str = "text/plain") -> str:
    """Upload ``body`` (UTF-8) with SSE-S3 and return its ``s3://`` URI."""
    aws.client("s3").put_object(
        Bucket=bucket, Key=key, Body=body.encode("utf-8"), ContentType=content_type, ServerSideEncryption="AES256"
    )
    return f"s3://{bucket}/{key}"


def get_text(aws: Any, bucket: str, key: str) -> str:
    """Download an object and decode it as UTF-8."""
    resp = aws.client("s3").get_object(Bucket=bucket, Key=key)
    return resp["Body"].read().decode("utf-8")


def list_keys(aws: Any, bucket: str, prefix: str) -> list[dict[str, Any]]:
    """All objects under ``prefix`` as ``{"key", "size", "last_modified"}``."""
    paginator = aws.client("s3").get_paginator("list_objects_v2")
    out: list[dict[str, Any]] = []
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        for obj in page.get("Contents", []):
            modified = obj.get("LastModified")
            out.append({"key": obj["Key"], "size": int(obj.get("Size", 0)), "last_modified": iso(modified) if modified else ""})
    return out
