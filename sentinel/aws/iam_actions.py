"""IAM remediation primitives (boto3).

These functions perform no gating of their own: the only caller that may run a
real write is :func:`sentinel.actions.approve`, after ``real_action_gate`` has
passed. Errors propagate to the caller, which records them.
"""
from __future__ import annotations

import time
from typing import Any

from ..models import iso

VALID_STATUSES = ("Active", "Inactive")
# IAM is eventually consistent: ListAccessKeys may briefly show the old status after
# UpdateAccessKey succeeds, so verification re-reads a few times before giving up.
VERIFY_ATTEMPTS = 3
VERIFY_DELAY_S = 1.0


def list_access_keys(aws: Any, user_name: str) -> list[dict[str, str]]:
    """Return ``[{"access_key_id", "status", "create_date"}]`` for an IAM user (paginated)."""
    client = aws.client("iam")
    keys: list[dict[str, str]] = []
    for page in client.get_paginator("list_access_keys").paginate(UserName=user_name):
        for meta in page.get("AccessKeyMetadata", []):
            created = meta.get("CreateDate")
            keys.append(
                {
                    "access_key_id": str(meta.get("AccessKeyId", "")),
                    "status": str(meta.get("Status", "")),
                    "create_date": iso(created) if created else "",
                }
            )
    return keys


def set_access_key_status(
    aws: Any,
    user_name: str,
    access_key_id: str,
    status: str,
    *,
    attempts: int | None = None,
    delay_s: float | None = None,
) -> dict[str, Any]:
    """Call ``iam:UpdateAccessKey`` and verify the new status with ``ListAccessKeys``.

    Verification is retried up to ``attempts`` times (``delay_s`` apart) to ride out IAM's
    eventual consistency. Returns ``{"status": <observed status or "not_found">, "verified": bool,
    "requested": status, "checks": <ListAccessKeys reads>}``.
    """
    if status not in VALID_STATUSES:
        raise ValueError(f"status must be one of {VALID_STATUSES}, got {status!r}")
    attempts = max(1, VERIFY_ATTEMPTS if attempts is None else attempts)
    delay_s = VERIFY_DELAY_S if delay_s is None else delay_s
    aws.client("iam").update_access_key(UserName=user_name, AccessKeyId=access_key_id, Status=status)
    observed, checks = "not_found", 0
    while checks < attempts:
        if checks:
            time.sleep(delay_s)
        try:
            keys = list_access_keys(aws, user_name)
        except Exception:
            if not checks:
                raise  # the first read failing is reported to the caller as before
            break  # a failed re-read keeps the last observed status (the write itself succeeded)
        checks += 1
        observed = next((k["status"] for k in keys if k["access_key_id"] == access_key_id), "not_found")
        if observed == status or observed == "not_found":
            break
    return {"status": observed, "verified": observed == status, "requested": status, "checks": checks}
