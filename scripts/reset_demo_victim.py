#!/usr/bin/env python3
"""Reactivate the demo victim's leaked access key after a demo run.

Uses the app identity (profile ``sentinel-app``) to call iam:UpdateAccessKey
Status=Active on DEMO_LEAKED_ACCESS_KEY_ID. Refuses any user that is not in
REAL_ACTION_USER_ALLOWLIST.

It also moves the app's local store (``<SENTINEL_VAR_DIR>/sentinel.db``) aside, because a
rehearsed approval is remembered there: without this, INC-001 stays "mitigated" and the
"Deactivate leaked access key" action is never proposed again. Stop the app first.
``--keep-local`` skips that step and ``--local-only`` skips AWS (e.g. after an offline rehearsal).
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts._common import (  # noqa: E402
    AWS_ERRORS,
    Out,
    app_profile,
    describe_error,
    init_settings,
    mask_key,
    use_profile,
)
from sentinel.aws.session import AwsSessionFactory  # noqa: E402


class ResetRefused(RuntimeError):
    """The requested reset is outside the guard rails."""


def check_allowed(user: str, allowlist: list[str], key_id: str) -> None:
    if user not in allowlist:
        raise ResetRefused(f"user {user!r} is not in REAL_ACTION_USER_ALLOWLIST {allowlist}")
    if not key_id:
        raise ResetRefused("DEMO_LEAKED_ACCESS_KEY_ID is not set in .env")


def key_status(iam: Any, user: str, key_id: str) -> str | None:
    """Current status of ``key_id`` on ``user`` (None when the key is not on that user)."""
    for page in iam.get_paginator("list_access_keys").paginate(UserName=user):
        for meta in page.get("AccessKeyMetadata", []):
            if meta.get("AccessKeyId") == key_id:
                return str(meta.get("Status"))
    return None


def set_status(aws: Any, iam: Any, user: str, key_id: str, status: str) -> None:
    """Prefer the app's own IAM primitive; fall back to plain boto3 if it is unavailable."""
    try:
        from sentinel.aws.iam_actions import set_access_key_status
    except ImportError:
        iam.update_access_key(UserName=user, AccessKeyId=key_id, Status=status)
        return
    set_access_key_status(aws, user, key_id, status)


def reset(aws: Any, user: str, key_id: str, status: str = "Active") -> tuple[str | None, str | None]:
    """Set the key status and return ``(before, after)``."""
    iam = aws.client("iam")
    before = key_status(iam, user, key_id)
    if before is None:
        raise ResetRefused(f"key {mask_key(key_id)} does not belong to {user}")
    if before != status:
        set_status(aws, iam, user, key_id, status)
    return before, key_status(iam, user, key_id)


def clear_local_store(db_path: Path) -> list[Path]:
    """Move the SQLite store (and its -wal/-shm files) aside to ``*.bak-<ts>``; return the new paths.

    Moving instead of deleting keeps the old audit chain for inspection. Missing files are skipped.
    """
    backup = f"{db_path.name}.bak-{time.strftime('%Y%m%d-%H%M%S')}"
    n = 1
    while any(db_path.with_name(backup + sfx).exists() for sfx in ("", "-wal", "-shm")):  # never overwrite a backup
        n += 1
        backup = f"{backup.split('~')[0]}~{n}"
    moved: list[Path] = []
    for suffix in ("", "-wal", "-shm"):  # keep SQLite's pairing: <backup>-wal belongs to <backup>
        path = db_path.with_name(db_path.name + suffix)
        if path.exists():
            target = db_path.with_name(backup + suffix)
            path.replace(target)
            moved.append(target)
    return moved


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--profile", default=None, help="app AWS CLI profile (default: AWS_PROFILE or sentinel-app; '' = default chain)")
    p.add_argument("--user", default=None, help="IAM user (default: DEMO_VICTIM_USER)")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--keep-local", action="store_true", help="do not move the local store (var/sentinel.db) aside")
    g.add_argument("--local-only", action="store_true", help="only move the local store aside; do not call AWS")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    settings = init_settings()
    out = Out()
    if not args.keep_local:
        out.step(f"Clearing the local store {settings.db_path} (stop the app first)")
        moved = clear_local_store(Path(settings.db_path))
        out.ok(f"moved aside: {', '.join(p.name for p in moved)}" if moved else "already empty")
        if args.local_only:
            return 0
    use_profile(app_profile(args.profile))
    user = args.user or settings.demo_victim_user
    key_id = settings.demo_leaked_access_key_id
    out.step(f"Reactivating {mask_key(key_id)} on {user}")
    try:
        check_allowed(user, settings.real_action_user_allowlist, key_id)
        before, after = reset(AwsSessionFactory(settings), user, key_id)
    except ResetRefused as exc:
        out.fail(f"Refused: {exc}")
        return 2
    except AWS_ERRORS as exc:
        out.fail(describe_error(exc))
        return 1
    out.info(f"before: {before}")
    (out.ok if after == "Active" else out.fail)(f"after:  {after}")
    return 0 if after == "Active" else 1


if __name__ == "__main__":
    sys.exit(main())
