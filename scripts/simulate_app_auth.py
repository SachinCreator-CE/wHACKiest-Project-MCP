#!/usr/bin/env python3
"""Write simulated app-auth traffic (INC-002 brute force on priya + benign arjun) to CloudWatch Logs.

Records come from ``sentinel.datasets.app_auth_simulation_records(now)``, are
tagged ``simulated: true`` and go to log group AUTH_LOG_GROUP
(``/sentinelai/app-auth``), stream ``simulated-app-traffic-<UTC date>``.
"""
from __future__ import annotations

import argparse
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts._common import (  # noqa: E402
    AWS_ERRORS,
    Out,
    app_profile,
    describe_error,
    init_settings,
    use_profile,
)
from sentinel.aws.session import AwsSessionFactory  # noqa: E402
from sentinel.config import Settings  # noqa: E402
from sentinel.models import utcnow  # noqa: E402

LOG_RETENTION_DAYS = 7
SOURCE = "simulated-app-traffic"


def stream_name(now: datetime) -> str:
    return f"{SOURCE}-{now:%Y-%m-%d}"


def build_records(now: datetime) -> list[dict[str, Any]]:
    """Simulation records, each explicitly tagged as simulated traffic."""
    from sentinel.datasets import app_auth_simulation_records

    records = [dict(r) for r in app_auth_simulation_records(now)]
    for r in records:
        r["simulated"] = True
        r["source"] = SOURCE
    return records


def summarize(records: list[dict[str, Any]]) -> list[str]:
    """One line per scenario, e.g. ``INC-002: 21 events (login_failed=18, ...)``."""
    by_scenario: dict[str, Counter[str]] = {}
    for r in records:
        by_scenario.setdefault(str(r.get("scenario", "?")), Counter())[str(r.get("event", "?"))] += 1
    return [
        f"{scenario}: {sum(c.values())} events ({', '.join(f'{k}={v}' for k, v in sorted(c.items()))})"
        for scenario, c in sorted(by_scenario.items())
    ]


def run(settings: Settings, aws: Any, *, now: datetime | None = None, dry_run: bool = False) -> dict[str, Any]:
    """Create the log group (7-day retention) and write the records unless ``dry_run``."""
    now = now or utcnow()
    records = build_records(now)
    result: dict[str, Any] = {
        "log_group": settings.auth_log_group,
        "stream": stream_name(now),
        "records": len(records),
        "written": 0,
        "summary": summarize(records),
    }
    if dry_run:
        return result
    from sentinel.aws.cloudwatch import ensure_log_group, put_auth_events

    ensure_log_group(aws, settings.auth_log_group, retention_days=LOG_RETENTION_DAYS)
    result["written"] = put_auth_events(aws, settings.auth_log_group, result["stream"], records)
    return result


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--profile", default=None, help="app AWS CLI profile (default: AWS_PROFILE or sentinel-app; '' = default chain)")
    p.add_argument("--dry-run", action="store_true", help="print what would be written without calling AWS")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    settings = init_settings()
    use_profile(app_profile(args.profile))
    out = Out()
    out.step("Simulated app-auth traffic → CloudWatch Logs" + (" (dry run)" if args.dry_run else ""))
    try:
        res = run(settings, AwsSessionFactory(settings), dry_run=args.dry_run)
    except AWS_ERRORS as exc:
        out.fail(describe_error(exc))
        return 1
    except ImportError as exc:
        out.fail(f"SentinelAI module unavailable: {exc}")
        return 1
    for line in res["summary"]:
        out.info(line)
    target = f"{res['log_group']} / {res['stream']}"
    if args.dry_run:
        out.ok(f"would write {res['records']} events to {target}")
    else:
        out.ok(f"wrote {res['written']} events to {target}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
