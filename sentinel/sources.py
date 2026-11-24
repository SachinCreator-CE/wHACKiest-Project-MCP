"""Data sources facade used by the engine, the agent tools and the API.

Every read goes through an MCP server when possible and is wrapped in a
``trace.span`` whose ``target`` says honestly where the data came from
(``"aws"`` for real AWS, ``"offline"`` for mock or local data). Each component
falls back on its own and records why in :attr:`DataSources.fallbacks`.

CloudTrail live path, per region::

    AWS Labs CloudTrail MCP  ->  boto3 LookupEvents  ->  mock CloudTrail MCP  ->  local synthetic data

LookupEvents allows 2 requests/s per account and region, so every real call
(MCP or boto3) in a region shares that region's async token bucket, and
throttling errors are retried with exponential backoff. Pagination is bounded,
and a failure after the first page keeps the live pages already fetched.
"""
from __future__ import annotations

import asyncio
import hashlib
import importlib
import json
import logging
import math
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from types import ModuleType
from typing import Any, TypeVar

from . import trace
from .aws.cloudtrail_direct import PAGE_SIZE, lookup_events_page
from .aws.session import AwsSessionFactory, safe_reason
from .config import Settings, leak_flagged_at
from .mcp_hub import AWSLABS_CLOUDTRAIL, MCPHub, rewire_hub
from .models import Event, SecretAlert, iso, parse_ts, utcnow
from .normalize import auth_outcome, cloudtrail_raw_from_record, normalize_alert, normalize_auth, normalize_cloudtrail
from .store import SQLiteStore

log = logging.getLogger(__name__)
T = TypeVar("T")

BACKEND_AWSLABS = "awslabs.cloudtrail-mcp-server"
BACKEND_BOTO3 = "boto3"
BACKEND_MOCK = "mock"
BACKEND_LOCAL = "local-data"  # in-process synthetic data when an MCP server is down
_BACKEND_RANK = {BACKEND_AWSLABS: 0, BACKEND_BOTO3: 1, BACKEND_MOCK: 2, BACKEND_LOCAL: 3}
# Parameters the AWS Labs tool accepts; next_token pages must repeat them exactly.
_LOOKUP_ARGS = ("start_time", "end_time", "attribute_key", "attribute_value", "max_results", "region")
_THROTTLE_CODES = {"ThrottlingException", "Throttling", "TooManyRequestsException", "RequestLimitExceeded"}
_THROTTLE_HINTS = ("throttl", "rate exceeded", "too many requests")
LOOKUP_RATE_PER_S = 2.0  # per account and region
THROTTLE_TRIES = 3
# Page cap beyond ceil(max_events / PAGE_SIZE): sparse attribute lookups can return empty pages that still carry a token.
EXTRA_PAGES = 16


class TokenBucket:
    """Async token bucket. Callers reserve a token and sleep off any debt.

    No lock is needed: the reservation is synchronous, and asyncio runs one
    coroutine at a time, so the bucket also works across event loops.
    """

    def __init__(self, rate: float, capacity: float | None = None, clock: Callable[[], float] = time.monotonic):
        self.rate = rate
        self.capacity = capacity if capacity is not None else rate
        self._clock = clock
        self._tokens = self.capacity
        self._last = clock()

    async def acquire(self) -> None:
        now = self._clock()
        self._tokens = min(self.capacity, self._tokens + (now - self._last) * self.rate) - 1
        self._last = now
        if self._tokens < 0:
            await asyncio.sleep(-self._tokens / self.rate)


def is_throttling(exc: BaseException) -> bool:
    """True for AWS throttling errors, whether from botocore or relayed by an MCP server."""
    response = getattr(exc, "response", None)
    if isinstance(response, dict) and response.get("Error", {}).get("Code") in _THROTTLE_CODES:
        return True
    text = str(exc).lower()
    return any(h in text for h in _THROTTLE_HINTS)


def _datasets() -> ModuleType:
    """The synthetic-data module (resolved lazily, so tests can substitute it)."""
    return importlib.import_module("sentinel.datasets")


def _valid_dataset_name(name: str) -> bool:
    return bool(name) and ".." not in name.replace("\\", "/").split("/") and not name.startswith(("/", "\\")) and ":" not in name


@dataclass
class _RegionResult:
    events: list[Event]
    backend: str
    live: bool
    reason: str | None = None
    partial: str | None = None  # live pages kept after pagination stopped early


class DataSources:
    """One place to read alerts, CloudTrail, auth logs, identities and datasets."""

    def __init__(self, settings: Settings, hub: MCPHub, aws: AwsSessionFactory, store: SQLiteStore):
        self.settings = settings
        self.hub = hub
        self.aws = aws
        self.store = store
        self.fallbacks: dict[str, dict[str, str]] = {}
        self.lookup_buckets: dict[str, TokenBucket] = {}
        self.backoff_base_s = 0.5

    # ------------------------------------------------------------ status
    @property
    def live(self) -> bool:
        return not self.settings.offline_only and self.aws.status().connected

    async def _is_live(self) -> bool:
        # status() may run STS GetCallerIdentity; keep it off the event loop.
        live = await asyncio.to_thread(lambda: self.live)
        await self.sync_hub(live)
        return live

    async def sync_hub(self, live: bool) -> None:
        """AWS came back (or went away) after startup: make the MCP children follow it (CONTRACT: fallback)."""
        if isinstance(self.hub, MCPHub):
            await rewire_hub(self.hub, live)

    def note_fallback(self, component: str, reason: str) -> None:
        self.fallbacks[component] = {"component": component, "reason": reason, "ts": iso()}
        log.info("fallback[%s]: %s", component, reason)

    def _clear_fallback(self, component: str) -> None:
        self.fallbacks.pop(component, None)

    def _not_live_reason(self) -> str:
        return f"AWS not connected: {self.aws.status().reason or 'unknown reason'}"

    def _note_offline(self, component: str) -> None:
        """AWS was expected (mode auto/aws) but isn't connected: record why."""
        if not self.settings.offline_only:
            self.note_fallback(component, self._not_live_reason())

    # ------------------------------------------------------------ GitHub
    async def github_alerts(self, state: str = "open", force_offline: bool = False) -> list[SecretAlert]:
        live = not force_offline and await self._is_live()
        try:
            with trace.span("GitHub MCP", "list_secret_scanning_alerts", target="offline", backend=BACKEND_MOCK) as sp:
                res = await self.hub.call("github", "list_secret_scanning_alerts", {"state": state, "offline": not live})
                raw_alerts = res.get("alerts") or []
                sp.summary = f"{len(raw_alerts)} alerts"
            self._clear_fallback("github")
        except Exception as exc:
            self.note_fallback("github", f"GitHub MCP unavailable ({exc}); using local synthetic alerts")
            raw_alerts = self._local_alerts(state, live)
        return sorted((normalize_alert(a) for a in raw_alerts), key=lambda a: a.number)

    def _local_alerts(self, state: str, live: bool) -> list[dict[str, Any]]:
        with trace.span("GitHub MCP", "list_secret_scanning_alerts", target="offline", backend=BACKEND_LOCAL) as sp:
            now = utcnow()
            live_key = self.settings.demo_leaked_access_key_id if live else ""
            flagged_at = None
            if live_key:
                flagged_at = iso(leak_flagged_at(self.settings, now))
            alerts = _datasets().synthetic_alerts(now=now, live_key=live_key or None, flagged_at=flagged_at)
            if state and state != "all":
                alerts = [a for a in alerts if a.get("state") == state]
            sp.summary = f"{len(alerts)} alerts"
        return alerts

    # --------------------------------------------------------- CloudTrail
    async def cloudtrail_lookup(
        self,
        attribute_key: str,
        attribute_value: str,
        hours_back: int | None = None,
        regions: list[str] | None = None,
        max_events: int = 200,
        force_offline: bool = False,
    ) -> tuple[list[Event], dict[str, Any]]:
        """Look up CloudTrail events across regions; returns ``(events, meta)``."""
        hours = hours_back or self.settings.cloudtrail_lookback_hours
        regions = list(dict.fromkeys(regions or self.settings.cloudtrail_regions))
        end = utcnow()
        start = end - timedelta(hours=hours)
        live = not force_offline and await self._is_live()
        if live:
            jobs = [self._ct_region_live(r, attribute_key, attribute_value, start, end, hours, max_events) for r in regions]
        else:
            reason = "forced offline" if force_offline else self._not_live_reason()
            jobs = [self._ct_region_mock(r, attribute_key, attribute_value, start, end, max_events, reason) for r in regions]
        results = await asyncio.gather(*jobs)

        by_id: dict[str, Event] = {}
        for res in results:
            for ev in res.events:
                by_id.setdefault(ev.id or f"{ev.region}:{ev.ts}:{ev.kind}", ev)
        events = sorted(by_id.values(), key=lambda e: e.ts)[-max_events:]
        distinct = {res.reason for res in results if res.reason}
        if len(distinct) == 1:
            fallback_reason: str | None = distinct.pop()
        else:
            fallback_reason = "; ".join(f"{r}: {res.reason}" for r, res in zip(regions, results) if res.reason) or None
        all_live = all(res.live for res in results)
        meta = {
            "live": all_live,
            "backend": max((res.backend for res in results), key=_BACKEND_RANK.__getitem__),
            "backends": {r: res.backend for r, res in zip(regions, results)},
            "regions": regions,
            "fallback_reason": fallback_reason,
            "partial": {r: res.partial for r, res in zip(regions, results) if res.partial},
            "count": len(events),
        }
        if live and all_live:
            self._clear_fallback("cloudtrail")
        elif force_offline:
            pass  # the caller chose offline data and records its own reason
        elif live or meta["backend"] == BACKEND_LOCAL:
            self.note_fallback("cloudtrail", fallback_reason or "CloudTrail lookup fell back to offline data")
        else:
            self._note_offline("cloudtrail")
        return events, meta

    async def _ct_region_live(
        self, region: str, key: str, value: str, start: datetime, end: datetime, hours: int, max_events: int
    ) -> _RegionResult:
        digest = hashlib.sha256(f"{key}={value}".encode()).hexdigest()[:24]
        cache_key = f"cloudtrail:{region}:{hours}:{max_events}:{digest}"
        cached = self.store.cache_get(cache_key)
        if isinstance(cached, dict):
            with trace.span("CloudTrail MCP", "lookup_events", target="aws", backend=cached["backend"], region=region) as sp:
                sp.summary = f"{len(cached['raw'])} events (cached)"
            return _RegionResult(self._norm_ct(cached["raw"], region, True), cached["backend"], True)

        notes: list[str] = []
        raw: list[dict[str, Any]] | None = None
        partial: str | None = None
        backend = BACKEND_AWSLABS
        if self.hub.is_registered(AWSLABS_CLOUDTRAIL):
            try:
                raw, partial = await self._ct_via_mcp(AWSLABS_CLOUDTRAIL, region, key, value, start, end, max_events, real=True)
            except Exception as exc:
                notes.append(f"AWS Labs CloudTrail MCP failed ({exc})")
        if raw is None:
            backend = BACKEND_BOTO3
            try:
                raw, partial = await self._ct_via_boto3(region, key, value, start, end, max_events)
            except Exception as exc:
                self.aws.mark_failure(exc)
                notes.append(f"boto3 LookupEvents failed ({safe_reason(exc)})")
        if raw is None:
            reason = "; ".join(notes)
            return await self._ct_region_mock(region, key, value, start, end, max_events, reason)
        if notes:
            log.info("CloudTrail %s served by %s: %s", region, backend, "; ".join(notes))
        if partial:
            # Real events from the pages that did succeed: keep them (live), but never cache an incomplete result.
            log.info("CloudTrail %s partial result from %s: %s", region, backend, partial)
        else:
            self.store.cache_set(cache_key, {"raw": raw, "backend": backend}, self.settings.cloudtrail_cache_ttl_s)
        return _RegionResult(self._norm_ct(raw, region, True), backend, True, partial=partial)

    async def _ct_region_mock(
        self, region: str, key: str, value: str, start: datetime, end: datetime, max_events: int, reason: str
    ) -> _RegionResult:
        try:
            raw, _ = await self._ct_via_mcp("cloudtrail_mock", region, key, value, start, end, max_events, real=False)
            return _RegionResult(self._norm_ct(raw, region, False), BACKEND_MOCK, False, reason)
        except Exception as exc:
            reason = f"{reason}; mock CloudTrail MCP failed ({exc})"
        with trace.span("CloudTrail MCP", "lookup_events", target="offline", backend=BACKEND_LOCAL, region=region) as sp:
            raw = self._local_cloudtrail(region, key, value, start, end)[:max_events]
            sp.summary = f"{len(raw)} events"
        return _RegionResult(self._norm_ct(raw, region, False), BACKEND_LOCAL, False, reason)

    @staticmethod
    def _norm_ct(raw: list[dict[str, Any]], region: str, live: bool) -> list[Event]:
        return [normalize_cloudtrail(r, region, live) for r in raw]

    def lookup_bucket(self, region: str) -> TokenBucket:
        """The LookupEvents token bucket for ``region`` (the AWS quota is per account and region)."""
        bucket = self.lookup_buckets.get(region)
        if bucket is None:
            # capacity 1: strict 1/rate spacing, so no 1 s window ever sees more than `rate` calls.
            bucket = self.lookup_buckets[region] = TokenBucket(LOOKUP_RATE_PER_S, capacity=1)
        return bucket

    async def _with_backoff(self, call: Callable[[], Awaitable[T]], bucket: TokenBucket | None) -> T:
        """Run ``call`` (rate limited by ``bucket`` when given) retrying throttling with exponential backoff."""
        for attempt in range(THROTTLE_TRIES):
            if bucket is not None:
                await bucket.acquire()
            try:
                return await call()
            except Exception as exc:
                if attempt == THROTTLE_TRIES - 1 or not is_throttling(exc):
                    raise
                await asyncio.sleep(self.backoff_base_s * 2**attempt)
        raise AssertionError("unreachable")

    async def _paginate(
        self,
        fetch: Callable[[str | None], Awaitable[tuple[list[dict[str, Any]], str | None]]],
        max_events: int,
        sp: Any,
        on_error: Callable[[BaseException], None] | None = None,
    ) -> tuple[list[dict[str, Any]], str | None]:
        """Shared stop conditions for both live paths. Returns ``(events, partial_note)``.

        Stops when the token runs out, ``max_events`` are collected, the page cap is hit or the
        server repeats a token. A failure after at least one good page keeps those pages.
        """
        events: list[dict[str, Any]] = []
        token: str | None = None
        seen: set[str] = set()
        pages = 0
        note: str | None = None
        max_pages = math.ceil(max_events / PAGE_SIZE) + EXTRA_PAGES
        while True:
            try:
                page, next_token = await fetch(token)
            except Exception as exc:
                if not pages:
                    raise
                if on_error is not None:
                    on_error(exc)
                note = f"page {pages + 1} failed ({safe_reason(exc)}); kept {len(events)} events from {pages} pages"
                break
            pages += 1
            events.extend(page)
            if not next_token or len(events) >= max_events:
                break
            if next_token == token or next_token in seen:
                note = f"server repeated a next_token after {pages} pages; stopped paginating"
                break
            if pages >= max_pages:
                note = f"stopped after {pages} pages (page cap); more events may exist"
                break
            seen.add(next_token)
            token = next_token
        sp.summary = f"{min(len(events), max_events)} events" + (f" ({pages} pages)" if pages > 1 else "") + (" (partial)" if note else "")
        return events[:max_events], note

    async def _ct_via_mcp(
        self, server: str, region: str, key: str, value: str, start: datetime, end: datetime, max_events: int, *, real: bool
    ) -> tuple[list[dict[str, Any]], str | None]:
        """Paginate ``lookup_events`` on an AWS Labs-compatible MCP server."""
        args: dict[str, Any] = {
            "start_time": iso(start),
            "end_time": iso(end),
            "attribute_key": key,
            "attribute_value": value,
            "max_results": PAGE_SIZE,
            "region": region,
        }
        backend = BACKEND_AWSLABS if real else BACKEND_MOCK
        bucket = self.lookup_bucket(region) if real else None

        async def fetch(token: str | None) -> tuple[list[dict[str, Any]], str | None]:
            page_args = dict(args)
            if token:
                page_args["next_token"] = token
            res = await self._with_backoff(lambda: self.hub.call(server, "lookup_events", page_args), bucket)
            if res.get("next_token"):
                params = res.get("query_params") or {}
                args.update({k: params[k] for k in _LOOKUP_ARGS if params.get(k) is not None})
            return res.get("events") or [], res.get("next_token")

        with trace.span("CloudTrail MCP", "lookup_events", target="aws" if real else "offline", backend=backend, region=region) as sp:
            start_server = getattr(self.hub, "start", None)
            if real and start_server is not None:
                await start_server(server)  # spawn first, so start-up time doesn't eat rate-limit slots
            return await self._paginate(fetch, max_events, sp)

    async def _ct_via_boto3(
        self, region: str, key: str, value: str, start: datetime, end: datetime, max_events: int
    ) -> tuple[list[dict[str, Any]], str | None]:
        bucket = self.lookup_bucket(region)

        async def fetch(token: str | None) -> tuple[list[dict[str, Any]], str | None]:
            return await self._with_backoff(
                lambda: asyncio.to_thread(lookup_events_page, self.aws, region, key, value, start, end, token), bucket
            )

        with trace.span("CloudTrail MCP", "lookup_events", target="aws", backend=BACKEND_BOTO3, region=region) as sp:
            return await self._paginate(fetch, max_events, sp, on_error=self.aws.mark_failure)

    @staticmethod
    def _local_cloudtrail(region: str, key: str, value: str, start: datetime, end: datetime) -> list[dict[str, Any]]:
        """Mock-server semantics in-process: filter synthetic records by region, window and attribute."""
        out = []
        for rec in _datasets().synthetic_cloudtrail_records(now=utcnow()):
            if rec.get("awsRegion", region) != region or not rec.get("eventTime"):
                continue
            if not start <= parse_ts(rec["eventTime"]) <= end:
                continue
            raw = cloudtrail_raw_from_record(rec)
            if key and not _attr_matches(raw, key, value):
                continue
            out.append(raw)
        return out

    # ------------------------------------------------------------ auth logs
    async def auth_events(
        self, user: str | None = None, hours_back: int | None = None, outcome: str | None = None, force_offline: bool = False
    ) -> tuple[list[Event], dict[str, Any]]:
        """App auth events (CloudWatch Logs when live) as ``(events, meta)``."""
        hours = hours_back or self.settings.cloudtrail_lookback_hours
        end = utcnow()
        start = end - timedelta(hours=hours)
        live = not force_offline and await self._is_live()
        meta: dict[str, Any] = {"live": False, "backend": "offline", "log_group": self.settings.auth_log_group, "fallback_reason": None}
        records: list[dict[str, Any]] | None = None
        if not force_offline:
            args = {"user": user, "start_time": iso(start), "end_time": iso(end), "outcome": outcome, "limit": 500}
            try:
                with trace.span("Identity MCP", "filter_auth_events", target="aws" if live else "offline") as sp:
                    res = await self.hub.call("identity", "filter_auth_events", args)
                    records = list(res.get("events") or [])
                    meta.update(
                        live=bool(res.get("live")),
                        backend=res.get("backend") or "offline",
                        log_group=res.get("log_group") or meta["log_group"],
                        fallback_reason=res.get("fallback_reason"),
                    )
                    sp.target = "aws" if meta["live"] else "offline"
                    sp.backend = meta["backend"]
                    sp.summary = f"{len(records)} events"
            except Exception as exc:
                meta["fallback_reason"] = f"Identity MCP unavailable ({exc})"
        if records is None:
            records = self._local_auth(user, start, end, outcome)
        events = sorted((normalize_auth(r, bool(meta["live"])) for r in records), key=lambda e: e.ts)
        meta["count"] = len(events)
        if live and meta["live"]:
            self._clear_fallback("auth")
        elif not force_offline and (live or meta["fallback_reason"]):
            self.note_fallback("auth", meta["fallback_reason"] or "auth logs served from offline data")
        elif not force_offline:
            self._note_offline("auth")
        return events, meta

    @staticmethod
    def _local_auth(user: str | None, start: datetime, end: datetime, outcome: str | None) -> list[dict[str, Any]]:
        with trace.span("Identity MCP", "filter_auth_events", target="offline", backend=BACKEND_LOCAL) as sp:
            records = [
                r
                for r in _datasets().synthetic_auth_records(now=utcnow())
                if (not user or r.get("user") == user)
                and r.get("ts")
                and start <= parse_ts(r["ts"]) <= end
                and (not outcome or outcome in (r.get("event"), auth_outcome(str(r.get("event")))))
            ]
            sp.summary = f"{len(records)} events"
        return records

    # ------------------------------------------------------------- identity
    async def get_user(self, username: str) -> dict[str, Any] | None:
        try:
            with trace.span("Identity MCP", "get_user", target="offline") as sp:
                user = (await self.hub.call("identity", "get_user", {"username": username})).get("user")
                sp.summary = "1 user" if user else "no user"
            self._clear_fallback("identity")
            return user if isinstance(user, dict) else None
        except Exception as exc:
            self.note_fallback("identity", f"Identity MCP unavailable ({exc}); using local directory")
        with trace.span("Identity MCP", "get_user", target="offline", backend=BACKEND_LOCAL) as sp:
            users = _datasets().load_records("identity/users.json")
            match = next(
                (u for u in users if username in (u.get("username"), u.get("user"), u.get("name"), u.get("login"))), None
            )
            sp.summary = "1 user" if match else "no user"
        return match

    # ------------------------------------------------------------- datasets
    async def list_datasets(self) -> tuple[list[str], dict[str, Any]]:
        res, meta = await self._logs_call("list_datasets", {})
        if res is None:
            names = self._local_dataset_op("list_datasets", lambda ds: ds.list_dataset_names())
        else:
            names = [str(n) for n in res.get("datasets") or []]
        meta["count"] = len(names)
        return names, meta

    async def read_dataset(self, name: str, limit: int = 200, contains: str | None = None) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        if not _valid_dataset_name(name):
            raise ValueError(f"invalid dataset name: {name!r}")
        res, meta = await self._logs_call("read_dataset", {"name": name, "limit": limit, "contains": contains})
        if res is not None and res.get("error"):
            raise ValueError(str(res["error"])[:300])  # unknown dataset: a caller mistake, not an outage
        if res is None:
            def read_local(ds: ModuleType) -> list[dict[str, Any]]:
                try:
                    rows = ds.load_records(name)
                except FileNotFoundError:  # never leak the local data/ path to the model
                    raise ValueError(f"unknown dataset {name!r}; call list_datasets") from None
                if contains:
                    needle = contains.lower()
                    rows = [r for r in rows if needle in json.dumps(r, default=str).lower()]
                return rows[:limit]

            records = self._local_dataset_op("read_dataset", read_local)
        else:
            records = list(res.get("records") or [])
        meta["count"] = len(records)
        return records, meta

    async def _logs_call(self, tool: str, args: dict[str, Any]) -> tuple[dict[str, Any] | None, dict[str, Any]]:
        """Call the Logs MCP; ``(None, meta)`` means the caller must use local data."""
        live = await self._is_live()
        meta: dict[str, Any] = {"live": False, "backend": "offline", "fallback_reason": None}
        try:
            with trace.span("Logs MCP", tool, target="aws" if live else "offline") as sp:
                res = await self.hub.call("logs", tool, args)
                meta.update(live=bool(res.get("live")), backend=res.get("backend") or "offline", fallback_reason=res.get("fallback_reason"))
                sp.target = "aws" if meta["live"] else "offline"
                sp.backend = meta["backend"]
                sp.summary = f"{len(res.get('records') or res.get('datasets') or [])} {'records' if 'records' in res else 'datasets'}"
        except Exception as exc:
            meta["fallback_reason"] = f"Logs MCP unavailable ({exc})"
            res = None
        if live and meta["live"]:
            self._clear_fallback("logs")
        elif live or res is None:
            self.note_fallback("logs", meta["fallback_reason"] or "datasets served from local files")
        else:
            self._note_offline("logs")
        return res, meta

    @staticmethod
    def _local_dataset_op(tool: str, op: Callable[[ModuleType], T]) -> T:
        with trace.span("Logs MCP", tool, target="offline", backend=BACKEND_LOCAL) as sp:
            result = op(_datasets())
            sp.summary = f"{len(result)} {'records' if tool == 'read_dataset' else 'datasets'}"  # type: ignore[arg-type]
        return result


def _attr_matches(raw: dict[str, Any], key: str, value: str) -> bool:
    """LookupEvents attribute semantics on an AWS Labs-shaped event."""
    if key in ("ResourceType", "ResourceName"):
        return any(r.get(key) == value for r in raw.get("Resources") or [])
    return str(raw.get(key, "")).lower() == str(value).lower() if key == "ReadOnly" else raw.get(key) == value
