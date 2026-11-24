"""Tool-call tracing shown in the UI ("CloudTrail MCP → lookup_events → 7 events in 820 ms").

Usage::

    with trace.collect() as entries:          # start a collection scope
        with trace.span("CloudTrail MCP", "lookup_events", target="aws",
                        backend="awslabs.cloudtrail-mcp-server", region="us-east-1") as sp:
            result = ...
            sp.summary = f"{len(events)} events"
    # entries is a list[TraceEntry]

``span`` records timing and marks ``ok=False`` + ``error`` when the block raises
(the exception is re-raised). Spans outside a ``collect()`` scope go to a
process-wide ring buffer (``recent()``) so background detection is visible too.
"""
from __future__ import annotations

import contextvars
import time
from collections import deque
from contextlib import contextmanager
from typing import Iterator

from .models import TraceEntry

_current: contextvars.ContextVar[list[TraceEntry] | None] = contextvars.ContextVar("sentinel_trace", default=None)
_recent: deque[TraceEntry] = deque(maxlen=200)


@contextmanager
def collect() -> Iterator[list[TraceEntry]]:
    entries: list[TraceEntry] = []
    token = _current.set(entries)
    try:
        yield entries
    finally:
        _current.reset(token)


def record(entry: TraceEntry) -> None:
    _recent.append(entry)
    cur = _current.get()
    if cur is not None:
        cur.append(entry)


@contextmanager
def span(server: str, tool: str, target: str = "local", backend: str = "", region: str = "") -> Iterator[TraceEntry]:
    entry = TraceEntry(server=server, tool=tool, target=target, backend=backend, region=region)
    t0 = time.perf_counter()
    try:
        yield entry
    except BaseException as exc:  # noqa: BLE001 - recorded then re-raised
        entry.ok = False
        entry.error = (entry.error or f"{type(exc).__name__}: {exc}")[:300]
        raise
    finally:
        entry.ms = int((time.perf_counter() - t0) * 1000)
        record(entry)


def recent(limit: int = 50) -> list[TraceEntry]:
    return list(_recent)[-limit:]


def fmt(e: TraceEntry) -> str:
    """Human string, e.g. 'CloudTrail MCP → lookup_events → 7 events in 820 ms'."""
    tail = e.summary if e.ok else f"error: {e.error}"
    return f"{e.server} → {e.tool} → {tail} in {e.ms} ms"
