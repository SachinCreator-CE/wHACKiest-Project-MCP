"""``python -m sentinel``: serve the SentinelAI console (default http://127.0.0.1:8000)."""
from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path
from typing import IO

import uvicorn

from .api import create_app
from .config import load_settings


def _env_port(default: int = 8000) -> int:
    raw = (os.environ.get("SENTINEL_PORT") or "").strip()
    try:
        port = int(raw) if raw else default
    except ValueError:
        port = 0
    if not 0 < port < 65536:
        print(f"SENTINEL_PORT={raw!r} is not a valid port; using {default}", file=sys.stderr)
        return default
    return port


def acquire_instance_lock(var_dir: Path) -> IO[str] | None:
    """Hold an exclusive lock on ``<var_dir>/sentinel.lock`` for the life of the process.

    Two servers on one var dir would both run detection against the same store (duplicate proposals);
    the second exits before its startup runs. Returns the open lock file (keep a reference), or None
    when another process holds the lock. Without ``fcntl`` (Windows) no lock is taken.
    """
    try:
        import fcntl
    except ImportError:  # pragma: no cover - non-POSIX
        return open(os.devnull, "w")
    var_dir.mkdir(parents=True, exist_ok=True)
    fh = open(var_dir / "sentinel.lock", "w")
    try:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        fh.close()
        return None
    fh.write(str(os.getpid()))
    fh.flush()
    return fh


def main(argv: list[str] | None = None) -> None:
    settings = load_settings()  # loads .env first, so SENTINEL_HOST/PORT/LOG_LEVEL may live there
    parser = argparse.ArgumentParser(prog="python -m sentinel", description="Run the SentinelAI SOC console.")
    parser.add_argument("--host", default=(os.environ.get("SENTINEL_HOST") or "").strip() or "127.0.0.1")
    parser.add_argument("--port", type=int, default=_env_port())
    parser.add_argument("--log-level", default=(os.environ.get("SENTINEL_LOG_LEVEL") or "").strip() or "info")
    args = parser.parse_args(argv)
    if args.log_level.lower() not in {"critical", "error", "warning", "info", "debug"}:
        print(f"log level {args.log_level!r} is not valid; using info", file=sys.stderr)
        args.log_level = "info"

    logging.basicConfig(level=args.log_level.upper(), format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    settings = load_settings()  # again, so config warnings (bad ints, regions, mode) are logged
    lock = acquire_instance_lock(Path(settings.var_dir))
    if lock is None:
        print(f"Another SentinelAI server is already using {settings.var_dir} (lock: sentinel.lock). "
              "Stop it, or set SENTINEL_VAR_DIR to a different directory.", file=sys.stderr)
        raise SystemExit(1)
    print(f"SentinelAI on http://{args.host}:{args.port}  (mode={settings.mode}, region={settings.aws_region})")
    uvicorn.run(create_app(settings), host=args.host, port=args.port, log_level=args.log_level.lower())
    lock.close()

if __name__ == "__main__":
    main()
