"""boto3 session factory + AWS connectivity status.

Uses boto3's default credential chain only (AWS_PROFILE=sentinel-app locally,
an instance role on EC2). Never prints or logs credentials; only the last four
digits of the account id are ever surfaced.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any

from ..config import Settings

try:
    import boto3
    from botocore.config import Config
    from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError, ProfileNotFound
except Exception:  # pragma: no cover - boto3 is a hard dependency, but keep import-safe
    boto3 = None  # type: ignore

_RETRY = {"max_attempts": 4, "mode": "adaptive"} if boto3 else None
# Per-service client tuning. bedrock-runtime gets short timeouts and a single retry: a hung model
# call must reach the offline fallback in seconds, not after 5 attempts x 60 s per Converse round.
_CLIENT_CONFIG: dict[str, dict[str, Any]] = {
    "bedrock-runtime": {"retries": {"total_max_attempts": 2, "mode": "standard"}, "connect_timeout": 3, "read_timeout": 25},
    # LookupEvents: no botocore retries. DataSources owns them (per-region token bucket + backoff); botocore's own
    # retries would bypass the bucket and multiply with the app's attempts.
    "cloudtrail": {"retries": {"total_max_attempts": 1, "mode": "standard"}, "connect_timeout": 5, "read_timeout": 60},
    # The connectivity probe (GetCallerIdentity) gates startup and /api/status: on a network that silently drops
    # packets the default 5 s connect x 4 adaptive attempts held the server ~25 s before it bound its port.
    "sts": {"retries": {"total_max_attempts": 2, "mode": "standard"}, "connect_timeout": 2, "read_timeout": 4},
}
_DEFAULT_CONFIG: dict[str, Any] = {"retries": _RETRY, "connect_timeout": 5, "read_timeout": 60}


def client_config(service: str) -> dict[str, Any]:
    """botocore ``Config`` kwargs for ``service``."""
    return dict(_CLIENT_CONFIG.get(service, _DEFAULT_CONFIG))


@dataclass
class AwsStatus:
    connected: bool
    account_suffix: str = ""  # last 4 digits only
    arn_kind: str = ""  # "user/sentinel-app" style, account id stripped
    region: str = ""
    reason: str = ""  # why not connected
    checked_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "connected": self.connected,
            "account_suffix": self.account_suffix,
            "principal": self.arn_kind,
            "region": self.region,
            "reason": self.reason,
        }

    @property
    def label(self) -> str:
        if self.connected:
            return f"AWS: connected (account …{self.account_suffix}, {self.region})"
        return "Offline fallback"


class AwsSessionFactory:
    """Thread-safe cache of boto3 clients keyed by (service, region)."""

    def __init__(self, settings: Settings):
        self.settings = settings
        self._lock = threading.Lock()
        self._session = None
        self._clients: dict[tuple[str, str], Any] = {}
        self._status: AwsStatus | None = None
        self._probe_lock = threading.Lock()  # single-flight STS probe

    def session(self):
        if boto3 is None:
            raise RuntimeError("boto3 not installed")
        with self._lock:
            if self._session is None:
                self._session = boto3.Session(region_name=self.settings.aws_region)
            return self._session

    def client(self, service: str, region: str | None = None):
        region = region or self.settings.aws_region
        key = (service, region)
        with self._lock:
            if key in self._clients:
                return self._clients[key]
        c = self.session().client(service, region_name=region, config=Config(**client_config(service)))
        with self._lock:
            self._clients[key] = c
        return c

    def status(self, refresh: bool = False, max_age_s: float = 300) -> AwsStatus:
        """STS GetCallerIdentity, cached. Offline mode never calls AWS.

        Single-flight: while one caller probes STS, other callers get the previous (stale) status instead of
        starting a probe of their own; only a caller with no status at all waits for the probe to finish.
        """
        if self.settings.offline_only:
            return AwsStatus(False, region=self.settings.aws_region, reason="SENTINEL_MODE=offline")
        if self._status and not refresh and time.time() - self._status.checked_at < max_age_s:
            return self._status
        if not self._probe_lock.acquire(blocking=self._status is None):
            return self._status  # type: ignore[return-value]  # another thread is probing; serve the stale value
        try:
            if self._status and not refresh and time.time() - self._status.checked_at < max_age_s:
                return self._status  # refreshed by the thread we waited for
            try:
                ident = self.client("sts").get_caller_identity()
                acct = str(ident.get("Account", ""))
                arn = str(ident.get("Arn", ""))
                kind = arn.split(":", 5)[-1] if arn.count(":") >= 5 else ""
                st = AwsStatus(True, account_suffix=acct[-4:], arn_kind=kind, region=self.settings.aws_region)
            except Exception as exc:  # NoCredentialsError, ProfileNotFound, ClientError, network
                st = AwsStatus(False, region=self.settings.aws_region, reason=_safe_reason(exc))
                if _is_credentials_error(exc):
                    self._reset_credentials()
            self._status = st
            return st
        finally:
            self._probe_lock.release()

    def _reset_credentials(self) -> None:
        """Drop the cached session and clients so the next call re-resolves the credential chain.

        boto3 resolves credentials (and parses ~/.aws/config) when a client is created; without this, credentials
        or a profile added after an offline start would never be seen until a restart.
        """
        with self._lock:
            self._session = None
            self._clients.clear()

    def mark_failure(self, exc: BaseException) -> None:
        """Called when an AWS call fails with a credentials problem so the header flips."""
        if _is_credentials_error(exc):
            self._status = AwsStatus(False, region=self.settings.aws_region, reason=_safe_reason(exc))
            self._reset_credentials()


def _is_credentials_error(exc: BaseException) -> bool:
    if boto3 is None:
        return True
    if isinstance(exc, (NoCredentialsError, ProfileNotFound)):
        return True
    if isinstance(exc, ClientError):
        code = exc.response.get("Error", {}).get("Code", "")
        return code in {"ExpiredToken", "ExpiredTokenException", "InvalidClientTokenId", "UnrecognizedClientException", "SignatureDoesNotMatch"}
    return False


def _safe_reason(exc: BaseException) -> str:
    """Short, credential-free description of an AWS error."""
    if boto3 is not None:
        if isinstance(exc, NoCredentialsError):
            return "No AWS credentials found (set AWS_PROFILE=sentinel-app)"
        if isinstance(exc, ProfileNotFound):
            profile = exc.kwargs.get("profile", "?") if hasattr(exc, "kwargs") else ""
            if isinstance(profile, str) and not profile.strip():
                return "AWS_PROFILE is set but empty; remove the line to use the default credential chain"
            return f"AWS profile not found: {profile}".strip()
        if isinstance(exc, ClientError):
            err = exc.response.get("Error", {})
            return f"{err.get('Code', 'ClientError')}: {str(err.get('Message', ''))[:160]}"
        if isinstance(exc, BotoCoreError):
            return f"{type(exc).__name__}: {str(exc)[:160]}"
    return f"{type(exc).__name__}: {str(exc)[:160]}"


safe_reason = _safe_reason
is_credentials_error = _is_credentials_error
