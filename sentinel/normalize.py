"""Normalise raw source records into the shared :mod:`sentinel.models` types.

* CloudTrail: AWS Labs ``lookup_events`` events (the raw boto3 ``LookupEvents``
  shape with ``CloudTrailEvent`` as a JSON string) -> :class:`Event`.
* App auth log records (CloudWatch Logs / offline JSONL) -> :class:`Event`.
* GitHub secret-scanning alerts -> :class:`SecretAlert`.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from .models import Event, SecretAlert, iso

# errorCode values that mean "the caller was not allowed", not "the call broke".
_DENIED_CODES = {"UnauthorizedOperation", "Client.UnauthorizedOperation", "AuthFailure"}
_AUTH_FAILURE_EVENTS = {"login_failed", "mfa_failed"}
# Detail fields worth keeping on Event.raw (the full record can be several KB).
_RAW_KEEP = (
    "eventID", "eventTime", "eventSource", "eventName", "awsRegion", "sourceIPAddress", "userAgent",
    "errorCode", "errorMessage", "readOnly", "eventType", "recipientAccountId",
)
_MAX_PARAMS_CHARS = 1000
# Attacker-controlled text (file paths, user agents, login reasons...) must stay one line: a
# newline could forge a bullet, heading or table row in chat answers and reports.
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f\u0085\u2028\u2029]+")
MAX_FIELD_CHARS = 300


def clean_field(value: Any, max_len: int = MAX_FIELD_CHARS) -> str:
    """One-line, length-capped string: control characters become a single space."""
    text = _CONTROL_RE.sub(" ", str(value if value is not None else "")).strip()
    return text if len(text) <= max_len else text[: max_len - 1] + "…"


def _clean_strings(d: dict[str, Any]) -> dict[str, Any]:
    """Shallow copy of ``d`` with every top-level string value passed through :func:`clean_field`."""
    return {k: clean_field(v, _MAX_PARAMS_CHARS) if isinstance(v, str) else v for k, v in d.items()}


def cloudtrail_outcome(error_code: str) -> str:
    """Map a CloudTrail ``errorCode`` to ``denied`` / ``failure`` / ``success``."""
    if not error_code:
        return "success"
    if error_code.startswith("AccessDenied") or error_code in _DENIED_CODES or "Unauthorized" in error_code:
        return "denied"
    return "failure"


def _detail(raw: dict[str, Any]) -> dict[str, Any]:
    """Parse ``CloudTrailEvent`` (JSON string or already-parsed dict); ``{}`` if unusable."""
    detail = raw.get("CloudTrailEvent")
    if isinstance(detail, dict):
        return detail
    if isinstance(detail, str) and detail:
        try:
            parsed = json.loads(detail)
        except ValueError:
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def _small(value: Any) -> Any:
    """Keep request parameters only when they serialise to something short."""
    if value is None:
        return None
    text = json.dumps(value, default=str)
    return value if len(text) <= _MAX_PARAMS_CHARS else {"truncated": text[:_MAX_PARAMS_CHARS]}


def _target_hint(params: Any) -> str:
    """Short object name for the summary, e.g. the policy in AttachUserPolicy."""
    if not isinstance(params, dict):
        return ""
    for key in ("policyArn", "policyName", "bucketName", "roleName", "userName", "groupName"):
        val = params.get(key)
        if isinstance(val, str) and val:
            return val.rsplit("/", 1)[-1]
    return ""


def normalize_cloudtrail(raw: dict[str, Any], region: str, live: bool) -> Event:
    """Convert one AWS Labs-shaped CloudTrail event into an :class:`Event`."""
    detail = _detail(raw)
    ident = detail.get("userIdentity") if isinstance(detail.get("userIdentity"), dict) else {}
    name = clean_field(raw.get("EventName") or detail.get("eventName") or "Unknown", 120)
    source = clean_field(raw.get("EventSource") or detail.get("eventSource") or "", 120)
    error_code = clean_field(detail.get("errorCode") or "", 120)
    actor = clean_field(ident.get("userName") or raw.get("Username") or str(ident.get("arn", "")).rsplit("/", 1)[-1], 200)
    params = detail.get("requestParameters")
    hint = clean_field(_target_hint(params), 200)
    service = source.split(".", 1)[0] if source else "aws"
    summary = f"{service}:{name}{f' ({hint})' if hint else ''} → {error_code or 'success'}"
    ts_value = raw.get("EventTime") or detail.get("eventTime")
    small_raw = _clean_strings({k: detail[k] for k in _RAW_KEEP if k in detail})
    if ident:
        small_raw["userIdentity"] = {k: ident[k] for k in ("type", "userName", "arn", "accessKeyId") if k in ident}
    if params is not None:
        small_raw["requestParameters"] = _small(params)
    return Event(
        id=str(raw.get("EventId") or detail.get("eventID") or ""),
        ts=iso(ts_value) if ts_value else iso(),
        source="cloudtrail",
        kind=name,
        actor=actor,
        ip=clean_field(detail.get("sourceIPAddress") or "", 200),
        outcome=cloudtrail_outcome(error_code),
        region=clean_field(detail.get("awsRegion") or region, 40),
        summary=summary,
        access_key_id=str(raw.get("AccessKeyId") or ident.get("accessKeyId") or ""),
        error_code=error_code,
        live=live,
        raw=small_raw,
    )


def cloudtrail_raw_from_record(rec: dict[str, Any]) -> dict[str, Any]:
    """Wrap a CloudTrail record (the inner detail JSON) in the AWS Labs event shape."""
    ident = rec.get("userIdentity") if isinstance(rec.get("userIdentity"), dict) else {}
    resources = [
        {"ResourceType": r.get("type", ""), "ResourceName": r.get("ARN") or r.get("name", "")}
        for r in rec.get("resources") or []
        if isinstance(r, dict)
    ]
    return {
        "EventId": rec.get("eventID", ""),
        "EventName": rec.get("eventName", ""),
        "ReadOnly": str(rec.get("readOnly", "false")).lower(),
        "AccessKeyId": ident.get("accessKeyId", ""),
        "EventTime": rec.get("eventTime", ""),
        "EventSource": rec.get("eventSource", ""),
        "Username": ident.get("userName", ""),
        "Resources": resources,
        "CloudTrailEvent": json.dumps(rec),
    }


def auth_outcome(event_name: str) -> str:
    """``failure`` for failed logins / MFA, ``success`` otherwise."""
    return "failure" if event_name in _AUTH_FAILURE_EVENTS else "success"


def normalize_auth(rec: dict[str, Any], live: bool) -> Event:
    """Convert one app-auth log record into an :class:`Event` (id = SHA-1 of the record)."""
    digest = hashlib.sha1(json.dumps(rec, sort_keys=True, default=str).encode()).hexdigest()
    kind = clean_field(rec.get("event") or "unknown", 60)
    user = clean_field(rec.get("user") or "", 120)
    ip = clean_field(rec.get("ip") or "", 120)
    geo = clean_field(rec.get("geo") or "", 120)
    where = f" from {ip}" if ip else ""
    summary = f"{kind} for {user}{where}" + (f" ({geo})" if geo else "")
    if rec.get("reason"):
        summary += f": {clean_field(rec['reason'])}"
    return Event(
        id=digest,
        ts=iso(rec["ts"]) if rec.get("ts") else iso(),
        source="app-auth",
        kind=kind,
        actor=user,
        ip=ip,
        outcome=auth_outcome(kind),
        summary=summary,
        live=live,
        simulated=bool(rec.get("simulated", False)),
        tags=[clean_field(rec["scenario"], 60)] if rec.get("scenario") else [],
        raw=_clean_strings(dict(rec)),
    )


def _login(v: Any) -> str:
    if isinstance(v, dict):
        return clean_field(v.get("login") or v.get("name") or "", 120)
    return clean_field(v or "", 120)


def normalize_alert(d: dict[str, Any]) -> SecretAlert:
    """Convert a (GitHub API-like) secret-scanning alert dict into a :class:`SecretAlert`."""
    repo = d.get("repository")
    repository = clean_field(repo.get("full_name") or repo.get("name") or "" if isinstance(repo, dict) else repo or "", 200)
    location = d.get("location") if isinstance(d.get("location"), dict) else {}
    loc_details = location.get("details") if isinstance(location.get("details"), dict) else {}
    return SecretAlert(
        number=int(d.get("number") or 0),
        state=clean_field(d.get("state") or "open", 40),
        secret_type=clean_field(d.get("secret_type") or "aws_access_key_id", 80),
        access_key_id=clean_field(d.get("access_key_id") or d.get("secret") or "", 128),
        repository=repository,
        path=clean_field(d.get("path") or loc_details.get("path") or ""),
        commit_sha=clean_field(d.get("commit_sha") or loc_details.get("commit_sha") or "", 80),
        created_at=iso(d["created_at"]) if d.get("created_at") else iso(),
        html_url=clean_field(d.get("html_url") or ""),
        pusher=_login(d.get("pusher") or d.get("push_protection_bypassed_by")),
        live=bool(d.get("live", False)),
    )
