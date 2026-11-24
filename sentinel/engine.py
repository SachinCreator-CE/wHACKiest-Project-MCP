"""Deterministic detection rules.

Pure functions over normalised :class:`Event` objects: no I/O, no clock reads
(``now`` is always passed in). Evidence strings are short sentences that the UI
shows and the voice agent reads aloud, so access key IDs in titles, summaries
and evidence are masked (``AKIA…WXYZ``). ``entities`` keep the full key because
remediation needs it; masking happens at the API edge.

Rules:

* ``R-LEAKED-KEY``: a GitHub secret-scanning alert joined to CloudTrail on the
  access key ID. Any use after the alert's ``created_at`` is suspicious.
* ``R-BRUTE-FORCE``: at least ``threshold`` failed logins for one app user in a
  sliding window of ``window_minutes``.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import Any, Iterable

from .masking import mask_access_key
from .models import Event, Incident, SecretAlert, iso, parse_ts

RULE_LEAKED_KEY = "R-LEAKED-KEY"
RULE_BRUTE_FORCE = "R-BRUTE-FORCE"

ESCALATION_EVENTS = {
    "CreateAccessKey", "AttachUserPolicy", "PutUserPolicy", "CreateUser", "AttachRolePolicy", "PutRolePolicy",
    "CreateLoginProfile", "UpdateLoginProfile", "AddUserToGroup", "AttachGroupPolicy", "CreatePolicyVersion",
    "UpdateAssumeRolePolicy", "PassRole",
}
RECON_EVENTS = {
    "GetCallerIdentity", "ListBuckets", "ListAttachedUserPolicies", "ListUserPolicies", "GetUser", "ListUsers",
    "ListRoles", "ListAccessKeys", "GetAccountAuthorizationDetails", "DescribeInstances",
}
_POLICY_ATTACH_EVENTS = {"AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy"}
ADMIN_POLICY = "AdministratorAccess"

LEAKED_KEY_ACTIONS = ["deactivate_access_key", "resolve_github_alert", "notify_owner"]
BRUTE_FORCE_ACTIONS = ["force_password_reset", "block_ip", "revoke_sessions"]

# Auth event kinds that show a login was stopped after the password was guessed -> spoken label.
_TAKEOVER_STOPPED = {
    "mfa_failed": "The MFA challenge failed",
    "blocked": "The login was blocked",
    "login_blocked": "The login was blocked",
    "account_locked": "The account was locked",
}


@dataclass
class DetectionResult:
    incidents: list[Incident] = field(default_factory=list)
    suppressed: list[dict[str, str]] = field(default_factory=list)  # {"rule","entity","reason"}

    def to_dict(self) -> dict[str, Any]:
        return {"incidents": [i.to_dict() for i in self.incidents], "suppressed": list(self.suppressed)}


# ------------------------------------------------------------------ helpers
def _ts(e: Event) -> datetime:
    return parse_ts(e.ts)


def _clock(ts: str | datetime) -> str:
    """'14:05 UTC' - short enough to read aloud."""
    return parse_ts(ts).strftime("%H:%M UTC")


def _stamp(ts: str | datetime) -> str:
    """'20 Nov 2026, 11:30 UTC'."""
    return parse_ts(ts).strftime("%d %b %Y, %H:%M UTC")


def _duration(seconds: float) -> str:
    if seconds < 60:
        return f"{max(int(seconds), 1)} s"
    return f"{round(seconds / 60)} min"


def _plural(n: int, word: str, plural: str | None = None) -> str:
    return f"{n} {word if n == 1 else (plural or word + 's')}"


def _join(items: Iterable[str]) -> str:
    return ", ".join(items)


def _sort_events(events: Iterable[Event]) -> list[Event]:
    # GitHub alert first on ties, then by id, so the order is fully deterministic.
    return sorted(events, key=lambda e: (_ts(e), e.source != "github", e.id))


def _tagged(e: Event, *tags: str) -> Event:
    """Copy of ``e`` with extra tags (inputs are never mutated)."""
    return replace(e, tags=list(dict.fromkeys([*e.tags, *tags])))


def _data_mode(events: list[Event]) -> str:
    live = sum(1 for e in events if e.live)
    if live == 0:
        return "synthetic"
    return "live" if live == len(events) else "mixed"


# ---------------------------------------------------------- R-LEAKED-KEY
def _api_name(e: Event) -> str:
    """'iam:AttachUserPolicy' from the CloudTrail eventSource, else the bare event name."""
    source = str(e.raw.get("eventSource") or "")
    return f"{source.split('.')[0]}:{e.kind}" if source else e.kind


def _request_params(e: Event) -> dict[str, Any]:
    params = e.raw.get("requestParameters")
    return params if isinstance(params, dict) else {}


def _policy_name(e: Event) -> str:
    """Policy name from requestParameters.policyArn, falling back to the summary text."""
    arn = str(_request_params(e).get("policyArn") or "")
    if arn:
        return arn.rsplit("/", 1)[-1]
    return ADMIN_POLICY if ADMIN_POLICY in e.summary else ""


def _is_admin_attach(e: Event) -> bool:
    return e.kind in _POLICY_ATTACH_EVENTS and _policy_name(e) == ADMIN_POLICY


def _describe_call(e: Event) -> str:
    """'iam:AttachUserPolicy (AdministratorAccess on bob)'."""
    name = _api_name(e)
    params = _request_params(e)
    policy = _policy_name(e) if e.kind in _POLICY_ATTACH_EVENTS else ""
    target = str(params.get("userName") or params.get("roleName") or params.get("groupName") or "")
    detail = " on ".join(x for x in (policy, target) if x)
    return f"{name} ({detail})" if detail else name


def _outcome_phrase(events: list[Event]) -> str:
    denied = sum(1 for e in events if e.outcome == "denied")
    if denied == len(events):
        return "all denied by IAM"
    if denied == 0:
        return "none denied"
    return f"{denied} denied by IAM"


def _alert_event(alert: SecretAlert, masked_key: str) -> Event:
    return Event(
        id=f"github-alert-{alert.number}",
        ts=iso(alert.created_at),
        source="github",
        kind="secret_scanning_alert",
        actor=alert.pusher or alert.repository,
        outcome="info",
        summary=f"Secret scanning alert #{alert.number}: AWS access key {masked_key} committed to "
        f"{alert.repository}/{alert.path}",
        access_key_id=alert.access_key_id,
        live=alert.live,
        tags=["exposure"],
        raw={"number": alert.number, "repository": alert.repository, "path": alert.path,
             "commit_sha": alert.commit_sha, "html_url": alert.html_url, "state": alert.state},
    )


def detect_leaked_key(
    alert: SecretAlert,
    events: list[Event],
    *,
    flagged_at: datetime,
    data_mode: str,
    now: datetime,
    incident_id: str = "INC-001",
) -> Incident | None:
    """R-LEAKED-KEY for one alert. Returns None when the key has no CloudTrail usage at all.

    No IP reputation is used: in the live demo the calls come from the presenter's laptop.
    """
    key = alert.access_key_id
    key_events = [e for e in events if e.access_key_id == key]
    if not key_events:
        return None
    masked = mask_access_key(key)
    flagged_at = parse_ts(flagged_at)

    post = _sort_events(e for e in key_events if _ts(e) > flagged_at)
    pre_count = len(key_events) - len(post)
    escalations = [e for e in post if e.kind in ESCALATION_EVENTS]
    recon = [e for e in post if e.kind in RECON_EVENTS]
    admin = [e for e in escalations if _is_admin_attach(e)]
    escalated_ok = [e for e in escalations if e.outcome == "success"]
    denied = [e for e in post if e.outcome == "denied"]
    scope = post or key_events  # what the IP/region/user facts describe
    ips = sorted({e.ip for e in scope if e.ip})
    regions = sorted({e.region for e in scope if e.region})
    actors = Counter(e.actor for e in scope if e.actor)
    iam_user = actors.most_common(1)[0][0] if actors else ""

    evidence = [
        f"GitHub secret scanning alert #{alert.number} flagged {masked} in {alert.repository}, "
        f"file {alert.path}, on {_stamp(alert.created_at)}."
    ]
    if post:
        evidence.append(
            f"The key was used {_plural(len(post), 'time')} after it was flagged, "
            f"from {_clock(post[0].ts)} to {_clock(post[-1].ts)}."
        )
        if denied:
            codes = ", ".join(dict.fromkeys(e.error_code or "AccessDenied" for e in denied))
            # IAM policy evaluation denies them all, but the error code differs by service (EC2 says UnauthorizedOperation).
            evidence.append(f"IAM denied {len(denied)} of those {_plural(len(post), 'call')} ({codes}).")
        if escalations:
            evidence.append(
                f"{_plural(len(escalations), 'privilege-escalation attempt')}: "
                f"{_join(_describe_call(e) for e in escalations)}; {_outcome_phrase(escalations)}."
            )
        if admin:
            target = _request_params(admin[0]).get("userName") or iam_user or "itself"
            verdict = "IAM denied it" if all(e.outcome == "denied" for e in admin) else "it SUCCEEDED"
            evidence.append(f"The caller tried to attach {ADMIN_POLICY} to {target}; {verdict}.")
        if escalated_ok:
            evidence.append(
                f"Warning: {_plural(len(escalated_ok), 'escalation call')} succeeded: "
                f"{_join(_describe_call(e) for e in escalated_ok)}."
            )
        if recon:
            evidence.append(
                f"{_plural(len(recon), 'reconnaissance call')}: {_join(dict.fromkeys(_api_name(e) for e in recon))}."
            )
    else:
        evidence.append(f"The key was used {_plural(pre_count, 'time')} before the alert and not since.")
    if ips or regions:
        evidence.append(
            f"Calls came from {_plural(len(ips), 'IP address', 'IP addresses')} ({_join(ips) or 'unknown'}) "
            f"in {_plural(len(regions), 'region')} ({_join(regions) or 'unknown'})."
        )
    evidence.append(
        "CloudTrail events are live from AWS; the GitHub alert is synthetic."
        if data_mode == "live"
        else "Synthetic demo data: offline GitHub alert and mock CloudTrail events."
    )

    if post:
        severity = "critical"
        title = f"Leaked AWS access key {masked} used after GitHub exposure"
        summary = (
            f"GitHub flagged {masked} in {alert.repository}. Since then it was used {_plural(len(post), 'time')} "
            f"as {iam_user or 'an unknown principal'}: {_plural(len(escalations), 'privilege-escalation attempt')} "
            f"and {_plural(len(recon), 'reconnaissance call')}; IAM denied {len(denied)} of the {len(post)}."
        )
    else:
        severity = "medium"
        title = f"Exposed AWS access key {masked} active before GitHub alert"
        summary = f"GitHub flagged {masked} in {alert.repository}; it was used before the alert but not since."

    timeline = [_alert_event(alert, masked)]
    for e in key_events:
        tags = ["post_flag"] if _ts(e) > flagged_at else []
        if e.kind in ESCALATION_EVENTS:
            tags.append("escalation")
        if e.kind in RECON_EVENTS:
            tags.append("recon")
        if _is_admin_attach(e):
            tags.append("admin_attach")
        timeline.append(_tagged(e, *tags))

    stamp = iso(now)
    return Incident(
        id=incident_id,
        title=title,
        severity=severity,
        status="open",
        summary=summary,
        created_at=stamp,
        updated_at=stamp,
        rule_ids=[RULE_LEAKED_KEY],
        entities={
            "access_key_id": key,
            "iam_user": iam_user,
            "repository": alert.repository,
            "file_path": alert.path,
            "alert_number": alert.number,
            "source_ips": ips,
            "regions": regions,
        },
        events=_sort_events(timeline),
        evidence=evidence,
        recommended_actions=list(LEAKED_KEY_ACTIONS),
        data_mode=data_mode,
        counts={
            "post_flag_uses": len(post),
            "pre_flag_uses": pre_count,
            "denied": len(denied),
            "escalation_attempts": len(escalations),
            "admin_attach_attempts": len(admin),
            "escalations_succeeded": len(escalated_ok),
            "recon_calls": len(recon),
            "distinct_ips": len(ips),
            "regions": len(regions),
        },
    )


# ---------------------------------------------------------- R-BRUTE-FORCE
def _densest_window(failures: list[Event], window_s: float) -> tuple[int, int]:
    """Indices [start, end) of the sliding window holding the most failures.

    The latest window wins ties, so after a rehearsal the burst just simulated on stage is the one reported.
    """
    best = (0, 0)
    start = 0
    for end, e in enumerate(failures):
        while (_ts(e) - _ts(failures[start])).total_seconds() > window_s:
            start += 1
        if end + 1 - start >= best[1] - best[0]:
            best = (start, end + 1)
    return best


def _stopped_after(success: Event, later: list[Event]) -> Event | None:
    """First MFA failure / block for the same session (same IP when known) after a success."""
    for e in later:
        if e.kind in _TAKEOVER_STOPPED and _ts(e) >= _ts(success) and (not e.ip or e.ip == success.ip):
            return e
    return None


def _suppressed_reason(user: str, events: list[Event], best: int, threshold: int, window_minutes: int) -> str:
    reason = (
        f"{_plural(best, 'failed login')} for {user} within {window_minutes} min "
        f"(threshold {threshold}); below the brute-force threshold."
    )
    last_fail = max(_ts(e) for e in events if e.kind == "login_failed")
    after = [e for e in events if _ts(e) >= last_fail]
    success = next((e for e in after if e.kind == "login_success"), None)
    if success:
        mfa_ok = any(e.kind == "mfa_success" for e in after)
        reason += (
            f" Followed by a successful login{' and MFA' if mfa_ok else ''} from {success.ip or 'an unknown IP'}"
            f"{' (' + str(success.raw.get('geo')) + ')' if success.raw.get('geo') else ''}: consistent with a typo."
        )
    return reason


def _bruteforce_incident(
    user: str, events: list[Event], failures: list[Event], window: tuple[int, int],
    *, threshold: int, window_minutes: int, now: datetime,
) -> Incident:
    burst = failures[window[0]:window[1]]
    start, end = _ts(burst[0]), _ts(burst[-1])
    ip_counts = Counter(e.ip for e in burst if e.ip)
    attacker_ips = [ip for ip, _ in sorted(ip_counts.items(), key=lambda kv: (-kv[1], kv[0]))]
    later = [e for e in events if _ts(e) >= start]
    successes = [e for e in later if e.kind == "login_success" and e.ip in ip_counts]
    stops = {s.id: _stopped_after(s, later) for s in successes}
    unstopped = [s for s in successes if stops[s.id] is None]
    geos = sorted({str(e.raw["geo"]) for e in burst if e.raw.get("geo")})
    span_text = _duration((end - start).total_seconds())

    evidence = [
        f"{len(burst)} failed logins for {user} in {span_text} from {_join(attacker_ips) or 'unknown IPs'}"
        f"{' (' + _join(geos) + ')' if geos else ''}; threshold is {threshold} in {window_minutes} min."
    ]
    for s in successes:
        evidence.append(f"The attacker then logged in successfully from {s.ip} at {_clock(s.ts)}: the password was guessed.")
        stop = stops[s.id]
        if stop:
            evidence.append(f"{_TAKEOVER_STOPPED[stop.kind]} at {_clock(stop.ts)}, so the account takeover was blocked.")
        else:
            evidence.append("No MFA failure or block followed: treat the account as compromised.")
    if not successes:
        evidence.append(f"No successful login from {_join(attacker_ips) or 'the attacking IPs'} was seen.")
    live = any(e.live for e in later)
    evidence.append(
        "Auth events read live from CloudWatch Logs (simulated app traffic)."
        if live
        else "Auth events from the offline synthetic dataset."
    )

    severity = "critical" if unstopped else "high"
    outcome = "account compromised" if unstopped else ("MFA blocked takeover" if successes else "no successful login")
    timeline = [
        _tagged(e, "burst") if e.kind == "login_failed" and start <= _ts(e) <= end else e
        for e in later
    ]
    stamp = iso(now)
    return Incident(
        id="",
        title=f"Brute-force attack on app user {user}: {len(burst)} failed logins in {span_text}",
        severity=severity,
        status="open",
        summary=(
            f"{len(burst)} failed logins for {user} from {_join(attacker_ips) or 'unknown IPs'} in {span_text}, "
            f"then {_plural(len(successes), 'successful login')} ({outcome})."
        ),
        created_at=stamp,
        updated_at=stamp,
        rule_ids=[RULE_BRUTE_FORCE],
        entities={"app_user": user, "attacker_ips": attacker_ips, "attacker_geo": geos},
        events=_sort_events(timeline),
        evidence=evidence,
        recommended_actions=list(BRUTE_FORCE_ACTIONS),
        data_mode=_data_mode(later),
        counts={
            "failed_logins": len(burst),
            "total_failed_logins": len(failures),
            "attacker_successes": len(successes),
            "takeovers_blocked": len(successes) - len(unstopped),
            "distinct_ips": len(attacker_ips),
        },
    )


def detect_bruteforce(
    auth_events: list[Event], *, threshold: int = 10, window_minutes: int = 10, now: datetime
) -> tuple[list[Incident], list[dict[str, str]]]:
    """R-BRUTE-FORCE per app user (matched case- and whitespace-insensitively). Incidents are sorted by user and have ``id == ""``
    (``detect`` numbers them). Users with failures below threshold are suppressed with a reason."""
    # Group case- and whitespace-insensitively ("Alice", "alice ", "alice" are one account), so alternating
    # the spelling cannot split an attack below threshold. Display the most common spelling (ties: sorted first).
    by_user: dict[str, list[Event]] = {}
    for e in auth_events:
        canon = (e.actor or "").strip().casefold()
        if canon:
            by_user.setdefault(canon, []).append(e)

    incidents: list[Incident] = []
    suppressed: list[dict[str, str]] = []
    for canon in sorted(by_user):
        spellings = Counter((e.actor or "").strip() for e in by_user[canon])
        user = min(spellings, key=lambda name: (-spellings[name], name))
        events = _sort_events(by_user[canon])
        failures = [e for e in events if e.kind == "login_failed"]
        if not failures:
            continue
        window = _densest_window(failures, window_minutes * 60)
        best = window[1] - window[0]
        if best >= threshold:
            incidents.append(_bruteforce_incident(
                user, events, failures, window, threshold=threshold, window_minutes=window_minutes, now=now,
            ))
        else:
            suppressed.append({
                "rule": RULE_BRUTE_FORCE,
                "entity": user,
                "reason": _suppressed_reason(user, events, best, threshold, window_minutes),
            })
    return incidents, suppressed


# ---------------------------------------------------------------- detect
def detect(
    alerts: list[SecretAlert],
    events_by_key: dict[str, list[Event]],
    auth_events: list[Event],
    *,
    now: datetime,
    data_modes: dict[str, str] | None = None,
) -> DetectionResult:
    """Run every rule. IDs: leaked-key incidents first (alert order), then brute force (by user).

    ``data_modes`` maps access key ID -> "live"|"synthetic" (default "synthetic").
    """
    data_modes = data_modes or {}
    result = DetectionResult()
    seen_keys: set[str] = set()
    for alert in alerts:
        key = alert.access_key_id
        masked = mask_access_key(key)
        if alert.state != "open":
            result.suppressed.append({"rule": RULE_LEAKED_KEY, "entity": masked,
                                      "reason": f"Alert #{alert.number} for {masked} is {alert.state}; skipped."})
            continue
        if key in seen_keys:
            continue
        seen_keys.add(key)
        inc = detect_leaked_key(
            alert, events_by_key.get(key, []), flagged_at=parse_ts(alert.created_at),
            data_mode=data_modes.get(key, "synthetic"), now=now,
            incident_id=f"INC-{len(result.incidents) + 1:03d}",
        )
        if inc is None:
            result.suppressed.append({"rule": RULE_LEAKED_KEY, "entity": masked,
                                      "reason": f"Alert #{alert.number} open, key {masked} unused in window."})
        else:
            result.incidents.append(inc)

    brute, suppressed = detect_bruteforce(auth_events, now=now)
    for inc in brute:
        inc.id = f"INC-{len(result.incidents) + 1:03d}"
        result.incidents.append(inc)
    result.suppressed.extend(suppressed)
    return result
