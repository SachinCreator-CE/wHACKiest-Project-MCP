"""Deterministic 0-100 risk score for an incident, with the factors that add up to it.

Pure: reads only the incident's counts, entities, rule ids, data mode and status (and events for a fallback),
never the clock, the network or randomness. ``score = clamp(sum(points), 0, 100)``.
"""
from __future__ import annotations

from typing import Any

from .models import Incident

CRITICAL_AT, HIGH_AT, MEDIUM_AT = 80, 60, 35

METHOD = (
    "Risk is the sum of weighted evidence factors (what the attacker did, whether it worked, and any approved "
    "mitigation), capped to 0-100: 80+ critical, 60+ high, 35+ medium, otherwise low."
)


def risk_label(score: int) -> str:
    if score >= CRITICAL_AT:
        return "CRITICAL"
    if score >= HIGH_AT:
        return "HIGH"
    if score >= MEDIUM_AT:
        return "MEDIUM"
    return "LOW"


def _n(counts: dict[str, Any], key: str) -> int:
    try:
        return max(0, int(counts.get(key, 0) or 0))
    except (TypeError, ValueError):
        return 0


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def _leaked_key_factors(c: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    post, pre = _n(c, "post_flag_uses"), _n(c, "pre_flag_uses")
    if post:
        out.append({"label": "Key used after GitHub exposure", "points": 35,
                    "detail": f"{_plural(post, 'call')} with the leaked key after GitHub flagged it."})
    else:
        out.append({"label": "Key exposed on GitHub", "points": 20,
                    "detail": "A live access key was committed to a repository."})
        if pre:
            out.append({"label": "Key used before the alert", "points": 15,
                        "detail": f"{_plural(pre, 'call')} before GitHub flagged it, none since."})
    ok = min(_n(c, "escalations_succeeded"), _n(c, "escalation_attempts"))
    denied_esc = max(0, _n(c, "escalation_attempts") - ok)
    if denied_esc:
        out.append({"label": "Denied privilege-escalation attempts", "points": min(20, 10 * denied_esc),
                    "detail": f"{_plural(denied_esc, 'attempt')} blocked by IAM (+10 each, capped at 20)."})
    if _n(c, "admin_attach_attempts"):
        out.append({"label": "AdministratorAccess attach attempt", "points": 15,
                    "detail": "The key tried to attach AdministratorAccess."})
    recon = _n(c, "recon_calls")
    if recon:
        out.append({"label": "Reconnaissance calls", "points": min(9, 3 * recon),
                    "detail": f"{_plural(recon, 'discovery call')} (+3 each, capped at 9)."})
    if _n(c, "regions") > 1:
        out.append({"label": "Multiple regions", "points": 5,
                    "detail": f"Activity spread across {_n(c, 'regions')} regions."})
    if _n(c, "escalations_succeeded"):
        out.append({"label": "Privilege escalation succeeded", "points": 25,
                    "detail": f"{_plural(_n(c, 'escalations_succeeded'), 'escalation call')} succeeded."})
    return out


def _brute_force_factors(c: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    failed = _n(c, "failed_logins")
    out.append({"label": "Failed logins over threshold", "points": min(55, 3 * failed),
                "detail": f"{_plural(failed, 'failed login')} in the burst (+3 each, capped at 55)."})
    succ, blocked = _n(c, "attacker_successes"), _n(c, "takeovers_blocked")
    if succ:
        out.append({"label": "Attacker login succeeded", "points": 20,
                    "detail": "The password was guessed: the attacker got past the first factor."})
        if blocked:
            out.append({"label": "MFA blocked the takeover", "points": -15,
                        "detail": "A second-factor failure or block stopped the session."})
        if blocked < succ:
            out.append({"label": "Takeover not stopped", "points": 20,
                        "detail": "No MFA failure or block followed a successful attacker login."})
    ips = _n(c, "distinct_ips")
    if ips:
        out.append({"label": "Attacker IP addresses", "points": min(9, 3 * ips),
                    "detail": f"{_plural(ips, 'source IP address', )} (+3 each, capped at 9)."})
    return out


def compute_risk(incident: Incident) -> dict[str, Any]:
    c = incident.counts or {}
    rules = set(incident.rule_ids or [])
    factors: list[dict[str, Any]] = []
    if "R-LEAKED-KEY" in rules:
        factors += _leaked_key_factors(c)
    if "R-BRUTE-FORCE" in rules:
        factors += _brute_force_factors(c)
    if not factors:
        base = {"critical": 80, "high": 60, "medium": 35, "low": 10}.get(str(incident.severity).lower(), 0)
        factors.append({"label": "Rule severity", "points": base,
                        "detail": f"No scoring model for this rule; using its {incident.severity} severity."})
    if str(incident.status).lower() in ("mitigated", "resolved"):
        factors.append({"label": "Mitigated by approved action", "points": -30,
                        "detail": "A human-approved action addressed this incident."})
    score = max(0, min(100, sum(f["points"] for f in factors)))
    return {"score": score, "label": risk_label(score), "factors": factors, "method": METHOD}
