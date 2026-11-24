"""Deterministic offline copilot, used when Bedrock is unavailable.

Keyword intent routing picks a playbook; each playbook calls the same
:func:`run_tool` functions as the Bedrock agent (so the trace stays honest) and
composes a grounded, templated answer from the masked tool results.

Routing order: audit log, ACT-id questions, real-action questions, then the
target incident is resolved (explicit INC id > a strong topic word such as
"priya" or "leaked" > the incident selected in the UI > a weak topic word such
as "key" > the conversation history) before the intent playbooks run.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from ..models import parse_ts
from .prompts import to_speech
from .tools import AgentContext, run_tool

_INC_RE = re.compile(r"\binc[-\s]?0*(\d{1,4})\b", re.I)
_ACT_RE = re.compile(r"\bact[-\s]?0*(\d{1,5})\b", re.I)
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
# Strong topic words outrank the incident selected in the UI; weak ones only apply without a selection.
_TOPICS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("benign", re.compile(r"\b(arjun|new laptop)")),
    ("brute", re.compile(r"\b(priya|brute|log ?ins?\b|password|mfa)")),
    ("leaked", re.compile(r"\b(leak|github|cloudtrail|access keys?\b|akia|secret|deactivat|rotat)")),
)
_WEAK_TOPICS: tuple[tuple[str, re.Pattern[str]], ...] = (("leaked", re.compile(r"\bkeys?\b")),)
_TOPIC_RULES = {"leaked": "R-LEAKED-KEY", "brute": "R-BRUTE-FORCE"}
_AUDIT_WORDS = ("audit", "hash chain", "who approved", "tamper")
_REMEDIATE_RE = re.compile(
    r"\b(fix|remediat|deactivat|contain|mitigat|next steps?|recommend|respond|block|rotat|reset|revok|disabl|notify"
    r"|what should|what (?:do|can) (?:we|i) do|what to do|should (?:we|i)|how do (?:we|i)|what now)"
)
_STATUS_RE = re.compile(r"^\W*(was|were|did|has|have|had|is|are)\b")
_ACTION_VERB_RE = re.compile(r"\b(deactivat|block|reset|revok|disabl|rotat|notif|resolv|contain|mitigat|fix|remediat)")
_APPROVE_RE = re.compile(r"\b(approve|execute|go ahead|run (?:it|the action))\b")
_REAL_ACTIONS_RE = re.compile(r"(allow_real_actions|real actions?|for real|really (?:run|deactivat|execut|change))")
_FALSE_POSITIVE_RE = re.compile(r"\b(false positive|benign|suppress|legit)")
_PROVENANCE_RE = re.compile(r"\b(live|synthetic|simulated|real data|fake|mock|provenance)\b")
_REGION_RE = re.compile(r"\bregions?\b")
_DENIED_RE = re.compile(r"\b(denied|deny|denies|accessdenied)\b")
_IP_RE = re.compile(r"\b(ips?|ip address(?:es)?|where .*\bfrom|geo|location)\b")
# Specific remediation requests, mapped to ACTION_CATALOG types.
_ACTION_HINTS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("revoke_sessions", re.compile(r"\bsessions?\b")),
    ("deactivate_access_key", re.compile(r"\b(deactivat|disabl\w* (?:the |that )?(?:access )?key|rotat|revok\w* (?:the |that )?(?:access )?key)")),
    ("block_ip", re.compile(r"\bblock")),
    ("force_password_reset", re.compile(r"\b(reset|password)")),
    ("resolve_github_alert", re.compile(r"\b(resolve|close)\b.*\balert")),
    ("notify_owner", re.compile(r"\bnotif")),
)
_DONE = {"executed", "simulated"}
_HELP = (
    "I can explain an incident, say whether it is a false positive, list its IPs, regions or denied calls, "
    "say which data is live and which is synthetic, show the audit log, check an action's status, or propose the next step."
)
_REAL_ACTION_NOTE = (
    "If approved, SentinelAI calls iam:UpdateAccessKey for real only when real actions are enabled, the IAM user "
    "is allowlisted and the incident uses live AWS data; otherwise the action is simulated and the result says why."
)


@dataclass
class Reply:
    """Spoken-friendly headline sentences plus optional bullet details for the chat panel."""

    sentences: list[str]
    details: list[str] = field(default_factory=list)
    proposed: list[str] = field(default_factory=list)

    def render(self, voice: bool) -> str:
        head = " ".join(s for s in self.sentences if s)
        if voice:
            return to_speech(head)
        # One line per bullet: data-derived text must never start a new bullet or section.
        details = [" ".join(str(d).split()) for d in self.details]
        return head + ("\n\n" + "\n".join(f"- {d}" for d in details) if details else "")


@dataclass
class OfflineAnswer:
    text: str
    proposed_actions: list[str]


def _when(ts: str | None) -> str:
    if not ts:
        return "an unknown time"
    try:
        return parse_ts(ts).strftime("%b %d %H:%M UTC")
    except ValueError:
        return ts


def _kinds(by_kind: dict[str, int]) -> str:
    return ", ".join(f"{k} ×{n}" if n > 1 else k for k, n in by_kind.items())


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def _distinct(events: list[dict], key: str) -> list[str]:
    return sorted({str(e[key]) for e in events if e.get(key)})


def _match(text: str, topics: tuple[tuple[str, re.Pattern[str]], ...]) -> str | None:
    for topic, pattern in topics:
        if pattern.search(text):
            return topic
    return None


def _requested_type(text: str) -> str | None:
    return _match(text, _ACTION_HINTS)


def _is_cloudtrail(e: dict) -> bool:
    return e.get("kind") != "secret_scanning_alert"


def _cloudtrail_view(timeline: dict[str, Any]) -> dict[str, Any]:
    """The CloudTrail part of a leaked-key timeline (drops the GitHub alert event)."""
    by_kind = {k: n for k, n in timeline.get("by_kind", {}).items() if k != "secret_scanning_alert"}
    events = [e for e in timeline.get("events", []) if _is_cloudtrail(e)]
    count = sum(by_kind.values())
    truncated = len(events) < count
    return {
        "count": count,
        "by_kind": by_kind,
        "events": events,
        "first_seen": events[0]["ts"] if events else None,
        "last_seen": (timeline.get("last_seen") if truncated else events[-1]["ts"]) if events else None,
        "denied": sum(1 for e in events if e.get("outcome") == "denied") if not truncated
        else timeline.get("by_outcome", {}).get("denied", 0),
    }


def _action_state(a: dict[str, Any]) -> str:
    by = f", decided by {a['decided_by']}" if a.get("decided_by") else ""
    if a["status"] == "simulated":
        return f"ran as a simulation{by}, so no real change was made"
    if a["status"] == "executed":
        return f"was executed for real{by}" + (f": {a['result']}" if a.get("result") else "")
    if a["status"] == "rejected":
        return f"was rejected{by}"
    if a["status"] == "superseded":
        return "was superseded: it targeted an earlier version of this incident and can no longer be approved"
    if a["status"] == "failed":
        return f"failed{by}" + (f": {a['result']}" if a.get("result") else "")
    return "is proposed and awaiting human approval in the SentinelAI Actions panel"


class OfflineAgent:
    """Rule-based answers built from real tool results."""

    def __init__(self, ctx: AgentContext):
        self.ctx = ctx

    async def answer(
        self, question: str, incident_id: str | None = None, voice: bool = False, history: list[dict] | None = None
    ) -> OfflineAnswer:
        reply = await self._route(question.lower(), incident_id, history)
        return OfflineAnswer(reply.render(voice), reply.proposed)

    async def _route(self, text: str, incident_id: str | None, history: list[dict] | None) -> Reply:
        if any(w in text for w in _AUDIT_WORDS):
            return await self._audit()
        act = _ACT_RE.search(text)
        if act:
            return await self._action_status(f"ACT-{int(act.group(1)):04d}", bool(_APPROVE_RE.search(text)))
        if _REAL_ACTIONS_RE.search(text):
            return self._real_actions()
        incidents = (await run_tool("list_incidents", {}, self.ctx)).get("incidents", [])
        topic = _match(text, _TOPICS)
        explicit = _INC_RE.search(text)
        if topic == "benign" and not explicit:
            return await self._benign("arjun")
        target = self._target(text, topic, incident_id, incidents, history)
        if _APPROVE_RE.search(text):
            return await self._cannot_approve(target, incidents)
        requested = _requested_type(text)
        if not target and (_REMEDIATE_RE.search(text) or _STATUS_RE.search(text) and _ACTION_VERB_RE.search(text)):
            # "block the attacker IP" with nothing selected means the incident that recommends blocking.
            target = self._incident_for(requested, incidents) or self._top_open(incidents)
        if _STATUS_RE.search(text) and _ACTION_VERB_RE.search(text):
            return await self._incident_action_status(target, requested)
        if _REMEDIATE_RE.search(text):
            return await self._remediate(target, requested)
        if _FALSE_POSITIVE_RE.search(text):
            return await self._false_positive(target) if target else await self._benign("arjun")
        if _PROVENANCE_RE.search(text):
            return self._provenance(incidents)
        if _REGION_RE.search(text):
            return await self._facts(target, incidents, "regions")
        if _DENIED_RE.search(text):
            return await self._facts(target, incidents, "denied")
        if _IP_RE.search(text):
            return await self._facts(target, incidents, "ips")
        if target:
            return await self._explain(target)
        if topic == "leaked":
            return await self._alerts_only()
        if topic == "brute":
            return await self._auth_only("priya")
        return self._overview(incidents)

    # ------------------------------------------------------------- routing
    @staticmethod
    def _topic_incident(topic: str | None, incidents: list[dict]) -> str | None:
        rule = _TOPIC_RULES.get(topic or "")
        for inc in incidents if rule else []:
            if rule in inc.get("rule_ids", []):
                return inc["id"]
        return None

    @classmethod
    def _target(
        cls, text: str, topic: str | None, incident_id: str | None, incidents: list[dict], history: list[dict] | None
    ) -> str | None:
        m = _INC_RE.search(text)
        if m:
            return f"INC-{int(m.group(1)):03d}"
        strong = cls._topic_incident(topic, incidents)
        if strong:
            return strong
        ids = {i["id"] for i in incidents}
        if incident_id and incident_id.upper() in ids:
            return incident_id.upper()
        weak = cls._topic_incident(_match(text, _WEAK_TOPICS), incidents)
        return weak or cls._history_target(history, incidents)

    @classmethod
    def _history_target(cls, history: list[dict] | None, incidents: list[dict]) -> str | None:
        """The incident the most recent turn was about (one INC id or one strong topic), if any."""
        ids = {i["id"] for i in incidents}
        for turn in reversed((history or [])[-6:]):
            content = turn.get("content") or turn.get("text") or "" if isinstance(turn, dict) else ""
            text = str(content).lower()
            named = {f"INC-{int(n):03d}" for n in _INC_RE.findall(text)} & ids
            if len(named) == 1:
                return named.pop()
            topics = {t for t, p in _TOPICS if p.search(text)} & set(_TOPIC_RULES)
            if len(topics) == 1 and not named:
                found = cls._topic_incident(topics.pop(), incidents)
                if found:
                    return found
        return None

    @classmethod
    def _incident_for(cls, action_type: str | None, incidents: list[dict]) -> str | None:
        """The highest-ranked incident that recommends ``action_type``, if any."""
        matching = [i for i in incidents if action_type and action_type in i.get("recommended_actions", [])]
        return cls._top_open(matching)

    @staticmethod
    def _top_open(incidents: list[dict]) -> str | None:
        open_incs = [i for i in incidents if i.get("status") == "open"] or incidents
        ranked = sorted(open_incs, key=lambda i: (_SEVERITY_RANK.get(i.get("severity", ""), 9), i["id"]))
        return ranked[0]["id"] if ranked else None

    async def _detail(self, incident_id: str) -> dict[str, Any]:
        return await run_tool("get_incident", {"incident_id": incident_id}, self.ctx)

    # ----------------------------------------------------------- playbooks
    def _overview(self, incidents: list[dict]) -> Reply:
        if not incidents:
            return Reply(["SentinelAI has no incidents right now. Run detection to scan GitHub alerts, CloudTrail and app logins."])
        pending = sum(i.get("pending_actions", 0) for i in incidents)
        listing = "; ".join(f"{i['id']} ({i['severity']}, {i['status']}): {i['title']}" for i in incidents)
        return Reply(
            [
                f"SentinelAI is tracking {_plural(len(incidents), 'incident')}: {listing}.",
                f"{_plural(pending, 'proposed action')} {'awaits' if pending == 1 else 'await'} human approval." if pending else "",
                _HELP,
            ],
            [f"{i['id']} data: {i.get('provenance', 'unknown provenance')}" for i in incidents],
        )

    async def _explain(self, incident_id: str) -> Reply:
        detail = await self._detail(incident_id)
        if "error" in detail:
            return Reply([f"I could not load {incident_id}: {detail['error']}."])
        inc = detail["incident"]
        if "R-LEAKED-KEY" in inc.get("rule_ids", []):
            return await self._explain_leaked(detail)
        if "R-BRUTE-FORCE" in inc.get("rule_ids", []):
            return await self._explain_brute(detail)
        return Reply(
            [f"{inc['id']} is {inc['severity']} and {inc['status']}: {inc['title']}. {inc.get('summary', '')}",
             f"Data: {detail['provenance']}."],
            inc.get("evidence", [])[:5],
        )

    async def _explain_leaked(self, detail: dict[str, Any]) -> Reply:
        inc = detail["incident"]
        ents, counts = inc.get("entities", {}), inc.get("counts", {})
        ct = _cloudtrail_view(detail["timeline"])
        key = ents.get("access_key_id", "")
        provenance, fresh_note = detail["provenance"], ""
        if key:
            fresh = await run_tool(
                "lookup_cloudtrail_events", {"attribute_key": "AccessKeyId", "attribute_value": key}, self.ctx
            )
            if "error" not in fresh:
                provenance = f"{fresh['provenance']}; the GitHub alert is synthetic"
                n = fresh.get("count", 0)
                fresh_note = (
                    f"A fresh CloudTrail lookup confirms {_plural(n, 'event')} for this key."
                    if n == ct["count"]
                    else f"A fresh CloudTrail lookup now returns {_plural(n, 'event')} for this key."
                )
        actors, ips = _distinct(ct["events"], "actor"), _distinct(ct["events"], "ip")
        regions = ents.get("regions") or _distinct(ct["events"], "region")
        sentences = [
            f"{inc['id']} is {inc['severity']} and {inc['status']}: GitHub secret scanning flagged access key {key} "
            f"in {ents.get('repository', 'a repository')}"
            + (f" (alert #{ents['alert_number']})" if ents.get("alert_number") else "") + ".",
        ]
        if ct["count"]:
            sentences.append(
                f"CloudTrail shows {_plural(ct['count'], 'call')} with that key"
                + (f" by {', '.join(actors)}" if actors else "")
                + (f" from {', '.join(ips)}" if ips else "")
                + (f" in {', '.join(regions)}" if regions else "")
                + f" between {_when(ct['first_seen'])} and {_when(ct['last_seen'])}: {_kinds(ct['by_kind'])}."
            )
        else:
            sentences.append("CloudTrail shows no calls with that key yet.")
        if ct["denied"]:
            sentences.append(f"{ct['denied']} of them were denied by IAM.")
        if counts.get("escalation_attempts"):
            sentences.append(
                f"That includes {_plural(counts['escalation_attempts'], 'privilege-escalation attempt')}, "
                "so treat the key as compromised."
            )
        sentences += [fresh_note, f"Data: {provenance}."]
        return Reply(sentences, inc.get("evidence", [])[:5] + self._action_lines(detail))

    async def _explain_brute(self, detail: dict[str, Any]) -> Reply:
        inc, timeline = detail["incident"], detail["timeline"]
        ents = inc.get("entities", {})
        user = ents.get("app_user", "the user")
        provenance = detail["provenance"]
        fresh = await run_tool("get_auth_events", {"user": user}, self.ctx)
        if "error" not in fresh:
            provenance = fresh["provenance"]
        kinds = timeline.get("by_kind", {})
        failed, success, mfa_failed = kinds.get("login_failed", 0), kinds.get("login_success", 0), kinds.get("mfa_failed", 0)
        ips = ents.get("attacker_ips") or _distinct(
            [e for e in timeline.get("events", []) if e.get("kind") == "login_failed"], "ip"
        )
        sentences = [
            f"{inc['id']} is {inc['severity']} and {inc['status']}: {failed} failed logins for {user}"
            + (f" from {', '.join(ips)}" if ips else "")
            + f" between {_when(timeline.get('first_seen'))} and {_when(timeline.get('last_seen'))}."
        ]
        if success and mfa_failed:
            sentences.append("The attacker then got the password right, but the MFA challenge failed, so MFA blocked the takeover.")
        elif success:
            sentences.append("A successful login followed the failures, so assume the account is compromised.")
        sentences.append(f"Data: {provenance}.")
        return Reply(sentences, inc.get("evidence", [])[:5] + self._action_lines(detail))

    async def _remediate(self, incident_id: str | None, requested: str | None = None) -> Reply:
        """Propose the next recommended step that has no decided action yet; never re-propose a decided one."""
        if not incident_id:
            return Reply(["There are no open incidents, so there is nothing to remediate right now."])
        detail = await self._detail(incident_id)
        if "error" in detail:
            return Reply([f"I could not load {incident_id}: {detail['error']}."])
        inc = detail["incident"]
        recommended = inc.get("recommended_actions", [])
        latest = {a["type"]: a for a in detail.get("actions", [])}  # ordered by id, so the latest wins
        sentences: list[str] = []
        if requested and requested not in recommended:
            sentences.append(f"{requested.replace('_', ' ').capitalize()} is not a recommended step for {inc['id']}.")
            requested = None
        if not recommended:
            return Reply(sentences + [f"{inc['id']} has no recommended remediation. Keep monitoring it."])
        if requested and latest.get(requested, {}).get("status") in _DONE | {"rejected"}:
            a = latest[requested]
            pending = [p for p in detail.get("actions", []) if p["status"] == "proposed"]
            sentences.append(f"{a['id']} {a['title']} has already been decided: it {_action_state(a)}. "
                             "I will not propose it again.")
            sentences.append(
                f"{inc['id']} is {inc['status']}."
                + (f" Still awaiting human approval: {', '.join(p['id'] + ' ' + p['title'] for p in pending)}." if pending else "")
            )
            return Reply(sentences, self._action_lines(detail))
        decided = [latest[t] for t in recommended if latest.get(t, {}).get("status") in _DONE | {"rejected"}]
        choice = requested or next((t for t in recommended if latest.get(t) not in decided), None)
        for a in decided:
            sentences.append(f"{a['id']} {a['title']} has already been decided: it {_action_state(a)}.")
        if choice is None:
            sentences.append(f"Every recommended step for {inc['id']} has been decided, so there is nothing left to propose; "
                             f"{inc['id']} is {inc['status']}.")
            return Reply(sentences, self._action_lines(detail))
        before = latest.get(choice)
        proposal = await run_tool(
            "propose_remediation",
            {"incident_id": inc["id"], "action_type": choice,
             "reason": f"Contain {inc['id']} ({inc['severity']}): {inc['title']}"},
            self.ctx,
        )
        proposed: list[str] = []
        if "error" in proposal:
            sentences.append(f"I could not propose {choice} for {inc['id']}: {proposal['error']}.")
        else:
            act = proposal["action"]
            proposed.append(act["id"])
            already = before is not None and before["id"] == act["id"]
            sentences.append(
                f"For {inc['id']} the {'step you asked for' if requested else 'next step' if decided else 'first step'} is: "
                f"{act['title']}. "
                + (f"It is already proposed as {act['id']}." if already else f"I proposed it as {act['id']}, status {act['status']}.")
            )
            sentences.append(f"{act['id']} has not run: a human must approve it in the SentinelAI Actions panel.")
        if choice == "deactivate_access_key":
            sentences.append(_REAL_ACTION_NOTE)
        others = [t for t in recommended if t != choice and latest.get(t) not in decided]
        details = [f"Also recommended: {', '.join(others)}"] if others else []
        return Reply(sentences, details + self._action_lines(detail), proposed)

    async def _incident_action_status(self, incident_id: str | None, requested: str | None) -> Reply:
        """Answer 'was the key deactivated?' style questions from the action history, without side effects."""
        if not incident_id:
            return Reply(["There are no incidents, so no actions have been proposed or run."])
        detail = await self._detail(incident_id)
        if "error" in detail:
            return Reply([f"I could not load {incident_id}: {detail['error']}."])
        inc, actions = detail["incident"], detail.get("actions", [])
        if requested:
            matching = [a for a in actions if a["type"] == requested]
            if not matching:
                what = requested.replace("_", " ")
                return Reply([f"No: there is no {what} action for {inc['id']}. {inc['id']} is {inc['status']}."],
                             self._action_lines(detail))
            a = matching[-1]
            verdict = "Yes" if a["status"] in _DONE else "No"
            return Reply([f"{verdict}: {a['id']} {a['title']} {_action_state(a)}.", f"{inc['id']} is {inc['status']}."],
                         self._action_lines(detail))
        if not actions:
            return Reply([f"No actions have been proposed for {inc['id']} yet. {inc['id']} is {inc['status']}."])
        return Reply([f"{inc['id']} is {inc['status']}. Its actions: "
                      + "; ".join(f"{a['id']} {a['title']} {_action_state(a)}" for a in actions) + "."])

    async def _action_status(self, action_id: str, approve: bool) -> Reply:
        action = self.ctx.store.get_action(action_id)
        if action is None:
            return Reply([f"I can't find {action_id}. Action ids look like ACT-0001; they are listed in the Actions panel."])
        detail = await self._detail(action.incident_id)
        a = next((x for x in detail.get("actions", []) if x["id"] == action_id), None)
        if a is None:
            return Reply([f"I could not load {action_id}."])
        sentences = [f"{a['id']} {a['title']} for {action.incident_id} {_action_state(a)}."]
        if approve:
            sentences.append(
                "I can't approve, reject or run actions myself"
                + (f": a human must approve {a['id']} in the SentinelAI Actions panel." if a["status"] == "proposed"
                   else ", and this one has already been decided.")
            )
        return Reply(sentences)

    async def _cannot_approve(self, target: str | None, incidents: list[dict]) -> Reply:
        ids = [target] if target else [i["id"] for i in incidents]
        pending: list[str] = []
        for incident_id in ids:
            detail = await self._detail(incident_id)
            pending += [f"{a['id']} {a['title']} ({incident_id})" for a in detail.get("actions", []) if a["status"] == "proposed"]
        return Reply([
            "I can't approve or run actions myself: a human must approve each one in the SentinelAI Actions panel.",
            f"Awaiting approval: {'; '.join(pending)}." if pending else "No actions are awaiting approval right now.",
        ])

    def _real_actions(self) -> Reply:
        s = self.ctx.settings
        return Reply([
            "ALLOW_REAL_ACTIONS controls whether an approved deactivate-access-key action calls AWS for real.",
            _REAL_ACTION_NOTE,
            f"Right now real actions are {'enabled' if s.allow_real_actions else 'disabled'} and the allowlist is "
            f"{', '.join(s.real_action_user_allowlist) or 'empty'}. Every other action type is always simulated.",
        ])

    async def _false_positive(self, incident_id: str) -> Reply:
        detail = await self._detail(incident_id)
        if "error" in detail:
            return Reply([f"I could not load {incident_id}: {detail['error']}."])
        inc = detail["incident"]
        counts, ents = inc.get("counts", {}), inc.get("entities", {})
        if "R-LEAKED-KEY" in inc.get("rule_ids", []):
            why = (f"the key GitHub flagged was used {_plural(counts.get('post_flag_uses', 0), 'time')} after the alert, "
                   f"including {_plural(counts.get('escalation_attempts', 0), 'privilege-escalation attempt')}"
                   f" (IAM denied {counts.get('denied', 0)} of the calls)")
        elif "R-BRUTE-FORCE" in inc.get("rule_ids", []):
            ips = ", ".join(ents.get("attacker_ips", [])) or "an unknown IP"
            why = (f"{_plural(counts.get('failed_logins', 0), 'failed login')} for {ents.get('app_user', 'the user')} from {ips}"
                   " is above the threshold of 10 in 10 minutes"
                   + (", and the attacker then guessed the password" if counts.get("attacker_successes") else ""))
        else:
            why = f"it matched {', '.join(inc.get('rule_ids', [])) or 'a detection rule'}"
        return Reply([
            f"No. {inc['id']} is not a false positive: {why}.",
            "The login pattern SentinelAI did suppress as benign is arjun's (1 failed login, then MFA passed).",
            f"Data: {detail['provenance']}.",
        ])

    def _provenance(self, incidents: list[dict]) -> Reply:
        lines = [f"{i['id']}: {i.get('provenance', 'unknown provenance')} (data mode {i.get('data_mode', 'unknown')})"
                 for i in incidents]
        mode = ("SentinelAI is running in offline mode, so it is not reading AWS right now." if self.ctx.settings.offline_only
                else "When AWS is connected, CloudTrail evidence and CloudWatch Logs reads are live.")
        return Reply(
            [mode, "The GitHub secret-scanning alert and the app login traffic are always synthetic demo data.",
             ("Per incident: " + "; ".join(lines) + ".") if lines else "There are no incidents yet."]
        )

    async def _facts(self, target: str | None, incidents: list[dict], fact: str) -> Reply:
        """Regions, denied calls or IPs for the target incident, or for every incident that has them."""
        ids = [target] if target else [i["id"] for i in incidents]
        if target:
            ids += [i["id"] for i in incidents if i["id"] != target]
        answers: list[str] = []
        for n, incident_id in enumerate(ids):
            if n and target and answers:
                break  # the target answered; only fall through to other incidents when it had nothing
            detail = await self._detail(incident_id)
            if "error" in detail:
                continue
            inc = detail["incident"]
            ents, counts = inc.get("entities", {}), inc.get("counts", {})
            ct = _cloudtrail_view(detail["timeline"]) if "R-LEAKED-KEY" in inc.get("rule_ids", []) else None
            if fact == "regions":
                regions = ents.get("regions") or (_distinct(ct["events"], "region") if ct else [])
                if regions:
                    answers.append(f"{inc['id']}'s CloudTrail calls ran in {_plural(len(regions), 'AWS region')}: {', '.join(regions)}.")
            elif fact == "denied" and ct and ct["count"]:
                kinds = _kinds({e["kind"]: 1 for e in ct["events"] if e.get("outcome") == "denied"})
                answers.append(f"IAM denied {counts.get('denied', ct['denied'])} of the {_plural(ct['count'], 'CloudTrail call')} "
                               f"in {inc['id']}" + (f": {kinds}." if kinds else "."))
            elif fact == "ips":
                ips = ents.get("source_ips") or ents.get("attacker_ips") or []
                geo = ents.get("attacker_geo") or []
                if ips:
                    answers.append(f"{inc['id']} activity came from {', '.join(ips)}" + (f" ({', '.join(geo)})" if geo else "") + ".")
        if not answers:
            what = {"regions": "AWS regions", "denied": "denied CloudTrail calls", "ips": "source IPs"}[fact]
            return Reply([f"I found no {what} in the current incidents."])
        if target and not answers[0].startswith(target):
            answers.insert(0, f"{target} has no {fact.replace('ips', 'IPs')} of its own.")
        return Reply(answers)

    async def _benign(self, user: str) -> Reply:
        auth = await run_tool("get_auth_events", {"user": user}, self.ctx)
        profile = await run_tool("get_user_profile", {"username": user}, self.ctx)
        if "error" in auth or not auth.get("count"):
            return Reply([f"I found no recent login events for {user}."])
        kinds = auth.get("by_kind", {})
        failed = kinds.get("login_failed", 0)
        ips = _distinct(auth.get("events", []), "ip")
        who = profile.get("user") or {}
        role = who.get("title") or who.get("role")
        return Reply(
            [
                f"{user}{f' ({role})' if role else ''} had {_plural(failed, 'failed login')}, then "
                f"{_plural(kinds.get('login_success', 0), 'successful login')} and "
                f"{_plural(kinds.get('mfa_success', 0), 'passed MFA check')}"
                + (f" from {', '.join(ips)}" if ips else "")
                + f" around {_when(auth.get('first_seen'))}.",
                "That is below the brute-force threshold of 10 failures in 10 minutes and MFA passed, "
                "so SentinelAI suppressed it as benign instead of opening an incident.",
                f"Data: {auth['provenance']}.",
            ]
        )

    async def _alerts_only(self) -> Reply:
        alerts = await run_tool("get_github_secret_alerts", {"state": "open"}, self.ctx)
        if "error" in alerts:
            return Reply([f"I could not read GitHub alerts: {alerts['error']}."])
        lines = [f"#{a.get('number')} {a.get('access_key_id')} in {a.get('repository')}/{a.get('path')}" for a in alerts["alerts"]]
        return Reply(
            [f"There are {_plural(alerts['count'], 'open secret-scanning alert')} but no leaked-key incident yet. "
             "Run detection to correlate them with CloudTrail.", f"Data: {alerts['provenance']}."],
            lines,
        )

    async def _auth_only(self, user: str) -> Reply:
        auth = await run_tool("get_auth_events", {"user": user, "outcome": "failure"}, self.ctx)
        if "error" in auth:
            return Reply([f"I could not read login events: {auth['error']}."])
        return Reply(
            [f"There is no brute-force incident open. I see {_plural(auth.get('count', 0), 'failed login event')} for {user}.",
             f"Data: {auth['provenance']}."]
        )

    async def _audit(self) -> Reply:
        log = await run_tool("get_audit_log", {"limit": 10}, self.ctx)
        if "error" in log:
            return Reply([f"I could not read the audit log: {log['error']}."])
        entries = log.get("entries", [])
        chain = "verifies, so it has not been tampered with" if log.get("chain_ok") else "does NOT verify; investigate tampering"
        sentences = [f"The audit log's hash chain {chain}."]
        if entries:
            last = entries[0]
            sentences.append(
                f"Latest entry: {last['action']} by {last['actor']} on {last.get('incident_id') or 'no incident'} "
                f"at {_when(last['ts'])}."
            )
        return Reply(
            sentences,
            [f"#{e['seq']} {_when(e['ts'])} · {e['actor']} · {e['action']} · {e.get('incident_id', '')}" for e in entries],
        )

    @staticmethod
    def _action_lines(detail: dict[str, Any]) -> list[str]:
        return [
            f"{a['id']} {a['title']}: {a['status']}" + (" (awaiting human approval)" if a["status"] == "proposed" else "")
            for a in detail.get("actions", [])
        ]
