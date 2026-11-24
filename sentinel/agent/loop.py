"""SentinelAgent: Bedrock Converse tool-use loop with a deterministic offline fallback.

Flow per question: mask the question and history -> Converse with TOOL_SPECS ->
run requested tools (masked, size-capped) -> feed ``toolResult`` blocks back ->
repeat up to ``settings.bedrock_max_turns`` tool rounds. A malformed tool call
(``malformed_tool_use``/``malformed_model_output``/``ModelErrorException``) is
retried once. Any other Bedrock failure (no credentials, AccessDenied, model not
enabled, validation, throttling, an unusable reply, or no answer within
``settings.bedrock_deadline_s``) falls back to :class:`OfflineAgent`, which calls
the same tools.
"""
from __future__ import annotations

import asyncio
from typing import Any

from .. import trace
from ..aws import bedrock
from ..aws.session import safe_reason
from ..masking import mask_text
from .offline import OfflineAgent
from .prompts import build_system_prompt, clean_answer, guard_action_claims, to_speech
from .tools import TOOL_CONFIG, AgentContext, run_tool

__all__ = ["AgentContext", "SentinelAgent", "history_to_messages"]

OFFLINE_MODEL_ID ="sentinel-offline-rules"
HISTORY_TURNS = 8
MAX_QUESTION_CHARS = 2000
DEFAULT_QUESTION = "Give me a status overview of current incidents."
BUDGET_NOTE ="Tool budget reached. Answer now using only the results above."
# Stop reasons / errors where the model garbled its own output: the same request is retried once.
RETRY_STOPS = ("malformed_tool_use", "malformed_model_output")
RETRY_ERRORS = ("ModelErrorException",)
# Stop reasons whose text is a complete answer; truncated ones get " …" appended.
FINAL_STOPS = ("end_turn", "stop_sequence", "guardrail_intervened", "content_filtered")
TRUNCATED_STOPS = ("max_tokens", "model_context_window_exceeded")


def _error_code(exc: BaseException) -> str:
    """botocore ClientError code (e.g. ``ModelErrorException``), else ''."""
    return str((getattr(exc, "response", None) or {}).get("Error", {}).get("Code", ""))


class BedrockUnusable(RuntimeError):
    """Bedrock answered, but not with something we can show (empty, malformed, too many tool rounds)."""


def _text_of(message: dict[str, Any]) -> str:
    return "\n".join(b["text"] for b in message.get("content", []) if b.get("text"))


def history_to_messages(history: list[dict] | None) -> list[dict[str, Any]]:
    """Convert UI chat history (``{"role", "content"|"text"}``) to masked, alternating Converse messages."""
    messages: list[dict[str, Any]] = []
    for item in (history or [])[-2 * HISTORY_TURNS :]:
        if not isinstance(item, dict):
            continue
        role = item.get("role")
        raw = item.get("content", item.get("text", ""))
        if isinstance(raw, list):  # Converse-style blocks; anything that is not a text block is ignored
            raw = "\n".join(b["text"] for b in raw if isinstance(b, dict) and isinstance(b.get("text"), str))
        if not isinstance(raw, str):  # null, numbers, objects: skipped instead of raising TypeError
            continue
        text = mask_text(raw.strip())[:MAX_QUESTION_CHARS]
        if role not in ("user", "assistant") or not text:
            continue
        if messages and messages[-1]["role"] == role:
            messages[-1]["content"][0]["text"] += "\n" + text
        else:
            messages.append({"role": role, "content": [{"text": text}]})
    while messages and messages[0]["role"] != "user":
        messages.pop(0)
    if messages and messages[-1]["role"] == "user":  # the new question must follow an assistant turn
        messages.pop()
    return messages


class SentinelAgent:
    """Answers analyst questions; records ``last_mode``/``last_error`` for ``/api/status``."""

    def __init__(self, ctx: AgentContext):
        self.ctx = ctx
        self.offline = OfflineAgent(ctx)
        self.last_mode: str | None = None
        self.last_error: str | None = None

    async def ask(
        self,
        question: str,
        incident_id: str | None = None,
        history: list[dict] | None = None,
        voice: bool = False,
    ) -> dict[str, Any]:
        settings = self.ctx.settings
        question = mask_text((question or "").strip())[:MAX_QUESTION_CHARS] or DEFAULT_QUESTION
        incident_id = self._canonical_incident_id(incident_id)
        proposed: list[str] = []
        with trace.collect() as entries:
            reason = await self._bedrock_blocker()
            answer: str | None = None
            if reason is None:
                try:
                    answer = await asyncio.wait_for(
                        self._ask_bedrock(question, incident_id, history, voice, proposed),
                        timeout=settings.bedrock_deadline_s,
                    )
                except (asyncio.TimeoutError, TimeoutError):
                    reason = f"Bedrock unavailable: no answer within {settings.bedrock_deadline_s} s"
                except Exception as exc:  # noqa: BLE001 - every Bedrock failure degrades to offline
                    self.ctx.aws.mark_failure(exc)
                    reason = f"Bedrock unavailable: {safe_reason(exc)}"
            if answer is None:
                result = await self.offline.answer(question, incident_id, voice, history)
                answer = result.text
                proposed += [a for a in result.proposed_actions if a not in proposed]
        self.last_mode = "bedrock" if reason is None else "offline"
        self.last_error = reason
        return {
            "answer": mask_text(answer),
            "mode": self.last_mode,
            "model_id": settings.bedrock_model_id if reason is None else OFFLINE_MODEL_ID,
            "fallback_reason": reason,
            "trace": [e.to_dict() for e in entries],
            "proposed_actions": proposed,
        }

    def _canonical_incident_id(self, incident_id: str | None) -> str | None:
        """The stored id of an existing incident, else None: caller text never reaches the system prompt."""
        raw = str(incident_id or "").strip().upper()
        if not raw or len(raw) > 20:
            return None
        inc = self.ctx.store.get_incident(raw)
        return inc.id if inc is not None else None

    async def _bedrock_blocker(self) -> str | None:
        """Why Bedrock must not be tried right now, or None."""
        if self.ctx.settings.offline_only:
            return "SENTINEL_MODE=offline"
        status = await asyncio.to_thread(self.ctx.aws.status)
        if not status.connected:
            return f"AWS not connected: {status.reason or 'unknown reason'}"
        return None

    async def _converse(self, messages: list[dict], system: str) -> dict[str, Any]:
        s = self.ctx.settings
        with trace.span("Bedrock", "converse", target="aws", backend=s.bedrock_model_id, region=s.bedrock_region) as sp:
            response = await asyncio.to_thread(bedrock.converse, self.ctx.aws, s, messages, system, TOOL_CONFIG)
            sp.summary = bedrock.usage_summary(response)
        return response

    async def _converse_once_retried(self, messages: list[dict], system: str) -> dict[str, Any]:
        """Converse, retrying once (same request, bad reply discarded) when the model garbled a tool call."""
        try:
            response = await self._converse(messages, system)
        except Exception as exc:  # noqa: BLE001
            if _error_code(exc) not in RETRY_ERRORS:
                raise
        else:
            if response.get("stopReason") not in RETRY_STOPS:
                return response
        return await self._converse(messages, system)

    async def _ask_bedrock(
        self, question: str, incident_id: str | None, history: list[dict] | None, voice: bool, proposed: list[str]
    ) -> str:
        system = build_system_prompt(voice=voice, incident_id=incident_id)
        messages = history_to_messages(history) + [{"role": "user", "content": [{"text": question}]}]
        max_rounds = max(1, self.ctx.settings.bedrock_max_turns)
        for round_no in range(max_rounds + 1):
            response = await self._converse_once_retried(messages, system)
            message = response["output"]["message"]
            stop = response.get("stopReason")
            messages.append(message)
            text = clean_answer(_text_of(message))
            if stop == "tool_use" and round_no < max_rounds:
                results = await self._run_tool_uses(message, proposed)
                if round_no == max_rounds - 1:
                    results.append({"text": BUDGET_NOTE})
                messages.append({"role": "user", "content": results})
                continue
            # On the last round a model may still emit a toolUse next to a complete answer: keep the answer.
            if (stop in FINAL_STOPS or (stop == "tool_use" and round_no == max_rounds)) and text:
                return guard_action_claims(to_speech(text) if voice else text)
            if stop in TRUNCATED_STOPS and text:
                return guard_action_claims(to_speech(text) if voice else text + " …")
            raise BedrockUnusable(f"stopReason={stop} with {'no' if not text else 'unusable'} text")
        raise BedrockUnusable("tool round limit reached without an answer")

    async def _run_tool_uses(self, message: dict[str, Any], proposed: list[str]) -> list[dict[str, Any]]:
        """Execute each toolUse block in order and build the matching toolResult blocks."""
        blocks: list[dict[str, Any]] = []
        for block in message.get("content", []):
            use = block.get("toolUse")
            if not use:
                continue
            result = await run_tool(use.get("name", ""), use.get("input") or {}, self.ctx)
            action_id = (result.get("action") or {}).get("id") if use.get("name") == "propose_remediation" else None
            if action_id and action_id not in proposed:
                proposed.append(action_id)
            blocks.append(
                bedrock.tool_result_block(self.ctx.settings.bedrock_model_id, use["toolUseId"], result, "error" in result)
            )
        if not blocks:
            raise BedrockUnusable("stopReason=tool_use without toolUse blocks")
        return blocks
