"""Amazon Bedrock Converse adapter.

A thin, synchronous wrapper around ``bedrock-runtime:Converse`` (the agent loop
runs it through ``asyncio.to_thread``). Credentials come from boto3's default
chain via :class:`~sentinel.aws.session.AwsSessionFactory`; nothing here logs
prompts or credentials.
"""
from __future__ import annotations

from typing import Any

from ..config import Settings
from .session import AwsSessionFactory

TEMPERATURE = 0.2
# Model families whose Converse API accepts ``toolResult.status`` (per the bedrock-runtime service
# model: Amazon Nova). The field is optional, so other models simply omit it.
_STATUS_MODELS = ("amazon.nova",)


def guardrail_config(settings: Settings) -> dict[str, Any] | None:
    """The ``guardrailConfig`` the agent sends, or None when no guardrail is configured."""
    if not settings.bedrock_guardrail_id:
        return None
    return {
        "guardrailIdentifier": settings.bedrock_guardrail_id,
        "guardrailVersion": settings.bedrock_guardrail_version or "DRAFT",
        "trace": "enabled",
    }


def tool_result_block(model_id: str, tool_use_id: str, result: dict[str, Any], error: bool) -> dict[str, Any]:
    """A Converse ``toolResult`` content block; ``status`` only for models that accept it."""
    block: dict[str, Any] = {"toolUseId": tool_use_id, "content": [{"json": result}]}
    if any(family in (model_id or "") for family in _STATUS_MODELS):
        block["status"] = "error" if error else "success"
    return {"toolResult": block}


def converse(
    aws: AwsSessionFactory,
    settings: Settings,
    messages: list[dict[str, Any]],
    system: str | list[dict[str, Any]],
    tool_config: dict[str, Any] | None,
) -> dict[str, Any]:
    """Call Converse once and return the raw response dict.

    ``system`` may be a plain string or a list of Converse system blocks. A
    Bedrock Guardrail is attached (with tracing) when ``BEDROCK_GUARDRAIL_ID``
    is set; the version defaults to ``DRAFT``.
    """
    blocks = [{"text": system}] if isinstance(system, str) else system
    request: dict[str, Any] = {
        "modelId": settings.bedrock_model_id,
        "messages": messages,
        "system": blocks,
        "inferenceConfig": {"maxTokens": settings.bedrock_max_tokens, "temperature": TEMPERATURE},
    }
    if tool_config:
        request["toolConfig"] = tool_config
    guardrail = guardrail_config(settings)
    if guardrail:
        request["guardrailConfig"] = guardrail
    client = aws.client("bedrock-runtime", settings.bedrock_region)
    return client.converse(**request)


def usage_summary(response: dict[str, Any]) -> str:
    """Short trace summary, e.g. ``"tool_use · 1830 in / 96 out tokens"``."""
    usage = response.get("usage") or {}
    return (
        f"{response.get('stopReason', '?')} · "
        f"{usage.get('inputTokens', 0)} in / {usage.get('outputTokens', 0)} out tokens"
    )
