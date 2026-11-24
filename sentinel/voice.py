"""Voice I/O through ElevenLabs (speech-to-text and text-to-speech).

The API key comes from ``ELEVENLABS_API_KEY`` or, when ``ELEVENLABS_SECRET_ID`` is
set and AWS is connected, from AWS Secrets Manager. The key is cached in memory
and never logged, traced or returned. Without a usable key (or in offline mode,
which never touches the network) every call raises :class:`VoiceUnavailable`
so the UI falls back to the browser Web Speech API.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import threading
import time
from typing import Any, Protocol

import httpx

from . import trace
from .aws.session import safe_reason
from .config import Settings
from .masking import mask_text

log = logging.getLogger(__name__)

API_BASE = "https://api.elevenlabs.io/v1"
TTS_OUTPUT_FORMAT = "mp3_44100_128"
TTS_MAX_CHARS = 1200
TTS_VOICE_SETTINGS = {"stability": 0.5, "similarity_boost": 0.75}
HTTP_TIMEOUT = httpx.Timeout(30.0, connect=5.0)
SECRET_RETRY_S = 60.0  # how long a failed Secrets Manager lookup is remembered
# After ElevenLabs rejects the key or the quota is used up (5 min), or is rate limited / unreachable (1 min), report the browser provider and skip
# ElevenLabs calls for a while instead of paying a failed round trip on every question.
AUTH_COOLDOWN_S = 300.0
NETWORK_COOLDOWN_S = 60.0
_DETAIL_STATUS_RE = re.compile(r"[a-z_]{1,40}")
SECRET_JSON_FIELDS = ("ELEVENLABS_API_KEY", "api_key")
SPAN_TARGET = "external"  # ElevenLabs is neither AWS nor an offline mock


class VoiceUnavailable(Exception):
    """Voice provider cannot be used; the message is a safe, user-facing reason."""


class _AwsLike(Protocol):
    def client(self, service: str, region: str | None = None) -> Any: ...
    def status(self, refresh: bool = False) -> Any: ...
    def mark_failure(self, exc: BaseException) -> None: ...


class VoiceService:
    """ElevenLabs STT/TTS with env or Secrets Manager key resolution."""

    def __init__(
        self,
        settings: Settings,
        aws: _AwsLike | None,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.settings = settings
        self.aws = aws
        self._transport = transport  # injectable for tests (httpx.MockTransport)
        self._lock = threading.Lock()
        self._secret_key: str | None = None
        self._secret_error: str | None = None
        self._secret_error_at = 0.0
        self._last_error: str | None = None
        self._cooldown_until = 0.0  # time.monotonic() deadline; 0 = no cooldown

    # ------------------------------------------------------------------ status
    def status(self) -> dict[str, Any]:
        """Which provider the UI should use and why (never includes the key)."""
        base = {"voice_id": self.settings.elevenlabs_voice_id, "last_error": self._last_error}
        if self.settings.offline_only:
            return {**base, "provider": "browser", "key_source": None,
                    "reason": "SENTINEL_MODE=offline: using the browser Web Speech API"}
        key, source, reason = self._resolve_key()
        if key is None:
            return {**base, "provider": "browser", "key_source": None, "reason": reason}
        paused = self._cooldown_reason()
        if paused:
            return {**base, "provider": "browser", "key_source": None, "reason": paused}
        return {**base, "provider": "elevenlabs", "key_source": source, "reason": f"ElevenLabs key from {source}"}

    # ------------------------------------------------------------- key lookup
    def _resolve_key(self) -> tuple[str | None, str | None, str]:
        """Return ``(key, key_source, reason)``; key is None when unavailable."""
        s = self.settings
        if s.elevenlabs_api_key.strip():
            return s.elevenlabs_api_key.strip(), "env", ""
        if not s.elevenlabs_secret_id:
            return None, None, "No ELEVENLABS_API_KEY or ELEVENLABS_SECRET_ID configured"
        with self._lock:
            if self._secret_key:
                return self._secret_key, "secrets-manager", ""
            if self._secret_error and time.time() - self._secret_error_at < SECRET_RETRY_S:
                return None, None, self._secret_error
            try:
                self._secret_key = self._fetch_secret()
                self._secret_error = None
                return self._secret_key, "secrets-manager", ""
            except VoiceUnavailable as exc:
                self._secret_error, self._secret_error_at = str(exc), time.time()
                return None, None, self._secret_error

    def _fetch_secret(self) -> str:
        """Read the key from Secrets Manager (caller holds the lock)."""
        if self.aws is None or not self.aws.status().connected:
            raise VoiceUnavailable("ELEVENLABS_SECRET_ID is set but AWS is not connected")
        region = self.settings.aws_region
        with trace.span("Secrets Manager", "get_secret_value", target="aws", backend="boto3", region=region) as sp:
            try:
                resp = self.aws.client("secretsmanager", region).get_secret_value(SecretId=self.settings.elevenlabs_secret_id)
            except Exception as exc:  # ClientError, credentials, network
                self.aws.mark_failure(exc)
                raise VoiceUnavailable(f"Secrets Manager lookup failed ({safe_reason(exc)})") from None
            key = _parse_secret(resp.get("SecretString"))
            sp.summary = "ElevenLabs key loaded"
        return key

    def _cooldown_reason(self) -> str | None:
        """Safe reason while ElevenLabs is paused after an auth/quota/network failure, else None."""
        remaining = self._cooldown_until - time.monotonic()
        if remaining <= 0 or not self._last_error:
            return None
        return f"{self._last_error}; using the browser Web Speech API (ElevenLabs retried in {max(1, round(remaining))} s)"

    def _require_key(self) -> str:
        if self.settings.offline_only:
            raise VoiceUnavailable("Offline mode: voice uses the browser Web Speech API")
        key, _source, reason = self._resolve_key()
        if key is None:
            raise VoiceUnavailable(reason)
        paused = self._cooldown_reason()
        if paused:
            raise VoiceUnavailable(paused)
        return key

    # ------------------------------------------------------------------- calls
    async def transcribe(self, audio: bytes, filename: str, content_type: str) -> dict[str, Any]:
        """Speech-to-text. Returns ``{"text", "provider", "ms"}``."""
        if not audio:
            raise ValueError("empty audio upload")
        key = await self._require_key_async()
        t0 = time.perf_counter()
        with trace.span("ElevenLabs", "speech_to_text", target=SPAN_TARGET, backend="elevenlabs") as sp:
            resp = await self._post(
                "/speech-to-text",
                key,
                files={"file": (filename or "audio.webm", audio, content_type or "application/octet-stream")},
                data={"model_id": self.settings.elevenlabs_stt_model},
            )
            try:
                text = str(resp.json().get("text") or "").strip()
            except (ValueError, AttributeError):
                raise self._fail("ElevenLabs returned an unexpected speech-to-text response") from None
            sp.summary = f"{len(text)} chars transcribed"
        self._last_error = None
        return {"text": text, "provider": "elevenlabs", "ms": int((time.perf_counter() - t0) * 1000)}

    async def speak(self, text: str) -> tuple[bytes, str]:
        """Text-to-speech of masked, markdown-free text. Returns ``(audio, mime)``."""
        spoken = prepare_tts_text(text)
        if not spoken:
            raise ValueError("nothing to speak")
        key = await self._require_key_async()
        voice_id = self.settings.elevenlabs_voice_id
        with trace.span("ElevenLabs", "text_to_speech", target=SPAN_TARGET, backend="elevenlabs") as sp:
            resp = await self._post(
                f"/text-to-speech/{voice_id}",
                key,
                params={"output_format": TTS_OUTPUT_FORMAT},
                json={"text": spoken, "model_id": self.settings.elevenlabs_tts_model, "voice_settings": TTS_VOICE_SETTINGS},
            )
            audio = resp.content
            mime = resp.headers.get("content-type", "").split(";")[0].strip().lower() or "audio/mpeg"
            if not mime.startswith("audio/"):
                raise self._fail("ElevenLabs returned non-audio content")
            if not audio:
                raise self._fail("ElevenLabs returned empty audio")
            sp.summary = f"{len(spoken)} chars → {len(audio) // 1024} KB mp3"
        self._last_error = None
        return audio, mime

    async def _require_key_async(self) -> str:
        # Secrets Manager is a blocking boto3 call; keep it off the event loop.
        return await asyncio.to_thread(self._require_key)

    async def _post(self, path: str, key: str, **kwargs: Any) -> httpx.Response:
        """POST to ElevenLabs, mapping HTTP/network failures to VoiceUnavailable."""
        try:
            async with httpx.AsyncClient(base_url=API_BASE, timeout=HTTP_TIMEOUT, transport=self._transport) as client:
                resp = await client.post(path, headers={"xi-api-key": key}, **kwargs)
        except httpx.TimeoutException:
            raise self._fail("ElevenLabs timed out", cooldown_s=NETWORK_COOLDOWN_S) from None
        except httpx.HTTPError as exc:
            raise self._fail(f"ElevenLabs unreachable ({type(exc).__name__})", cooldown_s=NETWORK_COOLDOWN_S) from None
        if resp.status_code >= 400:
            reason, cooldown_s = _http_error_reason(resp)
            if resp.status_code in (401, 403):
                with self._lock:
                    self._secret_key = None  # a rotated secret is re-read once the cooldown ends
            raise self._fail(reason, cooldown_s=cooldown_s)
        return resp

    def _fail(self, reason: str, *, cooldown_s: float = 0.0) -> VoiceUnavailable:
        self._last_error = reason
        if cooldown_s > 0:
            self._cooldown_until = time.monotonic() + cooldown_s
        log.warning("voice unavailable: %s", reason)
        return VoiceUnavailable(reason)


def _parse_secret(secret: str | None) -> str:
    """Accept a raw key or JSON with ELEVENLABS_API_KEY / api_key."""
    raw = (secret or "").strip()
    if not raw:
        raise VoiceUnavailable("ElevenLabs secret has no SecretString")
    if raw.startswith("{"):
        try:
            doc = json.loads(raw)
        except ValueError:
            raise VoiceUnavailable("ElevenLabs secret is not valid JSON") from None
        for field_name in SECRET_JSON_FIELDS:
            value = doc.get(field_name) if isinstance(doc, dict) else None
            if isinstance(value, str) and value.strip():
                return value.strip()
        raise VoiceUnavailable("ElevenLabs secret JSON has no ELEVENLABS_API_KEY or api_key field")
    return raw


def _http_error_reason(resp: httpx.Response) -> tuple[str, float]:
    """``(safe reason, cooldown seconds)`` for an ElevenLabs error response.

    The only body text echoed is ``detail.status`` when it is a plain status word (``[a-z_]{1,40}``).
    """
    detail_status = ""
    try:
        detail = resp.json().get("detail")
        if isinstance(detail, dict):
            detail_status = str(detail.get("status") or "")
    except (ValueError, AttributeError):
        pass
    if not _DETAIL_STATUS_RE.fullmatch(detail_status):
        detail_status = ""
    if detail_status == "quota_exceeded":
        return "ElevenLabs quota/rate limit", AUTH_COOLDOWN_S
    if resp.status_code == 429 or detail_status == "too_many_concurrent_requests":
        return "ElevenLabs quota/rate limit", NETWORK_COOLDOWN_S
    if resp.status_code in (401, 403):
        return "ElevenLabs rejected the API key", AUTH_COOLDOWN_S
    return f"ElevenLabs error (HTTP {resp.status_code}{', ' + detail_status if detail_status else ''})", 0.0


_FENCE_RE = re.compile(r"```.*?(?:```|\Z)", re.S)
_RULE_RE = re.compile(r"^\s*(?:[-*_]\s*){3,}$|^\s*\|?\s*:?-{3,}:?\s*(?:\|\s*:?-{3,}:?\s*)*\|?\s*$", re.M)
_IMAGE_RE = re.compile(r"!\[[^\]]*\]\([^)]*\)")
_LINK_RE = re.compile(r"\[([^\]]+)\]\([^)]*\)")
_LINE_PREFIX_RE = re.compile(r"^\s*(?:#{1,6}\s+|>\s?|[-*+]\s+|\d+[.)]\s+)", re.M)
_EMPHASIS_RE = re.compile(r"\*{1,3}|~~|`|(?<!\w)_{1,2}(?=\S)|(?<=\S)_{1,2}(?!\w)")
_SENTENCE_END = (".", "!", "?", ":", ";", "…")


def strip_markdown(text: str) -> str:
    """Turn chat markdown into plain sentences suitable for speech."""
    text = _FENCE_RE.sub(" ", text)
    text = _RULE_RE.sub("", text)
    text = _IMAGE_RE.sub("", text)
    text = _LINK_RE.sub(r"\1", text)
    text = _LINE_PREFIX_RE.sub("", text)
    text = _EMPHASIS_RE.sub("", text).replace("|", " ")
    lines = [" ".join(line.split()) for line in text.splitlines()]
    lines = [ln if ln.endswith(_SENTENCE_END) else ln + "." for ln in lines if ln]
    return " ".join(lines)


def prepare_tts_text(text: str, limit: int = TTS_MAX_CHARS) -> str:
    """Strip markdown, mask secrets, and cap length (cutting at a sentence or word)."""
    spoken = mask_text(strip_markdown(text or ""))
    if len(spoken) <= limit:
        return spoken
    cut = spoken[: limit - 1]
    sentence_end = max(cut.rfind(p + " ") for p in (".", "!", "?"))
    if sentence_end >= limit // 2:
        return cut[: sentence_end + 1]
    space = cut.rfind(" ")
    return (cut[:space] if space > 0 else cut).rstrip() + "…"
