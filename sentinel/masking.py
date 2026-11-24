"""First masking layer: redact secrets/PII before anything leaves the process
(Bedrock prompts, reports, UI text, logs). An optional Bedrock Guardrail is the
second layer.

* AWS secret access keys (40 chars) -> fully redacted.
* AWS access key IDs (AKIA/ASIA + 16) -> keep prefix + last 4: ``AKIA…WXYZ``.
  The last 4 characters are enough to correlate evidence without exposing the key.
* Emails -> ``p***@example.com``.
* Bearer / API tokens that look like ``sk_...``/``xi-api-key`` values -> redacted.
"""
from __future__ import annotations

import re
from typing import Any

# No \b anchors: "_AKIA…", "creds_AKIA…" and "%3DAKIA…" must be caught too (over-masking is the safe side).
ACCESS_KEY_RE = re.compile(r"((?:AKIA|ASIA|AIDA|AROA|AGPA|ANPA|ANVA|AIPA)[A-Z0-9]{12})([A-Z0-9]{4})(?![A-Z0-9])")
# 40 chars of base64-ish after a secret label ("aws_secret_access_key=", "AWS_SECRET_KEY = \"",
# "--aws-secret-access-key ", "aws secret access key: ", "SecretAccessKey": ...).
SECRET_KV_RE = re.compile(
    r"(?i)((?:aws[_\- ]?)?secret(?:[_\- ]?access)?(?:[_\- ]?key)?)(\s*[\"']?\s*(?:[:=]|\s)\s*[\"']?)([A-Za-z0-9/+=]{40})"
)
# A bare 40-char token with upper AND lower case AND a digit, '/' or '+' (an AWS secret access key, whatever
# its alphabet draw). Lower-case hex (git SHAs) and 64-char hex hashes never match. "/" may precede it
# ("path/<secret>"); "=" is not in the lookbehind, so "secret=" / "password=" / "token=" are caught too.
BARE_SECRET_RE = re.compile(
    r"(?<![A-Za-z0-9+])(?=[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=]))"
    r"(?=[A-Za-z0-9/+=]{0,39}[a-z])(?=[A-Za-z0-9/+=]{0,39}[A-Z])(?=[A-Za-z0-9/+=]{0,39}[0-9/+])[A-Za-z0-9/+=]{40}"
)
EMAIL_RE = re.compile(r"\b([A-Za-z0-9._%+-])[A-Za-z0-9._%+-]*@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
TOKEN_RE = re.compile(r"\b(sk_[A-Za-z0-9]{16,}|xi-[A-Za-z0-9]{16,}|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b")


def mask_access_key(key: str) -> str:
    if not key:
        return key
    m = ACCESS_KEY_RE.fullmatch(key)
    if not m:
        return key[:4] + "…" + key[-4:] if len(key) > 8 else "****"
    return m.group(1)[:4] + "…" + m.group(2)


def mask_text(text: str) -> str:
    if not text:
        return text
    text = SECRET_KV_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}[REDACTED-SECRET]", text)
    text = BARE_SECRET_RE.sub("[REDACTED-SECRET]", text)
    text = TOKEN_RE.sub("[REDACTED-TOKEN]", text)
    text = ACCESS_KEY_RE.sub(lambda m: m.group(1)[:4] + "…" + m.group(2), text)
    text = EMAIL_RE.sub(lambda m: f"{m.group(1)}***@{m.group(2)}", text)
    return text


def mask_obj(obj: Any) -> Any:
    """Recursively mask every string inside dicts/lists/tuples."""
    if isinstance(obj, str):
        return mask_text(obj)
    if isinstance(obj, dict):
        return {k: mask_obj(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [mask_obj(v) for v in obj]
    return obj
