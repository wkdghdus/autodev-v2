from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Any


SECRET_VALUE = "[REDACTED]"
SENSITIVE_KEY_RE = re.compile(
    r"(?i)(api[_-]?key|secret|token|password|credential|authorization|bearer|private[_-]?key)"
)
ASSIGNMENT_RE = re.compile(
    r"(?is)\b(api[_-]?key|secret|token|password)\s*[:=]\s*"
    r"('.*?'|\".*?\"|[^\s,;]+)"
)
BEARER_RE = re.compile(r"(?i)\bBearer\s+([A-Za-z0-9._~+/=-]+)")
AUTHORIZATION_RE = re.compile(
    r"(?is)\bauthorization\s*[:=]\s*(?:(Bearer|Basic)\s+)?"
    r"('.*?'|\".*?\"|[^\s,;]+)"
)
PRIVATE_KEY_RE = re.compile(
    r"(?is)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----"
)
URL_AUTH_RE = re.compile(r"(?i)(https?://)([^/\s:@]+):([^@\s/]+)@")


def redact_text(text: str, extra_canaries: list[str] | tuple[str, ...] = ()) -> str:
    redacted = AUTHORIZATION_RE.sub(
        lambda match: f"authorization={match.group(1) + ' ' if match.group(1) else ''}{SECRET_VALUE}",
        text,
    )
    redacted = BEARER_RE.sub(f"Bearer {SECRET_VALUE}", redacted)
    redacted = PRIVATE_KEY_RE.sub(SECRET_VALUE, redacted)
    redacted = URL_AUTH_RE.sub(lambda match: f"{match.group(1)}{SECRET_VALUE}:{SECRET_VALUE}@", redacted)
    redacted = ASSIGNMENT_RE.sub(lambda match: f"{match.group(1)}={SECRET_VALUE}", redacted)
    for canary in extra_canaries:
        if canary:
            redacted = redacted.replace(canary, SECRET_VALUE)
    return redacted


def sanitize(value: Any, extra_canaries: list[str] | tuple[str, ...] = ()) -> Any:
    if isinstance(value, Mapping):
        sanitized: dict[str, Any] = {}
        for key, item in value.items():
            clean_key = redact_text(str(key), extra_canaries)
            if SENSITIVE_KEY_RE.search(str(key)):
                sanitized[clean_key] = SECRET_VALUE
            else:
                sanitized[clean_key] = sanitize(item, extra_canaries)
        return sanitized
    if isinstance(value, (list, tuple)):
        return [sanitize(item, extra_canaries) for item in value]
    if isinstance(value, str):
        return redact_text(value, extra_canaries)
    return value


def sanitized_json(value: Any, extra_canaries: list[str] | tuple[str, ...] = ()) -> str:
    return json.dumps(sanitize(value, extra_canaries), indent=2, sort_keys=True) + "\n"
