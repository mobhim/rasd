"""Privacy controls.

* Victim-side identifiers (recipient numbers) are never stored: they are
  replaced by a keyed pseudonym (HMAC-SHA256) so repeat targeting can still
  be counted without knowing who was targeted.
* Message bodies are stored redacted. Redaction is LENGTH-PRESERVING so the
  evidence spans computed on the original text still line up.
* Attacker-side indicators (domains, payee IBANs, contact numbers) are kept
  in clear — they are the intelligence. Note a spoofed sender number may
  belong to an innocent party; exports mark sender-role indicators as such."""
from __future__ import annotations

import hashlib
import hmac
import re

from .models import Indicator

_CARD = re.compile(r"(?<!\d)(?:\d[ \-]?){13,19}(?!\d)")
_NID = re.compile(r"(?<!\d)[12]\d{9}(?!\d)")
_CODE = re.compile(r"(?:رمز|الرمز|كود|الكود|code|otp|pin|passcode|كلمة المرور|الرقم السري)[^\d\n]{0,25}(\d{4,8})(?!\d)", re.I)
MASK = "•"


def pseudonymize(value: str | None, key: bytes) -> str | None:
    if not value:
        return None
    norm = re.sub(r"\D", "", value) or value.strip().casefold()
    return "p_" + hmac.new(key, norm.encode(), hashlib.sha256).hexdigest()[:20]


def _luhn(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        n = int(ch)
        if alt:
            n = n * 2 - 9 if n > 4 else n * 2
        total += n
        alt = not alt
    return total % 10 == 0


def redact(text: str, indicators: list[Indicator]) -> tuple[str, dict[str, int]]:
    """Mask payment-card numbers, national-ID-like numbers and one-time codes."""
    keep = [(i.span.start, i.span.end) for i in indicators if i.span]
    chars, counts = list(text), {"card": 0, "national_id": 0, "code": 0}

    def protected(s: int, e: int) -> bool:
        return any(s < ke and ks < e for ks, ke in keep)

    def mask(s: int, e: int, kind: str) -> None:
        for i in range(s, e):
            if chars[i].isdigit():
                chars[i] = MASK
        counts[kind] += 1

    folded = text.translate({0x0660 + i: 0x30 + i for i in range(10)} | {0x06F0 + i: 0x30 + i for i in range(10)})
    for m in _CARD.finditer(folded):
        if not protected(*m.span()) and _luhn(re.sub(r"\D", "", m.group(0))):
            mask(*m.span(), "card")
    for m in _CODE.finditer(folded):
        if not protected(*m.span(1)):
            mask(*m.span(1), "code")
    for m in _NID.finditer(folded):
        if not protected(*m.span()) and chars[m.start()].isdigit():
            mask(*m.span(), "national_id")
    return "".join(chars), counts
