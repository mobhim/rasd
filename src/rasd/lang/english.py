"""Minimal English pack. Its purpose is architectural: it proves a second
language plugs in without touching the pipeline. Coverage is intentionally
small and is not part of any performance claim."""
from __future__ import annotations

import re
from functools import lru_cache

from ..models import Evidence
from ..text import OffsetText
from .base import LanguagePack, register

_TERMS = {
    "urgency": [r"urgent(?:ly)?", r"immediately", r"within \d+ hours?", r"right now", r"act now", r"final notice", r"last chance", r"expires? today"],
    "threat": [r"(?:will be|has been|is) (?:suspended|blocked|locked|closed|deactivated|restricted)", r"unauthori[sz]ed (?:login|access|transaction)", r"suspicious activity", r"legal action", r"penalty", r"fine of"],
    "authority": [r"dear (?:customer|client|user)", r"customer (?:service|support)", r"your bank", r"security (?:team|department)"],
    "reward": [r"congratulations", r"you(?: have|'ve)? won", r"winner", r"prize", r"refund of", r"cash reward"],
    "credential_request": [r"(?:enter|send|share|provide|confirm|verify)(?: \S+){0,4}? (?:otp|password|pin|cvv|verification code|card number|card details|one[- ]time code)"],
    "account_update": [r"(?:update|verify|confirm|reactivate|validate) your (?:account|details|information|identity|card|address)"],
    "payment_request": [r"pay (?:a |the )?(?:fee|fine|customs|shipping)", r"transfer (?:the )?(?:amount|\d+)", r"(?:delivery|customs|processing) fee"],
    "action_link": [r"(?:click|tap|visit|follow|open)(?: on)? (?:the |this )?(?:link|here)", r"via (?:the |this )?link"],
    "action_contact": [r"(?:contact|message|call|text) (?:us|me) (?:on|via|at) (?:whatsapp|telegram)", r"whatsapp:? ?\+?\d{6,}"],
    "secrecy": [r"do not tell anyone", r"keep (?:this|it) (?:confidential|secret)"],
    "lure_job": [r"work from home", r"part[- ]time job", r"daily (?:income|salary)", r"no experience"],
    "lure_investment": [r"guaranteed (?:profit|return)s?", r"daily (?:profit|return)s?", r"invest(?:ment)?", r"crypto", r"forex"],
    "lure_delivery": [r"(?:parcel|package|shipment)", r"delivery (?:failed|attempt)", r"incomplete address"],
    "benign_otp_notice": [r"(?:do not|don't|never) share (?:this |your )?(?:code|otp|password)(?: with anyone)?"],
}


class EnglishPack(LanguagePack):
    code = "en"
    formal_varieties = frozenset({"en"})

    def affinity(self, script_profile: dict[str, float]) -> float:
        return script_profile.get("latin", 0.0)

    def fold_term(self, term: str) -> str:
        return term.lower()

    def fold(self, cleaned: OffsetText) -> tuple[OffsetText, list[Evidence]]:
        return cleaned.map_chars(str.lower), []

    @lru_cache(maxsize=1)
    def tactic_patterns(self) -> dict[str, list[re.Pattern]]:
        return {k: [re.compile(rf"(?<![a-z])(?:{t})(?![a-z])") for t in v] for k, v in _TERMS.items()}


register(EnglishPack())
