"""Language-pack contract.

The engine core (indicator extraction, scoring, graph, XAI) is language
agnostic. Everything linguistic lives behind this interface, so adding a
language means adding one pack — no change to the pipeline or the graph."""
from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass

from ..models import Evidence, Span, VarietyResult
from ..text import OffsetText

# Language-independent tactic taxonomy. Packs map surface forms onto these ids.
TACTICS = (
    "urgency", "threat", "authority", "reward", "credential_request",
    "account_update", "payment_request", "action_link", "action_contact",
    "secrecy", "lure_job", "lure_investment", "lure_delivery",
    "benign_otp_notice",
)


@dataclass(frozen=True)
class TacticMatch:
    tactic: str
    span: Span
    term: str


class LanguagePack(ABC):
    code: str = "und"
    #: varieties in which institutions normally write (used for register-mismatch evidence)
    formal_varieties: frozenset[str] = frozenset()

    @abstractmethod
    def affinity(self, script_profile: dict[str, float]) -> float:
        """0..1 — how much of the message this pack can read."""

    @abstractmethod
    def fold(self, cleaned: OffsetText) -> tuple[OffsetText, list[Evidence]]:
        """Language-level normalisation; may emit obfuscation evidence."""

    @abstractmethod
    def fold_term(self, term: str) -> str:
        """Apply the same letter folding to a lexicon/brand term."""

    @abstractmethod
    def tactic_patterns(self) -> dict[str, list[re.Pattern]]:
        ...

    def tactics(self, folded: OffsetText) -> list[TacticMatch]:
        out: list[TacticMatch] = []
        for tactic, patterns in self.tactic_patterns().items():
            for p in patterns:
                for m in p.finditer(folded.text):
                    out.append(TacticMatch(tactic, folded.span(m.start(), m.end()), m.group(0)))
        return out

    def variety(self, folded: OffsetText) -> VarietyResult:
        return VarietyResult(label=self.code)

    def letter_class(self) -> str:
        """Regex character class of this language's letters (for word boundaries)."""
        return "a-z"


_REGISTRY: dict[str, LanguagePack] = {}


def register(pack: LanguagePack) -> LanguagePack:
    _REGISTRY[pack.code] = pack
    return pack


def packs() -> list[LanguagePack]:
    if not _REGISTRY:
        from . import arabic, english  # noqa: F401  (self-registering)
    return list(_REGISTRY.values())


def select_packs(script_profile: dict[str, float], min_affinity: float = 0.15) -> list[LanguagePack]:
    ranked = sorted(((p.affinity(script_profile), p) for p in packs()), key=lambda t: -t[0])
    return [p for a, p in ranked if a >= min_affinity]
