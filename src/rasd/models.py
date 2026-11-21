"""Core data model. Everything the engine concludes is expressed as Evidence
objects that point back to character spans of the *original* message, so every
score and every graph link can be audited."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


@dataclass(frozen=True)
class Span:
    start: int  # offsets into the ORIGINAL (un-normalised) text
    end: int
    text: str

    def to_dict(self) -> dict:
        return asdict(self)


class IndicatorType(str, Enum):
    URL = "url"
    DOMAIN = "domain"
    PHONE = "phone"
    IBAN = "iban"
    EMAIL = "email"
    HANDLE = "handle"
    WALLET = "wallet"
    SENDER_ID = "sender_id"


@dataclass
class Indicator:
    type: IndicatorType
    value: str                      # canonical form used as graph key
    raw: str = ""                   # as it appeared in the message
    span: Span | None = None
    role: str = "body"              # body | sender
    linkable: bool = True           # False for shared platforms / official domains
    attrs: dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> str:
        return f"{self.type.value}:{self.value}"

    def to_dict(self) -> dict:
        return {
            "type": self.type.value, "value": self.value, "raw": self.raw,
            "span": self.span.to_dict() if self.span else None,
            "role": self.role, "linkable": self.linkable, "attrs": self.attrs,
            "key": self.key,
        }


@dataclass
class Evidence:
    id: str                         # stable rule id, e.g. "tactic.credential_request"
    category: str                   # tactic | url | sender | obfuscation | combo | benign | advisory
    weight: float = 0.0             # log-odds contribution, filled in by the scorer
    spans: list[Span] = field(default_factory=list)
    detail: dict[str, Any] = field(default_factory=dict)
    source: str = "rule"            # rule | advisory (advisory = optional ML/LLM, capped)

    def to_dict(self) -> dict:
        return {
            "id": self.id, "category": self.category, "weight": round(self.weight, 4),
            "spans": [s.to_dict() for s in self.spans], "detail": self.detail,
            "source": self.source,
        }


@dataclass
class VarietyResult:
    """Language variety (dialect) estimate with the markers that produced it."""
    label: str = "unknown"
    scores: dict[str, float] = field(default_factory=dict)
    markers: dict[str, list[str]] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Message:
    text: str
    id: str | None = None
    sender: str | None = None       # sender id / number as displayed
    recipient: str | None = None    # victim side — pseudonymised before storage
    channel: str = "sms"            # sms | whatsapp | telegram | email | other
    received_at: str | None = None  # ISO-8601
    source: str = "unspecified"     # data provenance: real | synthetic | test | unspecified


@dataclass
class Analysis:
    message_id: str
    language: str
    variety: VarietyResult
    score: float
    verdict: str                    # benign | suspicious | malicious
    logit: float
    bias: float
    evidence: list[Evidence]
    indicators: list[Indicator]
    tactics: list[str]
    brands: list[str]
    fingerprint: int                # template simhash (indicators masked)
    guard_applied: str | None = None
    policy_version: str = ""

    def to_dict(self) -> dict:
        return {
            "message_id": self.message_id, "language": self.language,
            "variety": self.variety.to_dict(), "score": round(self.score, 4),
            "verdict": self.verdict, "logit": round(self.logit, 4), "bias": self.bias,
            "evidence": [e.to_dict() for e in self.evidence],
            "indicators": [i.to_dict() for i in self.indicators],
            "tactics": self.tactics, "brands": self.brands,
            "fingerprint": f"{self.fingerprint:016x}",
            "guard_applied": self.guard_applied, "policy_version": self.policy_version,
        }
