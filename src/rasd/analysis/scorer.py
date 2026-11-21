"""Additive evidence scorer. score = sigmoid(bias + sum(weights)).

Because the model is additive, the per-evidence contributions shown to the
analyst ARE the model — not a post-hoc approximation of it.

Decision guards (security constraints, independent of weights):
 1. `malicious` requires an actionable vector (link / contact / payee) or an
    explicit credential request. Tone alone can never convict a message.
 2. Advisory evidence (optional ML/LLM plug-ins) is capped and can never be
    the reason a verdict reaches `malicious`."""
from __future__ import annotations

import math

from ..models import Evidence
from .policy import Policy


def sigmoid(x: float) -> float:
    return 1.0 / (1.0 + math.exp(-x)) if x >= 0 else math.exp(x) / (1.0 + math.exp(x))


def score(evidence: list[Evidence], policy: Policy, has_vector: bool) -> tuple[float, float, str, str | None]:
    """Assigns weights in place. -> (probability, logit, verdict, guard_applied)."""
    core = adv = 0.0
    for e in evidence:
        if e.source == "advisory":
            e.weight = max(-policy.advisory_cap, min(policy.advisory_cap, float(e.detail.get("weight", 0.0))))
            adv += e.weight
        else:
            e.weight = policy.weights.get(e.id, 0.0)
            core += e.weight
    adv = max(-policy.advisory_cap, min(policy.advisory_cap, adv))
    logit = policy.bias + core + adv
    p, p_core = sigmoid(logit), sigmoid(policy.bias + core)

    def band(x: float) -> str:
        return "malicious" if x >= policy.malicious_threshold else "suspicious" if x >= policy.suspicious_threshold else "benign"

    verdict, guard = band(p), None
    if verdict == "malicious":
        if band(p_core) != "malicious":
            verdict, guard = "suspicious", "advisory_cannot_convict"
        elif not has_vector and not any(e.id == "tactic.credential_request" for e in evidence):
            verdict, guard = "suspicious", "no_actionable_vector"
    return p, logit, verdict, guard
