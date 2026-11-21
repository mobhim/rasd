"""Scoring policy: one additive log-odds weight per evidence id.

The default weights are expert priors — NOT learned from data. They can be
re-estimated on labelled data with `rasd.eval.calibrate` (interpretable
logistic regression over the same evidence ids), producing a new versioned
policy file. Either way the decision stays a transparent sum."""
from __future__ import annotations

import json
from dataclasses import dataclass, field

DEFAULT_WEIGHTS: dict[str, float] = {
    # --- persuasion tactics (language-independent ids, language packs provide matches)
    "tactic.urgency": 0.6, "tactic.threat": 1.2, "tactic.authority": 0.3, "tactic.reward": 1.0,
    "tactic.credential_request": 2.2, "tactic.account_update": 1.0, "tactic.payment_request": 0.8,
    "tactic.action_link": 0.4, "tactic.action_contact": 0.5, "tactic.secrecy": 1.2,
    "tactic.lure_job": 1.0, "tactic.lure_investment": 1.1, "tactic.lure_delivery": 0.4,
    "brand.mention": 0.3,
    # --- URL lexical evidence
    "url.brand_impersonation": 2.5, "url.typosquat": 2.5, "url.brand_in_path": 1.2, "url.ip_host": 1.5,
    "url.free_hosting": 0.9, "url.suspicious_tld": 0.8, "url.idn_host": 0.8, "url.userinfo_trick": 2.0,
    "url.deep_subdomains": 0.5, "url.sensitive_keyword": 0.6, "url.plain_http": 0.3, "url.shortener": 0.4,
    # --- cross-signal context
    "context.brand_link_mismatch": 2.2, "context.brand_unverifiable_link": 0.9,
    "context.authority_unverified_link": 0.8, "context.org_claim_from_personal_number": 1.2,
    "context.org_claim_personal_contact": 1.0, "context.foreign_contact_number": 0.8, "context.register_mismatch": 0.5,
    "payment.iban_in_message": 0.5, "payment.crypto_wallet": 1.2,
    "combo.credential_via_link": 1.0, "combo.threat_with_vector": 0.8, "combo.advance_fee": 1.2,
    "combo.reward_with_vector": 0.8, "combo.lure_offplatform_contact": 1.8,
    # --- evasion
    "obfuscation.invisible_chars": 1.0, "obfuscation.spaced_letters": 1.2, "obfuscation.lookalike_letters": 0.8,
    "obfuscation.defanged_url": 1.0, "obfuscation.mixed_script": 1.0,
    # --- benign evidence (negative)
    "url.official_domain": 0.0, "benign.official_links_only": -1.5, "benign.otp_notice": -1.5,
}


@dataclass
class Policy:
    version: str = "prior-0.3"
    bias: float = -3.0
    weights: dict[str, float] = field(default_factory=lambda: dict(DEFAULT_WEIGHTS))
    suspicious_threshold: float = 0.40
    malicious_threshold: float = 0.80
    advisory_cap: float = 1.0     # max |log-odds| any optional ML/LLM advisory signal may contribute

    def to_json(self) -> str:
        return json.dumps(self.__dict__, ensure_ascii=False, indent=2)

    @classmethod
    def load(cls, path: str) -> "Policy":
        with open(path, encoding="utf8") as fh:
            return cls(**json.load(fh))
