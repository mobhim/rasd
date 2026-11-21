"""Message analysis pipeline: clean -> extract indicators -> language packs ->
evidence assembly -> additive scoring. Deterministic and offline."""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Callable

from ..indicators.brands import BRANDS
from ..indicators.extract import extract
from ..indicators.url_features import analyze_urls
from ..lang import LanguagePack, select_packs
from ..models import Analysis, Evidence, Indicator, IndicatorType as T, Message, Span, VarietyResult
from ..text import OffsetText, clean, script_profile
from .policy import Policy
from .scorer import score

_TECH_TOKEN = re.compile(r"\S*(?:://|[.@/])\S*")
_NUM = re.compile(r"\d+")
_FP_TOKEN = re.compile(r"[^\W_]+")
#: optional advisory hook: (message, analysis-so-far evidence) -> extra Evidence(source="advisory")
Advisor = Callable[[Message, list[Evidence]], list[Evidence]]


def simhash(tokens: list[str]) -> int:
    if not tokens:
        return 0
    shingles = [" ".join(tokens[i:i + 2]) for i in range(max(1, len(tokens) - 1))]
    v = [0] * 64
    for sh in shingles:
        h = int.from_bytes(hashlib.blake2b(sh.encode(), digest_size=8).digest(), "big")
        for b in range(64):
            v[b] += 1 if (h >> b) & 1 else -1
    return sum(1 << b for b in range(64) if v[b] > 0)


def _overlaps(span: Span, blocked: list[tuple[int, int]]) -> bool:
    return any(span.start < e and s < span.end for s, e in blocked)


@dataclass
class Analyzer:
    policy: Policy = field(default_factory=Policy)
    default_region: str = "SA"
    advisors: list[Advisor] = field(default_factory=list)

    # ------------------------------------------------------------------ brands
    def _brand_mentions(self, pack_texts: dict[str, tuple[LanguagePack, OffsetText]],
                        blocked: list[tuple[int, int]]) -> dict[str, list[Span]]:
        found: dict[str, list[Span]] = {}
        for code, (pack, folded) in pack_texts.items():
            lc = pack.letter_class()
            for b in BRANDS:
                for name in b.names.get(code, ()):
                    pat = re.compile(rf"(?<![{lc}])(?:[وفبلك]|ال)?{re.escape(pack.fold_term(name))}(?![{lc}])"
                                     if code == "ar" else rf"(?<![{lc}0-9]){re.escape(pack.fold_term(name))}(?![{lc}0-9])")
                    for m in pat.finditer(folded.text):
                        sp = folded.span(m.start(), m.end())
                        if not _overlaps(sp, blocked):
                            found.setdefault(b.id, []).append(sp)
        return found

    # ------------------------------------------------------------------ main
    def analyze(self, msg: Message) -> Analysis:
        text = msg.text or ""
        mid = msg.id or hashlib.sha256(f"{msg.sender}|{msg.received_at}|{text}".encode()).hexdigest()[:16]
        cleaned, invisible = clean(text)
        indicators, evidence = extract(cleaned, msg.sender, self.default_region)
        if invisible:
            evidence.append(Evidence("obfuscation.invisible_chars", "obfuscation", spans=invisible[:10],
                                     detail={"count": len(invisible)}))
        blocked = [(i.span.start, i.span.end) for i in indicators
                   if i.span and i.type in (T.URL, T.DOMAIN, T.EMAIL, T.HANDLE, T.WALLET, T.IBAN)]

        from ..lang.base import packs as all_packs
        profile = script_profile(_TECH_TOKEN.sub(" ", cleaned.text))
        selected = select_packs(profile) or []
        primary = selected[0] if selected else None
        pack_texts: dict[str, tuple[LanguagePack, OffsetText]] = {}
        tactics: dict[str, list[Span]] = {}
        for pack in selected:
            folded, ev = pack.fold(cleaned)
            evidence.extend(ev)
            pack_texts[pack.code] = (pack, folded)
            for tm in pack.tactics(folded):
                if not _overlaps(tm.span, blocked):
                    tactics.setdefault(tm.tactic, []).append(tm.span)
        # Latin brand names appear inside messages of any language ("STC", "DHL")
        for pack in all_packs():
            if pack.code == "en" and "en" not in pack_texts:
                pack_texts["en"] = (pack, pack.fold(cleaned)[0])
        variety = primary.variety(pack_texts[primary.code][1]) if primary else VarietyResult("unknown")
        brands = self._brand_mentions(pack_texts, blocked)

        benign_otp = tactics.pop("benign_otp_notice", None)
        for tac, spans in tactics.items():
            evidence.append(Evidence(f"tactic.{tac}", "tactic", spans=_dedupe(spans)))
        for bid, spans in brands.items():
            evidence.append(Evidence("brand.mention", "tactic", spans=_dedupe(spans), detail={"brand": bid}))
        evidence.extend(analyze_urls(indicators))
        evidence.extend(self._context(indicators, tactics, brands, variety, primary, benign_otp, evidence))
        evidence = _merge_same_id(evidence)

        has_vector = any(i.role == "body" and not i.attrs.get("official") and i.type is not T.DOMAIN for i in indicators)
        for adv in self.advisors:
            for e in adv(msg, evidence):
                e.source = "advisory"
                e.category = "advisory"
                evidence.append(e)
        p, logit, verdict, guard = score(evidence, self.policy, has_vector)
        evidence.sort(key=lambda e: -abs(e.weight))

        return Analysis(mid, primary.code if primary else "und", variety, p, verdict, logit, self.policy.bias,
                        evidence, indicators, sorted(tactics), sorted(brands),
                        self._fingerprint(text, indicators, primary), guard, self.policy.version)

    # ------------------------------------------------------------------ context rules
    def _context(self, inds, tactics, brands, variety, primary, benign_otp, evidence) -> list[Evidence]:
        out: list[Evidence] = []
        urls = [i for i in inds if i.type is T.URL]
        unofficial = [u for u in urls if not u.attrs.get("official")]
        own_domain = [u for u in unofficial if not (u.attrs.get("shortener") or u.attrs.get("shared_platform"))]
        opaque = [u for u in unofficial if u.attrs.get("shortener") or u.attrs.get("shared_platform")]
        body_phones = [i for i in inds if i.type is T.PHONE and i.role == "body"]
        sender_phone = [i for i in inds if i.type is T.PHONE and i.role == "sender"]
        handles = [i for i in inds if i.type is T.HANDLE]
        ibans = [i for i in inds if i.type is T.IBAN]
        wallets = [i for i in inds if i.type is T.WALLET]
        contact = body_phones + handles
        sp = lambda items: [i.span for i in items if i.span]          # noqa: E731
        org_claim = bool(brands) or ("authority" in tactics and ("threat" in tactics or "account_update" in tactics
                                                                    or "credential_request" in tactics))
        bl = sorted(brands)

        if brands and own_domain:
            out.append(Evidence("context.brand_link_mismatch", "context", spans=sp(own_domain),
                                detail={"brands": bl, "domains": sorted({u.attrs["registered_domain"] for u in own_domain})}))
        elif brands and opaque:
            out.append(Evidence("context.brand_unverifiable_link", "context", spans=sp(opaque), detail={"brands": bl}))
        elif "authority" in tactics and unofficial:
            out.append(Evidence("context.authority_unverified_link", "context", spans=sp(unofficial)))
        if org_claim and sender_phone:
            out.append(Evidence("context.org_claim_from_personal_number", "context",
                                detail={"sender": sender_phone[0].value, "brands": bl}))
        if org_claim and contact:
            out.append(Evidence("context.org_claim_personal_contact", "context", spans=sp(contact), detail={"brands": bl}))
        if org_claim and primary and variety.label not in primary.formal_varieties and not variety.label.startswith("msa") \
                and variety.label != "unknown":
            out.append(Evidence("context.register_mismatch", "context",
                                detail={"variety": variety.label, "markers": variety.markers.get(variety.label, [])[:6]}))
        foreign = [i for i in body_phones if i.attrs.get("intl_prefix") is not None and i.attrs.get("country") is None]
        if foreign and primary and primary.code == "ar" and tactics:
            out.append(Evidence("context.foreign_contact_number", "context", spans=sp(foreign),
                                detail={"numbers": [i.value for i in foreign]}))
        if ibans:
            out.append(Evidence("payment.iban_in_message", "context", spans=sp(ibans)))
        if wallets:
            out.append(Evidence("payment.crypto_wallet", "context", spans=sp(wallets)))
        vector = unofficial or contact
        if ("credential_request" in tactics or "account_update" in tactics) and unofficial:
            out.append(Evidence("combo.credential_via_link", "combo", spans=sp(unofficial)))
        if "threat" in tactics and vector:
            out.append(Evidence("combo.threat_with_vector", "combo", spans=sp(vector)))
        if "reward" in tactics and "payment_request" in tactics:
            out.append(Evidence("combo.advance_fee", "combo"))
        if "reward" in tactics and vector:
            out.append(Evidence("combo.reward_with_vector", "combo", spans=sp(vector)))
        if ("lure_job" in tactics or "lure_investment" in tactics) and (contact or wallets or "action_contact" in tactics):
            out.append(Evidence("combo.lure_offplatform_contact", "combo", spans=sp(contact + wallets)))
        if urls and not unofficial and not contact:
            out.append(Evidence("benign.official_links_only", "benign", spans=sp(urls)))
        if benign_otp and not unofficial and not contact and "credential_request" not in tactics:
            out.append(Evidence("benign.otp_notice", "benign", spans=_dedupe(benign_otp)))
        return out

    def _fingerprint(self, text: str, inds: list[Indicator], primary: LanguagePack | None) -> int:
        """Template fingerprint: indicators and numbers masked, so two sends of
        the same script with rotated infrastructure get near-identical hashes."""
        chars = list(text)
        for i in sorted((i for i in inds if i.span), key=lambda i: -i.span.start):
            chars[i.span.start:i.span.end] = f" {i.type.value}x "
        t, _ = clean("".join(chars))
        if primary:
            t, _ = primary.fold(t)
        return simhash(_FP_TOKEN.findall(_NUM.sub("0", t.text.lower())))


def _dedupe(spans: list[Span]) -> list[Span]:
    seen, out = set(), []
    for s in sorted(spans, key=lambda s: (s.start, -s.end)):
        if (s.start, s.end) not in seen and not any(o.start <= s.start and s.end <= o.end for o in out):
            seen.add((s.start, s.end)); out.append(s)
    return out


def _merge_same_id(evidence: list[Evidence]) -> list[Evidence]:
    """One evidence item per rule id (brand mentions per brand): repeating a
    keyword ten times must not add ten times the weight."""
    merged: dict[tuple, Evidence] = {}
    for e in evidence:
        k = (e.id, e.detail.get("brand") if e.id == "brand.mention" else None)
        if k in merged:
            m = merged[k]
            m.spans = _dedupe(m.spans + e.spans)
            m.detail.setdefault("also", []).append(e.detail) if e.detail and e.detail != m.detail else None
        else:
            merged[k] = e
    # several brand mentions still count once in the sum
    first_brand = True
    for (rid, _), e in merged.items():
        if rid == "brand.mention":
            if not first_brand:
                e.id = "brand.mention.additional"
            first_brand = False
    return list(merged.values())
