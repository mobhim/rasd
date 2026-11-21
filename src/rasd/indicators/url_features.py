"""Lexical URL analysis — offline, no fetching. Emits evidence for brand
impersonation in hostnames, typosquats, abused TLDs and structural tricks."""
from __future__ import annotations

import re

from ..models import Evidence, Indicator, IndicatorType
from .brands import BRANDS

SUSPICIOUS_TLDS = frozenset("top xyz icu click shop online site live cfd sbs buzz rest cyou tk ml ga cf gq vip work "
                            "link bond lol mom quest monster win bid loan men pw cc ws su".split())
SENSITIVE_PATH = re.compile(r"(?:^|[/\-_.])(login|signin|verify|verification|update|secure|account|confirm|"
                            r"auth|otp|pay|payment|billing|unlock|recover|wallet|kyc|refund|track|claim)(?:$|[/\-_.?])")
_HOMO = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "$": "s"})


def _homofold(tok: str) -> str:
    return tok.translate(_HOMO).replace("rn", "m").replace("vv", "w")


def _dl1(a: str, b: str) -> bool:
    """Damerau-Levenshtein distance == 1."""
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        diff = [i for i in range(len(a)) if a[i] != b[i]]
        return len(diff) == 1 or (len(diff) == 2 and diff[1] == diff[0] + 1
                                  and a[diff[0]] == b[diff[1]] and a[diff[1]] == b[diff[0]])
    if len(a) > len(b):
        a, b = b, a
    i = 0
    while i < len(a) and a[i] == b[i]:
        i += 1
    return a[i:] == b[i + 1:]


def impersonated_brand(host_part: str) -> tuple[str, str, str] | None:
    """-> (brand_id, kind, token) where kind is exact|embedded|homoglyph|typosquat."""
    labels = [l for l in re.split(r"[.]", host_part) if l]
    toks = [t for l in labels for t in re.split(r"[^a-z0-9$]+", l) if t]
    for tok in toks:
        folded = _homofold(tok)
        alpha = re.sub(r"\d+$", "", tok)
        for b in BRANDS:
            for key in b.keys:
                if tok == key or alpha == key:
                    return b.id, "exact", tok
                if folded == key:
                    return b.id, "homoglyph", tok
                if len(key) >= 6 and key in folded:
                    return b.id, "embedded", tok
                if len(key) >= 6 and len(tok) >= 5 and _dl1(folded, key):
                    return b.id, "typosquat", tok
    return None


def analyze_urls(indicators: list[Indicator]) -> list[Evidence]:
    ev: list[Evidence] = []
    for ind in indicators:
        if ind.type is not IndicatorType.URL:
            continue
        a, spans = ind.attrs, [ind.span] if ind.span else []
        d = {"url": ind.value, "domain": a["registered_domain"]}
        if a.get("official"):
            ev.append(Evidence("url.official_domain", "benign", spans=spans, detail={**d, "brand": a["official"]}))
            continue
        if a.get("shortener"):
            ev.append(Evidence("url.shortener", "url", spans=spans, detail=d))
            continue
        if a.get("shared_platform"):
            continue
        host = a["host"]
        suffix = a.get("suffix") or ""
        name_part = host[: -len(suffix) - 1] if suffix and host.endswith(suffix) else host
        hit = None if a.get("ip_host") else impersonated_brand(name_part)
        if hit:
            brand, kind, tok = hit
            rid = "url.brand_impersonation" if kind in ("exact", "embedded") else "url.typosquat"
            ev.append(Evidence(rid, "url", spans=spans, detail={**d, "brand": brand, "kind": kind, "token": tok}))
        else:
            ph = impersonated_brand(re.sub(r"[/_\-]", ".", a.get("path") or ""))
            if ph and ph[1] in ("exact", "embedded"):
                ev.append(Evidence("url.brand_in_path", "url", spans=spans, detail={**d, "brand": ph[0]}))
        tld = suffix.split(".")[-1] if suffix else ""
        if a.get("ip_host"):
            ev.append(Evidence("url.ip_host", "url", spans=spans, detail=d))
        if a.get("private_suffix"):
            ev.append(Evidence("url.free_hosting", "url", spans=spans, detail={**d, "suffix": suffix}))
        elif tld in SUSPICIOUS_TLDS:
            ev.append(Evidence("url.suspicious_tld", "url", spans=spans, detail={**d, "tld": tld}))
        if a.get("idn"):
            ev.append(Evidence("url.idn_host", "url", spans=spans, detail=d))
        if a.get("userinfo"):
            ev.append(Evidence("url.userinfo_trick", "url", spans=spans, detail=d))
        if (a.get("subdomain") or "").count(".") >= 2:
            ev.append(Evidence("url.deep_subdomains", "url", spans=spans, detail=d))
        if SENSITIVE_PATH.search((a.get("subdomain") or "") + "/" + (a.get("path") or "")):
            ev.append(Evidence("url.sensitive_keyword", "url", spans=spans, detail=d))
        if a.get("scheme") == "http":
            ev.append(Evidence("url.plain_http", "url", spans=spans, detail=d))
    return ev
