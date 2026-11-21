"""Arabic language pack: orthographic folding, de-obfuscation, dialect
identification and tactic matching for MSA and regional dialects."""
from __future__ import annotations

import re
from functools import lru_cache

from ..models import Evidence, VarietyResult
from ..text import OffsetText
from .arabic_lexicon import DIALECT_MARKERS, TACTIC_TERMS
from .base import LanguagePack, register

_TASHKEEL = frozenset(chr(c) for c in list(range(0x064B, 0x0660)) + [0x0670, 0x0640] + list(range(0x06D6, 0x06EE)))
_FOLD = {
    "أ": "ا", "إ": "ا", "آ": "ا", "ٱ": "ا", "ٲ": "ا", "ٳ": "ا",
    "ى": "ي", "ة": "ه", "ؤ": "و", "ئ": "ي",
    # Persian/Urdu/Kurdish look-alikes commonly used to dodge keyword filters
    "ک": "ك", "ڪ": "ك", "گ": "ك", "ی": "ي", "ې": "ي", "ێ": "ي", "ے": "ي",
    "ە": "ه", "ہ": "ه", "ھ": "ه", "ۀ": "ه", "ۃ": "ه", "ڤ": "ف", "پ": "ب", "چ": "ج", "ژ": "ز",
    "ٹ": "ت", "ڈ": "د", "ڑ": "ر", "ں": "ن", "ۆ": "و", "ۇ": "و", "ۈ": "و", "ۋ": "و",
}
_LOOKALIKE = frozenset("کڪیېێےەہھۀۃ")
AR = "ء-ي"
_ELONG = re.compile(rf"([{AR}])\1{{2,}}")
_SPACED = re.compile(rf"(?<![{AR}])(?:[{AR}][ .\-_*•·|]){{3,}}[{AR}](?![{AR}])")
_TOKEN = re.compile(rf"[{AR}]+")
_PRON = "(?:ك|كم|كي|كن|ي|نا|ه|ها|هم)"
_PROCLITIC = rf"(?<![{AR}])(?:[وف])?(?:[بلك])?(?:ال|ل)?"


def _fold_char(ch: str) -> str:
    if ch in _TASHKEEL:
        return ""
    return _FOLD.get(ch, ch.lower())


def fold_str(s: str) -> str:
    return "".join(_fold_char(c) for c in s)


def _fold_pattern(s: str) -> str:
    """Fold Arabic letters only — never touch regex escapes such as \\S."""
    return "".join(c if c.isascii() else _fold_char(c) for c in s)


def compile_term(term: str) -> re.Pattern:
    t = re.sub(r"ة~", f"(?:ة|ت{_PRON})", term)
    t = re.sub(r"~", f"{_PRON}?", t)
    t = _fold_pattern(t).replace(" ", r"\s+")
    return re.compile(rf"{_PROCLITIC}(?:{t})(?![{AR}])")


class ArabicPack(LanguagePack):
    code = "ar"
    formal_varieties = frozenset({"msa"})

    def affinity(self, script_profile: dict[str, float]) -> float:
        return script_profile.get("arabic", 0.0)

    def letter_class(self) -> str:
        return AR

    def fold_term(self, term: str) -> str:
        return fold_str(term)

    def fold(self, cleaned: OffsetText) -> tuple[OffsetText, list[Evidence]]:
        evidence: list[Evidence] = []
        look = [cleaned.span(i, i + 1) for i, c in enumerate(cleaned.text) if c in _LOOKALIKE]
        if look:
            evidence.append(Evidence("obfuscation.lookalike_letters", "obfuscation", spans=look[:10],
                                     detail={"count": len(look)}))
        t = cleaned.map_chars(_fold_char)
        t = t.regex_sub(_ELONG, r"\1")
        spaced = [t.span(m.start(), m.end()) for m in _SPACED.finditer(t.text)]
        if spaced:
            evidence.append(Evidence("obfuscation.spaced_letters", "obfuscation", spans=spaced))
            t = t.regex_sub(_SPACED, lambda m: re.sub(r"[ .\-_*•·|]", "", m.group(0)))
        return t, evidence

    @lru_cache(maxsize=1)
    def tactic_patterns(self) -> dict[str, list[re.Pattern]]:
        return {k: [compile_term(t) for t in v] for k, v in TACTIC_TERMS.items()}

    @lru_cache(maxsize=1)
    def _markers(self) -> dict[str, dict[str, float]]:
        return {fold_str(k): v for k, v in DIALECT_MARKERS.items()}

    def variety(self, folded: OffsetText) -> VarietyResult:
        """Transparent lexical dialect identification. It reports the markers
        it used; it is deliberately replaceable by a trained DID model behind
        the same interface (see docs/03-architecture.md)."""
        markers = self._markers()
        scores: dict[str, float] = {}
        seen: dict[str, list[str]] = {}
        n_tokens = 0
        for m in _TOKEN.finditer(folded.text):
            tok = m.group(0)
            n_tokens += 1
            hit = markers.get(tok)
            if hit is None and len(tok) > 2 and tok[0] in "وفب":
                hit = markers.get(tok[1:])
            if not hit:
                continue
            for v, w in hit.items():
                scores[v] = scores.get(v, 0.0) + w
                if tok not in seen.setdefault(v, []):
                    seen[v].append(tok)
        if n_tokens == 0:
            return VarietyResult("unknown")
        dialects = {k: v for k, v in scores.items() if k != "msa"}
        if not dialects or max(dialects.values()) < 1.0:
            label = "msa"
        else:
            top = max(dialects, key=lambda k: dialects[k])
            label = top if dialects[top] >= scores.get("msa", 0.0) else "msa_mixed_" + top
        return VarietyResult(label, {k: round(v, 2) for k, v in scores.items()}, seen)


register(ArabicPack())
