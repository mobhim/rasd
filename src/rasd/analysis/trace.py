"""Normalisation trace: what the engine did to the text before reading it.

Each stage is the actual intermediate text produced by the pipeline functions
(`text.clean`, the language pack's `fold`, `privacy.redact`), with counts of
what changed. Nothing here re-implements the pipeline; it re-runs it and
records the intermediate states so they can be shown to an analyst."""
from __future__ import annotations

import unicodedata

from ..lang import select_packs
from ..models import Analysis
from ..privacy import redact
from ..text import INVISIBLE, clean, script_profile

_AR_DIGITS = set("٠١٢٣٤٥٦٧٨٩۰۱۲۳۴۵۶۷۸۹")
_TASHKEEL = {chr(c) for c in list(range(0x064B, 0x0660)) + [0x0670, 0x0640]}
_HAMZA_ETC = set("أإآٱؤئىة")
_LOOKALIKE = set("کڪیېێےەہھۀۃ")


def _count(text: str, chars: set) -> tuple[int, list[str]]:
    hits = [c for c in text if c in chars]
    return len(hits), sorted(set(hits))[:8]


def trace(text: str, analysis: Analysis) -> dict:
    stages = []
    inv, _ = _count(text, set(INVISIBLE))
    dig, dig_ex = _count(text, _AR_DIGITS)
    nfkc = sum(1 for c in text if ord(c) > 0x7F and c not in INVISIBLE and c not in _AR_DIGITS
               and unicodedata.normalize("NFKC", c) != c)
    cleaned, _ = clean(text)
    stages.append({"id": "original", "title": "النص الأصلي كما وصل", "text": text, "changes": []})
    stages.append({"id": "clean", "title": "تنظيف محايد لغويًا", "text": cleaned.text, "changes": [
        c for c in (
            {"kind": "invisible_removed", "label": "أحرف غير مرئية حُذفت", "count": inv},
            {"kind": "digits_folded", "label": "أرقام عربية-هندية وُحّدت", "count": dig, "examples": dig_ex},
            {"kind": "nfkc", "label": "أشكال عرض/حروف مزخرفة وُحّدت (NFKC)", "count": nfkc},
        ) if c["count"]]})
    packs = select_packs(script_profile(cleaned.text))
    if packs and packs[0].code == "ar":
        folded, ev = packs[0].fold(cleaned)
        tk, _ = _count(cleaned.text, _TASHKEEL)
        hz, hz_ex = _count(cleaned.text, _HAMZA_ETC)
        lk, lk_ex = _count(cleaned.text, _LOOKALIKE)
        spaced = sum(len(e.spans) for e in ev if e.id == "obfuscation.spaced_letters")
        stages.append({"id": "fold", "title": "توحيد الإملاء العربي وكشف التمويه", "text": folded.text, "changes": [
            c for c in (
                {"kind": "diacritics", "label": "تشكيل وتطويل حُذف", "count": tk},
                {"kind": "orthography", "label": "همزات وتاء مربوطة وألف مقصورة وُحّدت", "count": hz, "examples": hz_ex},
                {"kind": "lookalike", "label": "حروف فارسية/أردية شبيهة رُدّت إلى العربية", "count": lk, "examples": lk_ex},
                {"kind": "spaced", "label": "كلمات مفككة الأحرف أُعيد ضمّها", "count": spaced},
            ) if c["count"]]})
    elif packs:
        folded, _ = packs[0].fold(cleaned)
        stages.append({"id": "fold", "title": f"توحيد خاص بلغة {packs[0].code}", "text": folded.text, "changes": []})
    red, counts = redact(text, analysis.indicators)
    stages.append({"id": "redact", "title": "النسخة الآمنة للخصوصية (ما يُخزَّن)", "text": red, "changes": [
        c for c in (
            {"kind": "card", "label": "أرقام بطاقات طُمست", "count": counts["card"]},
            {"kind": "code", "label": "رموز تحقق طُمست", "count": counts["code"]},
            {"kind": "national_id", "label": "أرقام هوية طُمست", "count": counts["national_id"]},
        ) if c["count"]]})
    return {"stages": stages, "language": analysis.language, "variety": analysis.variety.to_dict()}
