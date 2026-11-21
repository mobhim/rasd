"""Explanations that are faithful by construction.

The scorer is additive, so each reason's contribution is exact. On top of the
ranked reasons we compute counterfactuals: the smallest set of evidence whose
removal would change the verdict — what an analyst needs to judge fragility."""
from __future__ import annotations

from ..analysis.scorer import sigmoid
from .catalog import CATALOG, GUARDS, VERDICT


class _Safe(dict):
    def __missing__(self, k):
        return "—"


def _fmt(eid: str, detail: dict, lang: str) -> str:
    tpl = CATALOG.get(eid, {}).get(lang) or CATALOG.get(eid, {}).get("en") or eid
    d = {k: ("، ".join(map(str, v)) if isinstance(v, list) else v) for k, v in (detail or {}).items()}
    return tpl.format_map(_Safe(d))


def _band(p: float, thresholds: tuple[float, float]) -> str:
    return "malicious" if p >= thresholds[1] else "suspicious" if p >= thresholds[0] else "benign"


def explain(analysis: dict, lang: str = "ar", thresholds: tuple[float, float] = (0.40, 0.80)) -> dict:
    ev = analysis["evidence"]
    logit, bias = analysis["logit"], analysis["bias"]
    pos_total = sum(e["weight"] for e in ev if e["weight"] > 0) or 1.0
    reasons = []
    for e in ev:
        if not e["weight"]:
            continue
        reasons.append({
            "id": e["id"], "text": _fmt(e["id"], e["detail"], lang), "weight": e["weight"],
            "direction": "raises" if e["weight"] > 0 else "lowers",
            "share_of_positive_evidence": round(e["weight"] / pos_total, 3) if e["weight"] > 0 else None,
            "score_without": round(sigmoid(logit - e["weight"]), 4),
            "spans": e["spans"], "source": e["source"],
        })
    # counterfactual: greedily drop the strongest supporting evidence until the band changes
    verdict_now = _band(sigmoid(logit), thresholds)
    cf, running = [], logit
    if verdict_now != "benign":
        for e in sorted((e for e in ev if e["weight"] > 0), key=lambda e: -e["weight"]):
            running -= e["weight"]; cf.append(e["id"])
            if _band(sigmoid(running), thresholds) != verdict_now:
                break
        else:
            cf = []
    v = VERDICT.get(lang, VERDICT["en"])[analysis["verdict"]]
    top = [r["text"] for r in reasons if r["weight"] > 0][:3]
    if lang == "ar":
        summary = f"الرسالة {v} (درجة الخطر {analysis['score']:.0%})." + (" أهم الأسباب: " + "؛ ".join(top) + "." if top else " لا توجد أدلة خطر ذات وزن.")
    else:
        summary = f"Message is {v} (risk {analysis['score']:.0%})." + (" Main reasons: " + "; ".join(top) + "." if top else " No weighted risk evidence.")
    return {
        "summary": summary, "verdict": analysis["verdict"], "score": analysis["score"],
        "model": {"type": "additive log-odds", "bias": bias, "logit": logit, "policy_version": analysis.get("policy_version"),
                  "formula": "score = sigmoid(bias + Σ weight_i)"},
        "reasons": reasons,
        "guard": GUARDS.get(analysis.get("guard_applied") or "", {}).get(lang),
        "counterfactual": {"remove_to_change_verdict": cf,
                           "note": ("أصغر مجموعة أدلة (بالترتيب) يؤدي حذفها إلى تغيّر الحكم" if lang == "ar"
                                    else "smallest ordered set of evidence whose removal changes the verdict")} if cf else None,
        "variety": analysis["variety"],
    }


def explain_campaign(c: dict, lang: str = "ar") -> dict:
    shared = [d for d in c["indicators"] if d["messages"] >= 2]
    lines = []
    if lang == "ar":
        level = {"high": "مرتفعة", "medium": "متوسطة", "low": "منخفضة"}[c["confidence"]]
        lines.append(f"{c['size']} رسالة رُبطت في حملة واحدة بثقة {level}.")
        for d in shared[:6]:
            lines.append(f"• {d['messages']} رسائل تشترك في {d['type']}: {d['value']}")
        if "corroborated" in c["link_kinds"]:
            lines.append("• بعض الروابط مبنية على إشارتين ضعيفتين مستقلتين معًا (رقم المرسل + القالب/المسار)، لا على مورد مشترك.")
        if c["bridges"]:
            lines.append("• تنبيه: الحملة تنقسم إلى مجموعتين لولا: " + "، ".join(c["bridges"][:3]) + " — تحقّق من هذا المورد قبل اعتماد الربط.")
        for r in c["related"]:
            lines.append(f"• حملة {r['campaign_id']} تستخدم نصًا مشابهًا ببنية مختلفة — لم تُدمج لأن تشابه النص ليس دليلًا كافيًا.")
        if c["associated_low_score_messages"]:
            lines.append(f"• {len(c['associated_low_score_messages'])} رسالة منخفضة الدرجة تشارك موارد الحملة — يُنصح بمراجعتها.")
    else:
        lines.append(f"{c['size']} messages linked into one campaign with {c['confidence']} confidence.")
        for d in shared[:6]:
            lines.append(f"• {d['messages']} messages share {d['type']}: {d['value']}")
        if "corroborated" in c["link_kinds"]:
            lines.append("• Some links rest on two independent weak signals combined (sender number + template/path), not a shared resource.")
        if c["bridges"]:
            lines.append("• Caution: the campaign would split without: " + ", ".join(c["bridges"][:3]) + " — verify before relying on the link.")
        for r in c["related"]:
            lines.append(f"• Campaign {r['campaign_id']} uses similar text on different infrastructure — not merged: text similarity is not sufficient.")
        if c["associated_low_score_messages"]:
            lines.append(f"• {len(c['associated_low_score_messages'])} low-score messages share campaign resources — review advised.")
    return {"campaign_id": c["id"], "confidence": c["confidence"], "confidence_reason": c["confidence_reason"], "narrative": lines}
