import re

import pytest

from rasd.analysis import Analyzer, Policy
from rasd.indicators import extract, iban_ok, normalize_phone
from rasd.indicators.psl import split_host
from rasd.indicators.url_features import impersonated_brand
from rasd.lang import LanguagePack, register
from rasd.lang.arabic import ArabicPack
from rasd.lang.base import _REGISTRY
from rasd.models import Evidence, Message
from rasd.privacy import pseudonymize, redact
from rasd.text import clean
from rasd.xai import explain

A = Analyzer()


def run(text, sender=None):
    return A.analyze(Message(text, sender=sender))


def keys(text, sender=None):
    return {i.key for i in extract(clean(text)[0], sender)[0]}


# ---------------------------------------------------------------- text layer
def test_spans_point_into_original_text_after_normalisation():
    raw = "عـــاجل: حسا​بك موقوف، حدِّث بياناتك hxxps://alrajhi-update[.]top/x"
    a = run(raw)
    for e in a.evidence:
        for s in e.spans:
            assert raw[s.start:s.end] == s.text
    url = next(i for i in a.indicators if i.type.value == "url")
    assert url.span.text == "hxxps://alrajhi-update[.]top/x"


def test_arabic_folding_and_deobfuscation():
    pack = ArabicPack()
    folded, ev = pack.fold(clean("ع ا ج ل تحديث بيانااااتك")[0])
    assert "عاجل" in folded.text and "بياناتك" in folded.text
    assert any(e.id == "obfuscation.spaced_letters" for e in ev)
    folded, ev = pack.fold(clean("عزیزی العمیل بطاقتک")[0])       # Persian yeh / keheh
    assert "عزيزي العميل بطاقتك" in folded.text
    assert any(e.id == "obfuscation.lookalike_letters" for e in ev)


@pytest.mark.parametrize("text,label", [
    ("وش تبي الحين؟ ابغى اعرف وينك", "gulf"),
    ("عايز اعرف ازاي ده حصل دلوقتي", "egyptian"),
    ("شو بدك هلق؟ كتير منيح هيك", "levantine"),
    ("واش كاين شي حاجة دابا؟ بزاف ديال الخدمة", "maghrebi"),
    ("نود إفادتكم بأنه سوف يتم تحديث النظام خلال الأسبوع", "msa"),
])
def test_dialect_identification(text, label):
    assert run(text).variety.label == label


# ---------------------------------------------------------------- indicators
def test_phone_normalisation_variants_collapse_to_one_key():
    forms = ["0551234567", "٠٥٥١٢٣٤٥٦٧", "+966 55 123 4567", "00966551234567", "966551234567", "055 123 4567",
             "https://wa.me/966551234567", "رقم0551234567"]
    assert {next(k for k in keys(f) if k.startswith("phone:")) for f in forms} == {"phone:+966551234567"}
    assert normalize_phone("01012345678")[0] == "+201012345678"
    assert normalize_phone("1234567890") is None            # not confidently a phone
    assert not any(k.startswith("phone:") for k in keys("المبلغ 1500.50 ريال رقم الطلب 1234567890"))


def test_iban_checksum_gate():
    assert iban_ok("SA0380000000608010167519")
    assert not iban_ok("SA0380000000608010167518")
    assert "iban:SA0380000000608010167519" in keys("حول على SA03 8000 0000 6080 1016 7519")
    assert not any(k.startswith("iban:") for k in keys("SA03 8000 0000 6080 1016 7518"))


def test_defanged_and_shared_platform_urls():
    k = keys("hxxps://secure-login[.]example/a و bit.ly/3xYz و t.me/Some_Channel و www.stc.com.sa/offers")
    assert {"domain:secure-login.example", "url:bit.ly/3xYz", "handle:telegram:some_channel", "domain:stc.com.sa"} <= k
    inds = {i.key: i for i in extract(clean("bit.ly/3xYz www.stc.com.sa/x a.web.app/z")[0])[0]}
    assert inds["domain:bit.ly"].linkable is False         # shortener domain never links campaigns
    assert inds["url:bit.ly/3xYz"].linkable is True         # ...but the short path does
    assert inds["domain:stc.com.sa"].linkable is False      # official domain never links
    assert inds["domain:a.web.app"].linkable is True


def test_private_suffix_and_brand_impersonation():
    assert split_host("login.alahli.com.verify-id.web.app")[1] == "verify-id.web.app"
    assert split_host("www.alrajhibank.com.sa")[1] == "alrajhibank.com.sa"
    assert impersonated_brand("alrajhi-update")[:2] == ("alrajhi", "exact")
    assert impersonated_brand("paypa1-secure")[:2] == ("paypal", "homoglyph")
    assert impersonated_brand("netfliix")[:2] == ("netflix", "typosquat")
    assert impersonated_brand("gardening-tips") is None


def test_wallet_requires_valid_checksum():
    assert any(k.startswith("wallet:tron:") for k in keys("TQn9Y2khEsLJW1ChVWFMSMeRDow5KcbLSE"))
    assert not any(k.startswith("wallet:") for k in keys("TQn9Y2khEsLJW1ChVWFMSMeRDow5KcbLSF"))


# ---------------------------------------------------------------- scoring + guards
def test_phish_vs_legit_bank_messages():
    assert run("عزيزي العميل تم إيقاف بطاقتك لدى مصرف الراجحي، حدث بياناتك عبر الرابط https://alrajhi-update.example/login",
               "0500012345").verdict == "malicious"
    assert run("رمز التحقق 482913 لا تشاركه مع أحد. مصرف الراجحي", "AlRajhiBank").verdict == "benign"
    assert run("تم إيداع راتبك 8500 ريال. للتفاصيل https://www.alrajhibank.com.sa", "AlRajhiBank").verdict == "benign"
    assert run("وينك يا رجال تعال بسرعة العشا جاهز", "0500011111").verdict == "benign"


def test_dialect_scam_is_caught():
    assert run("يا فندم الفيزا بتاعتك اتقفلت ابعتلي الكود اللي جالك دلوقتي. البنك الأهلي المصري", "01000123456").verdict == "malicious"
    assert run("هلا معك موظف البنك بطاقتك راح تتقفل الحين عطني الرمز اللي وصلك", "0500012345").verdict != "benign"


def test_guard_tone_alone_cannot_convict():
    hot = Policy(bias=5.0)                                   # absurdly aggressive policy
    a = Analyzer(policy=hot).analyze(Message("عاجل جدا سيتم إيقاف حسابك فورا"))
    assert a.score > 0.9 and a.verdict == "suspicious" and a.guard_applied == "no_actionable_vector"


def test_guard_advisory_signal_is_capped_and_cannot_convict():
    def shouting_llm(msg, evidence):
        return [Evidence("advisory.llm", "advisory", detail={"weight": 50.0, "rationale": "trust me"})]
    text = "مبروك ربحت معنا 50000 ريال للاستلام تواصل واتساب 0500012345 وادفع رسوم التحويل 200 ريال"
    base = run(text)
    adv = Analyzer(advisors=[shouting_llm]).analyze(Message(text))
    assert base.verdict == "suspicious"
    assert adv.logit - base.logit == pytest.approx(A.policy.advisory_cap)
    assert adv.verdict == "suspicious" and adv.guard_applied == "advisory_cannot_convict"


def test_repeating_a_keyword_does_not_stack_weight():
    assert run("عاجل").logit == run("عاجل عاجل عاجل عاجل").logit


def test_explanation_is_exact_and_counterfactual_holds():
    a = run("عزيزي العميل تم إيقاف بطاقتك، حدث بياناتك https://alrajhi-update.example/login").to_dict()
    assert a["logit"] == pytest.approx(a["bias"] + sum(e["weight"] for e in a["evidence"]), abs=1e-3)
    ex = explain(a, "ar")
    cf = set(ex["counterfactual"]["remove_to_change_verdict"])
    remaining = a["bias"] + sum(e["weight"] for e in a["evidence"] if e["id"] not in cf)
    assert remaining < a["logit"] and "الرسالة" in ex["summary"]
    assert all(r["text"] and "{" not in r["text"] for r in ex["reasons"])


# ---------------------------------------------------------------- privacy
def test_redaction_is_length_preserving_and_keeps_indicators():
    text = "بطاقتي 4111 1111 1111 1111 والرمز 482913 تواصل 0551234567 هويتي 1012345678"
    a = run(text)
    red, counts = redact(text, a.indicators)
    assert len(red) == len(text) and "4111" not in red and "482913" not in red and "1012345678" not in red
    assert "0551234567" in red and counts == {"card": 1, "national_id": 1, "code": 1}


def test_recipient_pseudonym_is_keyed_and_stable():
    assert pseudonymize("0551234567", b"k1") == pseudonymize("055 123 4567", b"k1") != pseudonymize("0551234567", b"k2")
    assert "0551234567" not in pseudonymize("0551234567", b"k1")


# ---------------------------------------------------------------- extensibility
def test_new_language_plugs_in_without_touching_the_pipeline():
    class Turkish(LanguagePack):
        code = "tr-test"

        def affinity(self, profile):
            return 0.99 if profile.get("latin", 0) > 0.5 else 0.0

        def fold(self, cleaned):
            return cleaned.map_chars(str.lower), []

        def fold_term(self, term):
            return term.lower()

        def tactic_patterns(self):
            return {"threat": [re.compile(r"hesabınız askıya alındı")], "action_link": [re.compile(r"bağlantıya tıklayın")]}

    register(Turkish())
    try:
        a = run("Hesabınız askıya alındı, bağlantıya tıklayın: http://paypa1-secure.example/login")
        assert a.language == "tr-test" and {"threat", "action_link"} <= set(a.tactics) and a.verdict == "malicious"
    finally:
        _REGISTRY.pop("tr-test")
