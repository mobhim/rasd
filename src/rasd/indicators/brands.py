"""Seed registry of frequently impersonated brands.

IMPORTANT: this is a seed for development and tests. `official_domains` drive
security decisions (a link to an official domain lowers risk, a brand mention
with a non-official link raises it), so a deployment MUST review and maintain
this list with the brand owners; load an override with `load_registry()`."""
from __future__ import annotations

import json
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Brand:
    id: str
    sector: str                       # bank | gov | telecom | delivery | payment | tech | retail
    domains: tuple[str, ...]          # official registered domains
    keys: tuple[str, ...]             # latin tokens seen in impersonating hostnames
    names: dict = field(default_factory=dict)   # lang -> surface names in running text


def _b(id, sector, domains, keys, ar=(), en=()):
    return Brand(id, sector, tuple(domains), tuple(keys), {"ar": tuple(ar), "en": tuple(en)})


BRANDS: list[Brand] = [
    _b("alrajhi", "bank", ["alrajhibank.com.sa"], ["alrajhi", "rajhi", "alrajhibank"], ["الراجحي", "مصرف الراجحي"], ["al rajhi", "alrajhi"]),
    _b("snb", "bank", ["alahli.com"], ["alahli", "snb", "ahli"], ["البنك الأهلي", "الأهلي السعودي", "البنك الاهلي السعودي"], ["snb", "alahli"]),
    _b("riyadbank", "bank", ["riyadbank.com"], ["riyadbank"], ["بنك الرياض"], ["riyad bank"]),
    _b("alinma", "bank", ["alinma.com"], ["alinma"], ["مصرف الإنماء", "الإنماء"], ["alinma"]),
    _b("stc", "telecom", ["stc.com.sa"], ["stc"], ["اس تي سي", "الاتصالات السعودية"], ["stc"]),
    _b("stcpay", "payment", ["stcpay.com.sa"], ["stcpay"], ["اس تي سي باي"], ["stc pay", "stcpay"]),
    _b("mobily", "telecom", ["mobily.com.sa"], ["mobily"], ["موبايلي"], ["mobily"]),
    _b("zain", "telecom", ["zain.com"], ["zain"], ["شركة زين", "زين السعودية", "زين الكويت"], ["zain"]),
    _b("absher", "gov", ["absher.sa", "moi.gov.sa"], ["absher"], ["أبشر", "منصة أبشر"], ["absher"]),
    _b("najiz", "gov", ["najiz.sa"], ["najiz"], ["ناجز"], ["najiz"]),
    _b("zatca", "gov", ["zatca.gov.sa"], ["zatca"], ["هيئة الزكاة", "الزكاة والضريبة"], ["zatca"]),
    _b("sama", "gov", ["sama.gov.sa"], ["sama"], ["البنك المركزي السعودي", "ساما"], ["sama"]),
    _b("spl", "delivery", ["splonline.com.sa"], ["spl", "splonline", "saudipost"], ["البريد السعودي", "سبل أونلاين"], ["saudi post", "spl"]),
    _b("smsa", "delivery", ["smsaexpress.com"], ["smsa", "smsaexpress"], ["سمسا"], ["smsa"]),
    _b("aramex", "delivery", ["aramex.com"], ["aramex"], ["أرامكس"], ["aramex"]),
    _b("dhl", "delivery", ["dhl.com"], ["dhl"], ["دي اتش ال"], ["dhl"]),
    _b("fedex", "delivery", ["fedex.com"], ["fedex"], ["فيديكس"], ["fedex"]),
    _b("emiratesnbd", "bank", ["emiratesnbd.com"], ["emiratesnbd", "enbd"], ["الإمارات دبي الوطني"], ["emirates nbd"]),
    _b("adcb", "bank", ["adcb.com"], ["adcb"], ["بنك أبوظبي التجاري"], ["adcb"]),
    _b("etisalat", "telecom", ["etisalat.ae"], ["etisalat"], ["اتصالات الإمارات", "شركة اتصالات"], ["etisalat"]),
    _b("du", "telecom", ["du.ae"], [], ["شركة دو"], []),
    _b("emiratespost", "delivery", ["emiratespost.ae"], ["emiratespost"], ["بريد الإمارات"], ["emirates post"]),
    _b("nbe", "bank", ["nbe.com.eg"], ["nbe", "ahlyeg"], ["البنك الأهلي المصري"], ["nbe"]),
    _b("banquemisr", "bank", ["banquemisr.com"], ["banquemisr"], ["بنك مصر"], ["banque misr"]),
    _b("cib", "bank", ["cibeg.com"], ["cibeg"], ["البنك التجاري الدولي"], ["cib"]),
    _b("vodafone", "telecom", ["vodafone.com.eg", "vodafone.com"], ["vodafone"], ["فودافون", "فودافون كاش"], ["vodafone"]),
    _b("fawry", "payment", ["fawry.com"], ["fawry"], ["فوري باي", "خدمة فوري", "ماكينة فوري"], ["fawry"]),
    _b("nbk", "bank", ["nbk.com"], ["nbk"], ["بنك الكويت الوطني"], ["nbk"]),
    _b("kfh", "bank", ["kfh.com"], ["kfh"], ["بيت التمويل الكويتي"], ["kfh"]),
    _b("qnb", "bank", ["qnb.com"], ["qnb"], ["بنك قطر الوطني"], ["qnb"]),
    _b("paypal", "payment", ["paypal.com"], ["paypal"], ["باي بال"], ["paypal"]),
    _b("apple", "tech", ["apple.com", "icloud.com"], ["apple", "icloud", "appleid"], ["آبل آي دي", "أبل آي دي", "حساب آبل", "حساب أبل", "آي كلاود", "ايكلاود"], ["apple", "icloud"]),
    _b("microsoft", "tech", ["microsoft.com", "live.com", "office.com"], ["microsoft", "office365", "outlook"], ["مايكروسوفت"], ["microsoft"]),
    _b("netflix", "tech", ["netflix.com"], ["netflix"], ["نتفليكس"], ["netflix"]),
    _b("amazon", "retail", ["amazon.com", "amazon.sa", "amazon.ae", "amazon.eg"], ["amazon"], ["أمازون"], ["amazon"]),
    _b("noon", "retail", ["noon.com"], ["noon"], ["نون دوت كوم", "متجر نون", "تطبيق نون"], ["noon"]),
    _b("whatsapp", "tech", ["whatsapp.com"], ["whatsapp"], [], []),
]


def load_registry(path: str) -> None:
    with open(path, encoding="utf8") as fh:
        data = json.load(fh)
    BRANDS[:] = [Brand(d["id"], d["sector"], tuple(d["domains"]), tuple(d.get("keys", ())), d.get("names", {})) for d in data]
    official_domains.cache_clear() if hasattr(official_domains, "cache_clear") else None


def official_domains() -> dict[str, str]:
    return {d: b.id for b in BRANDS for d in b.domains}
