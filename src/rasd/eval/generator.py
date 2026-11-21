"""Synthetic test bench with campaign-level ground truth.

WHY SYNTHETIC: no public Arabic dataset carries campaign labels (see
docs/01-research-gap.md). This generator produces a corpus where the truth
about "who sent what with which infrastructure" is known by construction.

SAFETY: every domain is under an RFC 2606/6761 reserved TLD (.example/.test/
.invalid) and can never resolve. Phone numbers use the pattern 05000xxxxx /
+201000xxxxx and IBANs use the non-existent bank code 00; any resemblance to a
real subscriber or account is coincidental and nothing here is ever contacted.

LIMITATION (stated wherever results are reported): templates and the detection
lexicon were authored by the same team, so detection figures on this corpus
are an upper bound, not field performance. The corpus exists to test
*properties* (robustness to obfuscation, behaviour under template reuse and
infrastructure rotation, hard negatives), not to claim real-world accuracy."""
from __future__ import annotations

import hashlib
import random
from datetime import datetime, timedelta, timezone

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
AR_DIGITS = str.maketrans("0123456789", "٠١٢٣٤٥٦٧٨٩")
LOOKALIKE = str.maketrans({"ك": "ک", "ي": "ی", "ه": "ە"})

# (dialect, text). Slots: {b}=brand name {url} {phone} {iban} {handle} {wallet} {amt} {h}
MAL: dict[str, list[tuple[str, str]]] = {
    "bank": [
        ("msa", "عزيزي العميل، تم تعليق بطاقتك لدى {b} لعدم تحديث البيانات. يرجى التحديث خلال {h} ساعة عبر الرابط {url}"),
        ("msa", "{b}: تم إيقاف حسابك مؤقتاً بسبب نشاط غير اعتيادي. لإعادة التفعيل ادخل على الرابط التالي {url}"),
        ("msa", "تنبيه من {b}: سيتم تجميد حسابك اليوم. لتفادي ذلك يجب توثيق هويتك فوراً {url}"),
        ("msa", "عميلنا العزيز نفيدكم بانتهاء صلاحية بطاقة الصراف، لتجديدها أدخل بيانات البطاقة والرمز السري هنا {url}"),
        ("gulf", "هلا طال عمرك معك موظف {b}، بطاقتك راح تتوقف الحين، ادخل الرابط وحدث بياناتك {url}"),
        ("gulf", "السلام عليكم معك خدمة العملاء {b} حسابك انقفل، عطني الرمز اللي وصلك على جوالك عشان نفتحه لك. للتواصل {phone}"),
        ("egyptian", "يا فندم الفيزا بتاعتك اتقفلت، ابعتلي الكود اللي جالك دلوقتي علشان نفعلها تاني. {b} {phone}"),
        ("egyptian", "مساء الخير حضرتك معاك {b}، الحساب بتاعك هيتقفل النهارده، دوس على اللينك ده وحدث بياناتك {url}"),
        ("levantine", "مرحبا معك {b}، حسابك رح يتسكر هلق، كبس عالرابط وفوت بياناتك {url}"),
        ("maghrebi", "سلام، لكونط ديالك ف {b} غادي يتبلوكا دابا، دخل للرابط وأكد المعلومات ديالك {url}"),
        ("msa", "تمت محاولة دخول غير مصرح بها إلى حسابك في {b}. إن لم تكن أنت، أرسل رمز التحقق المرسل إلى جوالك إلى الرقم {phone}"),
    ],
    "delivery": [
        ("msa", "{b}: تعذر توصيل شحنتك بسبب عنوان غير مكتمل. يرجى تحديث العنوان ودفع رسوم إعادة التوصيل {amt} ريال {url}"),
        ("msa", "لديك طرد بانتظار التسليم لدى {b}. سدد الرسوم الجمركية {amt} ريال خلال {h} ساعة لتجنب إرجاعه {url}"),
        ("gulf", "مرحبا معك مندوب {b}، ما قدرنا نوصل طردك، حدث عنوانك وادفع رسوم التوصيل من هنا {url}"),
        ("egyptian", "{b}: مقدرناش نوصل الشحنة بتاعتك، ادخل على اللينك وادفع رسوم الشحن {amt} جنيه {url}"),
        ("msa", "شحنتك رقم {h}{amt} متوقفة في المستودع. لإعادة جدولة التوصيل أكمل البيانات عبر {url} - {b}"),
    ],
    "gov": [
        ("msa", "{b}: تم رصد مخالفة مرورية على مركبتك. سدد خلال {h} ساعة لتفادي مضاعفة الغرامة {url}"),
        ("msa", "عزيزي المستفيد، سيتم إيقاف خدماتك في {b} لعدم تحديث بيانات الهوية. التحديث عبر الرابط {url}"),
        ("msa", "{b}: لديك مبلغ مسترد بقيمة {amt} ريال. لاستلامه أدخل بيانات بطاقتك عبر الرابط {url}"),
        ("gulf", "تنبيه {b}: عليك مخالفة ما تسددت وبتتحول للجهات المختصة، سددها الحين من الرابط {url}"),
    ],
    "prize": [
        ("msa", "مبروك! تم اختيارك للفوز بجائزة {amt} ريال من {b}. لاستلام الجائزة ادفع رسوم التحويل وتواصل واتساب {phone}"),
        ("msa", "تهانينا، ربحت معنا سحب {b} بمبلغ وقدره {amt} ريال. حول رسوم التأمين على الحساب التالي {iban} ثم راسلنا {phone}"),
        ("gulf", "ألف مبروك يالغالي ربحت {amt} ريال في سحب {b}، كلمنا واتس {phone} وعطنا رقم بطاقتك عشان نحول لك"),
        ("egyptian", "مبروك يا فندم كسبت {amt} جنيه من {b}، ابعت رسوم التحويل على {iban} وكلمنا واتساب {phone}"),
        ("maghrebi", "مبروك عليك ربحتي {amt} درهم مع {b}، باش تاخد الجائزة صيفط لينا رقم الكارط ديالك فالواتساب {phone}"),
    ],
    "job": [
        ("msa", "مطلوب موظفين للعمل من المنزل، دخل يومي {amt} ريال بدون خبرة. للتسجيل راسلنا على تليجرام {handle}"),
        ("gulf", "تبي دخل اضافي؟ شغل من البيت ساعتين باليوم وتاخذ {amt} ريال، كلمني واتس {phone}"),
        ("egyptian", "عايز شغل من البيت؟ هتكسب {amt} جنيه في اليوم من موبايلك، ابعتلي على الواتساب {phone}"),
        ("msa", "فرصة عمل: دوام جزئي براتب يومي {amt} ريال، المطلوب تقييم منتجات فقط. تواصل عبر تليجرام {handle}"),
        ("levantine", "بدك شغل من البيت؟ راتب يومي {amt} وما بدو خبرة، حكينا عالتلغرام {handle}"),
    ],
    "invest": [
        ("msa", "استثمر {amt} ريال واحصل على أرباح يومية مضمونة 15%. انضم لقناتنا على تليجرام {handle} وحول على المحفظة {wallet}"),
        ("gulf", "ياخي جربت منصة تداول تعطي أرباح مضمونة، ضاعفت راس مالي بأسبوع. كلم المدير تليجرام {handle}"),
        ("msa", "محفظة استثمارية بعائد يومي ثابت، ابدأ بمبلغ {amt} دولار USDT على العنوان {wallet} وراسل الدعم {handle} تليجرام"),
        ("egyptian", "عايز تضاعف فلوسك؟ استثمار مضمون وأرباح يومية، ابعت على المحفظة دي {wallet} وكلمنا تليجرام {handle}"),
    ],
}
BENIGN: list[tuple[str, str, str | None, str]] = [   # (kind, dialect, sender, text)
    ("otp", "msa", "{bs}", "رمز التحقق الخاص بك هو {code}. لا تشارك هذا الرمز مع أحد. {b}"),
    ("otp", "msa", "{bs}", "{b}: رمز الدخول {code} صالح لمدة 5 دقائق. لن يطلب منك موظف البنك هذا الرمز أبداً."),
    ("txn", "msa", "{bs}", "تم خصم مبلغ {amt} ريال من حسابك المنتهي بـ 4521 لدى {b}. الرصيد المتاح {amt}0 ريال."),
    ("txn", "msa", "{bs}", "شراء عبر نقاط البيع بمبلغ {amt} ريال من بطاقة مدى. {b}"),
    ("txn", "msa", "{bs}", "تم إيداع راتبك بمبلغ {amt}0 ريال في حسابك. للتفاصيل زر {official}"),
    ("txn", "msa", "{bs}", "عزيزي العميل، كشف حسابك الشهري جاهز. يمكنك الاطلاع عليه عبر التطبيق أو {official}"),
    ("bank_notice", "msa", "{bs}", "{b}: حرصاً على أمانكم، لن نطلب منكم بياناتكم السرية عبر الرسائل أو الاتصال. لا تشارك الرمز مع أي شخص."),
    ("bank_notice", "msa", "{bs}", "عميلنا العزيز، يرجى تحديث بياناتك بزيارة أقرب فرع أو عبر التطبيق الرسمي قبل نهاية الشهر. {b}"),
    ("bank_notice", "msa", "{bs}", "{b}: تم إيقاف بطاقتك المنتهية بـ 4521 بناءً على طلبك. لإصدار بطاقة جديدة استخدم التطبيق."),
    ("gov", "msa", "{bs}", "{b}: تم تسجيل مخالفة مرورية على المركبة. يمكنكم الاطلاع والسداد عبر المنصة الرسمية {official}"),
    ("gov", "msa", "{bs}", "عزيزي المستفيد، موعدك يوم الأحد الساعة 10 صباحاً. نأمل الحضور قبل الموعد بربع ساعة. {b}"),
    ("gov", "msa", "{bs}", "{b}: تنتهي صلاحية هويتك خلال 30 يوم، يمكنك التجديد إلكترونياً عبر {official}"),
    ("delivery", "msa", "{bs}", "{b}: شحنتك في الطريق إليك وسيتم التوصيل اليوم. للتتبع {official}"),
    ("delivery", "msa", "{bs}", "تم تسليم شحنتك بنجاح. شكراً لاستخدامك {b}."),
    ("delivery", "gulf", "{pn}", "السلام عليكم معك المندوب، انا عند الباب طلبك جاهز ممكن تنزل تستلم؟"),
    ("delivery", "egyptian", "{pn}", "معاك المندوب يا فندم، انا تحت البيت ومعايا الاوردر، الحساب {amt} جنيه كاش"),
    ("promo", "msa", "{shop}-AD", "خصم 40% على جميع المنتجات اليوم فقط! تسوق الآن {shopurl}"),
    ("promo", "msa", "{shop}-AD", "عرض نهاية الأسبوع: اشتر قطعتين واحصل على الثالثة مجاناً. آخر فرصة اليوم {shopurl}"),
    ("promo", "gulf", "{shop}-AD", "لا يفوتك! عروض الجمعة البيضاء بدت الحين، خصومات لين 70% {shopurl}"),
    ("promo", "msa", "{shop}-AD", "عميلنا العزيز، استخدم كود الخصم SAVE{code} واحصل على توصيل مجاني. تسوق عبر {shopurl}"),
    ("promo", "msa", "{bs}", "{b}: جدد باقتك الآن واحصل على ضعف البيانات. للاشتراك أرسل 1 إلى 900"),
    ("promo", "egyptian", "{shop}-AD", "عروض الصيف بدأت! خصومات كبيرة على كل حاجة لحد اخر الشهر {shopurl}"),
    ("telecom", "msa", "{bs}", "عزيزي المشترك، فاتورتك لشهر مايو {amt} ريال. آخر موعد للسداد 25 الشهر لتفادي إيقاف الخدمة. {b}"),
    ("telecom", "msa", "{bs}", "تم استهلاك 80% من باقة الإنترنت. لتجديد الباقة استخدم التطبيق. {b}"),
    ("chat", "gulf", "{pn}", "وينك يا رجال؟ تعال بسرعة العشا جاهز والشباب كلهم موجودين"),
    ("chat", "gulf", "{pn}", "هلا والله، ابي منك خدمة، تقدر تحول لي {amt} ريال الحين وبكرة ارجعها لك؟ هذا الايبان {iban}"),
    ("chat", "gulf", "{pn}", "يبه لا تنسى تجدد الاستمارة قبل تنتهي، ترى عليها غرامة اذا تأخرت"),
    ("chat", "egyptian", "{pn}", "ازيك يا حبيبي عامل ايه؟ عايز اشوفك النهارده ضروري، كلمني لما تفضى"),
    ("chat", "egyptian", "{pn}", "ابعتلي رقم الحساب بتاعك علشان احولك الفلوس اللي عليا، {amt} جنيه مش كده؟"),
    ("chat", "levantine", "{pn}", "شو اخبارك؟ بدي ياك تمرق عليي هلق ضروري، في شغلة مهمة بدي احكيك فيها"),
    ("chat", "levantine", "{pn}", "مرحبا خيي، بعتلك المصاري عالحساب، شوف اذا وصلو وخبرني"),
    ("chat", "maghrebi", "{pn}", "سلام خويا لاباس؟ واش نتلاقاو اليوم؟ عندي شي حاجة بغيت نهضر معاك عليها دابا"),
    ("chat", "gulf", "{pn}", "رقمي الجديد {phone} احفظه عندك، والقديم خلاص وقفته"),
    ("chat", "msa", "{pn}", "السلام عليكم، أرسلت لك الملف على البريد. أرجو المراجعة والرد اليوم إن أمكن لأن الموعد النهائي غداً"),
    ("chat", "gulf", "{pn}", "الرمز اللي طلبته للواي فاي {code}{code} لا تعطيه احد من العيال"),
    ("service", "msa", "{shop}", "تم تأكيد حجزك رقم {code}. للاستفسار أو تعديل الحجز تواصل معنا على {bizphone}"),
    ("service", "msa", "{shop}", "عيادات {shop}: نذكرك بموعدك غداً الساعة 5 مساءً. للإلغاء اتصل على {bizphone}"),
    ("service", "gulf", "{shop}", "طلبك جاهز للاستلام من الفرع. للتواصل واتساب {bizphone}"),
    ("service", "msa", "{shop}", "شكراً لتسوقك من {shop}. فاتورتك رقم {code} بمبلغ {amt} ريال. رابط الفاتورة {shopurl}"),
    ("job_legit", "msa", "{shop}", "نشكر تقدمك على وظيفة محاسب. نود دعوتك لمقابلة شخصية يوم الثلاثاء في مقر الشركة. للتأكيد {bizmail}"),
    ("charity", "msa", "{shop}", "ساهم معنا في إفطار صائم. تبرعك يصل عبر الحساب الرسمي للجمعية {iban} أو {shopurl}"),
]
BRANDS = {   # archetype -> [(arabic name, hostname key, official domain, sender id)]
    "bank": [("مصرف الراجحي", "alrajhi", "alrajhibank.com.sa", "AlRajhiBank"), ("البنك الأهلي السعودي", "alahli", "alahli.com", "SNB"),
             ("بنك الرياض", "riyadbank", "riyadbank.com", "RiyadBank"), ("البنك الأهلي المصري", "nbe", "nbe.com.eg", "NBE"),
             ("مصرف الإنماء", "alinma", "alinma.com", "Alinma")],
    "delivery": [("البريد السعودي", "splonline", "splonline.com.sa", "SPL"), ("أرامكس", "aramex", "aramex.com", "Aramex"),
                 ("سمسا", "smsa", "smsaexpress.com", "SMSA")],
    "gov": [("منصة أبشر", "absher", "absher.sa", "Absher"), ("ناجز", "najiz", "najiz.sa", "Najiz"),
            ("هيئة الزكاة", "zatca", "zatca.gov.sa", "ZATCA")],
    "prize": [("اس تي سي", "stc", "stc.com.sa", "stc"), ("موبايلي", "mobily", "mobily.com.sa", "Mobily"), ("فودافون", "vodafone", "vodafone.com.eg", "Vodafone")],
    "job": [("", "", "", "")], "invest": [("", "", "", "")],
}
_WORDS = ["update", "secure", "verify", "service", "portal", "online", "support", "account", "pay", "id", "sa", "app", "care", "help"]
_NEUTRAL = ["fastlink", "mycenter", "infopage", "servicesa", "webportal", "clientarea", "easyaccess", "quickpay"]
_TLDS = ["example", "test", "invalid"]
_SHOPS = ["Jarir", "Extra", "Danube", "Centrepoint", "Nahdi", "Panda", "AlBaik", "Namshi", "Styli", "Lulu"]


def _iban(rng: random.Random, cc: str = "SA") -> str:
    bban = "00" + "".join(rng.choice("0123456789") for _ in range(18))
    num = int("".join(str(int(c, 36)) for c in bban + cc + "00"))
    return f"{cc}{98 - num % 97:02d}{bban}"


def _tron(rng: random.Random) -> str:
    raw = b"\x41" + bytes(rng.randrange(256) for _ in range(20))
    raw += hashlib.sha256(hashlib.sha256(raw).digest()).digest()[:4]
    n, out = int.from_bytes(raw, "big"), ""
    while n:
        n, r = divmod(n, 58)
        out = B58[r] + out
    return out


def _phone(rng: random.Random, eg: bool = False) -> str:
    return ("01000" if eg else "05000") + "".join(rng.choice("0123456789") for _ in range(6 if eg else 5))


def _fmt_phone(rng: random.Random, p: str) -> str:
    style = rng.randrange(5)
    intl = ("+20" + p[1:]) if p.startswith("01") else ("+966" + p[1:])
    if style == 0:
        return p
    if style == 1:
        return intl
    if style == 2:
        return "00" + intl[1:]
    if style == 3:
        return p[:3] + " " + p[3:6] + " " + p[6:]
    return "https://wa.me/" + intl[1:]


def _obfuscate(rng: random.Random, text: str, url: str | None) -> tuple[str, list[str]]:
    kinds = []
    k = rng.choice(["defang", "digits", "zw", "spaced", "lookalike", "tashkeel"])
    if k == "defang" and url and url in text:
        text = text.replace(url, url.replace("https://", "hxxps://").replace(".", "[.]")); kinds.append(k)
    elif k == "digits":
        text = "".join(c.translate(AR_DIGITS) if not ("a" <= c.lower() <= "z") else c for c in _protect_urls(text)); kinds.append(k)
    elif k == "zw":
        words = text.split(" ")
        for i in rng.sample(range(len(words)), k=min(4, len(words))):
            w = words[i]
            if len(w) > 3 and "." not in w and "/" not in w:
                words[i] = w[:2] + "‌" + w[2:]
        text = " ".join(words); kinds.append(k)
    elif k == "spaced":
        for w in ("عاجل", "تنبيه", "مبروك", "حسابك", "بطاقتك", "تحديث", "الرابط"):
            if w in text:
                text = text.replace(w, " ".join(w), 1); kinds.append(k); break
    elif k == "lookalike":
        text = " ".join(w if ("." in w or "/" in w) else w.translate(LOOKALIKE) for w in text.split(" ")); kinds.append(k)
    elif k == "tashkeel":
        text = text.replace("ا", "اـ", 3).replace("ب", "بَ", 2); kinds.append(k)
    return text, kinds


def _protect_urls(text: str) -> str:
    return text   # digit folding only touches non-latin-adjacent chars; URLs here contain few digits


def generate(seed: int = 7, n_campaigns: int = 36, n_singletons: int = 60, n_benign: int = 620) -> list[dict]:
    rng = random.Random(seed)
    t0 = datetime(2026, 9, 1, tzinfo=timezone.utc)
    out: list[dict] = []
    fam_index = {(arch, i): f"{arch}-{i}" for arch, tpls in MAL.items() for i in range(len(tpls))}

    def make_domain(key: str) -> str:
        base = (f"{key}-{rng.choice(_WORDS)}" if key and rng.random() < 0.7 else rng.choice(_NEUTRAL)) + str(rng.randrange(10, 99))
        return f"{base}.{rng.choice(_TLDS)}"

    def emit_mal(arch, brand, tpl_idx, res, when, campaign, senders, orphan=False):
        dialect, tpl = MAL[arch][tpl_idx]
        eg = dialect == "egyptian"
        dom = make_domain(brand[1]) if orphan else (rng.choice(res["domains"]) if res["domains"] else None)
        url = None
        if "{url}" in tpl:
            dom = dom or make_domain(brand[1])
            path = res.get("path", "") if not orphan else ""
            url = rng.choice(["https://", "https://", "http://", ""]) + dom + path
        phone_raw = res["phones"] and rng.choice(res["phones"]) or _phone(rng, eg)
        text = tpl.format(b=brand[0], url=url or "", phone=_fmt_phone(rng, phone_raw), iban=res.get("iban") or _iban(rng),
                          handle=res.get("handle") or "@u" + str(rng.randrange(10**6)), wallet=res.get("wallet") or _tron(rng),
                          amt=rng.choice([150, 200, 350, 500, 1200, 5000, 25000]), h=rng.choice([12, 24, 48]))
        if "{phone}" not in tpl and res["phones"] and rng.random() < 0.35 and not orphan:
            text += " للاستفسار واتساب " + _fmt_phone(rng, rng.choice(res["phones"]))
        text = " ".join(text.split())
        obf: list[str] = []
        if rng.random() < 0.28:
            text, obf = _obfuscate(rng, text, url)
        sender = rng.choice(senders)
        out.append({"text": text, "sender": sender, "channel": rng.choice(["sms", "sms", "whatsapp"]),
                    "received_at": when.isoformat(), "label": 1, "campaign": campaign, "family": fam_index[(arch, tpl_idx)],
                    "dialect": dialect, "obfuscation": obf, "kind": arch, "orphan": orphan})

    archs = list(MAL)
    for c in range(n_campaigns):
        arch = archs[c % len(archs)]
        brand = rng.choice(BRANDS[arch])
        res = {"domains": [make_domain(brand[1]) for _ in range(rng.choice([1, 1, 2, 3]))] if arch in ("bank", "delivery", "gov") else [],
               "phones": [_phone(rng) for _ in range(rng.choice([0, 1, 1, 2]) if arch in ("bank", "delivery", "gov") else rng.choice([1, 1, 2]))],
               "path": rng.choice(["", "/login", "/sa/verify", "/track/id", "/pay"]),
               "iban": _iban(rng) if arch == "prize" else None,
               "handle": "@" + rng.choice(["rabeh", "easyjob", "vip_trade", "daily_income", "gulf_invest", "work_home"]) + str(rng.randrange(100, 999)),
               "wallet": _tron(rng) if arch == "invest" else None}
        families = rng.sample(range(len(MAL[arch])), k=min(len(MAL[arch]), rng.choice([1, 2, 2, 3])))
        senders = [_phone(rng) for _ in range(rng.choice([1, 2, 3]))] if rng.random() < 0.6 else [brand[3] or "INFO", "Notice"]
        start = t0 + timedelta(days=rng.randrange(0, 70), hours=rng.randrange(24))
        for _ in range(rng.randrange(4, 19)):
            emit_mal(arch, brand, rng.choice(families), res, start + timedelta(hours=rng.randrange(0, 24 * 9)),
                     f"C{c:02d}", senders, orphan=rng.random() < 0.08)
    for s in range(n_singletons):
        arch = rng.choice(archs)
        brand = rng.choice(BRANDS[arch])
        res = {"domains": [], "phones": [], "path": ""}
        emit_mal(arch, brand, rng.randrange(len(MAL[arch])), res, t0 + timedelta(days=rng.randrange(0, 80), hours=rng.randrange(24)),
                 None, [_phone(rng)], orphan=True)

    all_brands = [b for arch in ("bank", "delivery", "gov", "prize") for b in BRANDS[arch]]
    shops = {s: (f"{s.lower()}-store.example", _phone(rng), f"hr@{s.lower()}-store.example") for s in _SHOPS}
    for _ in range(n_benign):
        idx = rng.randrange(len(BENIGN))
        kind, dialect, sender_t, tpl = BENIGN[idx]
        brand = rng.choice([b for b in all_brands if kind not in ("gov",) or b in BRANDS["gov"]] if kind != "delivery"
                           else BRANDS["delivery"])
        if kind in ("otp", "txn", "bank_notice"):
            brand = rng.choice(BRANDS["bank"])
        if kind == "telecom" or (kind == "promo" and "{b}" in tpl):
            brand = rng.choice(BRANDS["prize"])
        shop = rng.choice(_SHOPS)
        pn = _phone(rng)
        text = tpl.format(b=brand[0], bs=brand[3], official="https://www." + brand[2], code=rng.randrange(1000, 9999),
                          amt=rng.choice([35, 120, 249, 480, 850]), shop=shop, shopurl="https://" + shops[shop][0] + rng.choice(["", "/offers", "/sale"]),
                          bizphone=_fmt_phone(rng, shops[shop][1]).replace("https://wa.me/", "+"), bizmail=shops[shop][2],
                          iban=_iban(rng), phone=_phone(rng), pn=pn)
        sender = sender_t.format(bs=brand[3], pn=pn, shop=shop)
        out.append({"text": text, "sender": sender, "channel": "whatsapp" if kind == "chat" else "sms",
                    "received_at": (t0 + timedelta(days=rng.randrange(0, 80), hours=rng.randrange(24))).isoformat(),
                    "label": 0, "campaign": None, "family": f"benign-{idx}", "dialect": dialect, "obfuscation": [],
                    "kind": "benign:" + kind, "orphan": False})
    rng.shuffle(out)
    for i, m in enumerate(out):
        m["id"] = f"syn-{i:05d}"
    return out
