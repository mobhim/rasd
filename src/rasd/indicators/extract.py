"""Indicator extraction: URLs, domains, phones, IBANs, e-mails, handles and
crypto wallets — robust to defanging, Arabic-Indic digits, spacing tricks and
invisible characters. Purely offline: nothing here touches the network."""
from __future__ import annotations

import hashlib
import re
from urllib.parse import parse_qs, urlsplit

from ..models import Evidence, Indicator, IndicatorType as T
from ..text import OffsetText, script_of
from . import psl
from .brands import official_domains

SHORTENERS = frozenset(
    "bit.ly tinyurl.com t.co cutt.ly is.gd rb.gy shorturl.at t.ly tiny.cc ow.ly goo.su s.id v.gd "
    "rebrand.ly bl.ink short.io lnkd.in buff.ly qr.ae u.to shorter.me urlz.fr clck.ru goo.gl "
    "2u.pw n9.cl surl.li urlis.net shrtco.de kutt.it tny.im x.gd linkr.it sho.rt".split())
SHARED_PLATFORMS = frozenset(
    "forms.gle google.com docs.google.com sites.google.com drive.google.com facebook.com fb.me fb.com "
    "instagram.com youtube.com youtu.be tiktok.com x.com twitter.com snapchat.com linktr.ee "
    "apple.com play.google.com apps.apple.com wa.me whatsapp.com t.me telegram.me telegram.org "
    "linkedin.com dropbox.com notion.site typeform.com jotform.com surveymonkey.com".split())
FREEMAIL = frozenset("gmail.com hotmail.com outlook.com yahoo.com live.com icloud.com proton.me protonmail.com mail.com gmx.com yandex.com aol.com".split())

_GTLD = ("com net org info biz xyz top online site shop store app dev io co me tv cc club vip live icu "
         "click link work life world today cloud tech space website fun pro one win bid loan men cfd sbs "
         "cyou buzz rest bond lol mom quest monster email support help center services finance bank "
         "gov edu int mobi name asia tel travel page blog news wiki digital agency group ltd pay cash "
         "money trade market express delivery post id ly gl gd su ru pw to ws st").split()
_CCTLD = ("ac ad ae af ag ai al am ao aq ar as at au aw ax az ba bb bd be bf bg bh bi bj bm bn bo br bs bt bw "
          "by bz ca cd cf cg ch ci ck cl cm cn cr cu cv cw cx cy cz de dj dk dm do dz ec ee eg er es et eu "
          "fi fj fk fm fo fr ga gb ge gf gg gh gi gm gn gp gq gr gt gu gw gy hk hn hr ht hu ie il im "
          "in iq ir is it je jm jo jp ke kg kh ki km kn kp kr kw ky kz la lb lc li lk lr ls lt lu lv "
          "ma mc md mg mh mk ml mm mn mo mp mq mr ms mt mu mv mw mx my mz na nc ne nf ng ni nl np "
          "nr nu nz om pa pe pf pg ph pk pl pm pn pr ps pt py qa re ro rs rw sa sb sc sd se sg sh si "
          "sk sl sm sn so sr ss sv sx sy sz tc td tf tg th tj tk tl tm tn tr tt tw tz ua ug uk us uy uz "
          "va vc ve vg vi vn vu wf ye yt za zm zw").split()
_IDN_TLD = "السعودية امارات مصر قطر عمان الاردن المغرب تونس الجزائر سورية فلسطين موقع شبكة بازار كوم عرب".split()
TLDS = frozenset(_GTLD) | frozenset(_CCTLD) | psl.RESERVED_TLDS | frozenset(_IDN_TLD)

_AR = "ء-ي"
_LBL = rf"[a-z0-9{_AR}](?:[a-z0-9{_AR}\-]{{0,61}}[a-z0-9{_AR}])?"
_PATH = rf"[^\s<>\"'،؛؀-ۿ]*"
_URL = re.compile(
    rf"(?:(?P<scheme>https?)://|(?<![\w@.\-])(?=www\.))(?P<auth>[^\s/<>\"'،؛?#]+){_PATH}"
    rf"|(?<![\w@.\-/])(?P<bare>(?:{_LBL}\.)+(?P<tld>[a-z]{{2,24}}|[{_AR}]{{2,12}}))(?::\d{{2,5}})?(?:[/?#]{_PATH})?(?![\w\-])",
    re.I)
_EMAIL = re.compile(r"(?<![\w.+\-])[a-z0-9][\w.+\-]{0,63}@((?:[a-z0-9\-]+\.)+[a-z]{2,24})(?![\w\-])", re.I)
_DEFANG = [
    (re.compile(r"hxxp(s?)", re.I), r"http\1"),
    (re.compile(r"\s?[\[({]\s?(?:\.|dot|نقطة|نقطه)\s?[\])}]\s?", re.I), "."),
    (re.compile(r"\[:\]"), ":"), (re.compile(r"\[/\]"), "/"),
    (re.compile(r"(?<=[a-z0-9])\s+\.\s*(?=(?:com|net|org|sa|ly|me|co|app|xyz|top|info|site|online|shop|live|link|click|example|test)\b)", re.I), "."),
]
_IPV4 = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_TRAIL = ".,;:!?)]}»\"'`؟…*"

_IBAN = re.compile(r"(?<![a-z0-9])([a-z]{2}\d{2}(?:[ \-]?[a-z0-9]{4}){2,7}(?:[ \-]?[a-z0-9]{1,3})?)(?![a-z0-9])", re.I)
IBAN_LEN = {"SA": 24, "AE": 23, "EG": 29, "KW": 30, "QA": 29, "BH": 22, "JO": 30, "LB": 28, "IQ": 23,
            "OM": 23, "TN": 24, "MR": 27, "LY": 25, "SD": 18, "PS": 29, "TR": 26, "GB": 22, "DE": 22,
            "FR": 27, "ES": 24, "IT": 27, "NL": 18, "CH": 21, "PK": 24, "CY": 28, "MT": 31}

# boundaries are ASCII-only on purpose: real messages glue numbers to Arabic words ("رقم0591795820")
_PHONE = re.compile(r"(?<![A-Za-z0-9=.\-+\x00])(?P<pfx>\+|00)?\d(?:[ \-.()]{0,2}\d){6,14}(?![A-Za-z0-9])")
# cc -> (allowed national-number lengths, required leading digits or "")
CC = {"966": ((9,), "5"), "971": ((9,), "5"), "20": ((10,), "1"), "965": ((8,), ""), "974": ((8,), ""),
      "973": ((8,), ""), "968": ((8,), ""), "962": ((9,), "7"), "961": ((7, 8), ""), "964": ((10,), "7"),
      "212": ((9,), ""), "213": ((9,), ""), "216": ((8,), ""), "967": ((9,), "7"), "963": ((9,), "9"),
      "970": ((9,), "5"), "249": ((9,), ""), "218": ((9,), "9"), "90": ((10,), "5"), "44": ((10,), "7"),
      "1": ((10,), ""), "91": ((10,), ""), "92": ((10,), "3"), "234": ((10,), ""), "62": ((9, 10, 11), "8"),
      "7": ((10,), "9"), "86": ((11,), "1"), "63": ((10,), "9"), "880": ((10,), "1"), "254": ((9,), "7")}
CC_COUNTRY = {"966": "SA", "971": "AE", "20": "EG", "965": "KW", "974": "QA", "973": "BH", "968": "OM",
              "962": "JO", "961": "LB", "964": "IQ", "212": "MA", "213": "DZ", "216": "TN", "967": "YE",
              "963": "SY", "970": "PS", "249": "SD", "218": "LY"}
LOCAL = {"SA": (r"05\d{8}", "966"), "AE": (r"05\d{8}", "971"), "EG": (r"01[0125]\d{8}", "20"),
         "JO": (r"07[789]\d{7}", "962"), "IQ": (r"07[3-9]\d{8}", "964"), "MA": (r"0[67]\d{8}", "212"),
         "DZ": (r"0[567]\d{8}", "213"), "KW": (r"[569]\d{7}", "965"), "QA": (r"[3567]\d{7}", "974"),
         "BH": (r"3\d{7}", "973"), "OM": (r"[79]\d{7}", "968")}
_LOCAL_FALLBACK = ("EG", "SA", "IQ", "JO")     # unambiguous-enough formats tried after the default region

_HANDLE = re.compile(r"(?<![\w@./])@([a-z][a-z0-9_.]{3,31})(?![\w@])", re.I)
_TG_CONTEXT = re.compile(r"telegram|تي?ل[يی]?[جغ]رام", re.I)
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_WALLETS = [
    ("btc", re.compile(r"(?<![a-z0-9])bc1[ac-hj-np-z02-9]{25,62}(?![a-z0-9])"), False),
    ("btc", re.compile(r"(?<![A-Za-z0-9])[13][1-9A-HJ-NP-Za-km-z]{25,34}(?![A-Za-z0-9])"), True),
    ("tron", re.compile(r"(?<![A-Za-z0-9])T[1-9A-HJ-NP-Za-km-z]{33}(?![A-Za-z0-9])"), True),
    ("eth", re.compile(r"(?<![A-Za-z0-9])0x[a-fA-F0-9]{40}(?![A-Za-z0-9])"), False),
]
_WORD = re.compile(r"[^\W\d_]{3,}")


def b58check_ok(s: str) -> bool:
    try:
        n = 0
        for c in s:
            n = n * 58 + _B58.index(c)
        raw = n.to_bytes(25, "big")
    except (ValueError, OverflowError):
        return False
    return hashlib.sha256(hashlib.sha256(raw[:-4]).digest()).digest()[:4] == raw[-4:]


def iban_ok(iban: str) -> bool:
    iban = iban.upper()
    if IBAN_LEN.get(iban[:2]) != len(iban):
        return False
    rearr = iban[4:] + iban[:4]
    return int("".join(str(int(c, 36)) for c in rearr)) % 97 == 1


def normalize_phone(raw: str, default_region: str = "SA") -> tuple[str, dict] | None:
    """-> (E.164, attrs) or None when the digits are not confidently a phone number."""
    s = raw.strip()
    intl = s.startswith("+") or s.startswith("00")
    d = re.sub(r"\D", "", s)
    if s.startswith("00"):
        d = d[2:]
    if intl:
        for n in (3, 2, 1):
            cc = d[:n]
            if cc in CC:
                lens, lead = CC[cc]
                nsn = d[n:].lstrip("0") if len(d[n:]) - 1 in lens and d[n:].startswith("0") else d[n:]
                if len(nsn) in lens and nsn.startswith(lead):
                    return f"+{cc}{nsn}", {"country": CC_COUNTRY.get(cc), "intl_prefix": True}
                return None
        return (f"+{d}", {"country": None, "intl_prefix": True}) if 8 <= len(d) <= 15 else None
    for n in (3, 2):                      # international digits written without + / 00
        cc = d[:n]
        if cc in CC_COUNTRY:
            lens, lead = CC[cc]
            if len(d) - n in lens and d[n:].startswith(lead) and (lead or len(d) >= 11):
                return f"+{d}", {"country": CC_COUNTRY[cc], "intl_prefix": False}
    for region in (default_region, *[r for r in _LOCAL_FALLBACK if r != default_region]):
        pat, cc = LOCAL.get(region, (None, None))
        if pat and re.fullmatch(pat, d):
            nsn = d[1:] if d.startswith("0") else d
            return f"+{cc}{nsn}", {"country": region, "assumed_region": True}
    return None


def _mask(t: OffsetText, spans: list[tuple[int, int]]) -> str:
    chars = list(t.text)
    for s, e in spans:
        chars[s:e] = "\x00" * (e - s)
    return "".join(chars)


def _parse_url(match: re.Match, t: OffsetText) -> tuple[list[Indicator], tuple[int, int]] | None:
    raw = match.group(0).rstrip(_TRAIL)
    if not raw:
        return None
    start, end = match.start(), match.start() + len(raw)
    if match.group("bare"):
        tld = match.group("tld").lower()
        if tld not in TLDS:
            return None
        if tld.isascii() and not match.group("bare").isascii() and "/" not in raw:
            return None                   # Arabic word glued to a latin token; not a hostname
    scheme = (match.group("scheme") or "").lower()
    try:
        parts = urlsplit(raw if scheme else "http://" + raw)
        host = (parts.hostname or "").strip(".").lower()
    except ValueError:
        return None
    if not host or "." not in host:
        return None
    span = t.span(start, end)
    idn = not host.isascii() or any(lbl.startswith("xn--") for lbl in host.split("."))
    try:
        ascii_host = host.encode("idna").decode() if not host.isascii() else host
    except UnicodeError:
        ascii_host = host
    is_ip = bool(_IPV4.match(host))
    sub, registered, suffix, private = ("", host, "", False) if is_ip else psl.split_host(ascii_host)
    path = parts.path.rstrip("/")
    attrs = {"host": ascii_host, "registered_domain": registered, "subdomain": sub, "suffix": suffix,
             "scheme": scheme or None, "path": path, "has_query": bool(parts.query), "idn": idn,
             "ip_host": is_ip, "private_suffix": private, "userinfo": "@" in parts.netloc,
             "port": parts.port if _safe_port(parts) else None}
    out: list[Indicator] = []
    seg = [s for s in path.split("/") if s]

    # messaging deep-links are contact indicators, not web infrastructure
    if registered in ("wa.me", "whatsapp.com") and host != "chat.whatsapp.com":
        num = seg[0] if registered == "wa.me" and seg else (parse_qs(parts.query).get("phone") or [""])[0]
        ph = normalize_phone("+" + re.sub(r"\D", "", num)) if num else None
        if ph:
            out.append(Indicator(T.PHONE, ph[0], raw, span, attrs={**ph[1], "channel": "whatsapp", "via": "link"}))
            return out, (start, end)
    if host == "chat.whatsapp.com" and seg:
        out.append(Indicator(T.HANDLE, f"whatsapp-group:{seg[-1]}", raw, span, attrs={"platform": "whatsapp"}))
        return out, (start, end)
    if registered in ("t.me", "telegram.me") and seg:
        name = seg[1] if seg[0] in ("s", "joinchat") and len(seg) > 1 else seg[0]
        out.append(Indicator(T.HANDLE, f"telegram:{name.lower()}", raw, span, attrs={"platform": "telegram", "via": "link"}))
        return out, (start, end)

    official = official_domains().get(registered)
    shortener = registered in SHORTENERS
    shared = registered in SHARED_PLATFORMS or ascii_host in SHARED_PLATFORMS
    attrs.update(official=official, shortener=shortener, shared_platform=shared)
    canonical = ascii_host + path
    path_is_identity = (shortener or shared) and bool(seg)
    out.append(Indicator(T.URL, canonical, raw, span, linkable=path_is_identity and not official, attrs=attrs))
    out.append(Indicator(T.DOMAIN, registered, raw, span,
                         linkable=not (official or shortener or shared),
                         attrs={"official": official, "shortener": shortener, "shared_platform": shared,
                                "private_suffix": private, "ip_host": is_ip}))
    return out, (start, end)


def _safe_port(parts) -> bool:
    try:
        parts.port
        return True
    except ValueError:
        return False


def extract(cleaned: OffsetText, sender: str | None = None, default_region: str = "SA") -> tuple[list[Indicator], list[Evidence]]:
    evidence: list[Evidence] = []
    t = cleaned
    defanged = []
    for pat, repl in _DEFANG:
        hits = [t.span(m.start(), m.end()) for m in pat.finditer(t.text)]
        if hits:
            defanged.extend(hits)
            t = t.regex_sub(pat, repl)
    out: list[Indicator] = []
    taken: list[tuple[int, int]] = []

    for m in _EMAIL.finditer(t.text):
        dom = m.group(1).lower()
        out.append(Indicator(T.EMAIL, m.group(0).lower(), m.group(0), t.span(m.start(), m.end()),
                             attrs={"domain": dom, "freemail": dom in FREEMAIL}))
        taken.append((m.start(), m.end()))
    masked = _mask(t, taken)
    n_urls = 0
    for m in _URL.finditer(masked):
        parsed = _parse_url(m, t)
        if parsed:
            inds, rng = parsed
            out.extend(inds); taken.append(rng); n_urls += 1
    if defanged and n_urls:
        evidence.append(Evidence("obfuscation.defanged_url", "obfuscation", spans=defanged[:5]))
    masked = _mask(t, taken)

    for m in _IBAN.finditer(masked):
        val = re.sub(r"[ \-]", "", m.group(1)).upper()
        if iban_ok(val):
            out.append(Indicator(T.IBAN, val, m.group(0), t.span(m.start(), m.end()), attrs={"country": val[:2], "bank_code": val[4:6]}))
            taken.append((m.start(), m.end()))
    masked = _mask(t, taken)
    for chain, pat, check in _WALLETS:
        for m in pat.finditer(masked):
            if check and not b58check_ok(m.group(0)):
                continue
            out.append(Indicator(T.WALLET, f"{chain}:{m.group(0)}", m.group(0), t.span(m.start(), m.end()), attrs={"chain": chain}))
            taken.append((m.start(), m.end()))
    masked = _mask(t, taken)
    for m in _PHONE.finditer(masked):
        ph = normalize_phone(m.group(0), default_region)
        if ph:
            ctx = masked[max(0, m.start() - 25):m.start()].lower()
            if re.search(r"واتس|whats|وتساب", ctx):
                ph[1]["channel"] = "whatsapp"
            out.append(Indicator(T.PHONE, ph[0], m.group(0), t.span(m.start(), m.end()), attrs=ph[1]))
            taken.append((m.start(), m.end()))
    tg = bool(_TG_CONTEXT.search(t.text))
    for m in _HANDLE.finditer(masked):
        name = m.group(1).lower().rstrip(".")
        out.append(Indicator(T.HANDLE, f"{'telegram' if tg else 'at'}:{name}", m.group(0), t.span(m.start(), m.end()),
                             attrs={"platform": "telegram" if tg else None}))

    # homoglyph words: Latin mixed with Cyrillic/Greek inside one token
    mixed = []
    for m in _WORD.finditer(masked):
        scripts = {script_of(c) for c in m.group(0)} - {"other"}
        if "latin" in scripts and scripts & {"cyrillic", "greek"}:
            mixed.append(t.span(m.start(), m.end()))
    if mixed:
        evidence.append(Evidence("obfuscation.mixed_script", "obfuscation", spans=mixed[:5]))

    if sender:
        s = sender.strip()
        ph = normalize_phone(s, default_region) if re.fullmatch(r"[+\d][\d \-()]{6,}", s) else None
        if ph:
            out.append(Indicator(T.PHONE, ph[0], s, None, role="sender", attrs=ph[1]))
        elif s:
            out.append(Indicator(T.SENDER_ID, s.casefold(), s, None, role="sender",
                                 attrs={"alphanumeric": not s.isdigit(), "shortcode": s.isdigit()}))
    # de-duplicate by (key, role), keep first occurrence
    seen, uniq = set(), []
    for ind in out:
        k = (ind.key, ind.role)
        if k not in seen:
            seen.add(k); uniq.append(ind)
    return uniq, evidence
