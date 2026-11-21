"""Registered-domain resolution.

A compact built-in suffix table (ICANN multi-label suffixes common in the
target region + private hosting suffixes) so the core has no dependencies.
Private hosting suffixes matter for campaign linking: two unrelated scams on
`*.web.app` must NOT be linked through `web.app`. Production deployments can
load the full Public Suffix List with `load_suffix_file()`."""
from __future__ import annotations

_SECOND_LEVEL = ("com", "net", "org", "gov", "edu", "co", "ac", "sch", "med", "pub", "mil", "info", "biz", "name", "or", "ne", "go")
_CC = ("sa ae eg kw qa bh om jo lb iq sy ye ly tn dz ma sd ps tr uk au in pk id my ng za br mx cn jp kr "
       "nz il ir af bd lk np th vn ph sg hk tw ke gh tz ug et ru ua ar co pe ve").split()
MULTI_SUFFIXES: set[str] = {f"{s}.{c}" for s in _SECOND_LEVEL for c in _CC}

# Free hosting / dynamic DNS / tunnelling: every customer gets a sub-domain.
PRIVATE_SUFFIXES: set[str] = {
    "web.app", "firebaseapp.com", "github.io", "gitlab.io", "pages.dev", "workers.dev", "r2.dev",
    "vercel.app", "netlify.app", "herokuapp.com", "onrender.com", "glitch.me", "repl.co", "replit.app",
    "blogspot.com", "wordpress.com", "weebly.com", "wixsite.com", "webflow.io", "square.site",
    "godaddysites.com", "my.canva.site", "canva.site", "framer.app", "carrd.co", "site123.me",
    "duckdns.org", "ddns.net", "no-ip.org", "hopto.org", "zapto.org", "serveo.net",
    "ngrok.io", "ngrok-free.app", "ngrok.app", "trycloudflare.com", "loca.lt",
    "000webhostapp.com", "infinityfreeapp.com", "epizy.com", "rf.gd", "azurewebsites.net",
    "cloudfront.net", "amazonaws.com", "appspot.com", "translate.goog", "myshopify.com",
    "blob.core.windows.net", "web.core.windows.net", "surge.sh", "codeanyapp.com", "plesk.page",
}
# RFC 2606 / RFC 6761 reserved names — used by the synthetic test bench.
RESERVED_TLDS = {"example", "test", "invalid", "localhost"}


def load_suffix_file(path: str) -> None:
    """Merge a Public Suffix List file (publicsuffix.org format)."""
    section_private = False
    with open(path, encoding="utf8") as fh:
        for line in fh:
            line = line.strip()
            if "BEGIN PRIVATE DOMAINS" in line:
                section_private = True
            if not line or line.startswith("//") or line.startswith("!") or "." not in line:
                continue
            (PRIVATE_SUFFIXES if section_private else MULTI_SUFFIXES).add(line.lstrip("*."))


def split_host(host: str) -> tuple[str, str, str, bool]:
    """-> (subdomain, registered_domain, suffix, on_private_suffix)."""
    labels = host.strip(".").lower().split(".")
    for n in (4, 3, 2):
        if len(labels) > n and ".".join(labels[-n:]) in PRIVATE_SUFFIXES:
            return ".".join(labels[:-n - 1]), ".".join(labels[-n - 1:]), ".".join(labels[-n:]), True
    n = 1
    for k in (3, 2):
        if len(labels) > k and ".".join(labels[-k:]) in MULTI_SUFFIXES:
            n = k
            break
    if len(labels) <= n:
        return "", host.lower(), ".".join(labels[-n:]), False
    return ".".join(labels[:-n - 1]), ".".join(labels[-n - 1:]), ".".join(labels[-n:]), False
