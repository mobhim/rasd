"""Static, read-only snapshot of the dashboard for hosts without a backend
(e.g. GitHub Pages).

Every file is a response of the REAL API (`create_app`) running the real
engine on the synthetic test bench — nothing is hand-written or simulated.
The snapshot is labelled as such in the UI; write actions (analyse, open an
investigation) are disabled, and monitoring figures are those measured once
at export time."""
from __future__ import annotations

import json
import shutil
from pathlib import Path

from fastapi.testclient import TestClient

from .api.app import DASHBOARD, create_app
from .eval.generator import generate
from .service import Rasd

TABLES = ("messages", "indicators", "investigations", "operations", "audit")


def fnv1a(s: str) -> str:
    """32-bit FNV-1a over UTF-8 — mirrored in static.js to locate indicator files."""
    h = 0x811C9DC5
    for b in s.encode("utf8"):
        h = ((h ^ b) * 0x01000193) & 0xFFFFFFFF
    return f"{h:08x}"


def export(out: str, seed: int = 7, n_campaigns: int = 20, n_singletons: int = 30, n_benign: int = 300) -> int:
    root = Path(out)
    data = root / "snapshot"
    if data.exists():
        shutil.rmtree(data)
    for sub in ("campaigns", "graph", "links", "messages", "indicators", "db"):
        (data / sub).mkdir(parents=True, exist_ok=True)
    c = TestClient(create_app(Rasd(), {"snapshot": "demo"}))
    h = {"X-API-Key": "snapshot"}
    corpus = generate(seed=seed, n_campaigns=n_campaigns, n_singletons=n_singletons, n_benign=n_benign)
    for i in range(0, len(corpus), 500):
        batch = [{"text": m["text"], "id": m["id"], "sender": m["sender"], "channel": m["channel"],
                  "received_at": m["received_at"], "source": "synthetic"} for m in corpus[i:i + 500]]
        r = c.post("/v1/messages", headers=h, json={"messages": batch})
        r.raise_for_status()
    n = 0

    def get(path: str, **params):
        r = c.get(path, headers=h, params=params)
        r.raise_for_status()
        return r.json()

    def put(rel: str, obj) -> None:
        nonlocal n
        with open(data / rel, "w", encoding="utf8") as fh:
            json.dump(obj, fh, ensure_ascii=False, separators=(",", ":"))
        n += 1

    put("overview.json", get("/v1/overview"))
    camps = get("/v1/campaigns")
    put("campaigns.json", camps)
    put("graph.json", get("/v1/graph"))
    put("template-families.json", get("/v1/template-families"))
    put("entities.json", get("/v1/entities"))
    put("investigations.json", get("/v1/investigations"))
    put("db-overview.json", get("/v1/db/overview"))
    put("db-schema.json", get("/v1/db/schema"))
    for cp in camps["campaigns"]:
        cid = cp["id"]
        d = get(f"/v1/campaigns/{cid}")
        put(f"campaigns/{cid}.json", d)
        put(f"graph/{cid}.json", get("/v1/graph", campaign_id=cid))
        ids = d["campaign"]["message_ids"]
        put(f"links/{cid}.json", {f"{a}|{b}": get("/v1/links/explain", a=a, b=b) for a in ids for b in ids if a < b})
    msgs, off = [], 0
    while True:
        page = get("/v1/messages", limit=500, offset=off)
        msgs += page["messages"]
        off += 500
        if off >= page["total"]:
            break
    put("messages.json", msgs)
    for m in msgs:
        put(f"messages/{m['id']}.json", get(f"/v1/messages/{m['id']}"))
    inds = get("/v1/indicators", limit=500)
    allind, off = list(inds["indicators"]), 500
    while off < inds["total"]:
        allind += get("/v1/indicators", limit=500, offset=off)["indicators"]
        off += 500
    put("indicators.json", allind)
    for i in allind:
        put(f"indicators/{fnv1a(i['key'])}.json", get("/v1/indicators/detail", type=i["type"], value=i["value"]))
    for t in TABLES:
        rows, off = [], 0
        while True:
            page = get(f"/v1/db/tables/{t}/rows", limit=200, offset=off)
            rows += page["rows"]
            off += 200
            if off >= page["total"]:
                break
        put(f"db/{t}.json", {"columns": page["columns"], "rows": rows})
    health = get("/v1/system/health")
    put("system-health.json", health)
    put("meta.json", {"generated_at": health["measured_at"], "seed": seed, "messages": len(msgs),
                      "source": "synthetic test bench (rasd.eval.generator) analysed by the real RASD engine and API"})
    # dashboard files, re-pointed at the snapshot
    for f in ("app.css", "core.js", "views.js", "static.js"):
        shutil.copy(DASHBOARD / f, root / f)
    html = (DASHBOARD / "index.html").read_text(encoding="utf8")
    html = html.replace('href="static/app.css"', 'href="app.css"').replace(
        '<script src="static/core.js"></script>',
        '<script>window.RASD_STATIC_BASE="snapshot/";</script><script src="static.js"></script><script src="core.js"></script>'
    ).replace('<script src="static/views.js"></script>', '<script src="views.js"></script>')
    (root / "index.html").write_text(html, encoding="utf8")
    return n
