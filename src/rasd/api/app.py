"""RASD HTTP API (FastAPI). All /v1 routes require an API key that maps to a
tenant. Keys come from RASD_API_KEYS="key1:tenantA,key2:tenantB"; when unset a
random key is generated at start-up and printed once (never a default key).

Everything the dashboard shows comes from these endpoints. The database
explorer endpoints are READ-ONLY; the only writes are message ingestion,
erasure/retention and investigation tracking."""
from __future__ import annotations

import hmac
import os
import secrets
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .. import __version__
from ..indicators.brands import BRANDS
from ..integrations.stix import campaign_bundle
from ..models import Message
from ..monitor import Metrics, health
from ..service import Rasd
from ..storage import EXPLORABLE, Store
from ..xai import explain, explain_campaign

DASHBOARD = Path(__file__).resolve().parent.parent / "dashboard"
Lang = Literal["ar", "en"]
IndType = Literal["url", "domain", "phone", "iban", "email", "handle", "wallet", "sender_id"]


class MessageIn(BaseModel):
    text: str = Field(min_length=1, max_length=5000)
    id: str | None = Field(default=None, max_length=64, pattern=r"^[\w\-.:]+$")
    sender: str | None = Field(default=None, max_length=64)
    recipient: str | None = Field(default=None, max_length=64, description="Pseudonymised (HMAC) before storage; never stored raw.")
    channel: Literal["sms", "whatsapp", "telegram", "email", "other"] = "sms"
    received_at: str | None = Field(default=None, description="ISO-8601 timestamp")
    source: Literal["real", "synthetic", "test", "unspecified"] = Field(
        default="unspecified", description="Data provenance. Synthetic/test data is labelled as such everywhere.")

    def to_message(self) -> Message:
        return Message(**self.model_dump())


class BatchIn(BaseModel):
    messages: list[MessageIn] = Field(min_length=1, max_length=500)


class InvestigationIn(BaseModel):
    campaign_id: str = Field(min_length=3, max_length=40, pattern=r"^cmp_[0-9a-f]+$")
    title: str = Field(min_length=1, max_length=200)
    notes: str = Field(default="", max_length=5000)


class InvestigationPatch(BaseModel):
    status: Literal["open", "closed"] | None = None
    notes: str | None = Field(default=None, max_length=5000)


def _keys() -> dict[str, str]:
    raw = os.environ.get("RASD_API_KEYS", "")
    keys = dict(p.split(":", 1) for p in raw.split(",") if ":" in p)
    if not keys:
        k = secrets.token_urlsafe(24)
        keys[k] = "default"
        print(f"[rasd] RASD_API_KEYS not set — generated one-off API key for tenant 'default': {k}", flush=True)
    return keys


def create_app(rasd: Rasd | None = None, api_keys: dict[str, str] | None = None) -> FastAPI:
    rasd = rasd or Rasd(store=Store(os.environ.get("RASD_DB", "rasd.db")))
    keys = api_keys or _keys()
    thresholds = (rasd.analyzer.policy.suspicious_threshold, rasd.analyzer.policy.malicious_threshold)
    app = FastAPI(title="RASD — Arabic Threat Intelligence API", version=__version__,
                  description="Evidence-graph detection of Arabic social-engineering campaigns.")
    app.state.rasd = rasd
    metrics = app.state.metrics = Metrics()

    def tenant_of(key: str) -> str | None:
        return next((t for k, t in keys.items() if hmac.compare_digest(k, key)), None)

    @app.middleware("http")
    async def observe(request: Request, call_next):
        t0 = time.perf_counter()
        status = 500
        try:
            response = await call_next(request)
            status = response.status_code
            return response
        finally:
            ms = (time.perf_counter() - t0) * 1000
            route = getattr(request.scope.get("route"), "path", request.url.path)
            if route.startswith("/v1") or route == "/healthz":
                metrics.add(request.method, route, status, ms)
                if request.method != "GET" or status >= 500:
                    rasd.store.record_op(tenant_of(request.headers.get("x-api-key", "")), f"{request.method} {route}",
                                         "ok" if status < 400 else "rejected" if status < 500 else "error", ms,
                                         detail=f"HTTP {status}")

    def tenant(x_api_key: str = Header(default="")) -> str:
        t = tenant_of(x_api_key)
        if t is None:
            raise HTTPException(401, "invalid or missing X-API-Key")
        return t

    def with_expl(a: dict, lang: str) -> dict:
        return {"analysis": a, "explanation": explain(a, lang, thresholds)}

    # ------------------------------------------------------------------ core
    @app.get("/healthz")
    def healthz():
        return {"status": "ok", "version": __version__, "policy": rasd.analyzer.policy.version}

    @app.post("/v1/analyze", summary="Analyse one message without storing it")
    def analyze(m: MessageIn, lang: Lang = "ar", t: str = Depends(tenant)):
        a, tr = rasd.analyze_traced(m.to_message())
        return {**with_expl(a, lang), "trace": tr, "correlation": rasd.correlate(t, a)}

    @app.get("/v1/demo/samples", summary="Messages from the database chosen to demonstrate the engine")
    def demo_samples(t: str = Depends(tenant)):
        g = rasd.graph(t)
        picks, seen_c, seen_v = [], set(), set()
        for c in sorted(g.campaigns, key=lambda c: (-c["shared_indicator_count"], c["id"])):
            for mid in c["message_ids"]:
                m = rasd.store.get(t, mid)
                if m and m["verdict"] == "malicious" and m["variety"] not in seen_v:
                    picks.append((m, "campaign")); seen_c.add(c["id"]); seen_v.add(m["variety"])
                    break
            if len(picks) >= 4:
                break
        for verdict, role in (("suspicious", "uncertain"), ("benign", "hard_negative")):
            for m in rasd.store.list(t, verdict, None, 200):
                full = rasd.store.get(t, m["id"])
                if role == "hard_negative" and not any(e["id"].startswith("benign.") for e in full["analysis"]["evidence"]):
                    continue
                if role == "uncertain" and m["id"] in g.msg_campaign:
                    continue
                picks.append((full, role))
                break
        return {"samples": [{"id": m["id"], "text": m["text"], "sender": next(
                    (i["raw"] for i in m["analysis"]["indicators"] if i["role"] == "sender"), None),
                    "role": role, "source": m["source"], "variety": m["variety"], "verdict": m["verdict"],
                    "campaign_id": g.msg_campaign.get(m["id"])} for m, role in picks],
                "note": "texts are the stored (redacted) records; their provenance label is kept"}

    @app.get("/v1/search", summary="Unified search across campaigns, indicators, entities and messages")
    def search(q: str = Query(min_length=2, max_length=200), t: str = Depends(tenant)):
        g = rasd.graph(t)
        ql = q.lower()
        camps = [{"id": c["id"], "size": c["size"], "confidence": c["confidence"], "brands": list(c["brands"])}
                 for c in g.campaigns if ql in c["id"] or any(ql in b for b in c["brands"])
                 or any(ql in d["value"].lower() for d in c["indicators"])][:20]
        inds = [{"key": r["key"], "type": r["type"], "value": r["value"], "messages": r["messages"], "campaign_ids": r["campaign_ids"]}
                for r in _groups(t) if ql in r["value"].lower()][:30]
        ents = sorted({b for n in g.nodes.values() for b in n.brands if ql in b})[:10]
        msgs = rasd.store.list(t, None, q, 20)
        for m in msgs:
            m["campaign_id"] = g.msg_campaign.get(m["id"]); m["text"] = m["text"][:180]
        return {"q": q, "campaigns": camps, "indicators": inds, "entities": ents, "messages": msgs,
                "total_messages": rasd.store.count(t, None, q)}

    @app.post("/v1/messages", summary="Ingest messages (analysed, redacted, stored, linked)")
    def ingest(batch: BatchIn, t: str = Depends(tenant)):
        t0 = time.perf_counter()
        out = [rasd.ingest(t, m.to_message()) for m in batch.messages]
        g = rasd.graph(t)
        rasd.store.record_op(t, "ingest", "ok", (time.perf_counter() - t0) * 1000, len(out),
                             f"sources={dict(Counter(m.source for m in batch.messages))}")
        return {"ingested": len(out), "results": [
            {"message_id": a["message_id"], "verdict": a["verdict"], "score": a["score"],
             "campaign_id": g.msg_campaign.get(a["message_id"])} for a in out]}

    @app.get("/v1/messages")
    def list_messages(verdict: Literal["benign", "suspicious", "malicious"] | None = None, q: str | None = None,
                      source: Literal["real", "synthetic", "test", "unspecified"] | None = None,
                      campaign: Literal["yes", "no"] | None = None,
                      day: str | None = Query(None, pattern=r"^\d{4}-\d{2}-\d{2}$"),
                      limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0), t: str = Depends(tenant)):
        g = rasd.graph(t)
        if campaign:
            rows = rasd.store.list(t, verdict, q, 100000, 0, source, day)
            rows = [r for r in rows if (r["id"] in g.msg_campaign) == (campaign == "yes")]
            total, rows = len(rows), rows[offset:offset + limit]
        else:
            total, rows = rasd.store.count(t, verdict, q, source, day), rasd.store.list(t, verdict, q, limit, offset, source, day)
        for r in rows:
            r["campaign_id"] = g.msg_campaign.get(r["id"])
        return {"messages": rows, "total": total, "limit": limit, "offset": offset}

    @app.get("/v1/messages/{mid}")
    def get_message(mid: str, lang: Lang = "ar", t: str = Depends(tenant)):
        r = rasd.store.get(t, mid)
        if not r:
            raise HTTPException(404, "message not found")
        g = rasd.graph(t)
        r["campaign_id"] = g.msg_campaign.get(mid)
        r["explanation"] = explain(r["analysis"], lang, thresholds)
        r["template_family"] = next((f["id"] for f in g.template_families if mid in f["message_ids"]), None)
        r["investigations"] = rasd.store.investigations(t, campaign_id=r["campaign_id"]) if r["campaign_id"] else []
        r["related_by_indicator"] = _related_messages(t, r["analysis"], mid)
        return r

    def _related_messages(t: str, analysis: dict, mid: str) -> list[dict]:
        out = []
        for i in analysis["indicators"]:
            if i["role"] != "body":
                continue
            others = [x for x in rasd.store.by_indicator(t, i["type"], i["value"]) if x != mid]
            if others:
                out.append({"key": i["key"], "linkable": i["linkable"], "messages": len(others), "message_ids": others[:20]})
        return out

    @app.delete("/v1/messages/{mid}", summary="Erase a message and its indicators")
    def delete_message(mid: str, t: str = Depends(tenant)):
        if not rasd.store.delete(t, mid):
            raise HTTPException(404, "message not found")
        rasd.store.audit(t, "delete_message", mid)
        return {"deleted": mid}

    @app.post("/v1/retention/purge", summary="Delete messages ingested more than N days ago")
    def purge(days: int = Query(ge=1), t: str = Depends(tenant)):
        n = rasd.store.purge_older_than(t, days)
        rasd.store.audit(t, "purge", f"days={days} deleted={n}")
        return {"deleted": n}

    # ------------------------------------------------------------------ campaigns & graph
    @app.get("/v1/campaigns")
    def campaigns(t: str = Depends(tenant)):
        g = rasd.graph(t)
        brief = ("id", "size", "first_seen", "last_seen", "confidence", "confidence_reason", "brands", "tactics",
                 "varieties", "shared_indicator_count", "link_kinds", "max_score")
        inv = Counter(i["campaign_id"] for i in rasd.store.investigations(t, "open"))
        return {"campaigns": [{**{k: c[k] for k in brief}, "open_investigations": inv.get(c["id"], 0),
                               "indicator_types": sorted({d["type"] for d in c["indicators"] if d["messages"] >= 2})}
                              for c in g.campaigns],
                "suppressed_indicators": g.suppressed}

    @app.get("/v1/campaigns/{cid}")
    def campaign(cid: str, lang: Lang = "ar", t: str = Depends(tenant)):
        c = rasd.graph(t).campaign(cid)
        if not c:
            raise HTTPException(404, "campaign not found")
        b = rasd.store.briefs(t, c["message_ids"][:300])
        briefs = [{k: b[m][k] for k in ("id", "received_at", "verdict", "score", "variety", "source", "text")}
                  for m in c["message_ids"][:300] if m in b]
        return {"campaign": c, "explanation": explain_campaign(c, lang), "messages": briefs,
                "investigations": rasd.store.investigations(t, campaign_id=cid)}

    @app.get("/v1/campaigns/{cid}/stix", summary="STIX 2.1 bundle for MISP / OpenCTI / TAXII")
    def campaign_stix(cid: str, t: str = Depends(tenant)):
        c = rasd.graph(t).campaign(cid)
        if not c:
            raise HTTPException(404, "campaign not found")
        rasd.store.audit(t, "export_stix", cid)
        return campaign_bundle(c)

    @app.get("/v1/template-families", summary="Script reuse across messages (weak evidence; not attribution)")
    def template_families(t: str = Depends(tenant)):
        return {"template_families": rasd.graph(t).template_families}

    @app.get("/v1/graph", summary="Investigation graph: direct evidence vs inferred relations")
    def graph(campaign_id: str | None = None, t: str = Depends(tenant)):
        g = rasd.graph(t)
        if campaign_id and not g.campaign(campaign_id):
            raise HTTPException(404, "campaign not found")
        return g.subgraph(campaign_id)

    @app.get("/v1/links/explain", summary="Why are two messages (not) linked?")
    def link(a: str, b: str, t: str = Depends(tenant)):
        return rasd.graph(t).explain_link(a, b)

    # ------------------------------------------------------------------ threat intelligence explorer
    def _groups(t: str) -> list[dict]:
        g = rasd.graph(t)
        out = rasd.store.indicator_groups(t)
        for d in out:
            d["campaign_ids"] = sorted({g.msg_campaign[m] for m in d["message_ids"] if m in g.msg_campaign})
            d["suppressed_reason"] = g.suppressed.get(d["key"])
        return out

    @app.get("/v1/indicators", summary="Search aggregated indicators of compromise")
    def indicators(type: IndType | None = None, q: str | None = None, role: Literal["body", "sender"] | None = None,
                   in_campaign: Literal["yes", "no"] | None = None, flagged_only: bool = False,
                   linkable: Literal["yes", "no"] | None = None,
                   sort: Literal["messages", "last_seen", "max_score"] = "messages",
                   limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0), t: str = Depends(tenant)):
        rows = _groups(t)
        if type:
            rows = [r for r in rows if r["type"] == type]
        if q:
            ql = q.lower()
            rows = [r for r in rows if ql in r["value"].lower()]
        if role:
            rows = [r for r in rows if role in r["roles"]]
        if in_campaign:
            rows = [r for r in rows if bool(r["campaign_ids"]) == (in_campaign == "yes")]
        if flagged_only:
            rows = [r for r in rows if r["malicious"] or r["suspicious"]]
        if linkable:
            rows = [r for r in rows if r["linkable"] == (linkable == "yes")]
        rows.sort(key=lambda r: (r[sort] or 0, r["key"]) if sort != "last_seen" else (r["last_seen"] or "", r["key"]), reverse=True)
        facets = dict(Counter(r["type"] for r in rows))
        page = rows[offset:offset + limit]
        for r in page:
            r["message_ids"] = r["message_ids"][:50]
        return {"indicators": page, "total": len(rows), "limit": limit, "offset": offset, "facets_by_type": facets}

    @app.get("/v1/indicators/detail", summary="One indicator: sightings, campaigns, co-occurring indicators")
    def indicator_detail(type: IndType, value: str, t: str = Depends(tenant)):
        ids = rasd.store.by_indicator(t, type, value)
        if not ids:
            raise HTTPException(404, "indicator not seen")
        g = rasd.graph(t)
        key = f"{type}:{value}"
        briefs = rasd.store.briefs(t, ids)
        co: dict = defaultdict(lambda: {"messages": 0})
        attrs, evidence = {}, Counter()
        for mid in ids:
            a = rasd.store.get(t, mid)["analysis"]
            for i in a["indicators"]:
                if i["key"] == key:
                    attrs = attrs or i["attrs"]
                elif i["role"] == "body":
                    co[i["key"]].update(type=i["type"], value=i["value"], linkable=i["linkable"])
                    co[i["key"]]["messages"] += 1
            for e in a["evidence"]:
                if any(key.split(":", 1)[1] in str(v) for v in e["detail"].values()):
                    evidence[e["id"]] += 1
        msgs = sorted(briefs.values(), key=lambda m: m["received_at"] or "")
        for m in msgs:
            m["campaign_id"] = g.msg_campaign.get(m["id"])
            m["text"] = m["text"][:200]
        return {"key": key, "type": type, "value": value, "attrs": attrs, "messages": msgs,
                "first_seen": msgs[0]["received_at"] if msgs else None, "last_seen": msgs[-1]["received_at"] if msgs else None,
                "campaign_ids": sorted({m["campaign_id"] for m in msgs if m["campaign_id"]}),
                "suppressed_reason": g.suppressed.get(key),
                "linkable": any(i["linkable"] for m in ids for i in rasd.store.get(t, m)["analysis"]["indicators"] if i["key"] == key),
                "co_occurring": sorted(({"key": k, **v} for k, v in co.items()), key=lambda d: -d["messages"])[:30],
                "evidence_referencing": dict(evidence)}

    @app.get("/v1/indicators/lookup", summary="Has this indicator been seen? In which campaign?")
    def lookup(type: IndType, value: str, t: str = Depends(tenant)):
        ids = rasd.store.by_indicator(t, type, value)
        g = rasd.graph(t)
        return {"type": type, "value": value, "message_ids": ids,
                "campaign_ids": sorted({g.msg_campaign[i] for i in ids if i in g.msg_campaign}),
                "suppressed_reason": g.suppressed.get(f"{type}:{value}")}

    @app.get("/v1/entities", summary="Impersonated organisations (brand mentions), from stored analyses")
    def entities(t: str = Depends(tenant)):
        g = rasd.graph(t)
        agg: dict = {}
        for c in g.campaigns:
            for b, n in c["brands"].items():
                agg.setdefault(b, {"campaigns": set(), "in_campaigns": 0})["campaigns"].add(c["id"])
                agg[b]["in_campaigns"] += n
        counts = Counter()
        flagged = Counter()
        for n in g.nodes.values():
            for b in n.brands:
                counts[b] += 1
                flagged[b] += n.verdict != "benign"
        info = {b.id: b for b in BRANDS}
        return {"entities": sorted(({"id": b, "type": "brand", "sector": info[b].sector if b in info else None,
                                     "official_domains": list(info[b].domains) if b in info else [],
                                     "mentions": counts[b], "flagged_mentions": flagged[b],
                                     "campaign_ids": sorted(agg.get(b, {}).get("campaigns", set()))}
                                    for b in counts), key=lambda d: -d["flagged_mentions"]),
                "note": "entities are organisations named in messages (impersonation targets); they never link campaigns"}

    # ------------------------------------------------------------------ investigations
    @app.get("/v1/investigations")
    def list_investigations(status: Literal["open", "closed"] | None = None, t: str = Depends(tenant)):
        g = rasd.graph(t)
        rows = rasd.store.investigations(t, status)
        for r in rows:
            c = g.campaign(r["campaign_id"])
            r["campaign_exists"] = c is not None
            r["campaign_size"] = c["size"] if c else None
        return {"investigations": rows}

    @app.post("/v1/investigations", status_code=201)
    def create_investigation(body: InvestigationIn, t: str = Depends(tenant)):
        if not rasd.graph(t).campaign(body.campaign_id):
            raise HTTPException(404, "campaign not found")
        inv = rasd.store.create_investigation(t, body.campaign_id, body.title, body.notes)
        rasd.store.audit(t, "open_investigation", f"{inv['id']} {body.campaign_id}")
        return inv

    @app.patch("/v1/investigations/{iid}")
    def update_investigation(iid: str, body: InvestigationPatch, t: str = Depends(tenant)):
        if not rasd.store.get_investigation(t, iid):
            raise HTTPException(404, "investigation not found")
        inv = rasd.store.update_investigation(t, iid, body.status, body.notes)
        rasd.store.audit(t, "update_investigation", f"{iid} status={body.status}")
        return inv

    # ------------------------------------------------------------------ overview
    @app.get("/v1/stats")
    def stats(t: str = Depends(tenant)):
        s = rasd.store.stats(t)
        g = rasd.graph(t)
        s["campaigns"] = len(g.campaigns)
        s["campaign_confidence"] = {lv: sum(1 for c in g.campaigns if c["confidence"] == lv) for lv in ("high", "medium", "low")}
        s["messages_in_campaigns"] = len(g.msg_campaign)
        s["template_families"] = len(g.template_families)
        return s

    @app.get("/v1/overview", summary="Executive overview — every figure computed from stored data")
    def overview(t: str = Depends(tenant)):
        s = stats(t)
        g = rasd.graph(t)
        flagged = s["by_verdict"].get("malicious", 0) + s["by_verdict"].get("suspicious", 0)
        link_types = Counter(d["type"] for c in g.campaigns for d in c["indicators"] if d["messages"] >= 2)
        recent = rasd.store.list(t, "malicious", None, 8) + rasd.store.list(t, "suspicious", None, 8)
        recent.sort(key=lambda r: r["received_at"] or "", reverse=True)
        for r in recent:
            r["campaign_id"] = g.msg_campaign.get(r["id"])
            r["text"] = r["text"][:160]
        top = sorted(g.campaigns, key=lambda c: (-c["size"], c["id"]))[:6]
        return {
            **s,
            "kpis": {"messages": s["messages"], "campaigns": s["campaigns"], "indicators": s["indicators_distinct"],
                     "high_risk": s["by_verdict"].get("malicious", 0), "flagged": flagged,
                     "open_investigations": len(rasd.store.investigations(t, "open"))},
            "correlation": {"flagged_messages": flagged, "linked_messages": len(g.msg_campaign),
                            "linked_share": round(len(g.msg_campaign) / flagged, 4) if flagged else None,
                            "confidence": s["campaign_confidence"], "linking_indicator_types": dict(link_types),
                            "template_families": len(g.template_families), "suppressed_indicators": len(g.suppressed),
                            "related_not_merged_pairs": sum(len(c["related"]) for c in g.campaigns) // 2},
            "top_campaigns": [{k: c[k] for k in ("id", "size", "confidence", "brands", "last_seen", "shared_indicator_count")} for c in top],
            "recent_detections": recent[:10],
            "recent_activity": rasd.store.ops(t, 10),
            "recent_investigations": rasd.store.investigations(t)[:6],
        }

    # ------------------------------------------------------------------ database intelligence center (read-only)
    @app.get("/v1/db/overview")
    def db_overview(t: str = Depends(tenant)):
        return {**rasd.store.db_overview(t), "integrity": rasd.store.integrity(t), "read_only": True}

    @app.get("/v1/db/schema")
    def db_schema(t: str = Depends(tenant)):
        return rasd.store.schema()

    @app.get("/v1/db/tables/{table}/rows")
    def db_rows(table: str, request: Request, q: str | None = None, limit: int = Query(50, ge=1, le=200),
                offset: int = Query(0, ge=0), t: str = Depends(tenant)):
        if table not in EXPLORABLE:
            raise HTTPException(404, "unknown table")
        filters = {k[2:]: v for k, v in request.query_params.items() if k.startswith("f_")}
        try:
            return rasd.store.table_rows(t, table, q, filters, limit, offset)
        except ValueError as e:
            raise HTTPException(422, str(e)) from e

    @app.get("/v1/db/tables/{table}/rows/{rowid}")
    def db_record(table: str, rowid: int, t: str = Depends(tenant)):
        if table not in EXPLORABLE:
            raise HTTPException(404, "unknown table")
        rec = rasd.store.table_record(t, table, rowid)
        if not rec:
            raise HTTPException(404, "record not found")
        return rec

    # ------------------------------------------------------------------ system monitoring
    @app.get("/v1/system/health", summary="Measured health of engine, database, pipeline and API")
    def system_health(t: str = Depends(tenant)):
        return health(rasd, t, metrics)

    if DASHBOARD.exists():
        @app.get("/", include_in_schema=False)
        def index():
            return FileResponse(DASHBOARD / "index.html")
        app.mount("/static", StaticFiles(directory=DASHBOARD), name="static")
    return app
