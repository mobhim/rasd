"""RASD HTTP API (FastAPI). All /v1 routes require an API key that maps to a
tenant. Keys come from RASD_API_KEYS="key1:tenantA,key2:tenantB"; when unset a
random key is generated at start-up and printed once (never a default key)."""
from __future__ import annotations

import hmac
import os
import secrets
from pathlib import Path
from typing import Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .. import __version__
from ..integrations.stix import campaign_bundle
from ..models import Message
from ..service import Rasd
from ..storage import Store
from ..xai import explain, explain_campaign

DASHBOARD = Path(__file__).resolve().parent.parent / "dashboard"
Lang = Literal["ar", "en"]


class MessageIn(BaseModel):
    text: str = Field(min_length=1, max_length=5000)
    id: str | None = Field(default=None, max_length=64, pattern=r"^[\w\-.:]+$")
    sender: str | None = Field(default=None, max_length=64)
    recipient: str | None = Field(default=None, max_length=64, description="Pseudonymised (HMAC) before storage; never stored raw.")
    channel: Literal["sms", "whatsapp", "telegram", "email", "other"] = "sms"
    received_at: str | None = Field(default=None, description="ISO-8601 timestamp")

    def to_message(self) -> Message:
        return Message(**self.model_dump())


class BatchIn(BaseModel):
    messages: list[MessageIn] = Field(min_length=1, max_length=500)


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

    def tenant(x_api_key: str = Header(default="")) -> str:
        for k, t in keys.items():
            if hmac.compare_digest(k, x_api_key):
                return t
        raise HTTPException(401, "invalid or missing X-API-Key")

    def with_expl(a: dict, lang: str) -> dict:
        return {"analysis": a, "explanation": explain(a, lang, thresholds)}

    @app.get("/healthz")
    def health():
        return {"status": "ok", "version": __version__, "policy": rasd.analyzer.policy.version}

    @app.post("/v1/analyze", summary="Analyse one message without storing it")
    def analyze(m: MessageIn, lang: Lang = "ar", t: str = Depends(tenant)):
        return with_expl(rasd.analyze(m.to_message()), lang)

    @app.post("/v1/messages", summary="Ingest messages (analysed, redacted, stored, linked)")
    def ingest(batch: BatchIn, t: str = Depends(tenant)):
        out = [rasd.ingest(t, m.to_message()) for m in batch.messages]
        g = rasd.graph(t)
        return {"ingested": len(out), "results": [
            {"message_id": a["message_id"], "verdict": a["verdict"], "score": a["score"],
             "campaign_id": g.msg_campaign.get(a["message_id"])} for a in out]}

    @app.get("/v1/messages")
    def list_messages(verdict: Literal["benign", "suspicious", "malicious"] | None = None, q: str | None = None,
                      limit: int = Query(50, le=500), offset: int = 0, t: str = Depends(tenant)):
        g = rasd.graph(t)
        rows = rasd.store.list(t, verdict, q, limit, offset)
        for r in rows:
            r["campaign_id"] = g.msg_campaign.get(r["id"])
        return {"messages": rows}

    @app.get("/v1/messages/{mid}")
    def get_message(mid: str, lang: Lang = "ar", t: str = Depends(tenant)):
        r = rasd.store.get(t, mid)
        if not r:
            raise HTTPException(404, "message not found")
        r["campaign_id"] = rasd.graph(t).msg_campaign.get(mid)
        r["explanation"] = explain(r["analysis"], lang, thresholds)
        return r

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

    @app.get("/v1/campaigns")
    def campaigns(t: str = Depends(tenant)):
        g = rasd.graph(t)
        brief = ("id", "size", "first_seen", "last_seen", "confidence", "confidence_reason", "brands", "tactics",
                 "varieties", "shared_indicator_count", "link_kinds", "max_score")
        return {"campaigns": [{k: c[k] for k in brief} for c in g.campaigns], "suppressed_indicators": g.suppressed}

    @app.get("/v1/campaigns/{cid}")
    def campaign(cid: str, lang: Lang = "ar", t: str = Depends(tenant)):
        c = rasd.graph(t).campaign(cid)
        if not c:
            raise HTTPException(404, "campaign not found")
        briefs = []
        for mid in c["message_ids"][:300]:
            m = rasd.store.get(t, mid)
            if m:
                briefs.append({k: m[k] for k in ("id", "received_at", "verdict", "score", "variety", "text")})
        return {"campaign": c, "explanation": explain_campaign(c, lang), "messages": briefs}

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

    @app.get("/v1/graph")
    def graph(campaign_id: str | None = None, t: str = Depends(tenant)):
        return rasd.graph(t).subgraph(campaign_id)

    @app.get("/v1/links/explain", summary="Why are two messages (not) linked?")
    def link(a: str, b: str, t: str = Depends(tenant)):
        return rasd.graph(t).explain_link(a, b)

    @app.get("/v1/indicators/lookup", summary="Has this indicator been seen? In which campaign?")
    def lookup(type: Literal["url", "domain", "phone", "iban", "email", "handle", "wallet", "sender_id"], value: str,
               t: str = Depends(tenant)):
        ids = rasd.store.by_indicator(t, type, value)
        g = rasd.graph(t)
        return {"type": type, "value": value, "message_ids": ids,
                "campaign_ids": sorted({g.msg_campaign[i] for i in ids if i in g.msg_campaign}),
                "suppressed_reason": g.suppressed.get(f"{type}:{value}")}

    @app.get("/v1/stats")
    def stats(t: str = Depends(tenant)):
        s = rasd.store.stats(t)
        g = rasd.graph(t)
        s["campaigns"] = len(g.campaigns)
        s["campaign_confidence"] = {lv: sum(1 for c in g.campaigns if c["confidence"] == lv) for lv in ("high", "medium", "low")}
        s["messages_in_campaigns"] = len(g.msg_campaign)
        s["template_families"] = len(g.template_families)
        return s

    if DASHBOARD.exists():
        @app.get("/", include_in_schema=False)
        def index():
            return FileResponse(DASHBOARD / "index.html")
        app.mount("/static", StaticFiles(directory=DASHBOARD), name="static")
    return app
