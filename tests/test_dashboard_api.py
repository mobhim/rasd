"""Backend behind the dashboard: provenance, read-only database explorer,
intelligence explorer, investigations, monitoring and the evidence graph."""
import sqlite3

import pytest
from fastapi.testclient import TestClient

from rasd.api.app import create_app
from rasd.service import Rasd
from rasd.storage import Store

PHISH = "عزيزي العميل تم إيقاف بطاقتك لدى مصرف الراجحي حدث بياناتك عبر الرابط https://{}/login خلال 24 ساعة"
H = {"X-API-Key": "k"}


@pytest.fixture()
def client():
    c = TestClient(create_app(Rasd(), {"k": "t", "k2": "other"}))
    msgs = [
        {"text": PHISH.format("alrajhi-a1.example"), "sender": "0500000001", "received_at": "2026-11-01T10:00:00Z", "source": "synthetic"},
        {"text": "مصرف الراجحي: حسابك موقوف، تواصل واتساب 0500007777 او الرابط alrajhi-a1.example/login", "sender": "0500000002",
         "received_at": "2026-11-02T10:00:00Z", "source": "synthetic"},
        {"text": PHISH.format("rajhi-b2.test"), "sender": "0500000003", "received_at": "2026-11-03T10:00:00Z", "source": "test"},
        {"text": PHISH.format("rajhi-b2.test"), "sender": "0500000004", "received_at": "2026-11-04T10:00:00Z", "source": "test"},
        {"text": "وينك يا رجال تعال العشا جاهز", "sender": "0500000005", "received_at": "2026-11-04T11:00:00Z"},
    ]
    assert c.post("/v1/messages", headers=H, json={"messages": msgs}).status_code == 200
    return c


def test_every_route_requires_a_key(client):
    for path in ("/v1/overview", "/v1/db/overview", "/v1/db/schema", "/v1/db/tables/messages/rows", "/v1/indicators",
                 "/v1/entities", "/v1/investigations", "/v1/system/health", "/v1/graph"):
        assert client.get(path).status_code == 401, path


def test_provenance_is_stored_and_reported(client):
    ov = client.get("/v1/overview", headers=H).json()
    assert ov["by_source"] == {"synthetic": 2, "test": 2, "unspecified": 1}
    assert client.get("/v1/messages", headers=H, params={"source": "test"}).json()["total"] == 2
    assert client.post("/v1/messages", headers=H, json={"messages": [{"text": "x", "source": "made-up"}]}).status_code == 422


def test_overview_figures_match_the_underlying_records(client):
    ov = client.get("/v1/overview", headers=H).json()
    k = ov["kpis"]
    assert k["messages"] == client.get("/v1/messages", headers=H).json()["total"] == 5
    assert k["high_risk"] == client.get("/v1/messages", headers=H, params={"verdict": "malicious"}).json()["total"]
    assert k["campaigns"] == len(client.get("/v1/campaigns", headers=H).json()["campaigns"]) == 2
    assert k["indicators"] == client.get("/v1/indicators", headers=H, params={"limit": 500}).json()["total"]
    assert ov["correlation"]["linked_messages"] == client.get("/v1/messages", headers=H, params={"campaign": "yes"}).json()["total"] == 4
    assert ov["correlation"]["related_not_merged_pairs"] == 1


def test_database_explorer_reports_the_real_schema(client):
    db = client.get("/v1/db/overview", headers=H).json()
    assert db["read_only"] and db["engine"] == "SQLite" and db["schema_version"] == "2"
    assert {t["name"]: t["rows"] for t in db["tables"]}["messages"] == 5
    assert all(c["status"] == "ok" for c in db["integrity"])
    sc = client.get("/v1/db/schema", headers=H).json()
    msgs = next(t for t in sc["tables"] if t["name"] == "messages")
    assert "source" in {c["name"] for c in msgs["columns"]} and msgs["declared_foreign_keys"] == []
    assert any(r["from"] == "indicators.message_id" and r["kind"] == "logical" for r in sc["relations"])
    assert {v["name"] for v in sc["derived_views"]} == {"campaigns", "template_families"}


def test_database_explorer_is_read_only_tenant_scoped_and_injection_safe(client):
    rows = client.get("/v1/db/tables/indicators/rows", headers=H, params={"q": "alrajhi-a1"}).json()
    assert rows["total"] >= 2 and all("alrajhi-a1" in r["value"] or "alrajhi-a1" in r["message_id"] for r in rows["rows"])
    assert client.get("/v1/db/tables/indicators/rows", headers={"X-API-Key": "k2"}).json()["total"] == 0
    assert client.get("/v1/db/tables/sqlite_master/rows", headers=H).status_code == 404
    assert client.get("/v1/db/tables/messages/rows", headers=H, params={"f_tenant": "other"}).status_code == 422
    assert client.get("/v1/db/tables/messages/rows", headers=H, params={"f_id": "x' OR 1=1 --"}).json()["total"] == 0
    assert client.get("/v1/db/tables/messages/rows", headers=H, params={"q": "%' OR '1'='1"}).json()["total"] == 0
    for verb in ("post", "put", "patch", "delete"):
        assert getattr(client, verb)("/v1/db/tables/messages/rows", headers=H).status_code == 405
    rid = rows["rows"][0]["_rowid"]
    rec = client.get(f"/v1/db/tables/indicators/rows/{rid}", headers=H).json()
    assert rec["related"]["message"]["id"] == rows["rows"][0]["message_id"] and "tenant" not in rec["record"]
    assert client.get(f"/v1/db/tables/indicators/rows/{rid}", headers={"X-API-Key": "k2"}).status_code == 404


def test_listings_never_expose_victim_or_card_data(client):
    client.post("/v1/messages", headers=H, json={"messages": [
        {"text": PHISH.format("alrajhi-a1.example") + " بطاقة 4111111111111111", "recipient": "0551112222"}]})
    blob = str(client.get("/v1/db/tables/messages/rows", headers=H, params={"limit": 200}).json())
    assert "4111111111111111" not in blob and "0551112222" not in blob


def test_intelligence_explorer_filters_and_detail(client):
    ind = client.get("/v1/indicators", headers=H, params={"type": "domain", "in_campaign": "yes"}).json()
    assert {r["value"] for r in ind["indicators"]} == {"alrajhi-a1.example", "rajhi-b2.test"}
    d = client.get("/v1/indicators/detail", headers=H, params={"type": "domain", "value": "alrajhi-a1.example"}).json()
    assert len(d["messages"]) == 2 and len(d["campaign_ids"]) == 1 and d["linkable"]
    assert "phone:+966500007777" in {c["key"] for c in d["co_occurring"]}
    assert "url.brand_impersonation" in d["evidence_referencing"]
    assert client.get("/v1/indicators/detail", headers=H, params={"type": "domain", "value": "never.example"}).status_code == 404
    ents = client.get("/v1/entities", headers=H).json()["entities"]
    assert ents[0]["id"] == "alrajhi" and len(ents[0]["campaign_ids"]) == 2


def test_graph_separates_direct_evidence_from_inference(client):
    g = client.get("/v1/graph", headers=H).json()
    kinds = {e["kind"]: e["direct"] for e in g["edges"]}
    assert kinds["uses"] is True and kinds["same_template"] is False
    camps = [n for n in g["nodes"] if n["kind"] == "campaign"]
    tpl = [e for e in g["edges"] if e["kind"] == "same_template"]
    assert len(camps) == 2 and len(tpl) == 1        # shown as related, never merged
    assert client.get("/v1/graph", headers=H, params={"campaign_id": "cmp_nope"}).status_code == 404


def test_investigation_workflow(client):
    cid = client.get("/v1/campaigns", headers=H).json()["campaigns"][0]["id"]
    assert client.post("/v1/investigations", headers=H, json={"campaign_id": "cmp_0000000000", "title": "x"}).status_code == 404
    inv = client.post("/v1/investigations", headers=H, json={"campaign_id": cid, "title": "تحقيق"}).json()
    assert client.get("/v1/overview", headers=H).json()["kpis"]["open_investigations"] == 1
    assert client.patch(f"/v1/investigations/{inv['id']}", headers=H, json={"status": "closed"}).json()["status"] == "closed"
    assert client.get("/v1/overview", headers=H).json()["kpis"]["open_investigations"] == 0
    assert client.get("/v1/investigations", headers={"X-API-Key": "k2"}).json()["investigations"] == []


def test_monitoring_reports_measured_values_and_records_operations(client):
    client.post("/v1/messages", headers=H, json={"messages": []})            # rejected request
    h = client.get("/v1/system/health", headers=H).json()
    assert h["status"] == "ok" and h["checks"]["engine"]["observed_verdict"] == "malicious"
    assert h["checks"]["engine"]["latency_ms"] > 0 and h["checks"]["api"]["requests_total"] >= 2
    assert any(o["op"] == "ingest" and o["items"] == 5 for o in h["recent_operations"])
    assert any(o["status"] == "rejected" for o in h["recent_failures"])
    assert h["resources"]["process_cpu_seconds"] >= 0


def test_v1_database_is_migrated_in_place(tmp_path):
    p = tmp_path / "old.db"
    con = sqlite3.connect(p)
    con.executescript("CREATE TABLE messages(tenant TEXT NOT NULL, id TEXT NOT NULL, received_at TEXT, ingested_at TEXT NOT NULL,"
                      " channel TEXT, recipient_pseudo TEXT, text_redacted TEXT NOT NULL, language TEXT, variety TEXT, score REAL,"
                      " verdict TEXT, analysis TEXT NOT NULL, PRIMARY KEY(tenant, id));"
                      "INSERT INTO messages VALUES('t','m1',NULL,'2026-01-01','sms',NULL,'x','ar','msa',0.1,'benign','{}');")
    con.commit(); con.close()
    s = Store(str(p))
    assert s.list("t")[0]["source"] == "unspecified" and s.db_overview("t")["schema_version"] == "2"
