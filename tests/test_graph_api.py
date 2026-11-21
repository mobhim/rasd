import pytest
from fastapi.testclient import TestClient

from rasd.api.app import create_app
from rasd.graph import engine
from rasd.models import Message
from rasd.service import Rasd

T = "2026-11-0{}T10:00:00+00:00"
PHISH = "عزيزي العميل تم إيقاف بطاقتك لدى مصرف الراجحي حدث بياناتك عبر الرابط https://{}/login خلال 24 ساعة"


def build(msgs):
    r = Rasd()
    ids = [r.ingest("t", Message(text, sender=s, received_at=T.format(i + 1), recipient="0559999999"))["message_id"]
           for i, (text, s) in enumerate(msgs)]
    return r, r.graph("t"), ids


def test_identical_text_with_disjoint_infrastructure_is_not_merged():
    r, g, ids = build([(PHISH.format("alrajhi-a1.example"), "0500000001"), (PHISH.format("alrajhi-a1.example"), "0500000002"),
                       (PHISH.format("rajhi-b2.test"), "0500000003"), (PHISH.format("rajhi-b2.test"), "0500000004")])
    assert len(g.campaigns) == 2 and all(c["size"] == 2 for c in g.campaigns)
    ex = g.explain_link(ids[0], ids[2])
    assert ex["linked"] is False and ex["weak_signals"][0]["similar"] is True
    assert g.campaigns[0]["related"][0]["relation"] == "same_template_different_infrastructure"
    fam = g.template_families[0]
    assert fam["size"] == 4 and len(fam["campaign_ids"]) == 2 and fam["evidence_level"] == "weak"


def test_different_text_same_infrastructure_is_linked_with_evidence_chain():
    r, g, ids = build([
        (PHISH.format("alrajhi-a1.example"), "0500000001"),
        ("مصرف الراجحي: حسابك موقوف، للتفعيل تواصل واتساب 0500007777 او الرابط alrajhi-a1.example/login", "0500000002"),
        ("بطاقتك راح تتقفل الحين! كلمنا واتس ٠٥٠٠٠٠٧٧٧٧ وعطنا الرمز اللي وصلك. بنك الراجحي", "0500000003")])
    assert len(g.campaigns) == 1 and g.campaigns[0]["size"] == 3
    ex = g.explain_link(ids[0], ids[2])
    assert ex["linked"] and [h["via"] for h in ex["path"]] == ["domain:alrajhi-a1.example", "phone:+966500007777"]
    assert g.campaigns[0]["confidence"] == "medium" and set(g.campaigns[0]["bridges"]) == {"domain:alrajhi-a1.example", "phone:+966500007777"}


def test_single_weak_signal_never_links_but_two_independent_ones_corroborate():
    same_sender_diff_text = [("مبروك ربحت جائزة 5000 ريال تواصل واتساب 0500001111 وادفع رسوم التحويل", "0500000009"),
                             ("مطلوب موظفين للعمل من المنزل دخل يومي 500 ريال راسلنا تليجرام @job_x1", "0500000009")]
    assert build(same_sender_diff_text)[1].campaigns == []
    same_sender_same_text = [(PHISH.format("alrajhi-a1.example"), "0500000009"), (PHISH.format("rajhi-b2.test"), "0500000009")]
    g = build(same_sender_same_text)[1]
    assert len(g.campaigns) == 1 and g.campaigns[0]["confidence"] == "low" and g.campaigns[0]["link_kinds"] == ["corroborated"]


def test_shared_platforms_and_official_domains_never_link():
    g = build([("مبروك ربحت جائزة ادفع رسوم التحويل وراسلنا https://bit.ly/aaa111", "X1"),
               ("مبروك ربحت جائزة كبرى ادفع رسوم الشحن عبر https://bit.ly/bbb222", "X2"),
               ("عاجل سيتم إيقاف حسابك حدث بياناتك https://www.alrajhibank.com.sa/x او واتساب 0500003333", "0500000001"),
               ("تنبيه تم تعليق بطاقتك راجع https://www.alrajhibank.com.sa/y او اتصل 0500004444 فورا", "0500000002")])[1]
    assert g.campaigns == []


def test_resource_seen_mostly_in_benign_traffic_is_suppressed():
    legit = [(f"طلبك رقم {i} جاهز للاستلام من الفرع. للتواصل 0500005555", "Store") for i in range(4)]
    scam = [("مبروك ربحت جائزة 9000 ريال ادفع رسوم التحويل واتصل 0500005555", "0500000001"),
            ("ألف مبروك فزت معنا بجائزة، سدد رسوم الشحن وتواصل واتساب 0500005555", "0500000002")]
    g = build(legit + scam)[1]
    assert "phone:+966500005555" in g.suppressed and g.campaigns == []


def test_validity_window_blocks_stale_links(monkeypatch):
    monkeypatch.setitem(engine.WINDOW_DAYS, "domain", 1)
    r = Rasd()
    for ts in ("2026-01-01T00:00:00+00:00", "2026-06-01T00:00:00+00:00"):
        r.ingest("t", Message(PHISH.format("alrajhi-a1.example") + " " + ts[:7], received_at=ts))
    assert r.graph("t").campaigns == []


@pytest.fixture()
def client():
    return TestClient(create_app(Rasd(), {"k-a": "tenant-a", "k-b": "tenant-b"}))


def test_api_end_to_end(client):
    h = {"X-API-Key": "k-a"}
    assert client.get("/healthz").json()["status"] == "ok"
    assert client.post("/v1/analyze", json={"text": "x"}).status_code == 401
    r = client.post("/v1/analyze", headers=h, json={"text": PHISH.format("alrajhi-a1.example"), "sender": "0500000001"}).json()
    assert r["analysis"]["verdict"] == "malicious" and r["explanation"]["reasons"]
    assert client.get("/v1/messages", headers=h).json()["messages"] == []          # analyze is stateless
    batch = {"messages": [{"text": PHISH.format("alrajhi-a1.example") + " بطاقة 4111111111111111", "sender": "0500000001",
                           "recipient": "0551112222", "received_at": "2026-11-01T10:00:00Z"},
                          {"text": "حسابك موقوف، حدث بياناتك الآن alrajhi-a1.example/login مصرف الراجحي", "sender": "0500000002",
                           "received_at": "2026-11-02T10:00:00Z"}]}
    res = client.post("/v1/messages", headers=h, json=batch).json()["results"]
    cid = res[0]["campaign_id"]
    assert cid and cid == res[1]["campaign_id"]
    m = client.get(f"/v1/messages/{res[0]['message_id']}", headers=h).json()
    assert "4111" not in m["text"] and m["recipient_pseudo"].startswith("p_") and "0551112222" not in str(m)
    c = client.get(f"/v1/campaigns/{cid}", headers=h).json()
    assert c["campaign"]["size"] == 2 and c["explanation"]["narrative"]
    stix = client.get(f"/v1/campaigns/{cid}/stix", headers=h).json()
    types = [o["type"] for o in stix["objects"]]
    assert types.count("campaign") == 1 and "indicator" in types and "relationship" in types
    assert any(o.get("pattern") == "[domain-name:value = 'alrajhi-a1.example']" for o in stix["objects"])
    look = client.get("/v1/indicators/lookup", headers=h, params={"type": "domain", "value": "alrajhi-a1.example"}).json()
    assert look["campaign_ids"] == [cid] and len(look["message_ids"]) == 2
    link = client.get("/v1/links/explain", headers=h, params={"a": res[0]["message_id"], "b": res[1]["message_id"]}).json()
    assert link["linked"] and link["path"][0]["via"] == "domain:alrajhi-a1.example"
    g = client.get("/v1/graph", headers=h, params={"campaign_id": cid}).json()
    assert {n["kind"] for n in g["nodes"]} >= {"campaign", "message", "indicator"} and g["edges"]
    assert {(e["kind"], e["direct"]) for e in g["edges"]} >= {("contains", True), ("member", False)}
    assert client.get("/v1/stats", headers=h).json()["campaigns"] == 1
    # tenant isolation
    hb = {"X-API-Key": "k-b"}
    assert client.get("/v1/messages", headers=hb).json()["messages"] == []
    assert client.get(f"/v1/campaigns/{cid}", headers=hb).status_code == 404
    # erasure
    assert client.delete(f"/v1/messages/{res[0]['message_id']}", headers=h).status_code == 200
    assert client.get("/v1/campaigns", headers=h).json()["campaigns"] == []


def test_api_rejects_oversized_and_malformed_input(client):
    h = {"X-API-Key": "k-a"}
    assert client.post("/v1/analyze", headers=h, json={"text": "x" * 5001}).status_code == 422
    assert client.post("/v1/analyze", headers=h, json={"text": "ok", "id": "../../etc"}).status_code == 422
    assert client.post("/v1/messages", headers=h, json={"messages": []}).status_code == 422
