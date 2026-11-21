"""The static snapshot is produced only from real API responses and is labelled synthetic."""
import json

from rasd.demo_export import export, fnv1a


def test_snapshot_is_complete_consistent_and_labelled(tmp_path):
    n = export(str(tmp_path), seed=3, n_campaigns=4, n_singletons=2, n_benign=20)
    snap = tmp_path / "snapshot"
    load = lambda p: json.loads((snap / p).read_text(encoding="utf8"))   # noqa: E731
    ov, msgs, inds = load("overview.json"), load("messages.json"), load("indicators.json")
    assert n == len(list(snap.rglob("*.json")))
    assert ov["by_source"] == {"synthetic": len(msgs)} and ov["kpis"]["messages"] == len(msgs)
    assert ov["kpis"]["indicators"] == len(inds)
    assert all((snap / "messages" / f"{m['id']}.json").exists() for m in msgs)
    assert all((snap / "indicators" / f"{fnv1a(i['key'])}.json").exists() for i in inds)
    for c in load("campaigns.json")["campaigns"]:
        assert (snap / "campaigns" / f"{c['id']}.json").exists() and (snap / "graph" / f"{c['id']}.json").exists()
    assert len(load("db/messages.json")["rows"]) == len(msgs)
    html = (tmp_path / "index.html").read_text(encoding="utf8")
    assert 'window.RASD_STATIC_BASE="snapshot/"' in html and "static/" not in html
    assert "synthetic" in load("meta.json")["source"]


def test_fnv1a_matches_reference_vectors():
    assert fnv1a("") == "811c9dc5" and fnv1a("a") == "e40c292c"
