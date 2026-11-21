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
    bundle = load("engine/bundle.json")["files"]
    assert "rasd/analysis/pipeline.py" in bundle and not any(k.startswith(("rasd/api", "rasd/storage", "rasd/graph")) for k in bundle)
    samples = load("demo/samples.json")["samples"]
    assert samples and all((snap / "demo" / f"{x['id']}.json").exists() for x in samples)
    assert '<script src="engine.js"></script>' in html and '<script src="demo.js"></script>' in html


def test_fnv1a_matches_reference_vectors():
    assert fnv1a("") == "811c9dc5" and fnv1a("a") == "e40c292c"


def test_engine_bundle_runs_standalone_and_matches_server(tmp_path):
    """The bundle shipped to the browser must be self-contained (stdlib only) and give
    exactly the server's result. Run it in a fresh interpreter with ONLY the bundle on the path."""
    import subprocess
    import sys

    from rasd.analysis import Analyzer
    from rasd.demo_export import engine_sources
    from rasd.models import Message
    for rel, src in engine_sources().items():
        f = tmp_path / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(src, encoding="utf8")
    text = "يا فندم الفيزا بتاعتك اتقفلت ابعتلي الكود اللي جالك دلوقتي. البنك الأهلي المصري"
    code = ("import json,sys; sys.path=[p for p in sys.path if 'site-packages' not in p and 'src' not in p]; sys.path.insert(0, %r);"
            "from rasd.analysis import Analyzer; from rasd.analysis.trace import trace; from rasd.models import Message;"
            "a=Analyzer().analyze(Message(%r, sender='01000123456')); trace(%r, a); print(json.dumps([a.verdict, a.score, len(a.evidence)]))") % (
        str(tmp_path), text, text)
    out = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, cwd=tmp_path)
    assert out.returncode == 0, out.stderr
    ref = Analyzer().analyze(Message(text, sender="01000123456"))
    assert json.loads(out.stdout) == [ref.verdict, ref.score, len(ref.evidence)]
