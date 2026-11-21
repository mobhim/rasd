"use strict";
/* In-browser RASD engine (static demo only).
   Loads Pyodide (CPython compiled to WebAssembly) and runs the UNMODIFIED RASD Python
   engine — the same source files as the server — inside the visitor's browser.
   The analysed text never leaves the device. No network access is made from Python. */
(() => {
  const BASE = window.RASD_STATIC_BASE || "snapshot/";
  const PYODIDE = window.RASD_PYODIDE_URL || "https://cdn.jsdelivr.net/pyodide/v0.29.3/full/";
  const listeners = new Set();
  const E = {status: "idle", error: null, ms: null, files: 0, py: null};
  const emit = () => listeners.forEach(f => { try { f(E); } catch { /* listener errors are not engine errors */ } });
  const script = src => new Promise((ok, fail) => { const s = document.createElement("script"); s.src = src; s.onload = ok; s.onerror = () => fail(new Error("تعذّر تحميل " + src)); document.head.appendChild(s); });
  let loading = null;
  E.onChange = f => { listeners.add(f); f(E); return () => listeners.delete(f); };
  E.load = () => loading || (loading = (async () => {
    E.status = "loading"; emit();
    const t0 = performance.now();
    try {
      if (!window.loadPyodide) await script(PYODIDE + "pyodide.js");
      const [py, bundle] = await Promise.all([window.loadPyodide({indexURL: PYODIDE}), fetch(BASE + "engine/bundle.json").then(r => { if (!r.ok) throw new Error("engine bundle missing"); return r.json(); })]);
      for (const [path, src] of Object.entries(bundle.files)) {
        const dir = ("/engine/" + path).split("/").slice(0, -1).join("/");
        py.FS.mkdirTree(dir); py.FS.writeFile("/engine/" + path, src);
      }
      py.runPython(`
import json, sys
sys.path.insert(0, "/engine")
from rasd.analysis import Analyzer
from rasd.analysis.trace import trace
from rasd.xai import explain
from rasd.models import Message
_A = Analyzer()
def rasd_run(text, sender):
    a = _A.analyze(Message(text, sender=sender or None))
    d = a.to_dict()
    th = (_A.policy.suspicious_threshold, _A.policy.malicious_threshold)
    return json.dumps({"analysis": d, "explanation": explain(d, "ar", th), "trace": trace(text, a)}, ensure_ascii=False)
`);
      E.py = py; E.files = Object.keys(bundle.files).length; E.version = bundle.version;
      E.ms = Math.round(performance.now() - t0); E.status = "ready"; emit();
    } catch (e) { E.status = "failed"; E.error = e.message || String(e); emit(); loading = null; throw e; }
  })());
  E.analyze = async (text, sender) => {
    await E.load();
    const t0 = performance.now();
    const out = JSON.parse(E.py.globals.get("rasd_run")(text, sender || null));
    out.engine = {runtime: "pyodide", ms: Math.round(performance.now() - t0), files: E.files, version: E.version};
    return out;
  };
  window.RASD_ENGINE = E;
})();
