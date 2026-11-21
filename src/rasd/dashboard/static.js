"use strict";
/* Read-only adapter for the static snapshot produced by `rasd export-demo`.
   It answers the same API paths from JSON files that the real API wrote, and applies the
   same filter/sort/paging semantics as the server for list endpoints. Writes are refused. */
(() => {
  const BASE = window.RASD_STATIC_BASE || "snapshot/";
  const cache = new Map();
  const load = f => { if (!cache.has(f)) cache.set(f, fetch(BASE + f).then(r => { if (!r.ok) throw new Error(r.status === 404 ? "not found in snapshot" : r.statusText); return r.json(); })); return cache.get(f); };
  const fnv1a = s => { let h = 0x811c9dc5; for (const b of new TextEncoder().encode(s)) { h ^= b; h = Math.imul(h, 0x01000193) >>> 0; } return h.toString(16).padStart(8, "0"); };
  const page = (rows, p, key) => { const limit = +(p.get("limit") || 50), offset = +(p.get("offset") || 0); return {[key]: rows.slice(offset, offset + limit), total: rows.length, limit, offset}; };
  const lc = s => String(s ?? "").toLowerCase();
  const SEARCH = {messages: ["id", "text_redacted", "verdict", "variety", "source"], indicators: ["message_id", "type", "value"], investigations: ["id", "campaign_id", "title", "notes"], operations: ["op", "status", "detail"], audit: ["action", "detail"]};

  /** Same evidence standard as Rasd.correlate(): only linkable, non-suppressed body indicators can link. */
  async function correlate(a) {
    const inds = await load("indicators.json"); const by = new Map(inds.map(i => [i.key, i]));
    const out = a.indicators.filter(i => i.role === "body").map(i => { const s = by.get(i.key);
      return {key: i.key, type: i.type, value: i.value, linkable: i.linkable, seen_in_messages: s ? s.messages : 0, message_ids: s ? s.message_ids.slice(0, 10) : [], campaign_ids: s ? s.campaign_ids : [], suppressed_reason: s ? s.suppressed_reason : null}; });
    const usable = out.filter(c => c.linkable && !c.suppressed_reason);
    return {indicators: out, would_join_campaigns: [...new Set(usable.flatMap(c => c.campaign_ids))].sort(), shares_resources_with_messages: [...new Set(usable.flatMap(c => c.message_ids))].sort().slice(0, 20),
      standard: "only actor-controlled resources (linkable, not suppressed) can link; text similarity never does"};
  }
  async function analyzeStatic(body) {
    let out;
    try { out = await window.RASD_ENGINE.analyze(body.text, body.sender); }
    catch (e) {
      const s = (await load("demo/samples.json")).samples.find(x => x.text === body.text);
      if (!s) throw new Error("محرك المتصفح غير متاح (" + (e.message || e) + ") — يمكن عرض النتائج المحسوبة مسبقًا للرسائل النموذجية فقط");
      out = await load(`demo/${s.id}.json`); out = {...out, engine: {runtime: "precomputed", note: "computed by the RASD engine when the snapshot was generated"}};
      return out;
    }
    return {...out, correlation: await correlate(out.analysis)};
  }

  window.RASD_STATIC = async (path, opts = {}) => {
    const u = new URL(path, "http://x"), p = u.searchParams, seg = u.pathname.replace(/^\/v1\//, "").split("/").map(decodeURIComponent);
    if (opts.method === "POST" && seg[0] === "analyze") return analyzeStatic(JSON.parse(opts.body || "{}"));
    if (opts.method && opts.method !== "GET") throw new Error("هذه لقطة ثابتة للقراءة فقط — شغّل خادم رصد لإجراء التعديلات");
    switch (seg[0]) {
      case "overview": return load("overview.json");
      case "demo": return load("demo/samples.json");
      case "search": {
        const q = lc(p.get("q")); const [camps, inds, msgs, ents] = await Promise.all([load("campaigns.json"), load("indicators.json"), load("messages.json"), load("entities.json")]);
        const full = await Promise.all(camps.campaigns.map(c => load(`campaigns/${c.id}.json`)));
        const mm = msgs.filter(m => lc(m.text).includes(q) || lc(m.id).includes(q));
        return {q, campaigns: full.filter(d => d.campaign.id.includes(q) || Object.keys(d.campaign.brands).some(b => b.includes(q)) || d.campaign.indicators.some(i => lc(i.value).includes(q))).slice(0, 20).map(d => ({id: d.campaign.id, size: d.campaign.size, confidence: d.campaign.confidence, brands: Object.keys(d.campaign.brands)})),
          indicators: inds.filter(i => lc(i.value).includes(q)).slice(0, 30).map(i => ({key: i.key, type: i.type, value: i.value, messages: i.messages, campaign_ids: i.campaign_ids})),
          entities: ents.entities.map(e => e.id).filter(e => e.includes(q)).slice(0, 10), messages: mm.slice(0, 20).map(m => ({...m, text: m.text.slice(0, 180)})), total_messages: mm.length};
      }
      case "stats": return load("overview.json");
      case "entities": return load("entities.json");
      case "template-families": return load("template-families.json");
      case "system": return load("system-health.json");
      case "investigations": { const d = await load("investigations.json"); const st = p.get("status"); return {investigations: d.investigations.filter(i => !st || i.status === st)}; }
      case "graph": return p.get("campaign_id") ? load(`graph/${p.get("campaign_id")}.json`) : load("graph.json");
      case "campaigns": return seg[1] ? load(`campaigns/${seg[1]}.json`) : load("campaigns.json");
      case "links": {
        const a = p.get("a"), b = p.get("b"); if (a === b) return {linked: false, reason: "same message"};
        const msgs = await load("messages.json"); const ma = msgs.find(m => m.id === a), mb = msgs.find(m => m.id === b);
        if (!ma?.campaign_id || ma.campaign_id !== mb?.campaign_id) return {linked: false, weak_signals: []};
        const l = await load(`links/${ma.campaign_id}.json`); return l[a < b ? `${a}|${b}` : `${b}|${a}`] || {linked: false};
      }
      case "messages": {
        if (seg[1]) return load(`messages/${seg[1]}.json`);
        let rows = await load("messages.json");
        const v = p.get("verdict"), q = lc(p.get("q")), src = p.get("source"), cmp = p.get("campaign"), dy = p.get("day");
        rows = rows.filter(m => (!v || m.verdict === v) && (!src || m.source === src) && (!dy || (m.received_at || "").startsWith(dy))
          && (!q || lc(m.text).includes(q) || lc(m.id).includes(q)) && (!cmp || (!!m.campaign_id) === (cmp === "yes")));
        return {...page(rows, p, "messages")};
      }
      case "indicators": {
        if (seg[1] === "detail") return load(`indicators/${fnv1a(p.get("type") + ":" + p.get("value"))}.json`);
        let rows = await load("indicators.json");
        const t = p.get("type"), q = lc(p.get("q")), role = p.get("role"), inc = p.get("in_campaign"), fl = p.get("flagged_only") === "true", lk = p.get("linkable"), sort = p.get("sort") || "messages";
        rows = rows.filter(r => (!t || r.type === t) && (!q || lc(r.value).includes(q)) && (!role || r.roles.includes(role))
          && (!inc || (r.campaign_ids.length > 0) === (inc === "yes")) && (!fl || r.malicious || r.suspicious) && (!lk || r.linkable === (lk === "yes")));
        rows = [...rows].sort((a, b) => sort === "last_seen" ? String(b.last_seen).localeCompare(String(a.last_seen)) || b.key.localeCompare(a.key) : (b[sort] || 0) - (a[sort] || 0) || b.key.localeCompare(a.key));
        const facets = {}; rows.forEach(r => { facets[r.type] = (facets[r.type] || 0) + 1; });
        return {...page(rows, p, "indicators"), facets_by_type: facets};
      }
      case "db": {
        if (seg[1] === "overview") return load("db-overview.json");
        if (seg[1] === "schema") return load("db-schema.json");
        const table = seg[2]; if (!SEARCH[table]) throw new Error("unknown table");
        const d = await load(`db/${table}.json`);
        if (seg[4]) {
          const rec = d.rows.find(r => String(r._rowid) === seg[4]); if (!rec) throw new Error("record not found");
          const related = {}; let record = {...rec};
          if (table === "messages") {
            const m = await load(`messages/${rec.id}.json`); record = {...rec, analysis: m.analysis};
            related.indicators = (await load("db/indicators.json")).rows.filter(i => i.message_id === rec.id).map(({_rowid, type, value, role, linkable}) => ({_rowid, type, value, role, linkable}));
          } else if (table === "indicators") {
            const m = (await load("db/messages.json")).rows.find(x => x.id === rec.message_id);
            related.message = m ? {_rowid: m._rowid, id: m.id, verdict: m.verdict, score: m.score, source: m.source, received_at: m.received_at} : null;
            related.same_value_rows = d.rows.filter(x => x.type === rec.type && x.value === rec.value).length;
          }
          return {table, record, related};
        }
        const q = lc(p.get("q")); const filters = [...p.entries()].filter(([k]) => k.startsWith("f_")).map(([k, v]) => [k.slice(2), v]);
        const rows = d.rows.filter(r => filters.every(([k, v]) => String(r[k]) === v) && (!q || SEARCH[table].some(c => lc(r[c]).includes(q))));
        return {table, columns: d.columns, ...page(rows, p, "rows")};
      }
    }
    throw new Error("unsupported in static snapshot: " + u.pathname);
  };
})();
