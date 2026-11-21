"use strict";
/* RASD dashboard core: API client, router, helpers, charts, evidence graph.
   SECURITY: every string that originates from a message or indicator is attacker-controlled.
   It is only ever inserted via esc(); indicators are rendered as text, never as links. */

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}[c]));
const fmt = n => n == null ? "—" : Number(n).toLocaleString("en-US");
const pct = (x, d = 0) => x == null ? "—" : (100 * x).toFixed(d) + "%";
const day = s => s ? esc(String(s).slice(0, 10)) : "—";
const dt = s => s ? esc(String(s).replace("T", " ").slice(0, 16)) : "—";
const bytes = b => typeof b !== "number" ? esc(b ?? "—") : b > 1e9 ? (b / 1e9).toFixed(2) + " GB" : b > 1e6 ? (b / 1e6).toFixed(1) + " MB" : b > 1e3 ? (b / 1e3).toFixed(1) + " KB" : b + " B";
const STATIC = !!window.RASD_STATIC;

const T = {
  verdict: {malicious: "احتيالية", suspicious: "مشبوهة", benign: "سليمة"},
  conf: {high: "مرتفعة", medium: "متوسطة", low: "منخفضة"},
  status: {ok: "سليم", degraded: "متدهور", failed: "فشل", fail: "فشل", warn: "تنبيه", unavailable: "غير متاح", open: "مفتوح", closed: "مغلق", error: "خطأ", rejected: "مرفوض"},
  tactic: {urgency: "استعجال", threat: "تهديد", authority: "صفة رسمية", reward: "جائزة", credential_request: "طلب بيانات سرية", account_update: "تحديث حساب", payment_request: "طلب دفع", action_link: "رابط", action_contact: "تواصل خارجي", secrecy: "سرّية", lure_job: "وظيفة", lure_investment: "استثمار", lure_delivery: "شحنة"},
  variety: {msa: "فصحى", gulf: "خليجية", egyptian: "مصرية", levantine: "شامية", maghrebi: "مغاربية", iraqi: "عراقية", en: "إنجليزية", unknown: "غير محدد"},
  type: {domain: "نطاق", url: "رابط", phone: "هاتف", iban: "آيبان", handle: "حساب", wallet: "محفظة", email: "بريد", sender_id: "اسم مرسل"},
  source: {real: "حقيقية", synthetic: "اصطناعية", test: "اختبار", unspecified: "غير محدد"},
  cat: {tactic: "أسلوب", url: "رابط", context: "سياق", combo: "تركيب", obfuscation: "تمويه", benign: "دليل براءة", advisory: "استشاري", payment: "دفع"},
};
const varName = v => !v ? "—" : v.startsWith("msa_mixed_") ? "فصحى + " + (T.variety[v.slice(10)] || v.slice(10)) : (T.variety[v] || v);
const pill = (v, map = T.verdict) => `<span class="pill ${esc(v)}">${esc(map[v] || v)}</span>`;
const tchip = t => `<span class="chip"><i class="tdot" style="background:var(--t-${esc(t)})"></i>${esc(T.type[t] || t)}</span>`;
const srcChip = s => s && s !== "unspecified" ? `<span class="chip src-${esc(s)}">${esc(T.source[s] || s)}</span>` : "";
const ICON = {
  overview: '<path d="M3 13h7V3H3zM14 21h7V11h-7zM3 21h7v-5H3zM14 7h7V3h-7z"/>',
  campaigns: '<circle cx="12" cy="12" r="3"/><circle cx="5" cy="5" r="2"/><circle cx="19" cy="5" r="2"/><circle cx="5" cy="19" r="2"/><circle cx="19" cy="19" r="2"/><path d="M7 7l3 3M17 7l-3 3M7 17l3-3M17 17l-3-3"/>',
  messages: '<rect x="3" y="5" width="18" height="14" rx="2"/><path d="M3 7l9 6 9-6"/>',
  intel: '<path d="M12 3l8 4v5c0 5-3.5 8-8 9-4.5-1-8-4-8-9V7z"/><path d="M9 12l2 2 4-4"/>',
  database: '<ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v14c0 1.7 3.6 3 8 3s8-1.3 8-3V5M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"/>',
  system: '<path d="M3 12h4l3-8 4 16 3-8h4"/>',
  analyze: '<circle cx="11" cy="11" r="7"/><path d="M21 21l-5-5"/>',
  refresh: '<path d="M20 11a8 8 0 1 0-2.3 5.7M20 4v7h-7"/>',
  close: '<path d="M6 6l12 12M18 6L6 18"/>',
  plus: '<path d="M12 5v14M5 12h14"/>', minus: '<path d="M5 12h14"/>', fit: '<path d="M4 9V4h5M20 9V4h-5M4 15v5h5M20 15v5h-5"/>',
  download: '<path d="M12 4v12M6 10l6 6 6-6M4 20h16"/>',
};
const icon = n => `<svg viewBox="0 0 24 24" aria-hidden="true">${ICON[n] || ""}</svg>`;

/* ---------------- API ---------------- */
let KEY = (() => { try { return sessionStorage.getItem("rasd_key") || ""; } catch { return ""; } })();
class AuthError extends Error {}
async function api(path, opts = {}) {
  if (STATIC) return window.RASD_STATIC(path, opts);
  const r = await fetch(path, {...opts, headers: {"X-API-Key": KEY, "Content-Type": "application/json", ...(opts.headers || {})}});
  if (r.status === 401) throw new AuthError("unauthorized");
  if (!r.ok) {
    const body = await r.json().catch(() => ({}));
    throw new Error(typeof body.detail === "string" ? body.detail : (body.detail ? JSON.stringify(body.detail) : r.statusText));
  }
  return r.json();
}
const qs = o => { const p = new URLSearchParams(); for (const [k, v] of Object.entries(o)) if (v !== "" && v != null && v !== false) p.set(k, v); const s = p.toString(); return s ? "?" + s : ""; };
function setKey(k) { KEY = k; try { k ? sessionStorage.setItem("rasd_key", k) : sessionStorage.removeItem("rasd_key"); } catch { /* storage unavailable */ } }

/* ---------------- routing ---------------- */
function parseHash() {
  const h = location.hash.slice(1) || "overview";
  const [path, query = ""] = h.split("?");
  const parts = path.split("/").map(decodeURIComponent);
  return {page: parts[0], arg: parts.slice(1).join("/"), params: Object.fromEntries(new URLSearchParams(query))};
}
const go = (h) => { location.hash = h; };
const link = (page, arg, params) => "#" + page + (arg ? "/" + encodeURIComponent(arg) : "") + (params ? qs(params) : "");

function bindRows(root = document) {
  $$("[data-go]", root).forEach(el => {
    if (el.dataset.bound) return; el.dataset.bound = 1;
    if (el.tagName === "TR") { el.tabIndex = 0; el.classList.add("row"); }
    const fn = e => { if (e.target.closest("a,button") && e.target.closest("a,button") !== el) return; go(el.dataset.go); };
    el.addEventListener("click", fn);
    el.addEventListener("keydown", e => { if (e.key === "Enter") fn(e); });
  });
}

/* ---------------- drawer ---------------- */
function drawer(title, html) {
  $("#drawer-title").innerHTML = title;
  $("#drawer-body").innerHTML = html;
  $("#drawer").classList.add("open"); $("#drawer-bg").classList.add("open");
  $("#drawer").setAttribute("aria-hidden", "false");
  bindRows($("#drawer-body"));
  $("#drawer-close").focus();
}
function closeDrawer() { $("#drawer").classList.remove("open"); $("#drawer-bg").classList.remove("open"); $("#drawer").setAttribute("aria-hidden", "true"); }

/* ---------------- charts ---------------- */
function tipFor(wrap) {
  let tip = $(".tip", wrap);
  if (!tip) { tip = document.createElement("div"); tip.className = "tip"; wrap.appendChild(tip); }
  return {
    show(html, x, y) { tip.innerHTML = html; tip.style.opacity = 1; const w = wrap.clientWidth, tw = tip.offsetWidth; tip.style.left = Math.min(Math.max(0, x - tw / 2), w - tw) + "px"; tip.style.top = Math.max(0, y - tip.offsetHeight - 10) + "px"; },
    hide() { tip.style.opacity = 0; },
  };
}

/** Stacked daily bars (malicious + suspicious). One y-axis; hover tooltip per day. */
function dailyBars(el, byDay, onPick) {
  const days = [...new Set(byDay.map(d => d.day))].sort();
  if (!days.length) { el.innerHTML = '<div class="empty">لا بيانات</div>'; return; }
  const val = (d, v) => (byDay.find(x => x.day === d && x.verdict === v) || {n: 0}).n;
  const rows = days.map(d => ({d, m: val(d, "malicious"), s: val(d, "suspicious"), b: val(d, "benign")}));
  const max = Math.max(1, ...rows.map(r => r.m + r.s));
  const nice = Math.ceil(max / 5) * 5 || 5;
  const W = 760, H = 220, L = 34, B = 24, Tp = 8, iw = W - L - 6, ih = H - B - Tp, bw = iw / rows.length;
  const y = v => Tp + ih - v / nice * ih;
  let g = "";
  for (let i = 0; i <= 4; i++) { const v = nice * i / 4, yy = y(v); g += `<line class="grid-l" x1="${L}" x2="${W - 6}" y1="${yy}" y2="${yy}"/><text class="ax" x="${L - 6}" y="${yy + 4}" text-anchor="end">${Math.round(v)}</text>`; }
  const step = Math.ceil(rows.length / 8);
  rows.forEach((r, i) => {
    const x = L + i * bw + 1, w = Math.max(1.5, bw - 2);
    const hm = r.m / nice * ih, hs = r.s / nice * ih, rr = Math.min(3, w / 2);
    if (r.m) g += `<rect x="${x}" y="${y(r.m)}" width="${w}" height="${hm}" fill="var(--crit)" rx="${rr}"/>`;
    if (r.s) g += `<rect x="${x}" y="${y(r.m + r.s)}" width="${w}" height="${Math.max(0, hs - 2)}" fill="var(--warn)" rx="${rr}"/>`;
    g += `<rect class="hit" data-i="${i}" x="${L + i * bw}" y="${Tp}" width="${bw}" height="${ih}" fill="transparent"/>`;
    if (i % step === 0) g += `<text class="ax" x="${x + w / 2}" y="${H - 6}" text-anchor="middle">${r.d.slice(5)}</text>`;
  });
  el.innerHTML = `<div class="chart"><svg viewBox="0 0 ${W} ${H}" role="img" aria-label="الرسائل المُشار إليها يوميًا">${g}<line x1="${L}" x2="${W - 6}" y1="${Tp + ih}" y2="${Tp + ih}" stroke="var(--line-2)"/><line class="xh" x1="0" x2="0" y1="${Tp}" y2="${Tp + ih}" stroke="var(--ink-2)" stroke-dasharray="3 3" opacity="0"/></svg></div>
  <div class="legend"><span><i class="tdot" style="background:var(--crit)"></i>احتيالية</span><span><i class="tdot" style="background:var(--warn)"></i>مشبوهة</span><span class="mute">حسب تاريخ الاستلام · انقر يومًا لعرض رسائله</span></div>`;
  const wrap = $(".chart", el), svg = $("svg", el), tip = tipFor(wrap), xh = $(".xh", svg);
  $$(".hit", svg).forEach(h => {
    const r = rows[+h.dataset.i];
    h.addEventListener("mousemove", e => {
      const box = wrap.getBoundingClientRect(), sx = box.width / W, cx = (L + (+h.dataset.i + .5) * bw);
      xh.setAttribute("x1", cx); xh.setAttribute("x2", cx); xh.setAttribute("opacity", .6);
      tip.show(`<div class="mono">${esc(r.d)}</div><div><i class="tdot" style="background:var(--crit)"></i> احتيالية <b>${r.m}</b></div><div><i class="tdot" style="background:var(--warn)"></i> مشبوهة <b>${r.s}</b></div><div class="mute">سليمة ${r.b}</div>`, cx * sx, e.clientY - box.top);
    });
    h.addEventListener("mouseleave", () => { tip.hide(); xh.setAttribute("opacity", 0); });
    h.addEventListener("click", () => onPick && onPick(r.d));
  });
}

/** Part-to-whole donut with 2px gaps; legend carries labels + values (identity never color-only). */
function donut(el, parts, center, onPick) {
  const total = parts.reduce((a, p) => a + p.v, 0);
  const R = 52, C = 2 * Math.PI * R;
  let off = 0, arcs = "";
  parts.forEach((p, i) => {
    if (!p.v) return;
    const len = p.v / total * C, gap = parts.filter(x => x.v).length > 1 ? 2 : 0;
    arcs += `<circle class="arc" data-i="${i}" r="${R}" cx="64" cy="64" fill="none" stroke="${p.c}" stroke-width="16" stroke-dasharray="${Math.max(0, len - gap)} ${C}" stroke-dashoffset="${-off}" style="cursor:pointer"><title>${esc(p.l)}: ${p.v}</title></circle>`;
    off += len;
  });
  el.innerHTML = `<div class="donut-wrap"><svg viewBox="0 0 128 128" width="136" height="136" role="img" aria-label="${esc(center.l)}" style="transform:rotate(-90deg);flex:none">${arcs}</svg>
    <div class="donut-legend">${parts.map((p, i) => `<div data-i="${i}" style="cursor:pointer"><i class="tdot" style="background:${p.c}"></i><span>${esc(p.l)}</span><span class="num">${fmt(p.v)}</span><span class="num mute">${total ? pct(p.v / total) : "—"}</span></div>`).join("")}
    <div style="border-top:1px solid var(--line);padding-top:8px"><span></span><span class="mute">${esc(center.l)}</span><span class="num">${fmt(total)}</span><span></span></div></div></div>`;
  $$("[data-i]", el).forEach(n => n.addEventListener("click", () => onPick && onPick(parts[+n.dataset.i])));
}

function hbars(rows, opts = {}) {
  const max = Math.max(1, ...rows.map(r => r.v));
  if (!rows.length) return '<div class="empty">لا بيانات</div>';
  return rows.map(r => `<div class="hbar" ${r.go ? `data-go="${esc(r.go)}" style="cursor:pointer"` : ""}><span>${r.html || esc(r.l)}</span><div class="track"><div class="fill" style="width:${Math.max(1.5, 100 * r.v / max)}%;background:${r.c || "var(--accent)"}"></div></div><span class="n">${opts.pct ? pct(r.v, 1) : fmt(r.v)}</span></div>`).join("");
}

/* ---------------- evidence graph ---------------- */
const NODE = {
  campaign: {r: 15}, message: {r: 6}, indicator: {r: 8}, entity: {r: 7},
};
function nodeColor(n) {
  if (n.kind === "campaign") return "var(--cmp)";
  if (n.kind === "message") return n.verdict === "malicious" ? "var(--crit)" : n.verdict === "suspicious" ? "var(--warn)" : "var(--good)";
  if (n.kind === "indicator") return `var(--t-${n.type}, var(--mute))`;
  return "var(--ent)";
}
const EDGE_TXT = {contains: "يحتوي المؤشر", uses: "تستخدم المورد", member: "عضو في الحملة", corroborated: "إشارتان ضعيفتان معًا", mentions: "تذكر الجهة", same_template: "نص مشابه — لم تُدمج"};
const EDGE_WHY = e => ({
  contains: "القيمة موجودة حرفيًا في نص الرسالة",
  uses: `${e.messages} رسائل من الحملة تحتوي هذا المورد`,
  member: "عضوية مستنتجة من حواف الأدلة المباشرة",
  corroborated: `إشارتان ضعيفتان مستقلتان معًا (قوة ${e.strength ?? "—"}): ${e.label.split(": ").slice(1).join(": ")}`,
  mentions: `ذُكرت في ${e.messages} رسائل — هدف انتحال، لا يربط الحملات`,
  same_template: "نص متشابه وبنية مختلفة — لم تُدمجا لأن تشابه النص ليس دليلًا كافيًا",
}[e.kind] || e.label);
function nodeShape(n, r) {
  const c = nodeColor(n);
  if (n.kind === "campaign") return `<circle class="ring" r="${r + 5}" fill="none" stroke="${c}" stroke-opacity=".35" stroke-width="1.5"/><circle r="${r}" fill="#0b1424" stroke="${c}" stroke-width="2.5"/><circle r="${r - 6}" fill="${c}"/>`;
  if (n.kind === "indicator") return `<rect class="ring" x="${-r}" y="${-r}" width="${2 * r}" height="${2 * r}" rx="3" fill="${c}" stroke="${n.bridge ? "var(--ink)" : "#0b1424"}" stroke-width="${n.bridge ? 2.5 : 1.5}"/>`;
  if (n.kind === "entity") return `<path class="ring" d="M0 ${-r - 1}L${r + 1} 0L0 ${r + 1}L${-r - 1} 0Z" fill="${c}" stroke="#0b1424" stroke-width="1.5"/>`;
  return `<circle class="ring" r="${r}" fill="${c}" stroke="#0b1424" stroke-width="1.5"/>`;
}

/**
 * Interactive evidence graph. Force layout (deterministic seed), wheel-zoom, drag-pan,
 * click a node -> details + its relations in the side panel. Solid edge = direct evidence,
 * dashed = inferred (derived membership, corroborated weak signals, template similarity).
 */
function evidenceGraph(host, data, onSelect) {
  const N = data.nodes.map((n, i) => ({...n, x: 0, y: 0, vx: 0, vy: 0, i}));
  const ix = new Map(N.map(n => [n.id, n]));
  const E = data.edges.map(e => ({...e, s: ix.get(e.source), t: ix.get(e.target)})).filter(e => e.s && e.t);
  const W = 1000, H = 640;
  // deterministic initial placement
  N.forEach((n, i) => { const a = i * 2.399963, rad = 30 + 12 * Math.sqrt(i); n.x = W / 2 + rad * Math.cos(a); n.y = H / 2 + rad * Math.sin(a); });
  const deg = new Map(); E.forEach(e => { deg.set(e.s.id, (deg.get(e.s.id) || 0) + 1); deg.set(e.t.id, (deg.get(e.t.id) || 0) + 1); });
  const iters = N.length > 250 ? 260 : 380;
  for (let it = 0; it < iters; it++) {
    const k = 1 - it / iters;
    for (let i = 0; i < N.length; i++) for (let j = i + 1; j < N.length; j++) {
      const a = N[i], b = N[j]; let dx = a.x - b.x, dy = a.y - b.y; const d2 = dx * dx + dy * dy + .01;
      if (d2 > 90000) continue;
      const f = Math.min(6, 900 / d2); dx *= f; dy *= f; a.vx += dx; a.vy += dy; b.vx -= dx; b.vy -= dy;
    }
    for (const e of E) {
      const want = e.kind === "member" ? 70 : e.kind === "same_template" ? 220 : e.kind === "mentions" ? 120 : 85;
      const dx = e.t.x - e.s.x, dy = e.t.y - e.s.y, d = Math.hypot(dx, dy) || 1, f = (d - want) * (e.kind === "same_template" ? .004 : .03);
      e.s.vx += dx / d * f; e.s.vy += dy / d * f; e.t.vx -= dx / d * f; e.t.vy -= dy / d * f;
    }
    for (const n of N) { n.vx += (W / 2 - n.x) * .004; n.vy += (H / 2 - n.y) * .006; n.x += n.vx * (0.6 * k + .05); n.y += n.vy * (0.6 * k + .05); n.vx *= .55; n.vy *= .55; }
  }
  // fit
  const xs = N.map(n => n.x), ys = N.map(n => n.y), pad = 60;
  let vb = N.length ? [Math.min(...xs) - pad, Math.min(...ys) - pad, Math.max(...xs) - Math.min(...xs) + 2 * pad, Math.max(...ys) - Math.min(...ys) + 2 * pad] : [0, 0, W, H];
  const fitVb = [...vb];
  const showLabel = n => n.kind !== "message" && (n.kind === "campaign" || N.length < 160 || (deg.get(n.id) || 0) > 2);
  const lbl = s => s.length > 30 ? s.slice(0, 29) + "…" : s;
  host.innerHTML = `<div class="graph-shell"><div class="graph-canvas">
    <div class="graph-tools"><button class="btn" data-z="in" title="تكبير">${icon("plus")}</button><button class="btn" data-z="out" title="تصغير">${icon("minus")}</button><button class="btn" data-z="fit" title="ملاءمة">${icon("fit")}</button></div>
    <svg viewBox="${vb.join(" ")}" role="img" aria-label="رسم الأدلة">
      <g class="edges">${E.map((e, i) => `<line class="gedge" data-i="${i}" x1="${e.s.x}" y1="${e.s.y}" x2="${e.t.x}" y2="${e.t.y}" stroke="${e.kind === "same_template" ? "var(--warn)" : e.direct ? "#6f86a8" : "#9aa9be"}" stroke-opacity="${e.direct ? .55 : .5}" stroke-width="${e.kind === "uses" ? Math.min(4, 1 + (e.messages || 1) / 4) : 1.2}" ${e.direct ? "" : 'stroke-dasharray="5 4"'}/>`).join("")}</g>
      <g class="nodes">${N.map(n => { const r = n.kind === "campaign" ? Math.min(26, NODE.campaign.r + Math.sqrt(n.size || 1) * 1.6) : NODE[n.kind].r;
        return `<g class="gnode" data-id="${esc(n.id)}" transform="translate(${n.x},${n.y})" tabindex="0" role="button" aria-label="${esc(n.kind + " " + n.label)}"><circle r="${r + 7}" fill="transparent"/>${nodeShape(n, r)}${showLabel(n) ? `<text x="${r + 5}" y="4">${esc(lbl(n.label))}</text>` : ""}<title>${esc(n.label)}</title></g>`; }).join("")}</g>
    </svg>
    <div class="graph-legend">
      <span><svg viewBox="0 0 22 12"><circle cx="11" cy="6" r="5" fill="none" stroke="var(--cmp)" stroke-width="2"/></svg>حملة</span>
      <span><svg viewBox="0 0 22 12"><circle cx="11" cy="6" r="4" fill="var(--crit)"/></svg>رسالة احتيالية</span>
      <span><svg viewBox="0 0 22 12"><circle cx="11" cy="6" r="4" fill="var(--warn)"/></svg>مشبوهة</span>
      ${[...new Set(N.filter(n => n.kind === "indicator").map(n => n.type))].map(t => `<span><svg viewBox="0 0 22 12"><rect x="6" y="1" width="10" height="10" rx="2" fill="var(--t-${esc(t)})"/></svg>${esc(T.type[t] || t)}</span>`).join("")}
      ${N.some(n => n.kind === "entity") ? `<span><svg viewBox="0 0 22 12"><path d="M11 0L17 6L11 12L5 6Z" fill="var(--ent)"/></svg>جهة منتحلة</span>` : ""}
      <span><svg viewBox="0 0 22 12"><line x1="0" y1="6" x2="22" y2="6" stroke="#6f86a8" stroke-width="2"/></svg>دليل مباشر</span>
      <span><svg viewBox="0 0 22 12"><line x1="0" y1="6" x2="22" y2="6" stroke="#9aa9be" stroke-width="2" stroke-dasharray="4 3"/></svg>علاقة مستنتجة</span>
      ${E.some(e => e.kind === "same_template") ? `<span><svg viewBox="0 0 22 12"><line x1="0" y1="6" x2="22" y2="6" stroke="var(--warn)" stroke-width="2" stroke-dasharray="4 3"/></svg>نص مشابه، لم تُدمج</span>` : ""}
      ${N.some(n => n.bridge) ? `<span><svg viewBox="0 0 22 12"><rect x="6" y="1" width="10" height="10" rx="2" fill="none" stroke="var(--ink)" stroke-width="2"/></svg>نقطة ربط وحيدة</span>` : ""}
    </div></div>
    <aside class="panel" aria-live="polite"><div class="note">انقر أي عقدة لعرض تفاصيلها والأدلة التي تربطها. الخطوط المتصلة دليل مباشر (القيمة موجودة حرفيًا في الرسالة)، والمتقطعة علاقة مستنتجة.</div>
    ${data.truncated ? '<div class="callout" style="margin-top:10px">الرسم مقتطع لحجمه؛ افتح حملة بعينها لرؤية كل عناصرها.</div>' : ""}</aside></div>`;
  const svg = $(".graph-canvas>svg", host), panel = $(".panel", host);
  const setVb = v => { vb = v; svg.setAttribute("viewBox", v.join(" ")); };
  const zoom = (f, cx = vb[0] + vb[2] / 2, cy = vb[1] + vb[3] / 2) => setVb([cx - (cx - vb[0]) * f, cy - (cy - vb[1]) * f, vb[2] * f, vb[3] * f]);
  $$("[data-z]", host).forEach(b => b.onclick = () => b.dataset.z === "fit" ? setVb([...fitVb]) : zoom(b.dataset.z === "in" ? .8 : 1.25));
  svg.addEventListener("wheel", e => { e.preventDefault(); const p = svg.createSVGPoint(); p.x = e.clientX; p.y = e.clientY; const q = p.matrixTransform(svg.getScreenCTM().inverse()); zoom(e.deltaY < 0 ? .88 : 1.14, q.x, q.y); }, {passive: false});
  let drag = null;
  svg.addEventListener("pointerdown", e => { if (e.target.closest(".gnode")) return; drag = {x: e.clientX, y: e.clientY, vb: [...vb]}; svg.classList.add("drag"); svg.setPointerCapture(e.pointerId); });
  svg.addEventListener("pointermove", e => { if (!drag) return; const s = vb[2] / svg.clientWidth; setVb([drag.vb[0] - (e.clientX - drag.x) * s, drag.vb[1] - (e.clientY - drag.y) * s, vb[2], vb[3]]); });
  svg.addEventListener("pointerup", () => { drag = null; svg.classList.remove("drag"); });
  const select = id => {
    const n = ix.get(id); if (!n) return;
    const nb = new Set([id]); const rel = E.filter(e => e.s.id === id || e.t.id === id);
    rel.forEach(e => { nb.add(e.s.id); nb.add(e.t.id); });
    $$(".gnode", svg).forEach(g => { g.classList.toggle("dim", !nb.has(g.dataset.id)); g.classList.toggle("sel", g.dataset.id === id); });
    $$(".gedge", svg).forEach(l => { const e = E[+l.dataset.i]; l.classList.toggle("dim", !(e.s.id === id || e.t.id === id)); });
    panel.innerHTML = onSelect(n, rel.map(e => ({...e, other: e.s.id === id ? e.t : e.s})));
    $$("[data-node]", panel).forEach(b => b.onclick = () => { const m = ix.get(b.dataset.node); select(b.dataset.node); const r = vb[2]; setVb([m.x - r / 2, m.y - vb[3] / 2, vb[2], vb[3]]); });
    bindRows(panel);
  };
  $$(".gnode", svg).forEach(g => { g.addEventListener("click", () => select(g.dataset.id)); g.addEventListener("keydown", e => { if (e.key === "Enter") select(g.dataset.id); }); });
  svg.addEventListener("dblclick", () => { $$(".dim", svg).forEach(x => x.classList.remove("dim")); $$(".sel", svg).forEach(x => x.classList.remove("sel")); });
  return {select};
}

/** Panel content for a selected graph node — every relation states its evidence type. */
function nodePanel(n, rel) {
  const rows = rel.map(r => `<li><span><button data-node="${esc(r.other.id)}">${esc(r.other.kind === "indicator" ? (T.type[r.other.type] || r.other.type) + ": " + r.other.label : r.other.label)}</button></span>
    <span>${esc(EDGE_TXT[r.kind] || r.kind)} · <span class="${r.direct ? "ev-direct" : "ev-inferred"}">${r.direct ? "دليل مباشر" : "علاقة مستنتجة"}</span></span><span class="note">${esc(EDGE_WHY(r))}</span></li>`).join("");
  let head = "", actions = "";
  if (n.kind === "campaign") { head = `<h3>حملة <span class="mono">${esc(n.label)}</span></h3><dl class="kv"><dt>الرسائل</dt><dd class="num">${n.size}</dd><dt>ثقة الربط</dt><dd>${pill(n.confidence, T.conf)}</dd></dl>`; actions = `<a class="btn" href="${link("campaigns", n.label)}">فتح الحملة</a>`; }
  else if (n.kind === "message") { head = `<h3>رسالة <span class="mono">${esc(n.label)}</span></h3><dl class="kv"><dt>الحكم</dt><dd>${pill(n.verdict)}</dd><dt>درجة الخطر</dt><dd class="num">${pct(n.score)}</dd></dl>`; actions = `<a class="btn" href="${link("messages", n.label)}">فتح التحقيق</a>`; }
  else if (n.kind === "indicator") { head = `<h3>${tchip(n.type)}</h3><div class="ltr" style="margin:6px 0">${esc(n.label)}</div><dl class="kv">${n.messages != null ? `<dt>رسائل</dt><dd class="num">${n.messages}</dd>` : ""}<dt>دوره</dt><dd>${n.bridge ? '<span class="pill warn">نقطة ربط وحيدة</span> لولاه لانقسمت الحملة' : "مورد يتحكم به المهاجم"}</dd></dl>`; actions = `<a class="btn" href="${link("intel", "", {type: n.type, value: n.label})}">ملف المؤشر</a>`; }
  else { head = `<h3>جهة منتحلة: ${esc(n.label)}</h3><p class="note">ذِكر اسم جهة في الرسالة دليل انتحال، لا يربط الحملات ببعضها.</p>`; actions = `<a class="btn" href="${link("intel", "", {tab: "entities"})}">الكيانات</a>`; }
  return `${head}<div class="toolbar" style="margin:6px 0 10px">${actions}</div><div class="note">العلاقات (${rel.length})</div><ul class="edge-list">${rows || '<li class="mute">لا علاقات</li>'}</ul>`;
}

/* ---------------- message highlighting ---------------- */
function highlight(text, evidence, indicators) {
  const best = new Array(text.length).fill(null);
  for (const e of evidence) if (e.weight) for (const s of e.spans) for (let i = s.start; i < Math.min(s.end, text.length); i++) if (!best[i] || Math.abs(e.weight) > Math.abs(best[i].weight)) best[i] = e;
  for (const ind of indicators || []) if (ind.span) for (let i = ind.span.start; i < Math.min(ind.span.end, text.length); i++) if (!best[i]) best[i] = {ind: true, text: (T.type[ind.type] || ind.type) + ": " + ind.value};
  let out = "", i = 0;
  while (i < text.length) {
    let j = i; while (j < text.length && best[j] === best[i]) j++;
    const seg = esc(text.slice(i, j)), b = best[i];
    out += !b ? seg : b.ind ? `<mark class="ind" title="${esc(b.text)}">${seg}</mark>` : `<mark class="${b.weight < 0 ? "neg" : ""}" title="${esc(b.label || b.id)} (${b.weight > 0 ? "+" : ""}${b.weight})">${seg}</mark>`;
    i = j;
  }
  return out;
}

window.RASD = {$, $$, esc, fmt, pct, day, dt, bytes, T, varName, pill, tchip, srcChip, icon, api, qs, setKey, AuthError, parseHash, go, link, bindRows, drawer, closeDrawer, dailyBars, donut, hbars, evidenceGraph, nodePanel, highlight, STATIC};
