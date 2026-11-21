"use strict";
(() => {
const {$, $$, esc, fmt, pct, day, dt, bytes, T, varName, pill, tchip, srcChip, icon, qs, setKey, AuthError, parseHash, go, link, bindRows, drawer, closeDrawer, dailyBars, donut, hbars, evidenceGraph, nodePanel, highlight, STATIC} = window.RASD;

// Navigation token: a response that arrives after the user navigated elsewhere is dropped,
// so a slow earlier page can never overwrite the current one.
let NAV = 0;
class Stale extends Error {}
const api = (...args) => { const tok = NAV; return window.RASD.api(...args).then(r => { if (tok !== NAV) throw new Stale(); return r; }); };

const PAGES = [
  ["demo", "العرض الموجَّه", "تتبّع رسالة واحدة من النص الخام حتى حملتها وسجلاتها"],
  ["overview", "نظرة عامة", "ملخص تنفيذي لكل ما رصده النظام"],
  ["campaigns", "الحملات", "رسائل يربطها مورد يتحكم به المهاجم — لا تشابه النص"],
  ["messages", "تحقيق الرسائل", "كل رسالة: حكمها، أدلتها، مؤشراتها، وحملتها"],
  ["intel", "الاستخبارات", "المؤشرات والكيانات وعائلات القوالب والتحقيقات"],
  ["database", "قاعدة البيانات", "الجداول الفعلية وعلاقاتها وسلامتها — للقراءة فقط"],
  ["system", "مراقبة النظام", "حالة المحرك وقاعدة البيانات والواجهة البرمجية — مقاسة لا محاكاة"],
  ["analyze", "فحص رسالة", "حلّل نصًا دون تخزينه"],
  ["search", "نتائج البحث", "بحث شامل في الحملات والمؤشرات والجهات والرسائل"],
];
const main = () => $("#content");
const loading = () => { main().innerHTML = '<div class="loading">جارٍ التحميل</div>'; };

/* ---------------- provenance banner ---------------- */
async function provenance() {
  const el = $("#prov");
  try {
    const s = await api("/v1/overview");
    const src = s.by_source || {}, total = s.messages;
    const parts = Object.entries(src).sort((a, b) => b[1] - a[1]);
    const realOnly = parts.length && parts.every(([k]) => k === "real");
    el.className = "prov" + (realOnly ? " real" : "");
    el.innerHTML = `<i></i>${STATIC ? "لقطة ثابتة للقراءة · " : ""}${!total ? "لا بيانات بعد" : realOnly ? "بيانات حقيقية" : parts.map(([k, v]) => `${esc(T.source[k] || k)} ${fmt(v)}`).join(" · ")}`;
    el.title = "مصدر البيانات المعروضة (data provenance) كما سُجّل عند الإدخال";
    el.hidden = false;
  } catch { el.hidden = true; }
}

/* ---------------- 1. overview ---------------- */
async function overview() {
  const o = await api("/v1/overview");
  const k = o.kpis, c = o.correlation;
  const v = o.by_verdict;
  main().innerHTML = `
  ${(o.by_source.synthetic || o.by_source.test) ? `<div class="callout">تعرض هذه اللوحة <b>بيانات ${o.by_source.real ? "مختلطة" : "اصطناعية/اختبارية"}</b> (${Object.entries(o.by_source).map(([s, n]) => `${esc(T.source[s] || s)}: ${fmt(n)}`).join("، ")}). البيانات الاصطناعية مولّدة بنطاقات ‎.example/.test‎ لا تُحَلّ، ولا تمثّل استخبارات تهديد حقيقية.</div>` : ""}
  <div class="kpis">
    <a class="kpi" href="${link("messages")}"><div class="v">${fmt(k.messages)}</div><div class="l">رسالة محلَّلة</div><div class="s">كل الرسائل المخزّنة</div></a>
    <a class="kpi acc" href="${link("campaigns")}"><div class="v">${fmt(k.campaigns)}</div><div class="l">حملة مكتشفة</div><div class="s">${fmt(c.confidence.high)} بثقة مرتفعة</div></a>
    <a class="kpi" href="${link("intel")}"><div class="v">${fmt(k.indicators)}</div><div class="l">مؤشر مستخرج</div><div class="s">قيم فريدة بكل أنواعها</div></a>
    <a class="kpi crit" href="${link("messages", "", {verdict: "malicious"})}"><div class="v">${fmt(k.high_risk)}</div><div class="l">رسالة عالية الخطورة</div><div class="s">حكم «احتيالية»</div></a>
    <a class="kpi" href="${link("messages", "", {campaign: "yes"})}"><div class="v">${pct(c.linked_share)}</div><div class="l">من المُشار إليه مربوط بحملة</div><div class="s">${fmt(c.linked_messages)} من ${fmt(c.flagged_messages)}</div></a>
    <a class="kpi" href="${link("intel", "", {tab: "investigations"})}"><div class="v">${fmt(k.open_investigations)}</div><div class="l">تحقيق مفتوح</div><div class="s">يفتحه المحلل على حملة</div></a>
  </div>
  <div class="grid g-main">
    <div class="card"><div class="card-h"><h2>نشاط التهديدات عبر الزمن</h2></div><div id="ov-daily"></div></div>
    <div class="card"><div class="card-h"><h2>توزيع الأحكام</h2></div><div id="ov-donut"></div>
      <div class="note" style="margin-top:14px">الحكم = مجموع أوزان أدلة مسمّاة؛ «احتيالية» تتطلب ناقل ضرر (رابط/رقم/حساب) أو طلبًا صريحًا لبيانات سرية.</div></div>
  </div>
  <div class="grid g3">
    <div class="card"><div class="card-h"><h2>ربط الحملات</h2><span class="sub">كيف تحوّلت الرسائل المُشار إليها إلى حملات</span></div>
      <div class="meter" title="مربوطة / غير مربوطة"><i style="width:${pct(c.linked_share || 0)};background:var(--accent)"></i><i style="flex:1;background:var(--surface-3)"></i></div>
      <div class="legend"><span><i class="tdot" style="background:var(--accent)"></i>مربوطة ${fmt(c.linked_messages)}</span><span><i class="tdot" style="background:var(--surface-3)"></i>دون دليل ربط ${fmt(c.flagged_messages - c.linked_messages)}</span></div>
      <h3 class="note" style="margin:16px 0 4px">ثقة الحملات</h3>
      ${hbars(["high", "medium", "low"].map(l => ({l: T.conf[l], v: c.confidence[l] || 0, c: l === "high" ? "var(--good)" : l === "medium" ? "var(--warn)" : "var(--faint)", go: link("campaigns", "", {confidence: l})})))}
      <dl class="kv" style="margin-top:14px"><dt>عائلات قوالب</dt><dd><a href="${link("intel", "", {tab: "families"})}" class="num">${fmt(c.template_families)}</a> <span class="note">نص متكرر — فرضية لا دليل</span></dd>
      <dt>حملات متشابهة النص لم تُدمج</dt><dd class="num">${fmt(c.related_not_merged_pairs)} زوج</dd>
      <dt>مؤشرات مستبعدة من الربط</dt><dd class="num">${fmt(c.suppressed_indicators)}</dd></dl></div>
    <div class="card"><div class="card-h"><h2>موارد الربط حسب النوع</h2><span class="sub">مؤشرات مشتركة داخل الحملات</span></div>
      ${hbars(Object.entries(c.linking_indicator_types).sort((a, b) => b[1] - a[1]).map(([t, n]) => ({html: tchip(t), v: n, c: `var(--t-${t})`, go: link("intel", "", {type: t, in_campaign: "yes"})})))}
      <h3 class="note" style="margin:16px 0 4px">لهجة الرسائل المُشار إليها</h3>
      ${hbars(Object.entries(o.by_variety).sort((a, b) => b[1] - a[1]).slice(0, 6).map(([kk, n]) => ({l: varName(kk), v: n})))}</div>
    <div class="card"><div class="card-h"><h2>أكبر الحملات</h2><a class="grow"></a><a href="${link("campaigns")}" class="note">الكل ←</a></div>
      <div class="tbl-wrap"><table class="t"><tbody>${o.top_campaigns.map(x => `<tr data-go="${link("campaigns", x.id)}"><td class="mono">${esc(x.id)}</td><td>${pill(x.confidence, T.conf)}</td><td class="num">${x.size}</td><td>${Object.keys(x.brands).slice(0, 2).map(b => `<span class="chip">${esc(b)}</span>`).join("")}</td></tr>`).join("") || '<tr><td class="empty">لا حملات</td></tr>'}</tbody></table></div></div>
  </div>
  <div class="grid g2">
    <div class="card"><div class="card-h"><h2>توزيع درجات الخطر</h2><span class="sub">عدد الرسائل في كل شريحة درجة، ملوّنة بالحكم النهائي. الحواجز قد تُبقي رسالة عالية الدرجة «مشبوهة».</span></div><div id="ov-hist"></div></div>
    <div class="card"><div class="card-h"><h2>التحقيقات الأخيرة</h2><a class="grow"></a><a href="${link("intel", "", {tab: "investigations"})}" class="note">الكل ←</a></div>
      ${(o.recent_investigations || []).length ? `<table class="t"><tbody>${o.recent_investigations.map(i => `<tr data-go="${link("campaigns", i.campaign_id)}"><td>${esc(i.title)}</td><td>${pill(i.status, T.status)}</td><td class="mono">${esc(i.campaign_id)}</td><td class="mono">${dt(i.updated_at)}</td></tr>`).join("")}</tbody></table>` : `<div class="empty">لا تحقيقات بعد${STATIC ? "" : " — افتح تحقيقًا من صفحة أي حملة"}</div>`}</div>
  </div>
  <div class="grid g2">
    <div class="card"><div class="card-h"><h2>أحدث الاكتشافات</h2><a class="grow"></a><a href="${link("messages", "", {verdict: "malicious"})}" class="note">الكل ←</a></div>
      <div class="tbl-wrap"><table class="t"><tbody>${o.recent_detections.map(m => `<tr data-go="${link("messages", m.id)}"><td class="mono nowrap">${day(m.received_at)}</td><td>${pill(m.verdict)}</td><td class="txt">${esc(m.text)}</td><td class="mono">${m.campaign_id ? esc(m.campaign_id) : '<span class="faint">—</span>'}</td></tr>`).join("") || '<tr><td class="empty">لا اكتشافات</td></tr>'}</tbody></table></div></div>
    <div class="card"><div class="card-h"><h2>آخر العمليات</h2><a class="grow"></a><a href="${link("system")}" class="note">المراقبة ←</a></div>
      ${o.recent_activity.length ? `<div class="tbl-wrap"><table class="t"><tbody>${o.recent_activity.map(a => `<tr><td class="mono">${dt(a.ts)}</td><td class="mono">${esc(a.op)}</td><td>${pill(a.status, T.status)}</td><td class="num">${a.items ?? ""}</td></tr>`).join("")}</tbody></table></div>` : `<div class="empty">لم تُسجَّل عمليات بعد${STATIC ? " (لقطة ثابتة)" : ""}</div>`}</div>
  </div>`;
  dailyBars($("#ov-daily"), o.by_day, d => go(link("messages", "", {day: d})));
  scoreHist($("#ov-hist"), o.score_hist || []);
  donut($("#ov-donut"), [{l: "احتيالية", v: v.malicious || 0, c: "var(--crit)", k: "malicious"}, {l: "مشبوهة", v: v.suspicious || 0, c: "var(--warn)", k: "suspicious"}, {l: "سليمة", v: v.benign || 0, c: "var(--good)", k: "benign"}], {l: "إجمالي الرسائل"}, p => go(link("messages", "", {verdict: p.k})));
  bindRows(main());
}

/* ---------------- 2. campaigns ---------------- */
async function campaigns(arg, p) {
  if (arg) return campaignDetail(arg, p);
  const tab = p.tab || "list";
  const d = await api("/v1/campaigns");
  const rows = d.campaigns.filter(c => (!p.confidence || c.confidence === p.confidence) && (!p.q || c.id.includes(p.q) || Object.keys(c.brands).some(b => b.includes(p.q))));
  main().innerHTML = `<div class="card">
    <div class="tabs" role="tablist"><button role="tab" aria-selected="${tab === "list"}" data-tab="list">قائمة الحملات (${d.campaigns.length})</button><button role="tab" aria-selected="${tab === "graph"}" data-tab="graph">خريطة الحملات</button></div>
    <div id="cmp-body"></div></div>
    ${Object.keys(d.suppressed_indicators).length ? `<div class="card"><div class="card-h"><h2>مؤشرات مستبعدة من الربط</h2><span class="sub">تظهر غالبًا في رسائل سليمة، فلا تُعدّ موردًا خاصًا بمهاجم</span></div>${Object.entries(d.suppressed_indicators).map(([kk, why]) => `<div><span class="ltr">${esc(kk)}</span> — <span class="note">${esc(why)}</span></div>`).join("")}</div>` : ""}`;
  $$("[data-tab]").forEach(b => b.onclick = () => go(link("campaigns", "", {...p, tab: b.dataset.tab})));
  const body = $("#cmp-body");
  if (tab === "graph") {
    body.innerHTML = '<div class="loading">جارٍ بناء الرسم</div>';
    const g = await api("/v1/graph");
    body.innerHTML = `<p class="note" style="margin-top:0">كل حملة مع الموارد التي تتشاركها رسائلها والجهات التي تنتحلها. الخطوط البرتقالية المتقطعة تربط حملات نصّها متشابه وبنيتها مختلفة — تُعرض ولا تُدمج.</p><div id="g"></div>`;
    evidenceGraph($("#g"), g, nodePanel, {enrich: graphEnrich});
    return;
  }
  body.innerHTML = `<div class="toolbar" style="margin-bottom:12px">
      <input class="in" id="cq" placeholder="بحث بالمعرّف أو الجهة" value="${esc(p.q || "")}" aria-label="بحث">
      <select class="in" id="cc" aria-label="الثقة"><option value="">كل مستويات الثقة</option>${["high", "medium", "low"].map(l => `<option value="${l}" ${p.confidence === l ? "selected" : ""}>${T.conf[l]}</option>`).join("")}</select>
      <span class="grow"></span><span class="note">${rows.length} حملة</span></div>
    <div class="tbl-wrap"><table class="t"><thead><tr><th>المعرّف</th><th>الرسائل</th><th>الثقة</th><th>موارد مشتركة</th><th>أنواع الربط</th><th>الجهات المنتحلة</th><th>الأساليب</th><th>أول ظهور</th><th>آخر ظهور</th><th>تحقيق</th></tr></thead><tbody>
    ${rows.map(c => `<tr data-go="${link("campaigns", c.id)}"><td class="mono">${esc(c.id)}</td><td class="num">${c.size}</td><td>${pill(c.confidence, T.conf)}</td><td class="num">${c.shared_indicator_count}</td><td>${c.indicator_types.map(tchip).join("")}</td><td>${Object.keys(c.brands).slice(0, 3).map(b => `<span class="chip">${esc(b)}</span>`).join("") || "—"}</td><td>${Object.keys(c.tactics).slice(0, 3).map(t => `<span class="chip">${esc(T.tactic[t] || t)}</span>`).join("")}</td><td class="mono">${day(c.first_seen)}</td><td class="mono">${day(c.last_seen)}</td><td>${c.open_investigations ? pill("open", T.status) : ""}</td></tr>`).join("") || '<tr><td colspan="10" class="empty">لا حملات مطابقة</td></tr>'}
    </tbody></table></div>`;
  const upd = () => go(link("campaigns", "", {q: $("#cq").value, confidence: $("#cc").value}));
  $("#cq").onkeydown = e => { if (e.key === "Enter") upd(); }; $("#cc").onchange = upd;
  bindRows(body);
}

async function campaignDetail(id, p = {}) {
  const [d, g] = await Promise.all([api("/v1/campaigns/" + encodeURIComponent(id)), api("/v1/graph" + qs({campaign_id: id}))]);
  const c = d.campaign;
  const opts = c.message_ids.map(m => `<option value="${esc(m)}">${esc(m)}</option>`).join("");
  main().innerHTML = `
  <div class="toolbar"><a class="btn ghost" href="${link("campaigns")}">→ كل الحملات</a><span class="grow"></span>
    <a class="btn" href="${link("intel", "", {tab: "investigations"})}">التحقيقات</a>
    <button class="btn" id="stix">${icon("download")} تصدير STIX 2.1</button></div>
  <div class="grid g-main">
    <div class="card"><div class="card-h"><h2>الحملة <span class="mono">${esc(c.id)}</span></h2>${pill(c.confidence, T.conf)}<span class="sub">${esc(d.explanation.confidence_reason)}</span></div>
      <ul class="steps">${d.explanation.narrative.map(l => `<li>${esc(l.replace(/^•\s*/, ""))}</li>`).join("")}</ul>
      <dl class="kv" style="margin-top:14px"><dt>المدة</dt><dd class="mono">${day(c.first_seen)} ← ${day(c.last_seen)}</dd>
      <dt>اللهجات</dt><dd>${Object.entries(c.varieties).map(([k, n]) => `<span class="chip">${esc(varName(k))} · ${n}</span>`).join("") || "—"}</dd>
      <dt>القنوات</dt><dd>${Object.entries(c.channels).map(([k, n]) => `<span class="chip">${esc(k)} · ${n}</span>`).join("") || "—"}</dd>
      <dt>الأساليب</dt><dd>${Object.entries(c.tactics).map(([k, n]) => `<span class="chip">${esc(T.tactic[k] || k)} · ${n}</span>`).join("")}</dd>
      <dt>الجهات المنتحلة</dt><dd>${Object.entries(c.brands).map(([k, n]) => `<span class="chip">${esc(k)} · ${n}</span>`).join("") || "—"}</dd></dl></div>
    <div class="card"><div class="card-h"><h2>موارد الحملة</h2><span class="sub">ما يجب تعطيله معًا · انقر لفتح ملف المؤشر</span></div>
      <div class="tbl-wrap"><table class="t"><thead><tr><th>النوع</th><th>القيمة</th><th>رسائل</th></tr></thead><tbody>
      ${c.indicators.map(i => `<tr data-go="${link("intel", "", {type: i.type, value: i.value})}"><td>${tchip(i.type)}</td><td class="ltr">${esc(i.value)}${c.bridges.includes(i.key) ? ' <span class="pill warn">نقطة ربط وحيدة</span>' : ""}</td><td class="num">${i.messages}</td></tr>`).join("")}</tbody></table></div></div>
  </div>
  <div class="card"><div class="card-h"><h2>رسم الأدلة</h2><span class="sub">الرسائل ومواردها والجهات المنتحلة. انقر أي عقدة لعرض الدليل الذي يربطها.</span></div><div id="g"></div></div>
  <div class="grid g2">
    <div class="card"><div class="card-h"><h2>لماذا رُبطت هاتان الرسالتان؟</h2><span class="sub">سلسلة الأدلة، حلقة بحلقة</span></div>
      <div class="toolbar"><select class="in" id="la" aria-label="الرسالة الأولى">${opts}</select><select class="in" id="lb" aria-label="الرسالة الثانية">${opts}</select><button class="btn pri" id="why">اشرح</button></div><div id="whyout" style="margin-top:12px"></div></div>
    <div class="card"><div class="card-h"><h2>التحقيقات</h2></div><div id="inv"></div></div>
  </div>
  <div class="card"><div class="card-h"><h2>رسائل الحملة (${c.size})</h2></div><div class="tbl-wrap"><table class="t"><thead><tr><th>التاريخ</th><th>الحكم</th><th>الدرجة</th><th>اللهجة</th><th>المصدر</th><th>النص (منقّح)</th></tr></thead><tbody>
    ${d.messages.map(m => `<tr data-go="${link("messages", m.id)}"><td class="mono">${day(m.received_at)}</td><td>${pill(m.verdict)}</td><td class="num">${pct(m.score)}</td><td>${esc(varName(m.variety))}</td><td>${srcChip(m.source)}</td><td class="txt">${esc(m.text)}</td></tr>`).join("")}</tbody></table></div></div>`;
  const G = evidenceGraph($("#g"), g, nodePanel, {enrich: graphEnrich});
  if (p.focus && G.focus(p.focus)) { $("#g").scrollIntoView({block: "center"}); $("#g .graph-shell").classList.add("pulse"); }
  if ($("#lb").options.length > 1) $("#lb").selectedIndex = $("#lb").options.length - 1;
  $("#why").onclick = async () => {
    const r = await api("/v1/links/explain" + qs({a: $("#la").value, b: $("#lb").value}));
    if (r.linked) G.highlight([...new Set(r.path.flatMap(h => ["msg:" + h.from, "msg:" + h.to, ...(h.kind === "hard" ? ["ind:" + h.via] : [])]))]);
    $("#whyout").innerHTML = r.linked ? `<div class="note" style="margin-bottom:6px">السلسلة مظلّلة في رسم الأدلة أعلاه.</div><ol class="steps">${r.path.map(h => `<li><span class="mono">${esc(h.from)}</span> ← <span class="chip ltr">${esc(h.via)}</span> ← <span class="mono">${esc(h.to)}</span><div class="note">${h.kind === "hard" ? "دليل قوي: مورد مشترك يتحكم به المهاجم" : "إشارتان ضعيفتان مستقلتان معًا"} · قوة ${h.strength}</div></li>`).join("")}</ol><div class="note">قوة السلسلة = أضعف حلقة فيها: <span class="num">${r.chain_strength}</span></div>`
      : `<div class="callout">${$("#la").value === $("#lb").value ? "اختر رسالتين مختلفتين." : "لا توجد سلسلة أدلة كافية تربط الرسالتين."}</div>`;
  };
  $("#stix").onclick = async () => { const b = await api(`/v1/campaigns/${encodeURIComponent(id)}/stix`); const a = document.createElement("a"); a.href = URL.createObjectURL(new Blob([JSON.stringify(b, null, 2)], {type: "application/json"})); a.download = id + ".stix.json"; a.click(); };
  renderInv(d.investigations, id);
  bindRows(main());
}

function renderInv(list, cid) {
  const el = $("#inv");
  el.innerHTML = `${list.map(i => `<div style="padding:8px 0;border-bottom:1px solid var(--line)"><div class="toolbar"><b>${esc(i.title)}</b>${pill(i.status, T.status)}<span class="grow"></span><span class="note mono">${dt(i.updated_at)}</span>
    ${STATIC ? "" : `<button class="btn" data-inv="${esc(i.id)}" data-st="${i.status === "open" ? "closed" : "open"}">${i.status === "open" ? "إغلاق" : "إعادة فتح"}</button>`}</div>${i.notes ? `<div class="note">${esc(i.notes)}</div>` : ""}</div>`).join("") || '<div class="note">لا تحقيقات على هذه الحملة.</div>'}
    ${STATIC ? '<div class="note" style="margin-top:10px">فتح التحقيقات يتطلب خادم رصد (هذه لقطة ثابتة للقراءة).</div>' : `<form id="invf" class="toolbar" style="margin-top:12px"><input class="in grow" name="title" required maxlength="200" placeholder="عنوان التحقيق" aria-label="عنوان التحقيق"><button class="btn pri">فتح تحقيق</button></form>`}`;
  $$("[data-inv]", el).forEach(b => b.onclick = async () => { await api("/v1/investigations/" + b.dataset.inv, {method: "PATCH", body: JSON.stringify({status: b.dataset.st})}); renderInv((await api("/v1/campaigns/" + encodeURIComponent(cid))).investigations, cid); });
  const f = $("#invf", el);
  if (f) f.onsubmit = async e => { e.preventDefault(); await api("/v1/investigations", {method: "POST", body: JSON.stringify({campaign_id: cid, title: f.title.value})}); renderInv((await api("/v1/campaigns/" + encodeURIComponent(cid))).investigations, cid); };
}

/* ---------------- 3. messages ---------------- */
async function messages(arg, p) {
  if (arg) return investigation(arg, p);
  const limit = 50, offset = +p.offset || 0;
  const d = await api("/v1/messages" + qs({verdict: p.verdict, q: p.q, source: p.source, campaign: p.campaign, day: p.day, limit, offset}));
  const rows = d.messages;
  main().innerHTML = `<div class="card">
    <div class="toolbar" style="margin-bottom:12px">
      <input class="in" id="mq" placeholder="بحث في النص أو المعرّف" value="${esc(p.q || "")}" aria-label="بحث" style="flex:1;min-width:180px">
      <select class="in" id="mv" aria-label="الحكم"><option value="">كل الأحكام</option>${["malicious", "suspicious", "benign"].map(v => `<option value="${v}" ${p.verdict === v ? "selected" : ""}>${T.verdict[v]}</option>`).join("")}</select>
      <select class="in" id="mc" aria-label="الحملة"><option value="">داخل حملة وخارجها</option><option value="yes" ${p.campaign === "yes" ? "selected" : ""}>ضمن حملة</option><option value="no" ${p.campaign === "no" ? "selected" : ""}>غير مربوطة</option></select>
      <select class="in" id="ms" aria-label="المصدر"><option value="">كل المصادر</option>${Object.entries(T.source).map(([k, l]) => `<option value="${k}" ${p.source === k ? "selected" : ""}>${l}</option>`).join("")}</select>
      <button class="btn pri" id="mgo">تطبيق</button></div>
    ${p.day ? `<div class="callout info" style="margin-bottom:10px">مُصفّاة على يوم الاستلام <span class="mono">${esc(p.day)}</span> — <a href="${link("messages", "", {...p, day: ""})}">إزالة</a></div>` : ""}
    <div class="tbl-wrap"><table class="t"><thead><tr><th>التاريخ</th><th>الحكم</th><th>الدرجة</th><th>اللهجة</th><th>القناة</th><th>المصدر</th><th>الحملة</th><th>النص (منقّح)</th></tr></thead><tbody>
    ${rows.map(m => `<tr data-go="${link("messages", m.id)}"><td class="mono">${day(m.received_at)}</td><td>${pill(m.verdict)}</td><td class="num">${pct(m.score)}</td><td>${esc(varName(m.variety))}</td><td>${esc(m.channel || "")}</td><td>${srcChip(m.source)}</td><td class="mono">${m.campaign_id ? esc(m.campaign_id) : '<span class="faint">—</span>'}</td><td class="txt">${esc(m.text)}</td></tr>`).join("") || '<tr><td colspan="8" class="empty">لا نتائج</td></tr>'}
    </tbody></table></div>
    <div class="pager"><span>${fmt(offset + 1)}–${fmt(Math.min(offset + limit, d.total))} من ${fmt(d.total)}</span>
    <button class="btn" id="prev" ${offset ? "" : "disabled"}>السابق</button><button class="btn" id="next" ${offset + limit < d.total ? "" : "disabled"}>التالي</button></div></div>`;
  const upd = (o = 0) => go(link("messages", "", {q: $("#mq").value, verdict: $("#mv").value, campaign: $("#mc").value, source: $("#ms").value, day: p.day, offset: o || ""}));
  $("#mgo").onclick = () => upd(); $("#mq").onkeydown = e => { if (e.key === "Enter") upd(); };
  ["#mv", "#mc", "#ms"].forEach(s => $(s).onchange = () => upd());
  $("#prev").onclick = () => upd(Math.max(0, offset - limit)); $("#next").onclick = () => upd(offset + limit);
  bindRows(main());
}

async function investigation(id, p) {
  const m = await api("/v1/messages/" + encodeURIComponent(id));
  const a = m.analysis, ex = m.explanation, tab = p.tab || "result";
  const label = Object.fromEntries(ex.reasons.map(r => [r.id, r.text]));
  const ev = a.evidence.map(e => ({...e, label: label[e.id]}));
  const risk = a.score, rc = a.verdict === "malicious" ? "var(--crit)" : a.verdict === "suspicious" ? "var(--warn)" : "var(--good)";
  const C = 2 * Math.PI * 44;
  main().innerHTML = `
  <div class="toolbar"><a class="btn ghost" href="${link("messages")}">→ كل الرسائل</a><span class="grow"></span>${m.campaign_id ? `<a class="btn" href="${link("campaigns", m.campaign_id)}">الحملة ${esc(m.campaign_id)}</a>` : ""}</div>
  <div class="grid g-main">
    <div class="card"><div class="card-h"><h2>نص الرسالة</h2><span class="grow"></span>${srcChip(m.source)}<span class="chip">${esc(m.channel)}</span><span class="note mono">${esc(m.id)}</span></div>
      <div class="msg" dir="auto">${highlight(m.text, ev, a.indicators)}</div>
      <div class="legend"><span><mark>&nbsp;أحمر&nbsp;</mark> يرفع الخطر</span><span><mark class="neg">&nbsp;أخضر&nbsp;</mark> يخفضه</span><span><mark class="ind">&nbsp;أزرق&nbsp;</mark> مؤشر مستخرج</span><span class="mute">مرّر المؤشر للتفاصيل</span></div>
      <div class="note" style="margin-top:8px">النص المخزَّن منقّح: أرقام البطاقات والرموز والهويات مطموسة، ورقم المستلم مستبدل بمعرّف مجهول${m.recipient_pseudo ? ` (<span class="mono">${esc(m.recipient_pseudo)}</span>)` : ""}.</div></div>
    <div class="card"><div class="risk"><div class="gauge"><svg viewBox="0 0 100 100"><circle cx="50" cy="50" r="44" fill="none" stroke="var(--surface-3)" stroke-width="9"/><circle cx="50" cy="50" r="44" fill="none" stroke="${rc}" stroke-width="9" stroke-linecap="round" stroke-dasharray="${C * risk} ${C}"/></svg><b>${(risk).toFixed(2)}</b></div>
      <div><div style="margin-bottom:6px">${pill(a.verdict)}</div><div class="note">درجة الخطر من 1.00</div><div class="note mono">policy ${esc(a.policy_version)}</div></div></div>
      <p style="margin:14px 0 0">${esc(ex.summary)}</p>${ex.guard ? `<div class="callout" style="margin-top:10px">${esc(ex.guard)}</div>` : ""}
      <dl class="kv" style="margin-top:14px"><dt>الحملة</dt><dd>${m.campaign_id ? `<a class="mono" href="${link("campaigns", m.campaign_id)}">${esc(m.campaign_id)}</a>` : "غير مربوطة بحملة"}</dd>
      <dt>عائلة قالب</dt><dd>${m.template_family ? `<a class="mono" href="${link("intel", "", {tab: "families", id: m.template_family})}">${esc(m.template_family)}</a> <span class="note">(دليل ضعيف)</span>` : "—"}</dd>
      <dt>الاستلام</dt><dd class="mono">${dt(m.received_at)}</dd><dt>الإدخال</dt><dd class="mono">${dt(m.ingested_at)}</dd></dl></div>
  </div>
  <div class="card"><div class="tabs" role="tablist">${[["result", "لماذا هذا الحكم؟"], ["indicators", `المؤشرات (${a.indicators.length})`], ["language", "التحليل اللغوي"], ["relations", "العلاقات"], ["meta", "السجل والبيانات الوصفية"]].map(([k, l]) => `<button role="tab" data-tab="${k}" aria-selected="${tab === k}">${l}</button>`).join("")}</div><div id="tabbody"></div></div>`;
  $$("[data-tab]").forEach(b => b.onclick = () => go(link("messages", id, {tab: b.dataset.tab})));
  const body = $("#tabbody");
  const mx = Math.max(1, ...ex.reasons.map(r => Math.abs(r.weight)));
  if (tab === "result") {
    body.innerHTML = `<div class="grid g-main"><div>${ex.reasons.map(r => `<div class="reason"><div class="w ${r.weight > 0 ? "pos" : "neg"}">${r.weight > 0 ? "+" : ""}${r.weight.toFixed(2)}</div><div>${esc(r.text)}<span class="cat">${esc(T.cat[r.id.split(".")[0]] || r.id.split(".")[0])}</span>${r.source === "advisory" ? ' <span class="chip">استشاري</span>' : ""}<div class="bar ${r.weight < 0 ? "neg" : ""}" style="width:${100 * Math.abs(r.weight) / mx}%"></div><div class="note">بدون هذا الدليل تصبح الدرجة <span class="num">${pct(r.score_without, 1)}</span></div></div></div>`).join("") || '<div class="empty">لا أدلة ذات وزن</div>'}</div>
      <div><div class="callout info"><b>كيف تُحسب الدرجة؟</b><br>نجمع وزن كل دليل (موجب يرفع الخطر، سالب يخفضه) ثم نحوّل المجموع إلى درجة بين 0 و1. لا يوجد نموذج مخفي: الأوزان المعروضة هي القرار نفسه.<div class="mono" style="margin-top:6px;font-size:12px">score = sigmoid(${a.bias} + Σw) = sigmoid(${a.logit})</div></div>
      ${ex.counterfactual ? `<div class="card" style="margin-top:14px;box-shadow:none"><h2 style="font-size:14px;margin:0 0 6px">هشاشة الحكم</h2><div class="note">لو سقطت هذه الأدلة بالترتيب لتغيّر الحكم:</div><ol class="steps">${ex.counterfactual.remove_to_change_verdict.map(i => `<li>${esc(label[i] || i)}</li>`).join("")}</ol></div>` : ""}</div></div>`;
  } else if (tab === "indicators") {
    body.innerHTML = `<div class="tbl-wrap"><table class="t"><thead><tr><th>النوع</th><th>القيمة المعيارية</th><th>كما وردت</th><th>الدور</th><th>يُستخدم للربط</th><th>خصائص</th></tr></thead><tbody>
      ${a.indicators.map(i => `<tr data-go="${link("intel", "", {type: i.type, value: i.value})}"><td>${tchip(i.type)}</td><td class="ltr">${esc(i.value)}</td><td class="ltr faint">${esc(i.raw)}</td><td>${i.role === "sender" ? "المرسل" : "المتن"}</td><td>${i.linkable ? '<span class="pill ok">نعم</span>' : '<span class="pill unavailable">لا</span>'}</td><td>${Object.entries(i.attrs).filter(([, v]) => v && v !== true || v === true).slice(0, 5).map(([k, v]) => `<span class="chip">${esc(k)}${v === true ? "" : ": " + esc(String(v).slice(0, 30))}</span>`).join("")}</td></tr>`).join("") || '<tr><td class="empty">لا مؤشرات</td></tr>'}</tbody></table></div>
      <div class="note" style="margin-top:8px">«لا يُستخدم للربط»: نطاقات رسمية، أو مختصرات روابط ومنصات عامة يشترك فيها الجميع — ربطها يخلق حملات وهمية.</div>`;
  } else if (tab === "language") {
    const vm = a.variety.markers || {};
    const obf = ev.filter(e => e.id.startsWith("obfuscation."));
    body.innerHTML = `<div class="grid g3">
      <div><h3 class="note">اللغة والتنوّع اللغوي</h3><div style="font-size:20px;margin:4px 0">${esc(varName(a.variety.label))} <span class="mono note">${esc(a.language)}</span></div>
      ${hbars(Object.entries(a.variety.scores || {}).sort((x, y) => y[1] - x[1]).map(([k, n]) => ({l: varName(k), v: n})))}
      <div class="note">العلامات التي حُدّدت بها اللهجة:</div><div>${Object.entries(vm).map(([k, ws]) => ws.map(w => `<span class="chip" title="${esc(varName(k))}">${esc(w)}</span>`).join("")).join("") || "—"}</div></div>
      <div><h3 class="note">أساليب الإقناع المرصودة</h3><div>${a.tactics.map(t => `<span class="chip">${esc(T.tactic[t] || t)}</span>`).join("") || "—"}</div>
      <h3 class="note" style="margin-top:14px">الجهات المذكورة</h3><div>${a.brands.map(b => `<span class="chip">${esc(b)}</span>`).join("") || "—"}</div></div>
      <div><h3 class="note">التمويه</h3>${obf.length ? obf.map(e => `<div class="reason" style="grid-template-columns:1fr"><div>${esc(e.label || e.id)}<div class="note ltr">${e.spans.slice(0, 3).map(s => esc(JSON.stringify(s.text))).join(" ")}</div></div></div>`).join("") : '<div class="note">لم يُرصد تمويه (أحرف مخفية، حروف شبيهة، روابط مموّهة، حروف مفككة).</div>'}
      <div class="note" style="margin-top:10px">التحليل يعمل بعد توحيد الإملاء (الهمزات، التاء المربوطة، الأرقام الهندية) مع الإبقاء على مواضع النص الأصلي للتظليل.</div></div></div>`;
  } else if (tab === "relations") {
    body.innerHTML = `<div class="note" style="margin-bottom:10px">رسائل أخرى تشترك مع هذه الرسالة في مؤشر بعينه. المؤشرات غير القابلة للربط (منصات عامة) معروضة للاطلاع لكنها لا تُنشئ حملة.</div>
      ${m.related_by_indicator.map(r => `<div style="padding:9px 0;border-bottom:1px solid var(--line)"><span class="ltr">${esc(r.key)}</span> ${r.linkable ? "" : '<span class="pill unavailable">لا يربط</span>'} <span class="note">· ${r.messages} رسالة أخرى</span><div>${r.message_ids.map(x => `<a class="chip mono" href="${link("messages", x)}">${esc(x)}</a>`).join("")}</div></div>`).join("") || '<div class="empty">لا تشترك هذه الرسالة في أي مؤشر مع رسائل أخرى</div>'}
      ${m.investigations.length ? `<h3 class="note" style="margin-top:14px">تحقيقات على حملتها</h3>${m.investigations.map(i => `<div>${esc(i.title)} ${pill(i.status, T.status)}</div>`).join("")}` : ""}`;
  } else {
    body.innerHTML = `<dl class="kv"><dt>المعرّف</dt><dd class="mono">${esc(m.id)}</dd><dt>مصدر البيانات</dt><dd>${esc(T.source[m.source] || m.source)}</dd><dt>القناة</dt><dd>${esc(m.channel)}</dd>
      <dt>تاريخ الاستلام</dt><dd class="mono">${dt(m.received_at)}</dd><dt>تاريخ الإدخال</dt><dd class="mono">${dt(m.ingested_at)}</dd>
      <dt>سياسة التقييم</dt><dd class="mono">${esc(a.policy_version)}</dd><dt>بصمة القالب</dt><dd class="mono">${esc(a.fingerprint)}</dd>
      <dt>المستلم</dt><dd class="mono">${esc(m.recipient_pseudo || "غير مسجّل")}</dd><dt>الحواجز المطبّقة</dt><dd>${esc(a.guard_applied || "لا شيء")}</dd></dl>
      <details><summary class="note" style="cursor:pointer">سجل التحليل الكامل (JSON)</summary><pre class="code">${esc(JSON.stringify(a, null, 2))}</pre></details>`;
  }
  bindRows(main());
}

/* ---------------- 4. intelligence explorer ---------------- */
async function intel(arg, p) {
  const tab = p.tab || "indicators";
  main().innerHTML = `<div class="card"><div class="tabs" role="tablist">${[["indicators", "مؤشرات الاختراق"], ["entities", "الكيانات"], ["families", "عائلات القوالب"], ["investigations", "التحقيقات"]].map(([k, l]) => `<button role="tab" data-tab="${k}" aria-selected="${tab === k}">${l}</button>`).join("")}</div><div id="ib"><div class="loading">جارٍ التحميل</div></div></div>`;
  $$("[data-tab]").forEach(b => b.onclick = () => go(link("intel", "", {tab: b.dataset.tab})));
  const body = $("#ib");
  if (tab === "entities") {
    const d = await api("/v1/entities");
    body.innerHTML = `<div class="note" style="margin-bottom:10px">${esc(d.note)}.</div><div class="tbl-wrap"><table class="t"><thead><tr><th>الجهة</th><th>القطاع</th><th>النطاقات الرسمية</th><th>ذُكرت في</th><th>منها مُشار إليه</th><th>الحملات</th></tr></thead><tbody>
      ${d.entities.map(e => `<tr><td><b>${esc(e.id)}</b></td><td>${esc(e.sector || "—")}</td><td>${e.official_domains.map(x => `<span class="ltr chip">${esc(x)}</span>`).join("")}</td><td class="num">${e.mentions}</td><td class="num">${e.flagged_mentions}</td><td>${e.campaign_ids.map(c => `<a class="chip mono" href="${link("campaigns", c)}">${esc(c)}</a>`).join("") || "—"}</td></tr>`).join("") || '<tr><td colspan="6" class="empty">لا كيانات</td></tr>'}</tbody></table></div>`;
    return;
  }
  if (tab === "families") {
    const d = await api("/v1/template-families");
    const fam = p.id ? d.template_families.filter(f => f.id === p.id) : d.template_families;
    body.innerHTML = `<div class="callout" style="margin-bottom:12px">دليل ضعيف: رسائل تتشارك النص نفسه تقريبًا. قد تكون جهة واحدة تبدّل مواردها، أو جهات مختلفة تنسخ القالب ذاته — لذلك لا تُدمج في حملة واحدة دون مورد مشترك.</div>
      ${p.id ? `<div class="toolbar" style="margin-bottom:10px"><a class="btn ghost" href="${link("intel", "", {tab: "families"})}">كل العائلات</a></div>` : ""}
      <div class="tbl-wrap"><table class="t"><thead><tr><th>العائلة</th><th>الرسائل</th><th>موارد مختلفة</th><th>حملات</th><th>رسائل غير مربوطة</th><th>الجهات</th><th>الرسائل</th></tr></thead><tbody>
      ${fam.map(f => `<tr><td class="mono">${esc(f.id)}</td><td class="num">${f.size}</td><td class="num">${f.distinct_hard_indicators}</td><td>${f.campaign_ids.map(c => `<a class="chip mono" href="${link("campaigns", c)}">${esc(c)}</a>`).join("") || "—"}</td><td class="num">${f.unlinked_messages}</td><td>${f.brands.map(b => `<span class="chip">${esc(b)}</span>`).join("") || "—"}</td><td>${f.message_ids.slice(0, p.id ? 999 : 4).map(x => `<a class="chip mono" href="${link("messages", x)}">${esc(x)}</a>`).join("")}${!p.id && f.message_ids.length > 4 ? `<a class="chip" href="${link("intel", "", {tab: "families", id: f.id})}">+${f.message_ids.length - 4}</a>` : ""}</td></tr>`).join("") || '<tr><td colspan="7" class="empty">لا عائلات</td></tr>'}</tbody></table></div>`;
    return;
  }
  if (tab === "investigations") {
    const d = await api("/v1/investigations" + qs({status: p.status}));
    body.innerHTML = `<div class="toolbar" style="margin-bottom:12px"><select class="in" id="ist" aria-label="الحالة"><option value="">كل الحالات</option><option value="open" ${p.status === "open" ? "selected" : ""}>مفتوحة</option><option value="closed" ${p.status === "closed" ? "selected" : ""}>مغلقة</option></select><span class="grow"></span><span class="note">يُفتح التحقيق من صفحة الحملة</span></div>
      <div class="tbl-wrap"><table class="t"><thead><tr><th>العنوان</th><th>الحالة</th><th>الحملة</th><th>رسائل الحملة الآن</th><th>آخر تحديث</th></tr></thead><tbody>
      ${d.investigations.map(i => `<tr data-go="${link("campaigns", i.campaign_id)}"><td>${esc(i.title)}</td><td>${pill(i.status, T.status)}</td><td class="mono">${esc(i.campaign_id)}${i.campaign_exists ? "" : ' <span class="pill warn">لم تعد موجودة</span>'}</td><td class="num">${i.campaign_size ?? "—"}</td><td class="mono">${dt(i.updated_at)}</td></tr>`).join("") || `<tr><td colspan="5" class="empty">لا تحقيقات${STATIC ? " (لقطة ثابتة)" : ""}</td></tr>`}</tbody></table></div>`;
    $("#ist").onchange = () => go(link("intel", "", {tab, status: $("#ist").value}));
    bindRows(body);
    return;
  }
  const limit = 50, offset = +p.offset || 0;
  const d = await api("/v1/indicators" + qs({type: p.type, q: p.q, role: p.role, in_campaign: p.in_campaign, flagged_only: p.flagged_only, linkable: p.linkable, sort: p.sort, limit, offset}));
  body.innerHTML = `<div class="toolbar" style="margin-bottom:12px">
      <input class="in" id="iq" placeholder="بحث في القيمة (نطاق، رقم، آيبان…)" value="${esc(p.q || "")}" style="flex:1;min-width:200px" aria-label="بحث">
      <select class="in" id="it" aria-label="النوع"><option value="">كل الأنواع</option>${Object.entries(T.type).map(([k, l]) => `<option value="${k}" ${p.type === k ? "selected" : ""}>${l}</option>`).join("")}</select>
      <select class="in" id="ic" aria-label="الحملة"><option value="">داخل حملة وخارجها</option><option value="yes" ${p.in_campaign === "yes" ? "selected" : ""}>ضمن حملة</option><option value="no" ${p.in_campaign === "no" ? "selected" : ""}>خارج الحملات</option></select>
      <select class="in" id="il" aria-label="الربط"><option value="">قابل وغير قابل للربط</option><option value="yes" ${p.linkable === "yes" ? "selected" : ""}>قابل للربط</option><option value="no" ${p.linkable === "no" ? "selected" : ""}>غير قابل للربط</option></select>
      <select class="in" id="io" aria-label="الترتيب">${[["messages", "الأكثر تكرارًا"], ["last_seen", "الأحدث ظهورًا"], ["max_score", "الأعلى خطرًا"]].map(([k, l]) => `<option value="${k}" ${(p.sort || "messages") === k ? "selected" : ""}>${l}</option>`).join("")}</select>
      <label class="note" style="display:inline-flex;gap:6px;align-items:center"><input type="checkbox" id="if" ${p.flagged_only ? "checked" : ""}> في رسائل مُشار إليها فقط</label></div>
    <div style="margin-bottom:10px">${Object.entries(d.facets_by_type).map(([t, n]) => `<a href="${link("intel", "", {...p, type: t, offset: ""})}" style="text-decoration:none">${tchip(t).replace("</span>", ` · ${n}</span>`)}</a>`).join("")}</div>
    <div class="tbl-wrap"><table class="t"><thead><tr><th>النوع</th><th>القيمة</th><th>رسائل</th><th>احتيالية / مشبوهة / سليمة</th><th>أعلى خطر</th><th>الحملات</th><th>أول ظهور</th><th>آخر ظهور</th><th>الربط</th></tr></thead><tbody>
    ${d.indicators.map(i => `<tr data-ind="${esc(i.type)}|${esc(i.value)}"><td>${tchip(i.type)}${i.roles.includes("sender") ? ' <span class="chip">مرسل</span>' : ""}</td><td class="ltr">${esc(i.value)}</td><td class="num">${i.messages}</td><td class="num"><span style="color:var(--crit)">${i.malicious}</span> / <span style="color:var(--warn)">${i.suspicious}</span> / <span style="color:var(--good)">${i.benign}</span></td><td class="num">${pct(i.max_score)}</td><td>${i.campaign_ids.map(c => `<span class="chip mono">${esc(c)}</span>`).join("") || '<span class="faint">—</span>'}</td><td class="mono">${day(i.first_seen)}</td><td class="mono">${day(i.last_seen)}</td><td>${i.suppressed_reason ? '<span class="pill warn">مستبعد</span>' : i.linkable ? '<span class="pill ok">نعم</span>' : '<span class="pill unavailable">لا</span>'}</td></tr>`).join("") || '<tr><td colspan="9" class="empty">لا مؤشرات مطابقة</td></tr>'}
    </tbody></table></div>
    <div class="pager"><span>${fmt(d.total ? offset + 1 : 0)}–${fmt(Math.min(offset + limit, d.total))} من ${fmt(d.total)}</span><button class="btn" id="prev" ${offset ? "" : "disabled"}>السابق</button><button class="btn" id="next" ${offset + limit < d.total ? "" : "disabled"}>التالي</button></div>`;
  const upd = (o = 0) => go(link("intel", "", {q: $("#iq").value, type: $("#it").value, in_campaign: $("#ic").value, linkable: $("#il").value, sort: $("#io").value, flagged_only: $("#if").checked ? "true" : "", offset: o || ""}));
  $("#iq").onkeydown = e => { if (e.key === "Enter") upd(); };
  ["#it", "#ic", "#il", "#io", "#if"].forEach(s => $(s).onchange = () => upd());
  $("#prev").onclick = () => upd(Math.max(0, offset - limit)); $("#next").onclick = () => upd(offset + limit);
  $$("[data-ind]", body).forEach(tr => { tr.tabIndex = 0; tr.classList.add("row"); const open = () => { const [t, ...v] = tr.dataset.ind.split("|"); indicatorDrawer(t, v.join("|")); }; tr.onclick = open; tr.onkeydown = e => { if (e.key === "Enter") open(); }; });
  if (p.value && p.type) indicatorDrawer(p.type, p.value);
}

async function indicatorDrawer(type, value) {
  drawer(`${tchip(type)} <span class="ltr">${esc(value)}</span>`, '<div class="loading">جارٍ التحميل</div>');
  let d;
  try { d = await api("/v1/indicators/detail" + qs({type, value})); }
  catch (e) { $("#drawer-body").innerHTML = `<div class="err">${esc(e.message)}</div>`; return; }
  $("#drawer-body").innerHTML = `
    <dl class="kv"><dt>القيمة المعيارية</dt><dd class="ltr">${esc(d.value)}</dd><dt>أول ظهور</dt><dd class="mono">${dt(d.first_seen)}</dd><dt>آخر ظهور</dt><dd class="mono">${dt(d.last_seen)}</dd>
    <dt>رسائل</dt><dd class="num">${d.messages.length}</dd><dt>يُستخدم للربط</dt><dd>${d.suppressed_reason ? `<span class="pill warn">مستبعد</span> ${esc(d.suppressed_reason)}` : d.linkable ? "نعم — مورد يتحكم به المهاجم" : "لا — منصة عامة أو نطاق رسمي"}</dd>
    <dt>الحملات</dt><dd>${d.campaign_ids.map(c => `<a class="chip mono" href="${link("campaigns", c)}">${esc(c)}</a>`).join("") || "—"}</dd></dl>
    ${Object.keys(d.attrs || {}).length ? `<h3 class="note">خصائص مستخرجة</h3><div>${Object.entries(d.attrs).filter(([, v]) => v !== null && v !== false && v !== "").map(([k, v]) => `<span class="chip">${esc(k)}: <span class="ltr">${esc(String(v))}</span></span>`).join("")}</div>` : ""}
    ${Object.keys(d.evidence_referencing).length ? `<h3 class="note" style="margin-top:14px">أدلة تستند إليه</h3><div>${Object.entries(d.evidence_referencing).map(([k, n]) => `<span class="chip mono">${esc(k)} · ${n}</span>`).join("")}</div>` : ""}
    <h3 class="note" style="margin-top:14px">مؤشرات ظهرت معه (العلاقات التاريخية)</h3>
    <table class="t"><tbody>${d.co_occurring.map(c => `<tr data-co="${esc(c.type)}|${esc(c.value)}"><td>${tchip(c.type)}</td><td class="ltr">${esc(c.value)}</td><td class="num">${c.messages}</td><td>${c.linkable ? "" : '<span class="pill unavailable">لا يربط</span>'}</td></tr>`).join("") || '<tr><td class="mute">لا شيء</td></tr>'}</tbody></table>
    <h3 class="note" style="margin-top:14px">الرسائل</h3>
    <table class="t"><tbody>${d.messages.map(m => `<tr data-go="${link("messages", m.id)}"><td class="mono">${day(m.received_at)}</td><td>${pill(m.verdict)}</td><td>${srcChip(m.source)}</td><td class="txt">${esc(m.text)}</td></tr>`).join("")}</tbody></table>`;
  bindRows($("#drawer-body"));
  $$("[data-co]", $("#drawer-body")).forEach(tr => { tr.classList.add("row"); tr.tabIndex = 0; tr.onclick = () => { const [t, ...v] = tr.dataset.co.split("|"); indicatorDrawer(t, v.join("|")); }; });
}

/* ---------------- 5. database intelligence center ---------------- */
async function database(arg, p) {
  const tab = p.tab || "overview";
  main().innerHTML = `<div class="card"><div class="tabs" role="tablist">${[["overview", "نظرة عامة"], ["schema", "المخطط والعلاقات"], ["records", "السجلات"], ["integrity", "سلامة البيانات"]].map(([k, l]) => `<button role="tab" data-tab="${k}" aria-selected="${tab === k}">${l}</button>`).join("")}</div><div id="db"><div class="loading">جارٍ التحميل</div></div></div>`;
  $$("[data-tab]").forEach(b => b.onclick = () => go(link("database", "", {tab: b.dataset.tab})));
  const body = $("#db");
  if (tab === "overview" || tab === "integrity") {
    const o = await api("/v1/db/overview");
    if (tab === "integrity") {
      body.innerHTML = `<div class="note" style="margin-bottom:10px">فحوص تُنفّذ الآن على قاعدة البيانات الفعلية (نطاق حسابك).${STATIC ? " في اللقطة الثابتة: نتائج وقت التصدير." : ""}</div>
        <div class="tbl-wrap"><table class="t"><thead><tr><th>الفحص</th><th>النتيجة</th><th>التفاصيل</th></tr></thead><tbody>${o.integrity.map(c => `<tr><td class="ltr">${esc(c.check)}</td><td>${pill(c.status, T.status)}</td><td class="mono">${esc(c.detail)}</td></tr>`).join("")}</tbody></table></div>`;
      return;
    }
    body.innerHTML = `<div class="kpis" style="grid-template-columns:repeat(auto-fit,minmax(150px,1fr))">
      <div class="kpi static"><div class="v" style="font-size:18px;color:${o.connection === "open" ? "var(--good)" : "var(--crit)"}">${o.connection === "open" ? "متصل" : esc(o.connection)}</div><div class="l">حالة الاتصال</div><div class="s">${esc(o.engine)} ${esc(o.engine_version)}</div></div>
      <div class="kpi static"><div class="v">${o.tables.length}</div><div class="l">جداول قابلة للاستكشاف</div><div class="s">+ ${o.derived_views.length} عرض مشتق غير مخزّن</div></div>
      <div class="kpi static"><div class="v">${fmt(o.tables.reduce((a, t) => a + t.rows, 0))}</div><div class="l">إجمالي السجلات</div><div class="s">${esc(o.row_counts_scope === "rows belonging to your tenant" ? "سجلات حسابك" : o.row_counts_scope)}</div></div>
      <div class="kpi static"><div class="v" style="font-size:22px">${bytes(o.size_bytes)}</div><div class="l">حجم الملف</div><div class="s">كل الحسابات · ${esc(o.journal_mode)}</div></div>
      <div class="kpi static"><div class="v">${esc(o.schema_version)}</div><div class="l">إصدار المخطط</div><div class="s">${o.integrity.every(c => c.status === "ok") ? "كل فحوص السلامة سليمة" : "يوجد فحص غير سليم"}</div></div></div>
      <div class="grid g2" style="margin-top:18px"><div><h3 class="note">الجداول</h3><table class="t"><thead><tr><th>الجدول</th><th>السجلات</th><th>الأعمدة</th><th>آخر كتابة</th></tr></thead><tbody>
      ${o.tables.map(t => `<tr data-go="${link("database", "", {tab: "records", table: t.name})}"><td class="mono">${esc(t.name)}</td><td class="num">${fmt(t.rows)}</td><td class="num">${t.columns}</td><td class="mono">${dt(t.last_write)}</td></tr>`).join("")}</tbody></table></div>
      <div><h3 class="note">عروض مشتقة (تُحسب ولا تُخزَّن)</h3>${o.derived_views.map(v => `<div style="padding:8px 0;border-bottom:1px solid var(--line)"><span class="mono">${esc(v.name)}</span> ← <span class="mono note">${v.computed_from.map(esc).join(" + ")}</span><div class="note">${esc(v.note_ar || v.note)}</div><div class="note mono">${esc(v.by)}</div></div>`).join("")}
      <h3 class="note" style="margin-top:14px">تصنيف مصدر البيانات (messages.source)</h3>${hbars(Object.entries(o.messages_by_source || {}).map(([k, n]) => ({l: T.source[k] || k, v: n, c: k === "real" ? "var(--good)" : k === "synthetic" ? "var(--warn)" : "#9085e9", go: link("database", "", {tab: "records", table: "messages", f_source: k})})))}
      <div class="callout info" style="margin-top:12px">ملف القاعدة: <span class="mono">${esc(o.file)}</span>${o.persistent ? "" : " — غير محفوظ على القرص"}. هذا المستكشف للقراءة فقط: لا يتيح أي تعديل.</div></div></div>`;
    bindRows(body);
    return;
  }
  if (tab === "schema") {
    const s = await api("/v1/db/schema");
    body.innerHTML = `<div class="note" style="margin-bottom:10px">المخطط الفعلي كما تُعيده SQLite. العلاقات <b>منطقية</b> (تفرضها طبقة التخزين في رصد)، إذ لا توجد مفاتيح أجنبية مُعلنة في SQLite — والمستكشف يتحقق منها في «سلامة البيانات». انقر جدولًا لعرض أعمدته.</div><div class="er" id="er"></div><div id="tbl-detail" style="margin-top:16px"></div>`;
    erDiagram($("#er"), s, name => schemaDetail(s, name));
    schemaDetail(s, p.table || "messages");
    return;
  }
  // records
  const table = p.table || "messages", limit = 25, offset = +p.offset || 0;
  const filters = Object.fromEntries(Object.entries(p).filter(([k]) => k.startsWith("f_")));
  const d = await api(`/v1/db/tables/${encodeURIComponent(table)}/rows` + qs({q: p.q, limit, offset, ...filters}));
  const cols = d.columns;
  const filterable = {messages: ["verdict", "source", "variety", "channel"], indicators: ["type", "role", "linkable"], investigations: ["status"], operations: ["status", "op"], audit: ["action"]}[table] || [];
  body.innerHTML = `<div class="toolbar" style="margin-bottom:12px">
      <select class="in" id="rt" aria-label="الجدول">${["messages", "indicators", "investigations", "operations", "audit"].map(t => `<option ${t === table ? "selected" : ""}>${t}</option>`).join("")}</select>
      <input class="in" id="rq" placeholder="بحث نصي" value="${esc(p.q || "")}" style="flex:1;min-width:160px" aria-label="بحث">
      ${filterable.map(c => `<input class="in" data-f="${c}" placeholder="${c} =" value="${esc(p["f_" + c] || "")}" style="width:120px" aria-label="${c}">`).join("")}
      <button class="btn pri" id="rgo">تطبيق</button></div>
    ${Object.keys(filters).length ? `<div class="toolbar" style="margin-bottom:8px"><span class="note">مرشحات نشطة:</span>${Object.entries(filters).map(([k, v]) => `<span class="chip mono">${esc(k.slice(2))} = ${esc(v)}</span>`).join("")}<a class="note" href="${link("database", "", {tab: "records", table})}">إزالة الكل</a></div>` : ""}
    <div class="note" style="margin-bottom:8px">جدول <span class="mono">${esc(table)}</span> · ${fmt(d.total)} سجل مطابق · مرتبة حسب ${table === "messages" ? "received_at" : table === "indicators" ? "rowid" : "الأحدث"} تنازليًا. انقر سجلًا لعرض تفاصيله ومصدره.</div>
    <div class="tbl-wrap"><table class="t"><thead><tr>${cols.map(c => `<th class="mono">${esc(c)}</th>`).join("")}</tr></thead><tbody>
    ${d.rows.map(r => `<tr data-rid="${r._rowid}">${cols.map(c => `<td class="${["text_redacted", "detail", "notes", "title"].includes(c) ? "txt" : "mono"}">${c === "verdict" ? pill(r[c]) : esc(r[c] == null ? "NULL" : String(r[c]).slice(0, 140))}</td>`).join("")}</tr>`).join("") || `<tr><td colspan="${cols.length}" class="empty">لا سجلات</td></tr>`}</tbody></table></div>
    <div class="pager"><span>${fmt(d.total ? offset + 1 : 0)}–${fmt(Math.min(offset + limit, d.total))} من ${fmt(d.total)}</span><button class="btn" id="prev" ${offset ? "" : "disabled"}>السابق</button><button class="btn" id="next" ${offset + limit < d.total ? "" : "disabled"}>التالي</button></div>`;
  const upd = (o = 0) => go(link("database", "", {tab: "records", table: $("#rt").value, q: $("#rt").value === table ? $("#rq").value : "", offset: o || "",
    ...($("#rt").value === table ? Object.fromEntries($$("[data-f]").map(i => ["f_" + i.dataset.f, i.value])) : {})}));
  $("#rgo").onclick = () => upd(); $("#rt").onchange = () => upd(); $("#rq").onkeydown = e => { if (e.key === "Enter") upd(); };
  $$("[data-f]").forEach(i => i.onkeydown = e => { if (e.key === "Enter") upd(); });
  $("#prev").onclick = () => upd(Math.max(0, offset - limit)); $("#next").onclick = () => upd(offset + limit);
  $$("[data-rid]", body).forEach(tr => { tr.classList.add("row"); tr.tabIndex = 0; const open = () => recordDrawer(table, tr.dataset.rid); tr.onclick = open; tr.onkeydown = e => { if (e.key === "Enter") open(); }; });
}

async function recordDrawer(table, rowid) {
  drawer(`<span class="mono">${esc(table)}</span> · rowid <span class="mono">${esc(rowid)}</span>`, '<div class="loading">جارٍ التحميل</div>');
  let d;
  try { d = await api(`/v1/db/tables/${encodeURIComponent(table)}/rows/${encodeURIComponent(rowid)}`); }
  catch (e) { $("#drawer-body").innerHTML = `<div class="err">${esc(e.message)}</div>`; return; }
  const r = d.record;
  const prov = table === "messages" ? `<div class="callout info" style="margin-bottom:12px"><b>المصدر:</b> ${esc(T.source[r.source] || r.source)} · <b>استُلمت:</b> <span class="mono">${dt(r.received_at)}</span> · <b>أُدخلت:</b> <span class="mono">${dt(r.ingested_at)}</span> · <b>سياسة التقييم:</b> <span class="mono">${esc(r.analysis.policy_version)}</span><div style="margin-top:6px"><a href="${link("messages", r.id)}">فتح في مساحة التحقيق ←</a></div></div>` : "";
  $("#drawer-body").innerHTML = `${prov}<dl class="kv">${Object.entries(r).filter(([k]) => k !== "analysis").map(([k, v]) => `<dt class="mono">${esc(k)}</dt><dd class="${k === "text_redacted" ? "" : "mono"}">${esc(v == null ? "NULL" : v)}</dd>`).join("")}</dl>
    ${d.related.indicators ? `<h3 class="note">سجلات indicators المرتبطة (message_id = ${esc(r.id)})</h3><table class="t"><tbody>${d.related.indicators.map(i => `<tr data-go="${link("intel", "", {type: i.type, value: i.value})}"><td class="mono">${i._rowid}</td><td>${tchip(i.type)}</td><td class="ltr">${esc(i.value)}</td><td class="mono">${esc(i.role)}</td></tr>`).join("") || '<tr><td class="mute">لا شيء</td></tr>'}</tbody></table>` : ""}
    ${d.related.message ? `<h3 class="note">الرسالة الأم (messages.id)</h3><table class="t"><tbody><tr data-go="${link("messages", d.related.message.id)}"><td class="mono">${esc(d.related.message.id)}</td><td>${pill(d.related.message.verdict)}</td><td>${srcChip(d.related.message.source)}</td><td class="mono">${day(d.related.message.received_at)}</td></tr></tbody></table><div class="note">السجلات بالقيمة نفسها في الجدول: <span class="num">${d.related.same_value_rows}</span> — <a href="${link("intel", "", {type: r.type, value: r.value})}">ملف المؤشر</a></div>` : ""}
    ${r.analysis ? `<details style="margin-top:12px"><summary class="note" style="cursor:pointer">عمود analysis (JSON)</summary><pre class="code">${esc(JSON.stringify(r.analysis, null, 2))}</pre></details>` : ""}`;
  bindRows($("#drawer-body"));
}

function erDiagram(el, s, onPick) {
  const tables = s.tables.filter(t => t.explorable);
  const pos = {messages: [30, 40], indicators: [500, 40], investigations: [500, 330], operations: [850, 40], audit: [850, 290]};
  const derived = {campaigns: [30, 420], template_families: [30, 530]};
  const W = 1120, rowH = 19, head = 30, boxW = 250;
  const boxH = t => head + t.columns.length * rowH + 10;
  let svg = "";
  const anchor = (name, side) => { const t = tables.find(x => x.name === name); const [x, y] = pos[name] || derived[name]; return side === "r" ? [x + boxW, y + head + 8] : [x, y + head + 8]; };
  // relations
  const rel = [["indicators", "messages", "logical", "message_id → id"], ["investigations", "campaigns", "derived", "campaign_id → id"]];
  const deriveLinks = [["campaigns", "messages"], ["campaigns", "indicators"], ["template_families", "messages"]];
  deriveLinks.forEach(([a, b]) => { const [x1, y1] = [derived[a][0] + 105, derived[a][1]]; const [x2, y2] = [pos[b][0] + boxW / 2, pos[b][1] + boxH(tables.find(t => t.name === b))]; svg += `<path d="M${x1} ${y1} C${x1} ${y1 - 60} ${x2} ${y2 + 60} ${x2} ${y2}" fill="none" stroke="var(--faint)" stroke-dasharray="3 4"/>`; });
  rel.forEach(([a, b, kind, lab]) => {
    const [x1, y1] = anchor(a, "l"); const [x2, y2] = b === "campaigns" ? [derived.campaigns[0] + 210, derived.campaigns[1] + 30] : anchor(b, "r");
    svg += `<path d="M${x1} ${y1} C${x1 - 70} ${y1} ${x2 + 70} ${y2} ${x2} ${y2}" fill="none" stroke="${kind === "logical" ? "var(--accent)" : "var(--warn)"}" stroke-width="1.6" ${kind === "derived" ? 'stroke-dasharray="6 4"' : ""}/><circle cx="${x2}" cy="${y2}" r="3.5" fill="${kind === "logical" ? "var(--accent)" : "var(--warn)"}"/><text x="${(x1 + x2) / 2}" y="${Math.min(y1, y2) - 8}" text-anchor="middle" style="font:11px var(--mono);fill:var(--mute)">${esc(lab)}</text>`;
  });
  tables.forEach(t => {
    const [x, y] = pos[t.name] || [40, 600]; const h = boxH(t);
    svg += `<g class="tbl" data-t="${esc(t.name)}" tabindex="0"><rect class="b" x="${x}" y="${y}" width="${boxW}" height="${h}" rx="8"/><rect class="h" x="${x}" y="${y}" width="${boxW}" height="${head}" rx="8"/><rect class="h" x="${x}" y="${y + head - 8}" width="${boxW}" height="8"/>
      <text class="tn" x="${x + 12}" y="${y + 20}">${esc(t.name)}</text>
      ${t.columns.map((c, i) => `<text class="${c.pk ? "pk" : ""}" x="${x + 12}" y="${y + head + 16 + i * rowH}">${c.pk ? "🔑 " : ""}${esc(c.name)}</text><text x="${x + boxW - 12}" y="${y + head + 16 + i * rowH}" text-anchor="end" style="fill:var(--faint)">${esc(c.type || "")}</text>`).join("")}</g>`;
  });
  Object.entries(derived).forEach(([n, [x, y]]) => { svg += `<g class="tbl derived"><rect class="b" x="${x}" y="${y}" width="210" height="60" rx="8"/><text class="tn" x="${x + 12}" y="${y + 24}">${esc(n)}</text><text x="${x + 12}" y="${y + 44}" style="fill:var(--faint)">عرض مشتق — غير مخزّن</text></g>`; });
  el.innerHTML = `<svg viewBox="0 0 ${W} 620" role="img" aria-label="مخطط الكيانات والعلاقات">${svg}</svg>
    <div class="legend" style="padding:8px 12px;direction:rtl"><span><svg width="26" height="8"><line x1="0" y1="4" x2="26" y2="4" stroke="var(--accent)" stroke-width="2"/></svg>علاقة منطقية بين جدولين</span><span><svg width="26" height="8"><line x1="0" y1="4" x2="26" y2="4" stroke="var(--warn)" stroke-width="2" stroke-dasharray="5 3"/></svg>إشارة إلى عرض مشتق</span><span><svg width="26" height="8"><line x1="0" y1="4" x2="26" y2="4" stroke="var(--faint)" stroke-width="1.5" stroke-dasharray="3 3"/></svg>يُحسب من</span><span>🔑 مفتاح أساسي</span></div>`;
  $$(".tbl[data-t]", el).forEach(g => { const pick = () => { $$(".tbl", el).forEach(x => x.classList.remove("sel")); g.classList.add("sel"); onPick(g.dataset.t); }; g.onclick = pick; g.onkeydown = e => { if (e.key === "Enter") pick(); }; });
}

function schemaDetail(s, name) {
  const t = s.tables.find(x => x.name === name); if (!t) return;
  const rels = s.relations.filter(r => r.from.startsWith(name + ".") || r.to.startsWith(name + "."));
  $("#tbl-detail").innerHTML = `<div class="grid g2"><div><div class="toolbar"><h3 style="margin:0" class="mono">${esc(t.name)}</h3><span class="grow"></span>${t.explorable ? `<a class="btn" href="${link("database", "", {tab: "records", table: t.name})}">تصفّح السجلات</a>` : ""}</div>
    ${t.columns.map(c => `<div class="schema-col"><span class="mono">${c.pk ? "🔑 " : ""}${esc(c.name)}</span><span class="mono faint">${esc(c.type)}${c.not_null ? " NOT NULL" : ""}</span><span class="mono faint">${c.default != null ? "= " + esc(c.default) : ""}</span></div>`).join("")}
    <h3 class="note" style="margin-top:12px">الفهارس</h3>${t.indexes.map(i => `<div class="mono note">${esc(i.name)} (${i.columns.map(esc).join(", ")})${i.unique ? " UNIQUE" : ""}</div>`).join("") || '<div class="note">لا فهارس</div>'}
    <h3 class="note" style="margin-top:12px">مفاتيح أجنبية مُعلنة</h3><div class="note">${t.declared_foreign_keys.length ? t.declared_foreign_keys.map(f => esc(f.column + " → " + f.references)).join("<br>") : "لا يوجد (العلاقات منطقية — انظر أدناه)"}</div>
    <h3 class="note" style="margin-top:12px">العلاقات</h3>${rels.map(r => `<div><span class="mono">${esc(r.from)} → ${esc(r.to)}</span> ${pill(r.kind === "logical" ? "ok" : "warn", {ok: "منطقية", warn: r.kind === "derived" ? "مشتقة" : "—"})}<div class="note">${esc(r.description_ar || r.description)}</div></div>`).join("") || '<div class="note">لا علاقات</div>'}</div>
    <div><h3 class="note">DDL</h3><pre class="code">${esc(t.ddl || "")}</pre></div></div>`;
}

/* ---------------- 6. system monitoring ---------------- */
async function system() {
  const h = await api("/v1/system/health");
  const c = h.checks, r = h.resources;
  const card = (key, title, body) => `<div class="kpi static"><div class="toolbar" style="justify-content:space-between"><b>${title}</b>${pill(c[key].status, T.status)}</div><div class="s" style="margin-top:8px;line-height:1.7">${body}</div></div>`;
  const ops = h.recent_operations, fails = h.recent_failures;
  main().innerHTML = `
  ${STATIC ? `<div class="callout">هذه لقطة ثابتة: القيم أدناه قيست مرة واحدة وقت إنشاء اللقطة (<span class="mono">${dt(h.measured_at)}</span>) وليست حالة حية.</div>` : ""}
  <div class="toolbar"><span>الحالة العامة: ${pill(h.status, T.status)}</span><span class="note">قيست في <span class="mono">${dt(h.measured_at)}</span> UTC</span><span class="grow"></span>${STATIC ? "" : `<button class="btn" id="remeasure">${icon("refresh")} إعادة القياس</button>`}</div>
  <div class="kpis" style="grid-template-columns:repeat(auto-fit,minmax(220px,1fr))">
    ${card("engine", "محرك الكشف", c.engine.error ? esc(c.engine.error) : `فحص برسالة مرجعية: الحكم المتوقع «احتيالية»، المرصود «${esc(T.verdict[c.engine.observed_verdict] || c.engine.observed_verdict)}»<br>زمن التحليل <span class="num">${c.engine.latency_ms} ms</span> · سياسة <span class="mono">${esc(c.engine.policy_version)}</span><br>حزم اللغة: <span class="mono">${(c.engine.language_packs || []).map(esc).join(", ")}</span>`)}
    ${card("database", "قاعدة البيانات", c.database.error ? esc(c.database.error) : `${esc(c.database.engine)} · ${c.database.persistent ? "ملف على القرص" : "في الذاكرة"}<br>الحجم ${bytes(c.database.size_bytes)} · زمن الفحص <span class="num">${c.database.latency_ms} ms</span><br>${c.database.integrity.filter(x => x.status === "ok").length}/${c.database.integrity.length} فحوص سلامة ناجحة`)}
    ${card("pipeline", "خط المعالجة والربط", c.pipeline.error ? esc(c.pipeline.error) : `بناء رسم الحملات <span class="num">${c.pipeline.graph_build_ms} ms</span><br>${fmt(c.pipeline.campaigns)} حملة · ${fmt(c.pipeline.messages_linked)} رسالة مربوطة<br>آخر عملية: ${c.pipeline.last_operation ? `<span class="mono">${esc(c.pipeline.last_operation.op)}</span> ${dt(c.pipeline.last_operation.ts)}` : "لا شيء مسجّل"}`)}
    ${card("api", "الواجهة البرمجية", `الإصدار <span class="mono">${esc(c.api.version)}</span> · يعمل منذ <span class="num">${Math.round(c.api.uptime_seconds / 60)}</span> دقيقة<br>${fmt(c.api.requests_total)} طلب · أخطاء خادم ${c.api.server_errors} · مرفوضة ${c.api.client_errors}<br>زمن الاستجابة p50 <span class="num">${c.api.latency_ms_p50 ?? "—"} ms</span> · p95 <span class="num">${c.api.latency_ms_p95 ?? "—"} ms</span>`)}
  </div>
  <div class="grid g2">
    <div class="card"><div class="card-h"><h2>موارد العملية</h2><span class="sub">من نظام التشغيل لحظة القياس؛ «غير متاح» يعني أنه لم يُقَس</span></div>
      <dl class="kv"><dt>الذاكرة المستخدمة (RSS)</dt><dd class="num">${bytes(r.memory_rss_bytes)}</dd><dt>زمن المعالج للعملية</dt><dd class="num">${r.process_cpu_seconds} s</dd>
      <dt>متوسط الحمل (دقيقة)</dt><dd class="num">${esc(r.load_avg_1m)} <span class="note">/ ${r.cpu_count} أنوية</span></dd>
      <dt>القرص (مجلد القاعدة)</dt><dd>${typeof r.disk_total_bytes === "number" ? `<div class="meter" style="margin:6px 0"><i style="width:${pct(1 - r.disk_free_bytes / r.disk_total_bytes)};background:var(--accent)"></i></div><span class="num">${bytes(r.disk_free_bytes)}</span> متاح من <span class="num">${bytes(r.disk_total_bytes)}</span>` : "غير متاح"}</dd>
      <dt>المنصة</dt><dd class="mono">${esc(r.platform)} · Python ${esc(r.python)}</dd></dl></div>
    <div class="card"><div class="card-h"><h2>المسارات الأكثر طلبًا</h2><span class="sub">${esc(c.api.scope === "since process start (in-memory)" ? "منذ بدء العملية (في الذاكرة)" : c.api.scope)}</span></div>
      <div class="tbl-wrap"><table class="t"><thead><tr><th>المسار</th><th>طلبات</th><th>أخطاء</th><th>متوسط</th></tr></thead><tbody>${c.api.routes.map(x => `<tr><td class="mono">${esc(x.route)}</td><td class="num">${x.count}</td><td class="num">${x.errors}</td><td class="num">${x.avg_ms} ms</td></tr>`).join("") || '<tr><td class="empty">لا طلبات بعد</td></tr>'}</tbody></table></div></div>
  </div>
  <div class="grid g2">
    <div class="card"><div class="card-h"><h2>آخر العمليات</h2><span class="sub">جدول operations</span></div>
      <div class="tbl-wrap"><table class="t"><thead><tr><th>الوقت</th><th>العملية</th><th>الحالة</th><th>عناصر</th><th>المدة</th></tr></thead><tbody>${ops.map(o => `<tr><td class="mono">${dt(o.ts)}</td><td class="mono">${esc(o.op)}</td><td>${pill(o.status, T.status)}</td><td class="num">${o.items ?? ""}</td><td class="num">${o.duration_ms != null ? o.duration_ms + " ms" : ""}</td></tr>`).join("") || '<tr><td colspan="5" class="empty">لا عمليات مسجّلة</td></tr>'}</tbody></table></div></div>
    <div class="card"><div class="card-h"><h2>العمليات الفاشلة والمرفوضة</h2></div>
      <div class="tbl-wrap"><table class="t"><thead><tr><th>الوقت</th><th>العملية</th><th>الحالة</th><th>التفاصيل</th></tr></thead><tbody>${fails.map(o => `<tr><td class="mono">${dt(o.ts)}</td><td class="mono">${esc(o.op)}</td><td>${pill(o.status, T.status)}</td><td class="mono">${esc(o.detail)}</td></tr>`).join("") || '<tr><td colspan="4" class="empty">لا إخفاقات مسجّلة</td></tr>'}</tbody></table></div></div>
  </div>
  <div class="card"><div class="card-h"><h2>العمليات خلال 24 ساعة</h2></div>${(c.pipeline.operations_24h || []).length ? `<div class="tbl-wrap"><table class="t"><thead><tr><th>العملية</th><th>الحالة</th><th>العدد</th><th>عناصر</th><th>متوسط المدة</th></tr></thead><tbody>${c.pipeline.operations_24h.map(o => `<tr><td class="mono">${esc(o.op)}</td><td>${pill(o.status, T.status)}</td><td class="num">${o.count}</td><td class="num">${o.items ?? ""}</td><td class="num">${o.avg_ms} ms</td></tr>`).join("")}</tbody></table></div>` : '<div class="empty">لا عمليات في آخر 24 ساعة</div>'}</div>`;
  const b = $("#remeasure"); if (b) b.onclick = () => system();
}

/* ---------------- 7. analyze ---------------- */
function analyze() {
  if (STATIC) { main().innerHTML = `<div class="card"><div class="callout">فحص الرسائل يتطلب خادم رصد يعمل؛ هذه نسخة عرض ثابتة للقراءة. شغّل المشروع محليًا: <span class="mono">rasd serve</span>.</div></div>`; return; }
  main().innerHTML = `<div class="card"><div class="card-h"><h2>فحص رسالة</h2><span class="sub">لا تُخزَّن الرسالة ولا تُضاف إلى أي حملة</span></div>
    <textarea class="in" id="tx" dir="auto" placeholder="الصق نص الرسالة هنا" aria-label="نص الرسالة"></textarea>
    <div class="toolbar" style="margin-top:10px"><input class="in ltr" id="sn" placeholder="المرسل (اختياري)" aria-label="المرسل"><button class="btn pri" id="run">حلّل</button></div></div><div id="out"></div>`;
  $("#run").onclick = async () => {
    const text = $("#tx").value; if (!text.trim()) return;
    $("#out").innerHTML = '<div class="loading">جارٍ التحليل</div>';
    try {
      const r = await api("/v1/analyze", {method: "POST", body: JSON.stringify({text, sender: $("#sn").value || null})});
      const a = r.analysis, ex = r.explanation, lab = Object.fromEntries(ex.reasons.map(x => [x.id, x.text]));
      const mx = Math.max(1, ...ex.reasons.map(x => Math.abs(x.weight)));
      $("#out").innerHTML = `<div class="grid g2"><div class="card"><div class="card-h"><h2>النتيجة</h2>${pill(a.verdict)}<span class="num">${a.score.toFixed(2)}</span></div><div class="msg" dir="auto">${highlight(text, a.evidence.map(e => ({...e, label: lab[e.id]})), a.indicators)}</div><p>${esc(ex.summary)}</p>${ex.guard ? `<div class="callout">${esc(ex.guard)}</div>` : ""}
        <div>${a.indicators.map(i => `<span class="chip">${esc(T.type[i.type] || i.type)}: <span class="ltr">${esc(i.value)}</span></span>`).join("")}</div></div>
        <div class="card"><div class="card-h"><h2>الأدلة</h2></div>${ex.reasons.map(x => `<div class="reason"><div class="w ${x.weight > 0 ? "pos" : "neg"}">${x.weight > 0 ? "+" : ""}${x.weight.toFixed(2)}</div><div>${esc(x.text)}<div class="bar ${x.weight < 0 ? "neg" : ""}" style="width:${100 * Math.abs(x.weight) / mx}%"></div></div></div>`).join("") || '<div class="empty">لا أدلة</div>'}</div></div>`;
    } catch (e) { $("#out").innerHTML = `<div class="err">${esc(e.message)}</div>`; }
  };
}

/* ---------------- graph enrichment: the evidence behind a node ---------------- */
function markText(text, needles) {
  let parts = [esc(text)];
  for (const n of needles.filter(Boolean).map(esc)) parts = parts.map(p => p.split(n).join(`<mark class="ind">${n}</mark>`));
  return parts.join("");
}
async function graphEnrich(n, slot, focus) {
  try {
    if (n.kind === "message") {
      const m = await window.RASD.api("/v1/messages/" + encodeURIComponent(n.label));
      const a = m.analysis, top = m.explanation.reasons.filter(r => r.weight > 0).slice(0, 3);
      slot.innerHTML = `<div class="note">نص الرسالة (منقّح) — المؤشرات مظلّلة:</div><div class="src-snip" dir="auto">${highlight(m.text, [], a.indicators)}</div>
        <div class="note">أقوى الأدلة:</div>${top.map(r => `<div class="note">+${r.weight.toFixed(2)} ${esc(r.text)}</div>`).join("")}`;
    } else if (n.kind === "indicator") {
      const [type, ...rest] = n.key.split(":"); const value = rest.join(":");
      const d = await window.RASD.api("/v1/indicators/detail" + qs({type, value}));
      slot.innerHTML = `<div class="note">يظهر حرفيًا في ${d.messages.length} رسالة — هذا هو الدليل المباشر:</div>${d.messages.slice(0, 4).map(m => `<div class="src-snip" dir="auto"><button class="linkbtn mono" data-focus="msg:${esc(m.id)}">${esc(m.id)}</button> ${pill(m.verdict)}<br>${markText(m.text, [value, value.replace(/^\+966/, "0")])}</div>`).join("")}${d.messages.length > 4 ? `<a class="note" href="${link("intel", "", {type, value})}">و${d.messages.length - 4} رسائل أخرى ←</a>` : ""}`;
      $$("[data-focus]", slot).forEach(b => b.onclick = () => { if (!focus(b.dataset.focus)) go(link("messages", b.dataset.focus.slice(4))); });
    }
  } catch (e) { slot.innerHTML = `<div class="note">${esc(e.message)}</div>`; }
}

/* ---------------- risk score histogram (one axis, stacked by verdict, hover per bin) ---------------- */
function scoreHist(el, rows) {
  const bins = [...Array(10)].map((_, i) => ({i, m: 0, s: 0, b: 0}));
  rows.forEach(r => { const k = r.verdict === "malicious" ? "m" : r.verdict === "suspicious" ? "s" : "b"; bins[r.bin][k] += r.n; });
  const max = Math.max(1, ...bins.map(b => b.m + b.s + b.b));
  const W = 520, H = 170, L = 30, B = 22, ih = H - B - 8, bw = (W - L) / 10;
  let g = "";
  bins.forEach(b => {
    let y = 8 + ih; const x = L + b.i * bw + 2, w = bw - 4;
    for (const [k, c] of [["b", "var(--good)"], ["s", "var(--warn)"], ["m", "var(--crit)"]]) { if (!b[k]) continue; const h = b[k] / max * ih; y -= h; g += `<rect x="${x}" y="${y}" width="${w}" height="${Math.max(0, h - 2)}" rx="3" fill="${c}"/>`; }
    g += `<rect class="hit" data-i="${b.i}" x="${L + b.i * bw}" y="8" width="${bw}" height="${ih}" fill="transparent"/><text class="ax" x="${x + w / 2}" y="${H - 6}" text-anchor="middle">${(b.i / 10).toFixed(1)}</text>`;
  });
  el.innerHTML = `<div class="chart"><svg viewBox="0 0 ${W} ${H}" role="img" aria-label="توزيع درجات الخطر"><text class="ax" x="${L - 6}" y="14" text-anchor="end">${max}</text><line x1="${L}" x2="${W}" y1="${8 + ih}" y2="${8 + ih}" stroke="var(--line-2)"/>${g}</svg></div>
    <div class="legend"><span><i class="tdot" style="background:var(--crit)"></i>احتيالية</span><span><i class="tdot" style="background:var(--warn)"></i>مشبوهة</span><span><i class="tdot" style="background:var(--good)"></i>سليمة</span><span class="mute">المحور الأفقي: درجة الخطر</span></div>`;
  const wrap = $(".chart", el), tip = window.RASD.tipFor ? window.RASD.tipFor(wrap) : null;
  $$(".hit", el).forEach(h => {
    const b = bins[+h.dataset.i];
    h.addEventListener("mousemove", e => { const box = wrap.getBoundingClientRect(); if (tip) tip.show(`<div class="mono">${(b.i / 10).toFixed(1)}–${((b.i + 1) / 10).toFixed(1)}</div><div>احتيالية <b>${b.m}</b> · مشبوهة <b>${b.s}</b> · سليمة <b>${b.b}</b></div>`, e.clientX - box.left, e.clientY - box.top); });
    h.addEventListener("mouseleave", () => tip && tip.hide());
  });
}

/* ---------------- unified search ---------------- */
async function search(arg, p) {
  const q = (p.q || "").trim();
  $("#gsearch").q.value = q;
  if (q.length < 2) { main().innerHTML = '<div class="card empty">اكتب حرفين على الأقل في مربع البحث أعلاه.</div>'; return; }
  const r = await api("/v1/search" + qs({q}));
  const sec = (title, n, body) => `<div class="card"><div class="card-h"><h2>${title} <span class="num mute">${n}</span></h2></div>${n ? body : '<div class="note">لا نتائج</div>'}</div>`;
  main().innerHTML = `<div class="note">نتائج البحث عن «<b style="color:var(--ink)">${esc(q)}</b>»</div>
  <div class="grid g2">
    ${sec("الحملات", r.campaigns.length, `<table class="t"><tbody>${r.campaigns.map(c => `<tr data-go="${link("campaigns", c.id)}"><td class="mono">${esc(c.id)}</td><td>${pill(c.confidence, T.conf)}</td><td class="num">${c.size}</td><td>${c.brands.slice(0, 3).map(b => `<span class="chip">${esc(b)}</span>`).join("")}</td></tr>`).join("")}</tbody></table>`)}
    ${sec("المؤشرات", r.indicators.length, `<div class="tbl-wrap"><table class="t"><tbody>${r.indicators.map(i => `<tr data-go="${link("intel", "", {type: i.type, value: i.value})}"><td>${tchip(i.type)}</td><td class="ltr">${esc(i.value)}</td><td class="num">${i.messages}</td><td>${i.campaign_ids.map(c => `<span class="chip mono">${esc(c)}</span>`).join("")}</td></tr>`).join("")}</tbody></table></div>`)}
  </div>
  ${sec("الجهات المنتحلة", r.entities.length, r.entities.map(e => `<a class="chip" href="${link("intel", "", {tab: "entities"})}">${esc(e)}</a>`).join(""))}
  ${sec("الرسائل", r.total_messages, `<div class="tbl-wrap"><table class="t"><tbody>${r.messages.map(m => `<tr data-go="${link("messages", m.id)}"><td class="mono">${esc(m.id)}</td><td>${pill(m.verdict)}</td><td class="mono">${m.campaign_id ? esc(m.campaign_id) : "—"}</td><td class="txt">${esc(m.text)}</td></tr>`).join("")}</tbody></table></div>${r.total_messages > r.messages.length ? `<a class="note" href="${link("messages", "", {q})}">كل ${r.total_messages} رسالة ←</a>` : ""}`)}`;
  bindRows(main());
}

/* ---------------- login & router ---------------- */
function login(msg) {
  $("#page-title").textContent = "تسجيل الدخول"; $("#page-sub").textContent = "";
  main().innerHTML = `<div class="card" style="max-width:460px"><div class="card-h"><h2>مفتاح الواجهة البرمجية</h2></div>
    <form id="lf"><input class="in ltr" name="k" type="password" autocomplete="off" placeholder="X-API-Key" required style="width:100%"><div class="note" style="margin:8px 0 12px">يُحفظ في جلسة هذا المتصفح فقط (sessionStorage) ويُرسل في ترويسة X-API-Key. يُضبط على الخادم بالمتغير RASD_API_KEYS.</div>
    ${msg ? `<div class="err" style="margin-bottom:10px">${esc(msg)}</div>` : ""}<button class="btn pri">دخول</button></form></div>`;
  $("#lf").onsubmit = e => { e.preventDefault(); setKey(e.target.k.value.trim()); route(); };
}

const VIEWS = {overview, campaigns, messages, intel, database, system, analyze, search,
  demo: (arg, p) => window.RASD_DEMO(arg, p, {main, api})};
async function route() {
  closeDrawer();
  NAV++;
  const {page, arg, params} = parseHash();
  const p = PAGES.find(x => x[0] === page) || PAGES[0];
  $$("#nav a").forEach(a => { if (a.dataset.p === p[0]) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current"); });
  $("#page-title").textContent = p[1]; $("#page-sub").textContent = p[2];
  document.title = p[1] + " · رصد";
  $("#side").classList.remove("open");
  loading(); window.scrollTo(0, 0);
  try { await (VIEWS[p[0]])(arg, params); provenance(); }
  catch (e) { if (e instanceof Stale) return; if (e instanceof AuthError) login(KEYED() ? "المفتاح غير صالح" : ""); else main().innerHTML = `<div class="err">تعذّر التحميل: ${esc(e.message)}</div>`; }
}
const KEYED = () => { try { return !!sessionStorage.getItem("rasd_key"); } catch { return false; } };

function shell() {
  $("#nav").innerHTML = PAGES.filter(([k]) => k !== "search").map(([k, l], i) => `${i === 1 || i === 7 ? '<div class="sep"></div>' : ""}<a href="#${k}" data-p="${k}">${icon(k)}<span>${l}</span></a>`).join("");
  $("#mode").innerHTML = STATIC ? '<i></i>عرض ثابت · المحرك في المتصفح' : '<i></i>وضع حي · متصل بالخادم';
  $("#mode").className = "mode " + (STATIC ? "static" : "live");
  $("#mode").title = STATIC ? "لا خادم ولا قاعدة بيانات حية: لقطة من استجابات الواجهة البرمجية الحقيقية على بيانات اصطناعية، مع محرك رصد يعمل في متصفحك" : "كل البيانات من خادم رصد وقاعدة بياناته عبر الواجهة البرمجية";
  $("#site-link").hidden = !STATIC;
  $("#gsearch").onsubmit = e => { e.preventDefault(); const q = e.target.q.value.trim(); if (q.length >= 2) go(link("search", "", {q})); };
  $("#drawer-close").onclick = closeDrawer; $("#drawer-bg").onclick = closeDrawer;
  document.addEventListener("keydown", e => { if (e.key === "Escape") closeDrawer(); });
  $("#menu").onclick = () => $("#side").classList.toggle("open");
  $("#logout").hidden = STATIC;
  $("#logout").onclick = () => { setKey(""); route(); };
  addEventListener("hashchange", route);
  route();
}
shell();
})();
