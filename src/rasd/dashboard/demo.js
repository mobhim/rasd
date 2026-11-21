"use strict";
/* Guided demonstration: one connected journey from a raw Arabic message to its evidence,
   its campaign, the evidence graph and the database records.
   Live mode: the RASD server analyses the text (/v1/analyze).
   Static mode: the unmodified RASD engine runs in the browser (engine.js / Pyodide). */
(() => {
const {$, $$, esc, fmt, pct, T, varName, pill, tchip, srcChip, link, highlight, STATIC} = window.RASD;

const ROLE = {campaign: ["رسالة من حملة مكتشفة", "تشترك في موارد مع رسائل أخرى"], uncertain: ["حالة غير محسومة", "مشبوهة لكن دون دليل ربط"], hard_negative: ["رسالة سليمة تشبه الاحتيال", "اختبار للإنذار الكاذب"]};
const STEPS = [["normalize", "التطبيع"], ["indicators", "المؤشرات"], ["score", "الدرجة"], ["evidence", "الأدلة"], ["correlate", "الربط بالحملات"], ["records", "السجلات"]];
const whyNot = i => i.type === "url" ? "لا — يُربط عبر نطاقه المسجّل" : i.type === "domain" ? "لا — نطاق رسمي أو مختصِر أو منصة عامة" : "لا";
const sig = x => x >= 0 ? 1 / (1 + Math.exp(-x)) : Math.exp(x) / (1 + Math.exp(x));

async function demo(arg, p, ctx) {
  const {main, api} = ctx;
  const samples = (await api("/v1/demo/samples")).samples;
  main().innerHTML = `
  <section class="demo-hero">
    <div><p class="eyebrow">عرض موجَّه · ${STATIC ? "يعمل في متصفحك" : "متصل بخادم رصد"}</p>
    <h2>تتبّع رسالة واحدة حتى حملتها</h2>
    <p>اختر رسالة أو اكتب رسالتك، ثم تابع ما يفعله رصد خطوة بخطوة: كيف يقرأ النص، ما المؤشرات التي يستخرجها، لماذا يحكم، وبأي دليل يربطها بحملة قائمة.</p></div>
    <div class="engine-box" id="engine-box">${STATIC ? '<div class="loading">جارٍ تجهيز المحرك</div>' : `<b>المحرك:</b> خادم رصد عبر <span class="mono">POST /v1/analyze</span><div class="note">لا تُخزَّن الرسالة ولا تُضاف إلى أي حملة.</div>`}</div>
  </section>
  <div class="card"><div class="card-h"><h2><span class="step-n">1</span> اختر رسالة</h2><span class="sub">رسائل من قاعدة البيانات المعروضة (${esc(T.source[samples[0]?.source] || "")}) — أو اكتب نصًا من عندك</span></div>
    <div class="samples">${samples.map((s, i) => `<button class="sample" data-i="${i}" aria-pressed="false"><span class="toolbar"><b>${esc(ROLE[s.role]?.[0] || s.role)}</b><span class="grow"></span>${srcChip(s.source)}<span class="chip">${esc(varName(s.variety))}</span></span><span class="sample-txt" dir="auto">${esc(s.text)}</span><span class="note">${esc(ROLE[s.role]?.[1] || "")}</span></button>`).join("")}</div>
    <div class="grid" style="grid-template-columns:minmax(0,1fr) auto;margin-top:14px;align-items:end">
      <textarea class="in" id="dtx" dir="auto" placeholder="أو الصق رسالة هنا…" aria-label="نص الرسالة"></textarea>
      <div style="display:flex;flex-direction:column;gap:8px"><input class="in ltr" id="dsn" placeholder="المرسل (اختياري)" aria-label="المرسل"><button class="btn pri" id="drun" style="justify-content:center;padding:10px 22px">حلّل الرسالة</button></div>
    </div>
    ${STATIC ? '<p class="note" style="margin:10px 0 0">النص الذي تكتبه يُحلَّل محليًا في متصفحك ولا يُرسل إلى أي خادم. الروابط لا تُفتح ولا يُتصل بأي رقم.</p>' : ""}
  </div>
  <div id="dout"></div>`;

  if (STATIC) {
    const box = $("#engine-box");
    window.RASD_ENGINE.onChange(E => {
      if (!box.isConnected) return;
      box.innerHTML = E.status === "ready" ? `<b>المحرك جاهز ${pill("ok", {ok: "يعمل"})}</b><div class="note">محرك رصد نفسه (Python، ${E.files} ملفًا بلا أي تعديل) يعمل داخل متصفحك عبر Pyodide · جُهّز في ${(E.ms / 1000).toFixed(1)} ث</div>`
        : E.status === "failed" ? `<b>تعذّر تحميل المحرك ${pill("degraded", {degraded: "محدود"})}</b><div class="note">${esc(E.error)}. ستُعرض نتائج الرسائل النموذجية كما حسبها المحرك عند إنشاء اللقطة؛ تحليل نص جديد يتطلب المحرك.</div>`
        : `<div class="loading" style="padding:4px;text-align:start">جارٍ تحميل محرك رصد في المتصفح (≈10MB لأول مرة)</div><div class="note">Python + المحرك كما هو، دون خادم.</div>`;
    });
    window.RASD_ENGINE.load().catch(() => {});
  }
  let chosen = null;
  $$(".sample").forEach(b => b.onclick = () => {
    $$(".sample").forEach(x => x.setAttribute("aria-pressed", "false")); b.setAttribute("aria-pressed", "true");
    chosen = samples[+b.dataset.i]; $("#dtx").value = chosen.text; $("#dsn").value = chosen.sender || ""; run();
  });
  $("#dtx").addEventListener("input", () => { chosen = null; $$(".sample").forEach(x => x.setAttribute("aria-pressed", "false")); });
  $("#drun").onclick = () => run();
  async function run() {
    const text = $("#dtx").value.trim(); if (!text) { $("#dtx").focus(); return; }
    const out = $("#dout"); out.innerHTML = '<div class="card loading">يحلّل المحرك الرسالة</div>';
    try {
      const r = await api("/v1/analyze", {method: "POST", body: JSON.stringify({text, sender: $("#dsn").value || null})});
      render(out, text, r, chosen);
      out.querySelector(".stepper").scrollIntoView({behavior: "smooth", block: "start"});
    } catch (e) { if (e.name !== "Stale" && e.constructor.name !== "Stale") out.innerHTML = `<div class="err">${esc(e.message)}</div>`; }
  }
  if (p.sample && samples[+p.sample]) $$(".sample")[+p.sample].click();
}

function render(out, text, r, sample) {
  const a = r.analysis, ex = r.explanation, tr = r.trace, co = r.correlation;
  const label = Object.fromEntries(ex.reasons.map(x => [x.id, x.text]));
  const ev = a.evidence.map(e => ({...e, label: label[e.id]}));
  const [tS, tM] = ex.model.thresholds || [0.4, 0.8];
  const band = s => s >= tM ? "malicious" : s >= tS ? "suspicious" : "benign";
  const rc = v => v === "malicious" ? "var(--crit)" : v === "suspicious" ? "var(--warn)" : "var(--good)";
  const C = 2 * Math.PI * 44;
  const eng = r.engine ? (r.engine.runtime === "pyodide" ? `حُلّلت في متصفحك بمحرك رصد (Pyodide) خلال ${r.engine.ms} ms` : "نتيجة محسوبة مسبقًا بمحرك رصد عند إنشاء اللقطة (المحرك في المتصفح غير متاح)") : "حُلّلت على خادم رصد";
  const tactics = ev.filter(e => e.id.startsWith("tactic.") || e.id.startsWith("obfuscation."));
  const joins = co.would_join_campaigns;
  const shared = co.indicators.filter(i => i.linkable && !i.suppressed_reason && i.seen_in_messages);
  out.innerHTML = `
  <nav class="stepper" aria-label="مراحل التحليل">${STEPS.map(([k, l], i) => `<a href="#d-${k}" data-step="${k}"><span>${i + 2}</span>${l}</a>`).join("")}<span class="grow"></span><span class="note">${esc(eng)}</span></nav>

  <section class="card dsec" id="d-normalize"><div class="card-h"><h2><span class="step-n">2</span> كيف قرأ رصد النص؟</h2><span class="sub">كل مرحلة هي النص الفعلي الناتج عن دوال المحرك. التحليل يتم على النص الموحَّد، والتظليل يعود إلى النص الأصلي.</span></div>
    <ol class="stages">${tr.stages.map(s => `<li><div class="toolbar"><b>${esc(s.title)}</b><span class="grow"></span>${s.changes.map(c => `<span class="chip ${c.kind === "card" || c.kind === "code" || c.kind === "national_id" ? "src-real" : ""}">${esc(c.label)} · ${c.count}${c.examples?.length ? ` <span class="ltr">${esc(c.examples.join(" "))}</span>` : ""}</span>`).join("") || '<span class="note">دون تغيير</span>'}</div><div class="stage-txt" dir="auto">${esc(s.text)}</div></li>`).join("")}</ol>
    <div class="toolbar note">اللهجة: <b style="color:var(--ink)">${esc(varName(a.variety.label))}</b> ${Object.entries(a.variety.markers || {}).map(([k, ws]) => ws.slice(0, 5).map(w => `<span class="chip" title="${esc(varName(k))}">${esc(w)}</span>`).join("")).join("")}</div></section>

  <section class="card dsec" id="d-indicators"><div class="card-h"><h2><span class="step-n">3</span> المؤشرات الرقمية المستخرجة</h2><span class="sub">صيغ مختلفة للقيمة نفسها تُوحَّد في مفتاح واحد (أرقام هندية، ‎+966‎، ‎00966‎، روابط wa.me، روابط مموّهة) — لهذا يمكن الربط.</span></div>
    ${a.indicators.length ? `<div class="tbl-wrap"><table class="t"><thead><tr><th>النوع</th><th>كما ورد في الرسالة</th><th></th><th>المفتاح الموحَّد</th><th>الدور</th><th>صالح للربط؟</th></tr></thead><tbody>${a.indicators.map(i => `<tr><td>${tchip(i.type)}</td><td class="ltr faint">${esc(i.raw)}</td><td class="mute">←</td><td class="ltr">${esc(i.value)}</td><td>${i.role === "sender" ? "المرسل" : "المتن"}</td><td>${i.linkable ? pill("ok", {ok: "نعم"}) : pill("unavailable", {unavailable: whyNot(i)})}</td></tr>`).join("")}</tbody></table></div>` : '<div class="empty">لم تُستخرج مؤشرات: لا روابط ولا أرقام ولا حسابات. لهذا لا يمكن ربط هذه الرسالة بأي حملة.</div>'}</section>

  <section class="card dsec" id="d-score"><div class="card-h"><h2><span class="step-n">4</span> درجة الخطر وأين الدليل في النص</h2></div>
    <div class="grid g-main"><div><div class="msg" dir="auto">${highlight(text, ev, a.indicators)}</div>
      <div class="legend"><span><mark>&nbsp;أحمر&nbsp;</mark> يرفع الخطر</span><span><mark class="neg">&nbsp;أخضر&nbsp;</mark> يخفضه</span><span><mark class="ind">&nbsp;أزرق&nbsp;</mark> مؤشر مستخرج</span></div>
      <h3 class="note" style="margin:14px 0 6px">أنماط لغوية مريبة رُصدت</h3><div>${tactics.map(e => `<span class="chip">${esc(e.label || e.id)}</span>`).join("") || '<span class="note">لا شيء</span>'}</div></div>
      <div><div class="risk"><div class="gauge"><svg viewBox="0 0 100 100"><circle cx="50" cy="50" r="44" fill="none" stroke="var(--surface-3)" stroke-width="9"/><circle cx="50" cy="50" r="44" fill="none" stroke="${rc(a.verdict)}" stroke-width="9" stroke-linecap="round" stroke-dasharray="${C * a.score} ${C}"/></svg><b>${a.score.toFixed(2)}</b></div>
        <div>${pill(a.verdict)}<div class="note" style="margin-top:6px">العتبات: مشبوهة ≥ ${tS} · احتيالية ≥ ${tM}</div></div></div>
        <p>${esc(ex.summary)}</p>${ex.guard ? `<div class="callout">${esc(ex.guard)}</div>` : ""}</div></div></section>

  <section class="card dsec" id="d-evidence"><div class="card-h"><h2><span class="step-n">5</span> الأدلة — وجرّب بنفسك</h2><span class="sub">الدرجة = مجموع أوزان هذه الأدلة. ألغِ أي دليل لترى كيف تتغير الدرجة: هذا هو النموذج نفسه، لا تقريب له.</span></div>
    <div class="grid g-main"><div id="ev-list">${ex.reasons.map((x, i) => `<label class="reason toggle"><div class="w ${x.weight > 0 ? "pos" : "neg"}">${x.weight > 0 ? "+" : ""}${x.weight.toFixed(2)}</div><div><input type="checkbox" checked data-w="${x.weight}" data-i="${i}"> ${esc(x.text)}<span class="cat">${esc(T.cat[x.id.split(".")[0]] || "")}</span></div></label>`).join("") || '<div class="empty">لا أدلة ذات وزن</div>'}</div>
      <div><div class="card whatif" style="box-shadow:none"><div class="note">الدرجة بعد التعديل</div><div class="toolbar"><b class="num" id="wi-score" style="font-size:30px">${a.score.toFixed(2)}</b><span id="wi-band">${pill(a.verdict)}</span></div>
        <div class="meter" style="margin:8px 0"><i id="wi-bar" style="width:${pct(a.score)};background:${rc(a.verdict)}"></i></div>
        <div class="note mono" id="wi-formula">sigmoid(${a.bias} + ${(a.logit - a.bias).toFixed(2)}) = ${a.score.toFixed(3)}</div>
        <div class="note" style="margin-top:8px">حواجز القرار (لا إدانة بالأسلوب وحده) تُطبَّق في المحرك ولا تظهر في هذا الحساب التجريبي.</div>
        <button class="btn" id="wi-reset" style="margin-top:8px">إعادة كل الأدلة</button></div>
      ${ex.counterfactual ? `<div class="callout info" style="margin-top:12px"><b>الواقع المضاد:</b> أصغر مجموعة أدلة يكفي سقوطها لتغيّر الحكم: ${ex.counterfactual.remove_to_change_verdict.map(i => `<span class="chip">${esc(label[i] || i)}</span>`).join("")} <button class="btn" id="wi-cf" style="margin-top:6px">طبّقه</button></div>` : ""}</div></div></section>

  <section class="card dsec" id="d-correlate"><div class="card-h"><h2><span class="step-n">6</span> هل تنتمي إلى حملة؟</h2><span class="sub">${esc("القاعدة: يُربط فقط عبر مورد يتحكم به المهاجم (نطاق، رقم تواصل، آيبان، محفظة، حساب). تشابه النص وحده لا يربط أبدًا.")}</span></div>
    ${joins.length ? `<div class="verdict-callout"><b>تنضم إلى ${joins.length === 1 ? "الحملة" : "الحملات"} ${joins.map(c => `<span class="mono">${esc(c)}</span>`).join("، ")}</b><div>لأنها تشترك مع رسائل مخزّنة في: ${shared.map(i => `${tchip(i.type)} <span class="ltr">${esc(i.value)}</span> <span class="note">(${i.seen_in_messages} رسائل)</span>`).join(" · ")}</div>
      <div class="toolbar" style="margin-top:12px">${joins.map(c => { const k = shared.find(i => i.campaign_ids.includes(c)); return `<a class="btn pri" href="${link("campaigns", c, k ? {focus: "ind:" + k.key} : {})}">افتح الحملة ${esc(c)} في رسم الأدلة ←</a>`; }).join("")}</div></div>`
      : `<div class="verdict-callout none"><b>لا تنضم إلى أي حملة</b><div>${a.indicators.some(i => i.role === "body") ? "لا يظهر أي من مؤشراتها القابلة للربط في الرسائل المخزّنة." : "لا تحتوي مؤشرات يمكن الربط بها."} ${a.verdict !== "benign" ? "حتى لو كان نصها يشبه رسائل حملة ما، لا يربطها رصد دون مورد مشترك." : ""}</div></div>`}
    ${co.indicators.length ? `<div class="tbl-wrap" style="margin-top:12px"><table class="t"><thead><tr><th>المؤشر</th><th>شوهد في رسائل مخزّنة</th><th>الحملات</th><th>يُستخدم للربط</th></tr></thead><tbody>${co.indicators.map(i => `<tr><td>${tchip(i.type)} <span class="ltr">${esc(i.value)}</span></td><td class="num">${i.seen_in_messages}</td><td>${i.campaign_ids.map(c => `<a class="chip mono" href="${link("campaigns", c, {focus: "ind:" + i.key})}">${esc(c)}</a>`).join("") || "—"}</td><td>${i.suppressed_reason ? pill("warn", {warn: "مستبعد"}) + ` <span class="note">${esc(i.suppressed_reason)}</span>` : i.linkable ? pill("ok", {ok: "نعم"}) : pill("unavailable", {unavailable: whyNot(i)})}</td></tr>`).join("")}</tbody></table></div>` : ""}</section>

  <section class="card dsec" id="d-records"><div class="card-h"><h2><span class="step-n">7</span> افحص السجلات في قاعدة البيانات</h2><span class="sub">كل ما سبق مخزّن في جداول فعلية يمكنك فحصها.</span></div>
    <div class="records-grid">
      ${sample ? `<a class="rec-link" href="${link("messages", sample.id)}"><b>مساحة تحقيق الرسالة</b><span class="mono">${esc(sample.id)}</span><span class="note">هذه الرسالة مخزّنة: افتح تحقيقها الكامل</span></a>
      <a class="rec-link" href="${link("database", "", {tab: "records", table: "messages", q: sample.id})}"><b>جدول messages</b><span class="mono">id = ${esc(sample.id)}</span><span class="note">السجل الخام: النص المنقّح، المصدر، الطوابع الزمنية</span></a>` : ""}
      ${shared.slice(0, 3).map(i => `<a class="rec-link" href="${link("database", "", {tab: "records", table: "indicators", f_type: i.type, f_value: i.value})}"><b>جدول indicators</b><span class="ltr">${esc(i.value)}</span><span class="note">${i.seen_in_messages} صفوف لهذه القيمة — كل صف يشير إلى رسالة</span></a>`).join("")}
      <a class="rec-link" href="${link("database", "", {tab: "schema"})}"><b>المخطط والعلاقات</b><span class="mono">messages ← indicators</span><span class="note">كيف ترتبط الجداول، وأين تُحسب الحملات</span></a>
    </div>
    ${!sample ? '<p class="note">رسالتك لم تُخزَّن؛ الروابط أعلاه تفتح السجلات المخزّنة التي تشترك معها في المؤشرات.</p>' : ""}</section>`;

  // what-if: recompute the additive score live
  const boxes = $$("#ev-list input", out);
  const recompute = () => {
    const logit = a.bias + boxes.filter(b => b.checked).reduce((s, b) => s + +b.dataset.w, 0);
    const s = sig(logit), v = band(s);
    $("#wi-score", out).textContent = s.toFixed(2); $("#wi-band", out).innerHTML = pill(v);
    $("#wi-bar", out).style.width = pct(s); $("#wi-bar", out).style.background = rc(v);
    $("#wi-formula", out).textContent = `sigmoid(${a.bias} + ${(logit - a.bias).toFixed(2)}) = ${s.toFixed(3)}`;
  };
  boxes.forEach(b => b.onchange = recompute);
  $("#wi-reset", out).onclick = () => { boxes.forEach(b => { b.checked = true; }); recompute(); };
  const cf = $("#wi-cf", out);
  if (cf) cf.onclick = () => { const ids = new Set(ex.counterfactual.remove_to_change_verdict); boxes.forEach(b => { b.checked = !ids.has(ex.reasons[+b.dataset.i].id); }); recompute(); };
  // stepper follows the scroll position
  const links = $$(".stepper a", out);
  const obs = new IntersectionObserver(es => es.forEach(e => { if (e.isIntersecting) links.forEach(l => l.classList.toggle("on", l.dataset.step === e.target.id.slice(2))); }), {rootMargin: "-40% 0px -55% 0px"});
  $$(".dsec", out).forEach(s => obs.observe(s));
  links.forEach(l => l.onclick = e => { e.preventDefault(); $(l.getAttribute("href"), out).scrollIntoView({behavior: "smooth", block: "start"}); });
}

window.RASD_DEMO = demo;
})();
