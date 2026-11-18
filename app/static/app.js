const $ = (id) => document.getElementById(id);
const SEV_BG = { High: "bg-red-600", Medium: "bg-orange-600", Low: "bg-yellow-600", Info: "bg-blue-600" };
const GRADE_COLOR = { A: "text-emerald-400", B: "text-lime-400", C: "text-yellow-400", D: "text-orange-400", F: "text-red-500" };

const I18N = {
  tr: {
    banner: "<b>Yalnızca etik kullanım.</b> Sadece sahibi olduğunuz veya yazılı izin aldığınız sistemleri tarayın. İzinsiz tarama yasa dışı olabilir.",
    tabScan: "Tarama", tabHistory: "Geçmiş", tabInv: "Envanter & Kurallar", tabSched: "Zamanlanmış & Yönetim",
    risksTitle: "⚠️ Taramanın riskleri (taramadan önce okuyun)",
    presetsTitle: "⚡ Hazır Tarama Modları (Otomatik Ayarlı)",
    autoTuneBtn: "🤖 Hedefi Analiz Et & Otomatik Ayarla",
    methodsTitle: "💻 Hazır Python / CLI / API Metodları (tek satırda çalıştır)",
    modulesTitle: "Taranacak Modüller (İstediğiniz modülleri seçin)",
    modAll: "Tümünü Seç", modPassive: "Sadece Pasif", modActive: "Sadece Aktif", modNone: "Temizle",
    grpPassive: "Pasif", grpActive: "Aktif", modSelected: "modül seçili",
    noModErr: "Lütfen en az bir tarama modülü seçin.",
    targetsLabel: "Hedef URL veya alan adları (her satıra bir tane)",
    profile: "Hız profili", pGentle: "Nazik (yavaş, güvenli)", pNormal: "Normal", pFast: "Hızlı",
    repeat: "Tekrarla", rNone: "Tekrarlama",
    scope: "İzin kapsamı (alan adları)", winStart: "İzinli pencere başlangıcı", winEnd: "İzinli pencere bitişi",
    cve: "CVE + EPSS + KEV + OSV + RDAP sorgusu", notify: "Bitince bildirim gönder",
    consent: "Bu hedefin sahibi olduğumu veya test etmek için açık yetkim olduğunu onaylıyorum.",
    scanBtn: "Taramayı başlat", liveLog: "Canlı log", batch: "Toplu rapor",
    schedHint: "Zamanlanmış taramalar sunucu çalışırken yürür. Bildirimler için TELEGRAM_*, WEBHOOK_URL veya SMTP_* ayarlayın.",
    auditTitle: "Denetim günlüğü (kim, ne zaman, neyi taradı)",
    risk: "Risk", fix: "Nasıl düzeltilir", evidence: "Kanıt", refs: "Kaynaklar", mitigation: "Önlem",
    owasp: "OWASP Top 10 dağılımı", changes: "Önceki taramadan değişiklikler",
    nNew: "Yeni", nFixed: "Düzeltilen", nSame: "Değişmeyen",
    triOpen: "Açık", triFp: "Yanlış pozitif", triAcc: "Risk kabul edildi", triFixed: "Düzeltildi (doğrulandı)",
    triNote: "Not", triSave: "Kaydet", verifyFix: "✓ Düzelttim, doğrula", verifying: "Doğrulanıyor...",
    conf: "Güven", cfgTitle: "🔧 Bulgulara göre hazır sunucu yapılandırması (nginx / Apache / IIS)",
    trendTitle: "📈 Güvenlik puanı trendi",
    invTitle: "Teknoloji, açık port ve sertifika süresi envanteri",
    rulesTitle: "Özel YAML kuralları (GET tabanlı)",
    rulesHint: "Her kural <hedef><path> adresine GET isteği atar ve durum kodu / regex eşleşirse bulgu üretir.",
    authDocTitle: "İmzalı yetki belgeleri (HMAC-SHA256)", aoBtn: "Belge oluştur ve imzala",
    adminTitle: "Kullanıcılar, API anahtarları ve yedekleme", backupBtn: "Veritabanını yedekle",
    usersLabel: "Kullanıcılar (RBAC)", keysLabel: "API anahtarları (X-API-Key)",
    view: "Aç", del: "Sil", noItems: "Kayıt yok", every: "her", hours: "saat", next: "sonraki",
    running: "Çalışıyor", queued: "Sırada", completed: "Tamamlandı", failed: "Başarısız",
    lost: "Sunucu bağlantısı koptu: ", certDays: "Sertifika kalan gün",
  },
  en: {
    banner: "<b>Ethical use only.</b> Scan only systems you own or have explicit written permission to test. Unauthorised scanning may be illegal.",
    tabScan: "Scan", tabHistory: "History", tabInv: "Inventory & Rules", tabSched: "Schedules & Admin",
    risksTitle: "⚠️ Risks of running a scan (read before scanning)",
    presetsTitle: "⚡ Ready-to-Use Scan Modes (Auto-Configured)",
    autoTuneBtn: "🤖 Probe Target & Auto-Tune",
    methodsTitle: "💻 Ready-to-Use Python / CLI / API Methods (one-liners)",
    modulesTitle: "Scan Modules (Choose which modules to run)",
    modAll: "Select All", modPassive: "Passive Only", modActive: "Active Only", modNone: "Clear",
    grpPassive: "Passive", grpActive: "Active", modSelected: "modules selected",
    noModErr: "Please select at least one scan module.",
    targetsLabel: "Target URLs or domains (one per line)",
    profile: "Speed profile", pGentle: "Gentle (slow, safest)", pNormal: "Normal", pFast: "Fast",
    repeat: "Repeat", rNone: "Do not repeat",
    scope: "Authorised scope (domains)", winStart: "Permitted window start", winEnd: "Permitted window end",
    cve: "CVE + EPSS + KEV + OSV + RDAP lookup", notify: "Send notification when done",
    consent: "I confirm I own this target or have explicit authorisation to test it.",
    scanBtn: "Start scan", liveLog: "Live log", batch: "Batch report",
    schedHint: "Scheduled scans run while the server is running. For notifications set TELEGRAM_*, WEBHOOK_URL or SMTP_*.",
    auditTitle: "Audit log (who scanned what, when)",
    risk: "Risk", fix: "How to fix", evidence: "Evidence", refs: "References", mitigation: "Mitigation",
    owasp: "OWASP Top 10 breakdown", changes: "Changes since previous scan",
    nNew: "New", nFixed: "Fixed", nSame: "Unchanged",
    triOpen: "Open", triFp: "False positive", triAcc: "Risk accepted", triFixed: "Fixed (verified)",
    triNote: "Note", triSave: "Save", verifyFix: "✓ Verify fix", verifying: "Verifying...",
    conf: "Confidence", cfgTitle: "🔧 Generated server hardening config (nginx / Apache / IIS)",
    trendTitle: "📈 Security score trend",
    invTitle: "Technology, open ports & certificate expiry inventory",
    rulesTitle: "Custom YAML rules (GET-only)",
    rulesHint: "Each rule requests <base><path> and raises a finding when status/regex matches.",
    authDocTitle: "Signed authorisation documents (HMAC-SHA256)", aoBtn: "Create & sign document",
    adminTitle: "Users, API keys & database backup", backupBtn: "Backup database now",
    usersLabel: "Users (RBAC)", keysLabel: "API keys (X-API-Key)",
    view: "Open", del: "Delete", noItems: "No entries", every: "every", hours: "h", next: "next",
    running: "Running", queued: "Queued", completed: "Completed", failed: "Failed",
    lost: "Lost connection to server: ", certDays: "Cert days left",
  },
};
let lang = localStorage.getItem("lang") || "en";
let trackers = [];
const t = (k) => I18N[lang][k] || k;
const pick = (o, k) => (lang === "tr" && o[k + "_tr"]) ? o[k + "_tr"] : (o[k] || "");
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

fetch("/api/config").then((r) => r.json()).then((c) => { trackers = c.trackers || []; }).catch(() => {});

function applyLang() {
  document.documentElement.lang = lang;
  document.querySelectorAll("[data-i18n]").forEach((el) => { el.innerHTML = t(el.dataset.i18n); });
  $("langBtn").textContent = lang === "tr" ? "EN" : "TR";
  loadRisks();
  renderPresets();
  renderModules();
  if (current) renderCurrent();
}
$("langBtn").onclick = () => { lang = lang === "tr" ? "en" : "tr"; localStorage.setItem("lang", lang); applyLang(); };

function applyTheme() {
  document.documentElement.classList.toggle("light", localStorage.getItem("theme") === "light");
}
$("themeBtn").onclick = () => {
  localStorage.setItem("theme", localStorage.getItem("theme") === "light" ? "dark" : "light");
  applyTheme();
};

const TABS = [["tabScan", "viewScan"], ["tabHistory", "viewHistory"], ["tabInv", "viewInv"], ["tabSched", "viewSched"]];
function showTab(name) {
  for (const [tab, view] of TABS) {
    $(view).classList.toggle("hidden", tab !== name);
    $(tab).classList.toggle("bg-sky-600", tab === name);
    $(tab).classList.toggle("bg-slate-800", tab !== name);
  }
  if (name === "tabHistory") loadHistory();
  if (name === "tabInv") loadInventoryAndRules();
  if (name === "tabSched") loadSchedules();
}
TABS.forEach(([tab]) => ($(tab).onclick = () => showTab(tab)));

function loadRisks() {
  fetch("/api/risks").then((r) => r.json()).then((list) => {
    const lvl = { High: "text-red-400", Medium: "text-orange-400", Low: "text-yellow-400", Info: "text-blue-400" };
    $("risks").innerHTML = list.map((r) => `
      <div class="border-l-2 border-slate-700 pl-3">
        <b class="${lvl[r.level] || ""}">[${esc(r.level)}]</b> <b>${esc(pick(r, "title"))}</b>
        <p class="text-slate-400">${esc(pick(r, "description"))}</p>
        <p><span class="text-emerald-400">${t("mitigation")}:</span> ${esc(pick(r, "mitigation"))}</p>
      </div>`).join("");
  });
}

const tracked = {};
let current = null, currentId = null, timer = null, lastCfgId = null;
let presets = {}, selectedPreset = "auto";
let modulesCatalog = [], selectedModules = new Set();

Promise.all([
  fetch("/api/presets").then((r) => r.json()).catch(() => ({})),
  fetch("/api/modules").then((r) => r.json()).catch(() => ([])),
]).then(([p, m]) => {
  presets = p || {};
  modulesCatalog = m || [];
  const initMods = (presets[selectedPreset] && presets[selectedPreset].modules) || modulesCatalog.map((x) => x.id);
  selectedModules = new Set(initMods);
  renderPresets();
  renderModules();
});

function selectPreset(id) {
  selectedPreset = id;
  const p = presets[id];
  if (p) {
    $("profile").value = p.profile || "normal";
    $("cve").checked = !!p.cve_lookup;
    $("notify").checked = !!p.notify;
    $("repeat").value = String(p.repeat_hours || 0);
    selectedModules = new Set(p.modules || []);
  }
  renderPresets();
  renderModules();
}

function renderModules() {
  const grid = $("moduleGrid");
  if (!grid || !modulesCatalog.length) return;
  $("modCount").textContent = `(${selectedModules.size} / ${modulesCatalog.length} ${t("modSelected")})`;
  grid.innerHTML = modulesCatalog.map((m) => {
    const on = selectedModules.has(m.id);
    const isPassive = m.group === "passive";
    const badgeCls = isPassive ? "bg-emerald-900/70 text-emerald-300" : "bg-amber-900/70 text-amber-300";
    return `
      <label class="cursor-pointer flex items-start gap-2 p-2 rounded border transition ${on ? "border-sky-500/80 bg-sky-950/30" : "border-slate-800 bg-slate-900/60 opacity-65 hover:opacity-100"}">
        <input type="checkbox" data-mod="${esc(m.id)}" ${on ? "checked" : ""} class="mt-0.5">
        <div class="flex-1 min-w-0">
          <div class="flex items-center justify-between gap-1">
            <span class="font-semibold text-slate-100 truncate">${esc(pick(m, "name"))}</span>
            <span class="text-[10px] px-1.5 py-0.2 rounded ${badgeCls}">${esc(isPassive ? t("grpPassive") : t("grpActive"))}</span>
          </div>
          <div class="text-[11px] text-slate-400 leading-snug mt-0.5">${esc(pick(m, "desc"))}</div>
        </div>
      </label>`;
  }).join("");
  grid.querySelectorAll("input[data-mod]").forEach((cb) => {
    cb.onchange = () => {
      if (cb.checked) selectedModules.add(cb.dataset.mod);
      else selectedModules.delete(cb.dataset.mod);
      if (cb.dataset.mod === "cve") $("cve").checked = cb.checked;
      selectedPreset = "custom";
      renderPresets();
      renderModules();
    };
  });
}

$("modAll").onclick = () => { selectedModules = new Set(modulesCatalog.map((m) => m.id)); $("cve").checked = true; selectedPreset = "custom"; renderPresets(); renderModules(); };
$("modPassive").onclick = () => { selectedModules = new Set(modulesCatalog.filter((m) => m.group === "passive").map((m) => m.id)); $("cve").checked = selectedModules.has("cve"); selectedPreset = "custom"; renderPresets(); renderModules(); };
$("modActive").onclick = () => { selectedModules = new Set(modulesCatalog.filter((m) => m.group === "active").map((m) => m.id)); $("cve").checked = false; selectedPreset = "custom"; renderPresets(); renderModules(); };
$("modNone").onclick = () => { selectedModules.clear(); $("cve").checked = false; selectedPreset = "custom"; renderPresets(); renderModules(); };
$("cve").addEventListener("change", () => {
  if ($("cve").checked) selectedModules.add("cve");
  else selectedModules.delete("cve");
  renderModules();
});

function renderPresets() {
  const box = $("presetCards");
  if (!box) return;
  box.innerHTML = Object.entries(presets).map(([id, p]) => `
    <button type="button" data-preset="${esc(id)}"
      class="text-left p-2.5 rounded-lg border transition ${id === selectedPreset ? "border-sky-500 bg-sky-950/50" : "border-slate-800 bg-slate-800/60 hover:border-slate-700"}">
      <div class="font-semibold text-slate-100">${esc(pick(p, "name"))}</div>
      <div class="text-slate-400 mt-0.5 leading-snug">${esc(pick(p, "description"))}</div>
      <div class="text-[11px] text-sky-400 mt-1">${esc(p.profile)} · ${p.modules.length} ${lang === "tr" ? "modül" : "modules"}${p.cve_lookup ? " · CVE" : ""}${p.repeat_hours ? " · " + p.repeat_hours + "h" : ""}</div>
    </button>`).join("");
  box.querySelectorAll("button[data-preset]").forEach((b) => (b.onclick = () => selectPreset(b.dataset.preset)));
  const sample = ($("targets")?.value.split(/\r?\n/)[0] || "example.com").trim() || "example.com";
  const modArr = [...selectedModules];
  const modListPy = JSON.stringify(modArr);
  const modListCli = modArr.join(" ");
  if ($("methodSnippets")) {
    $("methodSnippets").textContent =
`# Python (auto-configured helper methods + custom module selection)
from app import auto_scan, quick_scan, production_safe_scan, full_audit, api_security_scan, tls_dns_scan, run_preset

result = auto_scan("${sample}")                                   # 🤖 Smart auto-tuned scan
result = run_preset("${sample}", modules=${modListPy})  # 🧩 Run with ${modArr.length} selected module(s)

# CLI (command line with selected modules)
python -m app.cli ${sample} --consent --modules ${modListCli || "headers tls"} --format html --lang ${lang} --out report.html

# REST API (with selected modules)
POST /api/scan   {"target": "${sample}", "consent": true, "preset": "${selectedPreset}", "modules": ${modListPy}}`;
  }
}

$("targets").addEventListener("input", renderPresets);

$("autoTuneBtn").onclick = async () => {
  const first = ($("targets").value.split(/\r?\n/).map((s) => s.trim()).filter(Boolean))[0];
  if (!first) { $("autoTuneInfo").textContent = lang === "tr" ? "Önce hedef URL/alan adı girin." : "Enter a target URL or domain first."; return; }
  $("autoTuneInfo").textContent = lang === "tr" ? "Hedef analiz ediliyor..." : "Probing target...";
  try {
    const r = await fetch("/api/autotune", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target: first, consent: true }),
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.detail || "Auto-tune failed");
    selectedPreset = "auto";
    $("profile").value = d.profile;
    $("cve").checked = !!d.cve_lookup;
    selectedModules = new Set(d.modules || []);
    renderPresets();
    renderModules();
    $("autoTuneInfo").textContent = `✓ Auto-tuned (${d.profile}, ${d.modules.length} modules${d.cve_lookup ? ", CVE enabled" : ""}): ${(d.notes || []).join(" · ")}`;
  } catch (e) {
    $("autoTuneInfo").textContent = e.message;
  }
};

$("start").onclick = async () => {
  $("error").textContent = "";
  if (selectedModules.size === 0) {
    $("error").textContent = t("noModErr");
    return;
  }
  const targets = $("targets").value.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
  const scope = $("scope").value.split(/[,\s]+/).filter(Boolean);
  $("start").disabled = true;
  try {
    const r = await fetch("/api/scan", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        targets, consent: $("consent").checked, preset: selectedPreset,
        modules: [...selectedModules], profile: $("profile").value,
        scope_domains: scope, window_start: $("winStart").value || null, window_end: $("winEnd").value || null,
        cve_lookup: $("cve").checked, notify: $("notify").checked, repeat_hours: parseInt($("repeat").value, 10),
      }),
    });
    const data = await r.json();
    if (!r.ok) throw new Error(data.detail || "Request failed");
    data.ids.forEach((id, i) => { tracked[id] = { target: targets[i] || id, status: "queued", progress: 0 }; });
    $("progressBox").classList.remove("hidden");
    select(data.ids[0]);
    startPolling();
  } catch (e) {
    $("error").textContent = e.message;
  } finally {
    $("start").disabled = false;
  }
};

function select(id) { currentId = id; current = null; lastCfgId = null; $("log").textContent = ""; $("results").classList.add("hidden"); poll(id); renderList(); }

function renderList() {
  $("scanList").innerHTML = Object.entries(tracked).map(([id, s]) => `
    <button data-id="${esc(id)}" class="px-3 py-1 rounded text-xs ${id === currentId ? "bg-sky-600" : "bg-slate-800"}">
      ${esc(s.target)} · ${esc(t(s.status))} ${s.progress}%</button>`).join("");
  $("scanList").querySelectorAll("button").forEach((b) => (b.onclick = () => select(b.dataset.id)));
  const done = Object.keys(tracked).filter((i) => tracked[i].status === "completed");
  const b = $("expBatch");
  b.classList.toggle("hidden", done.length < 2);
  b.href = `/api/batch/export?ids=${done.join(",")}&format=html&lang=${lang}`;
}

function startPolling() {
  clearInterval(timer);
  timer = setInterval(async () => {
    const active = Object.keys(tracked).filter((i) => !["completed", "failed"].includes(tracked[i].status));
    for (const id of active) await poll(id);
    if (!active.length) clearInterval(timer);
  }, 1500);
}

async function poll(id) {
  try {
    const d = await (await fetch(`/api/scan/${id}`)).json();
    if (tracked[id]) Object.assign(tracked[id], { status: d.status, progress: d.progress });
    if (id === currentId) { current = d; renderCurrent(); }
    renderList();
  } catch (e) {
    $("error").textContent = t("lost") + e.message;
  }
}

function updateExportLinks() {
  if (!current) return;
  const pw = encodeURIComponent($("encPw").value || "");
  for (const [id, f] of [["expJson", "json"], ["expHtml", "html"], ["expPdf", "pdf"], ["expSarif", "sarif"]])
    $(id).href = `/api/scan/${current.id}/export?format=${f}&lang=${lang}${pw ? "&password=" + pw : ""}`;
}
$("encPw").oninput = updateExportLinks;

async function loadConfigsAndTrends(d) {
  if (lastCfgId === d.id && d.status === "completed") return;
  if (d.status === "completed") lastCfgId = d.id;
  try {
    const cfg = await (await fetch(`/api/scan/${d.id}/configs`)).json();
    $("cfgNginx").textContent = cfg.nginx || "";
    $("cfgApache").textContent = cfg.apache || "";
    $("cfgIis").textContent = cfg.iis || "";
    const pts = await (await fetch(`/api/trends?target=${encodeURIComponent(d.target)}`)).json();
    if (pts.length >= 2) {
      $("trendBox").classList.remove("hidden");
      const w = 500, h = 70;
      const coords = pts.map((p, i) => `${Math.round(10 + (i / (pts.length - 1)) * (w - 20))},${Math.round(h - 10 - ((p.score || 0) / 100) * (h - 20))}`).join(" ");
      $("trendSvg").innerHTML = `<svg viewBox="0 0 ${w} ${h}" class="w-full h-16"><polyline fill="none" stroke="#38bdf8" stroke-width="2" points="${coords}"/>` +
        pts.map((p, i) => `<circle cx="${Math.round(10 + (i / (pts.length - 1)) * (w - 20))}" cy="${Math.round(h - 10 - ((p.score || 0) / 100) * (h - 20))}" r="3" fill="#38bdf8"><title>${p.score}/100 (${p.grade})</title></circle>`).join("") + `</svg>`;
    } else {
      $("trendBox").classList.add("hidden");
    }
  } catch (_) {}
}

function renderCurrent() {
  const d = current;
  if (!d) return;
  $("statusText").textContent = t(d.status);
  $("pct").textContent = d.progress + "%";
  $("bar").style.width = d.progress + "%";
  const log = $("log");
  const atBottom = log.scrollTop + log.clientHeight >= log.scrollHeight - 20;
  log.textContent = d.logs.join("\n");
  if (atBottom) log.scrollTop = log.scrollHeight;
  if (d.status === "failed" && d.error) $("error").textContent = d.error;

  $("results").classList.remove("hidden");
  $("grade").textContent = d.grade || "?";
  $("grade").className = "text-5xl font-extrabold " + (GRADE_COLOR[d.grade] || "");
  $("score").textContent = `${d.score ?? "?"}/100`;
  $("summary").innerHTML = ["High", "Medium", "Low", "Info"].map((s) =>
    `<span class="keep ${SEV_BG[s]} px-3 py-1 rounded-full text-sm font-semibold">${s}: ${d.summary[s]}</span>`).join("");
  $("tech").textContent = d.tech.length ? d.tech.join(", ") : "";
  updateExportLinks();
  loadConfigsAndTrends(d);

  const ow = Object.entries(d.owasp || {});
  $("owasp").innerHTML = ow.length ? `<b>${t("owasp")}:</b> ` + ow.map(([k, v]) =>
    `<span class="inline-block bg-slate-800 rounded px-2 py-0.5 mr-1 mb-1 text-xs">${esc(k)}: ${v}</span>`).join("") : "";

  const df = d.diff;
  $("diff").innerHTML = df ? `<b>${t("changes")}:</b>
    <span class="text-red-400">${t("nNew")} ${df.new.length}</span> ·
    <span class="text-emerald-400">${t("nFixed")} ${df.fixed.length}</span> ·
    <span class="text-slate-400">${t("nSame")} ${df.persisting.length}</span>
    ${df.new.length ? `<div class="text-xs text-red-300 mt-1">+ ${df.new.map((x) => esc(x.title)).join("<br>+ ")}</div>` : ""}
    ${df.fixed.length ? `<div class="text-xs text-emerald-300 mt-1">✓ ${df.fixed.map((x) => esc(x.title)).join("<br>✓ ")}</div>` : ""}` : "";

  const open = new Set([...document.querySelectorAll("#findings details[open]")].map((x) => x.dataset.k));
  const typing = document.activeElement && document.activeElement.closest("#findings");
  if (typing && d.status !== "completed") return;
  const order = { High: 0, Medium: 1, Low: 2, Info: 3 };
  const sorted = d.findings.map((f, i) => ({ f, i })).sort((a, b) => order[a.f.severity] - order[b.f.severity]);
  const trackerBtns = trackers.map((tr) => `<button data-tr="${esc(tr)}" class="issue-btn bg-slate-700 hover:bg-slate-600 rounded px-2 py-1">+ ${esc(tr)}</button>`).join("");
  $("findings").innerHTML = sorted.map(({ f, i }) => {
    const tri = f.triage || { status: "open", note: "" };
    const fix = pick(f, "fix_details"), impact = pick(f, "impact");
    const muted = tri.status === "false_positive" || tri.status === "fixed";
    const statusLabel = tri.status === "false_positive" ? "triFp" : tri.status === "accepted" ? "triAcc" : "triFixed";
    return `
    <details data-k="${i}" class="bg-slate-900 border border-slate-800 rounded-lg p-4 ${muted ? "opacity-50" : ""}"
             ${(open.has(String(i)) || (f.severity === "High" && !open.size && tri.status === "open")) ? "open" : ""}>
      <summary class="cursor-pointer flex items-center gap-2 flex-wrap">
        <span class="keep ${SEV_BG[f.severity]} text-xs px-2 py-0.5 rounded">${f.severity}</span>
        <b>${esc(f.title)}</b>
        <span class="text-xs text-slate-500">${esc(f.category)}${f.cwe ? " · " + esc(f.cwe) : ""}${f.owasp ? " · " + esc(f.owasp) : ""} · ${t("conf")}: ${esc(f.confidence || "Medium")}</span>
        ${tri.status !== "open" ? `<span class="text-xs text-amber-400">[${esc(t(statusLabel))}]</span>` : ""}
      </summary>
      <p class="text-sm text-slate-400 mt-2">${esc(f.description)}</p>
      ${impact ? `<p class="text-sm mt-2"><span class="text-red-400 font-semibold">${t("risk")}:</span> ${esc(impact)}</p>` : ""}
      ${fix ? `<p class="text-sm mt-2 text-emerald-400 font-semibold">${t("fix")}</p>
        <pre class="text-xs bg-black text-slate-200 p-3 rounded mt-1 overflow-auto whitespace-pre-wrap">${esc(fix)}</pre>` : ""}
      ${f.evidence ? `<p class="text-xs text-slate-500 mt-2">${t("evidence")}</p>
        <pre class="text-xs bg-black text-slate-300 p-2 rounded overflow-auto whitespace-pre-wrap">${esc(f.evidence)}</pre>` : ""}
      ${f.references && f.references.length ? `<p class="text-xs mt-2 text-slate-500">${t("refs")}: ${
        f.references.filter((r) => /^https:\/\//.test(r)).map((r) =>
          `<a class="text-sky-400 underline" target="_blank" rel="noopener noreferrer" href="${esc(r)}">${esc(r)}</a>`).join(" · ")}</p>` : ""}
      <div class="flex flex-wrap gap-2 items-center mt-3 text-xs" data-title="${esc(f.title)}" data-evidence="${esc(f.evidence)}" data-cat="${esc(f.category)}">
        <select class="tri-status bg-slate-800 rounded px-2 py-1">
          <option value="open" ${tri.status === "open" ? "selected" : ""}>${t("triOpen")}</option>
          <option value="false_positive" ${tri.status === "false_positive" ? "selected" : ""}>${t("triFp")}</option>
          <option value="accepted" ${tri.status === "accepted" ? "selected" : ""}>${t("triAcc")}</option>
          <option value="fixed" ${tri.status === "fixed" ? "selected" : ""}>${t("triFixed")}</option>
        </select>
        <input class="tri-note bg-slate-800 rounded px-2 py-1 flex-1 min-w-[10rem]" placeholder="${t("triNote")}" value="${esc(tri.note)}">
        <button class="tri-save bg-slate-700 hover:bg-slate-600 rounded px-3 py-1">${t("triSave")}</button>
        <button class="recheck-btn bg-emerald-700 hover:bg-emerald-600 rounded px-3 py-1">${t("verifyFix")}</button>
        ${trackerBtns}
      </div>
    </details>`;
  }).join("");

  document.querySelectorAll(".tri-save").forEach((btn) => (btn.onclick = async () => {
    const box = btn.parentElement;
    await fetch("/api/triage", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        target: d.target, title: box.dataset.title, evidence: box.dataset.evidence,
        status: box.querySelector(".tri-status").value, note: box.querySelector(".tri-note").value,
      }),
    });
    lastCfgId = null; poll(d.id);
  }));

  document.querySelectorAll(".recheck-btn").forEach((btn) => (btn.onclick = async () => {
    const box = btn.parentElement;
    btn.textContent = t("verifying"); btn.disabled = true;
    try {
      await fetch("/api/recheck", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ scan_id: d.id, category: box.dataset.cat, title: box.dataset.title, evidence: box.dataset.evidence }),
      });
    } finally {
      lastCfgId = null; poll(d.id);
    }
  }));

  document.querySelectorAll(".issue-btn").forEach((btn) => (btn.onclick = async () => {
    const box = btn.parentElement;
    const r = await fetch("/api/issues", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scan_id: d.id, tracker: btn.dataset.tr, title: box.dataset.title, evidence: box.dataset.evidence }),
    });
    const out = await r.json();
    if (out.url) window.open(out.url, "_blank");
  }));
}

async function loadHistory() {
  const list = await (await fetch("/api/history")).json();
  $("historyList").innerHTML = list.length ? list.map((s) => `
    <div class="bg-slate-900 border border-slate-800 rounded p-3 flex items-center justify-between gap-3 flex-wrap">
      <div><b>${esc(s.target)}</b>
        <div class="text-xs text-slate-500">${new Date(s.started_at * 1000).toLocaleString()} · ${esc(t(s.status))}</div></div>
      <div class="flex items-center gap-3">
        <span class="text-2xl font-bold ${GRADE_COLOR[s.grade] || ""}">${esc(s.grade || "?")}</span>
        <span class="text-xs">H ${s.summary.High ?? 0} · M ${s.summary.Medium ?? 0} · L ${s.summary.Low ?? 0}</span>
        <button data-id="${esc(s.id)}" class="open bg-slate-700 hover:bg-slate-600 rounded px-3 py-1">${t("view")}</button>
      </div></div>`).join("") : `<p class="text-slate-500">${t("noItems")}</p>`;
  $("historyList").querySelectorAll(".open").forEach((b) => (b.onclick = () => {
    tracked[b.dataset.id] = tracked[b.dataset.id] || { target: b.dataset.id, status: "completed", progress: 100 };
    showTab("tabScan"); $("progressBox").classList.remove("hidden"); select(b.dataset.id);
  }));
}

async function loadInventoryAndRules() {
  const inv = await (await fetch("/api/inventory")).json();
  $("invList").innerHTML = inv.length ? inv.map((row) => `
    <div class="bg-slate-900 border border-slate-800 rounded p-3 flex items-center justify-between gap-3 flex-wrap">
      <div>
        <b>${esc(row.target)}</b>
        <div class="text-xs text-slate-400">Tech: ${esc((row.tech || []).join(", ") || "-")} · Ports: ${esc((row.ports || []).join(", ") || "-")}
          ${row.cert_days_left != null ? ` · ${t("certDays")}: <b>${row.cert_days_left}</b>` : ""}</div>
      </div>
      <span class="text-2xl font-bold ${GRADE_COLOR[row.grade] || ""}">${esc(row.grade)} (${row.score})</span>
    </div>`).join("") : `<p class="text-slate-500">${t("noItems")}</p>`;

  const rules = await (await fetch("/api/rules")).json();
  $("rulesYaml").value = rules.yaml || "";
}

$("saveRules").onclick = async () => {
  const r = await fetch("/api/rules", {
    method: "PUT", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ yaml_text: $("rulesYaml").value }),
  });
  const d = await r.json();
  $("rulesMsg").textContent = r.ok ? `OK (${d.count} rules)` : (d.detail || "Error");
};

async function loadSchedules() {
  const list = await (await fetch("/api/schedules")).json();
  $("schedList").innerHTML = list.length ? list.map((s) => `
    <div class="bg-slate-900 border border-slate-800 rounded p-3 flex items-center justify-between gap-3">
      <div><b>${esc(s.target)}</b>
        <div class="text-xs text-slate-500">${t("every")} ${s.interval_hours} ${t("hours")} · ${esc(s.profile)} · ${t("next")}: ${new Date(s.next_run * 1000).toLocaleString()}</div></div>
      <button data-id="${s.id}" class="del bg-red-700 hover:bg-red-600 rounded px-3 py-1">${t("del")}</button>
    </div>`).join("") : `<p class="text-slate-500">${t("noItems")}</p>`;
  $("schedList").querySelectorAll(".del").forEach((b) => (b.onclick = async () => {
    await fetch(`/api/schedules/${b.dataset.id}`, { method: "DELETE" }); loadSchedules();
  }));

  const docs = await (await fetch("/api/authorisations")).json().catch(() => []);
  $("aoList").innerHTML = docs.map((d) =>
    `<div class="bg-black/40 p-2 rounded"><b>${esc(d.id)}</b> · ${esc(d.owner_name)} · [${esc((d.scope_domains || []).join(", "))}] · <span class="text-emerald-400">${d.valid ? "HMAC OK" : "INVALID"}</span> <code class="text-slate-500">${esc((d.signature || "").slice(0, 28))}...</code></div>`).join("");

  const users = await (await fetch("/api/users")).json().catch(() => []);
  $("uList").innerHTML = users.map((u) =>
    `<div class="flex justify-between bg-black/40 px-2 py-1 rounded"><span>${esc(u.username)} (${esc(u.role)})</span><button data-u="${esc(u.username)}" class="u-del text-red-400">×</button></div>`).join("");
  $("uList").querySelectorAll(".u-del").forEach((b) => (b.onclick = async () => {
    await fetch(`/api/users/${encodeURIComponent(b.dataset.u)}`, { method: "DELETE" }); loadSchedules();
  }));

  const keys = await (await fetch("/api/keys")).json().catch(() => []);
  $("kList").innerHTML = keys.map((k) =>
    `<div class="flex justify-between bg-black/40 px-2 py-1 rounded"><span>#${k.id} ${esc(k.name)} (${esc(k.role)})</span><button data-k="${k.id}" class="k-del text-red-400">×</button></div>`).join("");
  $("kList").querySelectorAll(".k-del").forEach((b) => (b.onclick = async () => {
    await fetch(`/api/keys/${b.dataset.k}`, { method: "DELETE" }); loadSchedules();
  }));

  const audit = await (await fetch("/api/audit")).json().catch(() => []);
  $("auditList").innerHTML = audit.slice(0, 50).map((a) =>
    `<div>${new Date(a.ts * 1000).toLocaleString()} · ${esc(a.client)} · <b>${esc(a.action)}</b> · ${esc(a.target)} <span class="text-slate-600">${esc(a.detail)}</span></div>`).join("");
}

$("aoCreate").onclick = async () => {
  await fetch("/api/authorisations", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      owner_name: $("aoOwner").value, contact: $("aoContact").value,
      scope_domains: $("aoScope").value.split(/[,\s]+/).filter(Boolean),
    }),
  });
  loadSchedules();
};
$("uAdd").onclick = async () => {
  await fetch("/api/users", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username: $("uName").value, password: $("uPass").value, role: $("uRole").value }),
  });
  $("uName").value = ""; $("uPass").value = ""; loadSchedules();
};
$("kAdd").onclick = async () => {
  const r = await fetch("/api/keys", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name: $("kName").value, role: $("kRole").value }),
  });
  const d = await r.json();
  if (d.key) { $("kNew").classList.remove("hidden"); $("kNew").textContent = `X-API-Key: ${d.key}`; }
  $("kName").value = ""; loadSchedules();
};
$("backupBtn").onclick = async () => {
  const r = await fetch("/api/maintenance/backup", { method: "POST" });
  const d = await r.json();
  alert(d.path ? `Backup: ${d.path}` : "Backup skipped");
};

applyTheme();
applyLang();
