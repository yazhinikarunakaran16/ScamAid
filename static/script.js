const btn = document.getElementById("checkBtn");
const input = document.getElementById("message");
const resultBox = document.getElementById("result");
const errorBox = document.getElementById("errorBox");
const themeBtn = document.getElementById("themeBtn");
const langBtn = document.getElementById("langBtn");
const listenBtn = document.getElementById("listenBtn");
const copyBtn = document.getElementById("copyBtn");

const COLORS = { safe: "#16a34a", suspicious: "#f59e0b", scam: "#dc2626" };
const LABELS = {
  en: { msg: "Your message (warning words highlighted)", why: "Why?", warn: "Warning signs",
        advice: "What should you do?", brk: "How the score was calculated",
        risk: "Risk score", riskEst: "Risk estimate", total: "Total", brkAI: "Rule-based warning signs (AI score may differ)", aiTotal: "AI risk score",
        btn: "தமிழில் பார்க்க", none: "No warning signs were added to the score.",
        noFlags: "No obvious warning signs found.", found: "Found",
        copy: "📋 Copy", copied: "✅ Copied",
        scoreNote: "This is an estimate, not a guarantee. 0-39 low risk, 40-59 suspicious, 60+ likely scam. The score is built from the warning signs listed below.",
        note: "Before sharing, remove names, phone numbers, OTPs and account numbers. The copied text does not include your original message.",
        verdict: { safe: "safe", suspicious: "suspicious", scam: "scam" },
        ai: "AI + rules", rules: "Rule-based check" },
  ta: { msg: "உங்கள் செய்தி (எச்சரிக்கை சொற்கள் குறிக்கப்பட்டுள்ளன)", why: "ஏன்?", warn: "எச்சரிக்கை அறிகுறிகள்",
        advice: "நீங்கள் என்ன செய்ய வேண்டும்?", brk: "மதிப்பெண் எப்படி வந்தது",
        risk: "ஆபத்து மதிப்பெண்", riskEst: "ஆபத்து மதிப்பீடு", total: "மொத்தம்", brkAI: "விதி அடிப்படையிலான எச்சரிக்கைகள் (AI மதிப்பெண் வேறுபடலாம்)", aiTotal: "AI ஆபத்து மதிப்பெண்",
        btn: "View in English", none: "மதிப்பெண்ணில் எந்த எச்சரிக்கையும் சேர்க்கப்படவில்லை.",
        noFlags: "வெளிப்படையான எச்சரிக்கை அறிகுறிகள் இல்லை.", found: "கண்டறிந்தது",
        copy: "📋 நகலெடு", copied: "✅ நகலெடுக்கப்பட்டது",
        scoreNote: "இது ஒரு மதிப்பீடு மட்டுமே, உத்தரவாதம் அல்ல. 0-39 குறைந்த ஆபத்து, 40-59 சந்தேகம், 60+ மோசடிக்கு வாய்ப்பு அதிகம். கீழே உள்ள எச்சரிக்கை அறிகுறிகளிலிருந்து மதிப்பெண் கணக்கிடப்படுகிறது.",
        note: "பகிரும் முன் பெயர்கள், தொலைபேசி எண்கள், OTP, கணக்கு எண்களை நீக்கவும். நகலெடுத்த உரையில் உங்கள் அசல் செய்தி இல்லை.",
        verdict: { safe: "பாதுகாப்பு", suspicious: "சந்தேகம்", scam: "மோசடி" },
        ai: "AI + விதிகள்", rules: "விதி அடிப்படையிலான சோதனை" }
};

let lang = "en";
let lastData = null;
let lastText = "";

// ---------- Theme ----------
function applyTheme(t) {
  document.documentElement.setAttribute("data-theme", t);
  if (themeBtn) themeBtn.textContent = t === "dark" ? "☀️" : "🌙";
}
let savedTheme = null;
try { savedTheme = localStorage.getItem("theme"); } catch (e) {}
applyTheme(savedTheme || (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light"));
themeBtn.addEventListener("click", () => {
  const next = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark";
  applyTheme(next);
  try { localStorage.setItem("theme", next); } catch (e) {}
});

// ---------- Examples ----------
document.querySelectorAll(".ex-btn").forEach(b => {
  b.addEventListener("click", () => { input.value = b.dataset.text; input.focus(); });
});

// ---------- Error state ----------
function showError() {
  errorBox.textContent = "Analysis temporarily unavailable. Please try again in a minute. / பகுப்பாய்வு தற்காலிகமாக கிடைக்கவில்லை. ஒரு நிமிடம் கழித்து மீண்டும் முயற்சிக்கவும்.";
  errorBox.classList.remove("hidden");
  resultBox.classList.add("hidden");
}

// ---------- Check ----------
btn.addEventListener("click", async () => {
  const text = input.value.trim();
  if (!text) { alert("Please paste a message first."); return; }

  errorBox.classList.add("hidden");
  btn.disabled = true;
  btn.textContent = "Checking...";
  const slowTimer = setTimeout(() => {
    btn.textContent = "Still working... server may be waking up";
  }, 6000);
  const ctrl = new AbortController();
  const abortTimer = setTimeout(() => ctrl.abort(), 60000);

  try {
    const res = await fetch("/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text }),
      signal: ctrl.signal
    });
    if (!res.ok) throw new Error("Bad status " + res.status);
    const data = await res.json();
    if (!data || !data.verdict) throw new Error("Bad data");
    lastData = data;
    lastText = text;
    render();
    resultBox.classList.remove("hidden");
    resultBox.scrollIntoView({ behavior: "smooth" });
  } catch (err) {
    showError();
  }

  clearTimeout(slowTimer);
  clearTimeout(abortTimer);
  btn.disabled = false;
  btn.textContent = "Check Message";
});

langBtn.addEventListener("click", () => {
  lang = lang === "en" ? "ta" : "en";
  if (lastData) render();
});

// ---------- Render ----------
function esc(s) {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function highlight(text, words) {
  let html = esc(text);
  const list = [...new Set(words)].filter(Boolean).sort((a, b) => b.length - a.length);
  list.forEach(w => {
    const safe = esc(w).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    html = html.replace(new RegExp(safe, "gi"), m => "<mark>" + m + "</mark>");
  });
  return html;
}

function render() {
  const d = lastData;
  const L = LABELS[lang];
  const ta = lang === "ta";
  const verdict = (d.verdict || "suspicious").toLowerCase();
  const score = Number(d.risk_score) || 0;
  const isAI = d.mode === "ai";

  const badge = document.getElementById("verdict");
  badge.textContent = L.verdict[verdict] || verdict;
  badge.className = "badge " + verdict;
  document.getElementById("scoreText").textContent = (isAI ? L.risk : L.riskEst) + ": " + score + "/100";
  document.getElementById("modeText").textContent = isAI ? L.ai : L.rules;
  langBtn.textContent = L.btn;
  copyBtn.textContent = L.copy;

  const fill = document.getElementById("meterFill");
  fill.style.background = COLORS[verdict] || COLORS.suspicious;
  fill.style.width = "0";
  setTimeout(() => { fill.style.width = score + "%"; }, 50);

  document.getElementById("scoreNote").textContent = L.scoreNote;
  document.getElementById("hBreak").textContent = isAI ? L.brkAI : L.brk;
  document.getElementById("hWhy").textContent = L.why;
  document.getElementById("hWarn").textContent = L.warn;
  document.getElementById("hAdvice").textContent = L.advice;
  document.getElementById("hMessage").textContent = L.msg;
  document.getElementById("privacyNote").textContent = L.note;

  // Score breakdown
  const ul = document.getElementById("breakdown");
  ul.innerHTML = "";
  const items = d.breakdown || [];
  if (items.length) {
    items.forEach(b => {
      const li = document.createElement("li");
      const name = document.createElement("span");
      name.textContent = ta ? b.label_ta : b.label;
      const pts = document.createElement("b");
      pts.textContent = (b.points > 0 ? "+" : "") + b.points;
      li.appendChild(name);
      li.appendChild(pts);
      ul.appendChild(li);
    });
    const tot = document.createElement("li");
    tot.className = "total";
    const tn = document.createElement("span");
    tn.textContent = isAI ? L.aiTotal : L.total;
    const tp = document.createElement("b");
    tp.textContent = (isAI ? "" : "= ") + score + " / 100";
    tot.appendChild(tn);
    tot.appendChild(tp);
    ul.appendChild(tot);
  } else {
    const li = document.createElement("li");
    li.textContent = L.none;
    ul.appendChild(li);
  }

  document.getElementById("reason").textContent = (ta ? d.reason_ta : d.reason) || "";
  document.getElementById("advice").textContent = (ta ? d.advice_ta : d.advice) || "";

  // Warning signs with explanation + found words
  const box = document.getElementById("findings");
  box.innerHTML = "";
  const found = [];
  if (d.findings && d.findings.length) {
    d.findings.forEach(f => {
      (f.found || []).forEach(w => found.push(w));
      const div = document.createElement("div");
      div.className = "finding";
      const t = document.createElement("b");
      t.textContent = ta ? f.title_ta : f.title;
      const p = document.createElement("p");
      p.textContent = ta ? f.explain_ta : f.explain;
      div.appendChild(t);
      div.appendChild(p);
      if (f.found && f.found.length) {
        const c = document.createElement("p");
        c.className = "found";
        c.textContent = L.found + ": " + f.found.join(", ");
        div.appendChild(c);
      }
      box.appendChild(div);
    });
  } else {
    const p = document.createElement("span");
    p.className = "no-flags";
    p.textContent = L.noFlags;
    box.appendChild(p);
  }

  document.getElementById("highlighted").innerHTML = highlight(lastText, found);
}

// ---------- Voice: read result aloud ----------
function hasVoice(prefix) {
  return window.speechSynthesis.getVoices().some(v => v.lang.toLowerCase().startsWith(prefix));
}

listenBtn.addEventListener("click", () => {
  if (!("speechSynthesis" in window)) { alert("Your browser does not support voice."); return; }
  const synth = window.speechSynthesis;
  if (synth.speaking) { synth.cancel(); return; }
  if (!lastData) { alert("Please check a message first."); return; }

  const ta = lang === "ta";
  const L = LABELS[lang];
  const verdict = (lastData.verdict || "suspicious").toLowerCase();
  const reason = (ta ? lastData.reason_ta : lastData.reason) || "";
  const advice = (ta ? lastData.advice_ta : lastData.advice) || "";
  const text = L.verdict[verdict] + ". " + L.risk + " " + (Number(lastData.risk_score) || 0) + ". " + reason + " " + advice;

  const u = new SpeechSynthesisUtterance(text);
  u.lang = ta ? "ta-IN" : "en-IN";
  u.rate = 0.9;
  if (ta && !hasVoice("ta")) {
    alert("This device has no Tamil voice installed, so it may not speak Tamil.");
  }
  synth.speak(u);
});
if ("speechSynthesis" in window) { window.speechSynthesis.getVoices(); }

// ---------- Copy result (no original message, no personal details) ----------
copyBtn.addEventListener("click", async () => {
  if (!lastData) return;
  const ta = lang === "ta";
  const L = LABELS[lang];
  const verdict = (lastData.verdict || "suspicious").toLowerCase();
  const reason = (ta ? lastData.reason_ta : lastData.reason) || "";
  const advice = (ta ? lastData.advice_ta : lastData.advice) || "";
  const label = lastData.mode === "ai" ? L.risk : L.riskEst;
  const text = "ScamAid: " + L.verdict[verdict] + " (" + label + ": " + (Number(lastData.risk_score) || 0) + "/100)\n\n" +
    reason + "\n\n" + advice + "\n\nhttps://scamaid.onrender.com";
  try {
    await navigator.clipboard.writeText(text);
    copyBtn.textContent = L.copied;
  } catch (e) {
    alert("Could not copy. Please select the text and copy it manually.");
  }
  setTimeout(() => { copyBtn.textContent = L.copy; }, 2000);
});