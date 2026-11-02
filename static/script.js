const btn = document.getElementById("checkBtn");
const input = document.getElementById("message");
const resultBox = document.getElementById("result");
const themeBtn = document.getElementById("themeBtn");
const langBtn = document.getElementById("langBtn");

const COLORS = { safe: "#16a34a", suspicious: "#f59e0b", scam: "#dc2626" };
const LABELS = {
  en: { msg: "Your message", why: "Why?", warn: "Warning signs", advice: "What should you do?",
        risk: "Risk score", btn: "தமிழில் பார்க்க", none: "No obvious warning signs found.",
        verdict: { safe: "safe", suspicious: "suspicious", scam: "scam" }, ai: "AI + rules", rules: "Rules" },
  ta: { msg: "உங்கள் செய்தி", why: "ஏன்?", warn: "எச்சரிக்கை அறிகுறிகள்", advice: "நீங்கள் என்ன செய்ய வேண்டும்?",
        risk: "ஆபத்து மதிப்பெண்", btn: "View in English", none: "வெளிப்படையான எச்சரிக்கை அறிகுறிகள் இல்லை.",
        verdict: { safe: "பாதுகாப்பு", suspicious: "சந்தேகம்", scam: "மோசடி" }, ai: "AI + விதிகள்", rules: "விதிகள்" }
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

// ---------- Check ----------
btn.addEventListener("click", async () => {
  const text = input.value.trim();
  if (!text) { alert("Please paste a message first."); return; }
  btn.disabled = true;
  btn.textContent = "Checking...";
  try {
    const res = await fetch("/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text })
    });
    lastData = await res.json();
    lastText = text;
    render();
    resultBox.classList.remove("hidden");
    resultBox.scrollIntoView({ behavior: "smooth" });
  } catch (err) {
    alert("Something went wrong. Is the server running?");
  }
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

  const badge = document.getElementById("verdict");
  badge.textContent = L.verdict[verdict] || verdict;
  badge.className = "badge " + verdict;
  document.getElementById("scoreText").textContent = L.risk + ": " + score + "/100";
  document.getElementById("modeText").textContent = d.mode === "ai" ? L.ai : L.rules;
  langBtn.textContent = L.btn;

  const fill = document.getElementById("meterFill");
  fill.style.background = COLORS[verdict] || COLORS.suspicious;
  fill.style.width = "0";
  setTimeout(() => { fill.style.width = score + "%"; }, 50);

  document.getElementById("hMessage").textContent = L.msg;
  document.getElementById("hWhy").textContent = L.why;
  document.getElementById("hWarn").textContent = L.warn;
  document.getElementById("hAdvice").textContent = L.advice;

  const found = [];
  (d.findings || []).forEach(f => (f.found || []).forEach(w => found.push(w)));
  document.getElementById("highlighted").innerHTML = highlight(lastText, found);

  document.getElementById("reason").textContent = (ta ? d.reason_ta : d.reason) || "";
  document.getElementById("advice").textContent = (ta ? d.advice_ta : d.advice) || "";

  const box = document.getElementById("findings");
  box.innerHTML = "";
  if (d.findings && d.findings.length) {
    d.findings.forEach(f => {
      const div = document.createElement("div");
      div.className = "finding";
      const t = document.createElement("b");
      t.textContent = ta ? f.title_ta : f.title;
      const p = document.createElement("p");
      p.textContent = ta ? f.explain_ta : f.explain;
      div.appendChild(t);
      div.appendChild(p);
      box.appendChild(div);
    });
  } else {
    const p = document.createElement("span");
    p.className = "no-flags";
    p.textContent = L.none;
    box.appendChild(p);
  }
}
// ---------- Voice: read result aloud ----------
const listenBtn = document.getElementById("listenBtn");

function hasVoice(prefix) {
  return window.speechSynthesis.getVoices().some(v => v.lang.toLowerCase().startsWith(prefix));
}

listenBtn.addEventListener("click", () => {
  if (!("speechSynthesis" in window)) {
    alert("Your browser does not support voice.");
    return;
  }
  const synth = window.speechSynthesis;
  if (synth.speaking) {
    synth.cancel();
    return;
  }
  if (!lastData) {
    alert("Please check a message first.");
    return;
  }

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
    alert("This device has no Tamil voice installed, so it may not speak Tamil. Try on your phone, or use English.");
  }
  synth.speak(u);
});

if ("speechSynthesis" in window) {
  window.speechSynthesis.getVoices();
}
// ---------- Copy result ----------
const copyBtn = document.getElementById("copyBtn");
const reportLink = document.getElementById("reportLink");

copyBtn.addEventListener("click", async () => {
  if (!lastData) return;
  const ta = lang === "ta";
  const L = LABELS[lang];
  const verdict = (lastData.verdict || "suspicious").toLowerCase();
  const reason = (ta ? lastData.reason_ta : lastData.reason) || "";
  const advice = (ta ? lastData.advice_ta : lastData.advice) || "";
  const text = "ScamAid: " + L.verdict[verdict] + " (" + L.risk + ": " + (Number(lastData.risk_score) || 0) + "/100)\n\n" +
    reason + "\n\n" + advice + "\n\nhttps://scamaid.onrender.com";
  try {
    await navigator.clipboard.writeText(text);
    copyBtn.textContent = ta ? "✅ நகலெடுக்கப்பட்டது" : "✅ Copied";
  } catch (e) {
    alert("Could not copy. Please select the text and copy it manually.");
  }
  setTimeout(() => { copyBtn.textContent = "📋 Copy"; }, 2000);
});