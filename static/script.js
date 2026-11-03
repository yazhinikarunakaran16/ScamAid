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
        risk: "Risk score", riskEst: "Risk estimate", total: "Total",
        brkAI: "Rule-based warning signs (AI score may differ)", aiTotal: "AI risk score",
        btn: "தமிழில் பார்க்க", none: "No warning signs were added to the score.",
        noFlags: "No obvious warning signs found.", found: "Found",
        copy: "📋 Copy", copied: "✅ Copied",
        scoreNote: "This is an estimate, not a guarantee. 0-39 low risk, 40-59 suspicious, 60+ likely scam. The score is built from the warning signs listed below.",
        note: "Before sharing, remove names, phone numbers, OTPs and account numbers. The copied text does not include your original message.",
        verdict: { safe: "safe", suspicious: "suspicious", scam: "scam" },
        ai: "AI + rules", rules: "Rule-based check" },
  ta: { msg: "உங்கள் செய்தி (எச்சரிக்கை சொற்கள் குறிக்கப்பட்டுள்ளன)", why: "ஏன்?", warn: "எச்சரிக்கை அறிகுறிகள்",
        advice: "நீங்கள் என்ன செய்ய வேண்டும்?", brk: "மதிப்பெண் எப்படி வந்தது",
        risk: "ஆபத்து மதிப்பெண்", riskEst: "ஆபத்து மதிப்பீடு", total: "மொத்தம்",
        brkAI: "விதி அடிப்படையிலான எச்சரிக்கைகள் (AI மதிப்பெண் வேறுபடலாம்)", aiTotal: "AI ஆபத்து மதிப்பெண்",
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