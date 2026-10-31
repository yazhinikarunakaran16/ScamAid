const btn = document.getElementById("checkBtn");
const input = document.getElementById("message");
const resultBox = document.getElementById("result");
const themeBtn = document.getElementById("themeBtn");

const COLORS = { safe: "#16a34a", suspicious: "#f59e0b", scam: "#dc2626" };

// ---------- Theme (dark / light) ----------
function applyTheme(t) {
  document.documentElement.setAttribute("data-theme", t);
  if (themeBtn) themeBtn.textContent = t === "dark" ? "☀️" : "🌙";
}

let savedTheme = null;
try { savedTheme = localStorage.getItem("theme"); } catch (e) {}
applyTheme(savedTheme || (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light"));

if (themeBtn) {
  themeBtn.addEventListener("click", () => {
    const next = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark";
    applyTheme(next);
    try { localStorage.setItem("theme", next); } catch (e) {}
  });
}

// ---------- Example buttons ----------
document.querySelectorAll(".ex-btn").forEach(b => {
  b.addEventListener("click", () => {
    input.value = b.dataset.text;
    input.focus();
  });
});

// ---------- Check message ----------
btn.addEventListener("click", async () => {
  const text = input.value.trim();
  if (!text) {
    alert("Please paste a message first.");
    return;
  }

  btn.disabled = true;
  btn.textContent = "Checking...";

  try {
    const res = await fetch("/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text })
    });
    const data = await res.json();
    showResult(data);
  } catch (err) {
    alert("Error: " + err.message);
  }

  btn.disabled = false;
  btn.textContent = "Check Message";
});

function showResult(data) {
  const verdict = (data.verdict || "suspicious").toLowerCase();
  const score = Number(data.risk_score) || 0;

  const badge = document.getElementById("verdict");
  badge.textContent = verdict;
  badge.className = "badge " + verdict;

  document.getElementById("scoreText").textContent = "Risk score: " + score + "/100";

  const fill = document.getElementById("meterFill");
  fill.style.background = COLORS[verdict] || COLORS.suspicious;
  fill.style.width = "0";
  setTimeout(() => { fill.style.width = score + "%"; }, 50);

  document.getElementById("reason").textContent = data.reason || "";
  document.getElementById("advice").textContent = data.advice || "";
    highlight(input.value, data.matched || []);

  const flagsBox = document.getElementById("flags");
  flagsBox.innerHTML = "";
  if (data.flags && data.flags.length) {
    data.flags.forEach(f => {
      const span = document.createElement("span");
      span.className = "flag";
      span.textContent = f;
      flagsBox.appendChild(span);
    });
  } else {
    const p = document.createElement("span");
    p.className = "no-flags";
    p.textContent = "No obvious red flags found.";
    flagsBox.appendChild(p);
  }

  resultBox.classList.remove("hidden");
  resultBox.scrollIntoView({ behavior: "smooth" });
}
function highlight(text, words) {
  const box = document.getElementById("highlighted");
  box.innerHTML = "";

  const escaped = words.map(w => w.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
  const parts = ["https?:\\/\\/\\S+", "www\\.\\S+", ...escaped];
  const re = new RegExp("(" + parts.join("|") + ")", "gi");

  text.split(re).forEach((piece, i) => {
    if (!piece) return;
    if (i % 2 === 1) {
      const mark = document.createElement("mark");
      mark.textContent = piece;
      if (/^(https?:|www\.)/i.test(piece)) mark.className = "link";
      box.appendChild(mark);
    } else {
      box.appendChild(document.createTextNode(piece));
    }
  });
}