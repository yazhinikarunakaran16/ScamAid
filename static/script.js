const btn = document.getElementById("checkBtn");
const input = document.getElementById("message");
const resultBox = document.getElementById("result");
const themeBtn = document.getElementById("themeBtn");

const COLORS = { safe: "#16a34a", suspicious: "#f59e0b", scam: "#dc2626" };

// ---------- Theme ----------
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

  const label = data.mode === "ai" ? "Risk score (AI-assisted)" : "Risk score (rule-based estimate)";
  document.getElementById("scoreText").textContent = label + ": " + score + "/100";

  const fill = document.getElementById("meterFill");
  fill.style.background = COLORS[verdict] || COLORS.suspicious;
  fill.style.width = "0";
  setTimeout(() => { fill.style.width = score + "%"; }, 50);

  document.getElementById("reason").textContent = data.reason || "";
  document.getElementById("advice").textContent = data.advice || "";

  highlight(input.value, data.matched || []);

  const box = document.getElementById("findings");
  box.innerHTML = "";
  if (data.findings && data.findings.length) {
    data.findings.forEach(f => {
      const item = document.createElement("div");
      item.className = "finding";
      const t = document.createElement("b");
      t.textContent = f.title;
      const p = document.createElement("p");
      p.textContent = f.explain;
      item.appendChild(t);
      item.appendChild(p);
      if (f.found && f.found.length) {
        const s = document.createElement("span");
        s.className = "found";
        s.textContent = "Found: " + f.found.join(", ");
        item.appendChild(s);
      }
      box.appendChild(item);
    });
  } else {
    const n = document.createElement("span");
    n.className = "no-flags";
    n.textContent = "No common scam warning signs found.";
    box.appendChild(n);
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