const btn = document.getElementById("checkBtn");
const input = document.getElementById("message");
const resultBox = document.getElementById("result");

const COLORS = { safe: "#16a34a", suspicious: "#f59e0b", scam: "#dc2626" };

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
    alert("Something went wrong. Is the server running?");
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