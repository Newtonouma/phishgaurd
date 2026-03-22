/* popup.js — PhishGuard Extension Popup Logic */

const API = "https://phishgaurd-production-1c76.up.railway.app";

// Check API status
async function checkAPI() {
  try {
    const r = await fetch(`${API}/health`, { signal: AbortSignal.timeout(2000) });
    const d = await r.json();
    document.getElementById("api-status").innerHTML =
      `<span class="dot dot-green"></span>Online — ${d.trained ? "Trained ✅" : "Not trained"}`;
  } catch {
    document.getElementById("api-status").innerHTML =
      `<span class="dot dot-red"></span>Offline (standalone mode)`;
  }
}

// Check current tab
chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
  const url = tabs[0]?.url || "";
  const isGmail = url.includes("mail.google.com");
  document.getElementById("page-status").textContent = isGmail ? "Gmail ✓" : "Not Gmail";
  document.getElementById("analyse-btn").disabled = !isGmail;
  if (!isGmail) {
    document.getElementById("status-msg").textContent = "Navigate to Gmail to use PhishGuard";
  }
});

// Load auto-analyse setting
chrome.storage.sync.get(["autoAnalyse"], (s) => {
  const el = document.getElementById("auto-toggle");
  el.checked = s.autoAnalyse !== false;
  document.getElementById("auto-label").textContent = el.checked ? "On" : "Off";
});

document.getElementById("auto-toggle").addEventListener("change", (e) => {
  chrome.storage.sync.set({ autoAnalyse: e.target.checked });
  document.getElementById("auto-label").textContent = e.target.checked ? "On" : "Off";
});

// Analyse button
document.getElementById("analyse-btn").addEventListener("click", () => {
  document.getElementById("status-msg").textContent = "Sending to PhishGuard…";
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    chrome.tabs.sendMessage(tabs[0].id, { action: "analyse" }, (resp) => {
      document.getElementById("status-msg").textContent =
        resp?.status === "analysing" ? "Analysing… check the email panel" : "Done";
      setTimeout(window.close, 1200);
    });
  });
});

// Dashboard button
document.getElementById("dashboard-btn").addEventListener("click", () => {
  chrome.tabs.create({ url: `${API}/dashboard` });
});

checkAPI();
