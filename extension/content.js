/**
 * content.js  —  PhishGuard Gmail Content Script
 * ================================================
 * Injects a PhishGuard analysis panel into Gmail.
 * Reads the open email, sends it to the background
 * service worker for classification, and displays
 * the result + explanation inline.
 *
 * UWS MSc IT with Data Analytics | Banner ID: B01821745
 */

"use strict";

// ── Configuration ─────────────────────────────────────────
const API_BASE = "https://phishgaurd-production-1c76.up.railway.app";
const DEBOUNCE_MS = 800;

// ── State ─────────────────────────────────────────────────
let currentEmailId   = null;
let analysisPanel    = null;
let debounceTimer    = null;

// ── Inject PhishGuard button into Gmail toolbar ───────────
function injectButton() {
  if (document.getElementById("phishguard-btn")) return;

  const toolbar = document.querySelector(
    '[gh="tm"] .G-tF, [data-tooltip="More options"] ~ div, .ade[role="toolbar"]'
  );
  if (!toolbar) return;

  const btn = document.createElement("div");
  btn.id = "phishguard-btn";
  btn.className = "phishguard-toolbar-btn";
  btn.title = "Analyse with PhishGuard";
  btn.innerHTML = `
    <span class="pg-icon">🛡</span>
    <span class="pg-label">PhishGuard</span>
  `;
  btn.addEventListener("click", analyseCurrentEmail);
  toolbar.appendChild(btn);
}

// ── Extract email body from Gmail DOM ─────────────────────
function extractEmailText() {
  // Try multiple Gmail DOM selectors (Gmail changes its DOM periodically)
  const selectors = [
    ".a3s.aiL",           // Main email body
    ".a3s",               // Fallback body
    "[data-message-id] .y6",
    ".gmail_quote",
  ];

  let body = "";
  for (const sel of selectors) {
    const el = document.querySelector(sel);
    if (el && el.innerText.trim().length > 20) {
      body = el.innerText.trim();
      break;
    }
  }

  // Extract subject
  const subjectEl = document.querySelector("h2.hP, .ha h2");
  const subject   = subjectEl ? subjectEl.innerText.trim() : "";

  // Extract sender
  const senderEl  = document.querySelector(".gD[email], .go .gD");
  const sender    = senderEl ? (senderEl.getAttribute("email") || senderEl.innerText) : "";

  return { subject, sender, body, full: `Subject: ${subject}\nFrom: ${sender}\n\n${body}` };
}

// ── Main analysis function ────────────────────────────────
async function analyseCurrentEmail() {
  const email = extractEmailText();

  if (!email.body || email.body.length < 10) {
    showPanel({
      error: "Could not read email body. Please open a specific email first.",
    });
    return;
  }

  showPanel({ loading: true, subject: email.subject });

  try {
    const response = await fetch(`${API_BASE}/predict`, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text: email.full }),
    });

    if (!response.ok) {
      let serverMsg = `API returned ${response.status}`;
      try {
        const errBody = await response.json();
        if (errBody?.error) serverMsg = errBody.error;
      } catch (_) {
        // Keep default serverMsg when body is not JSON.
      }

      showPanel({
        error: `PhishGuard API is reachable but could not analyse this email right now. ${serverMsg}`,
      });
      return;
    }

    const result = await response.json();
    showPanel({ result, subject: email.subject, sender: email.sender });

  } catch (err) {
    // Network failure/offline fallback: rule-based client-side detection
    const fallback = offlineFallback(email.full);
    showPanel({ result: fallback, subject: email.subject, offline: true });
  }
}

// ── Offline rule-based fallback (when API not reachable) ──
function offlineFallback(text) {
  const lower  = text.toLowerCase();
  const urgent = ["urgent", "immediately", "suspended", "expires", "verify",
                   "click here", "act now", "password", "account limited"].filter(w => lower.includes(w));
  const urlCount = (text.match(/https?:\/\/\S+/gi) || []).length;
  const excl     = (text.match(/!/g) || []).length;

  let score = 0;
  score += urgent.length * 15;
  score += urlCount > 0 ? 20 : 0;
  score += excl > 3 ? 10 : 0;
  score += lower.includes("congratulations") ? 25 : 0;
  score += lower.includes("prize") || lower.includes("winner") ? 30 : 0;

  const isPhish = score >= 40;
  return {
    label:       isPhish ? "PHISHING" : "LEGITIMATE",
    confidence:  Math.min(95, 40 + score),
    model:       "Offline Rules",
    explanation: isPhish
      ? `⚠️ PHISHING detected (offline analysis).\n\nSuspicious indicators found:\n` +
        urgent.map(w => `• "${w}"`).join("\n") +
        (urlCount > 0 ? `\n• ${urlCount} URL(s) detected` : "") +
        "\n\nThis is a rule-based offline analysis. Connect to the PhishGuard API for full ML classification."
      : "✅ No obvious phishing indicators detected (offline analysis).\n\nNote: This is a basic rule check. Use the full app for comprehensive ML analysis.",
    all_models:  {},
  };
}

// ── Panel rendering ───────────────────────────────────────
function showPanel(options) {
  // Remove existing panel
  const existing = document.getElementById("phishguard-panel");
  if (existing) existing.remove();

  const panel = document.createElement("div");
  panel.id = "phishguard-panel";
  panel.className = "phishguard-panel";

  if (options.loading) {
    panel.innerHTML = `
      <div class="pg-panel-header">
        <span class="pg-logo">🛡 PhishGuard</span>
        <button class="pg-close" data-action="close-panel">✕</button>
      </div>
      <div class="pg-loading">
        <div class="pg-spinner"></div>
        <span>Analysing email…</span>
      </div>
    `;
  } else if (options.error) {
    panel.innerHTML = `
      <div class="pg-panel-header">
        <span class="pg-logo">🛡 PhishGuard</span>
        <button class="pg-close" data-action="close-panel">✕</button>
      </div>
      <div class="pg-error">${options.error}</div>
    `;
  } else {
    const r      = options.result;
    const isPhish = r.label === "PHISHING";
    const colour  = isPhish ? "#EA5455" : "#28C76F";
    const emoji   = isPhish ? "⚠️" : "✅";
    const offline = options.offline ? ' <span class="pg-offline-badge">offline</span>' : "";

    // Per-model mini results
    let modelHtml = "";
    if (r.all_models && Object.keys(r.all_models).length > 0) {
      modelHtml = Object.entries(r.all_models).map(([name, res]) => {
        const mc = res.label === "PHISHING" ? "#EA5455" : "#28C76F";
        return `<div class="pg-model-chip" style="border-color:${mc};color:${mc}">
          <b>${name.replace(" (LinearSVC)","")}</b><br>
          ${res.label} ${res.confidence.toFixed(0)}%
        </div>`;
      }).join("");
    }

    panel.innerHTML = `
      <div class="pg-panel-header">
        <span class="pg-logo">🛡 PhishGuard</span>
        <span class="pg-badge" style="background:${colour}">${emoji} ${r.label}</span>
        <button class="pg-close" data-action="close-panel">✕</button>
      </div>
      ${options.subject ? `<div class="pg-subject">${options.subject}</div>` : ""}
      <div class="pg-confidence" style="color:${colour}">
        ${r.confidence.toFixed(0)}% confidence${offline} — Model: ${r.model}
      </div>
      ${modelHtml ? `<div class="pg-models-row">${modelHtml}</div>` : ""}
      <div class="pg-explanation">${
        r.explanation
          ? r.explanation.replace(/\*\*(.*?)\*\*/g, "<strong>$1</strong>").replace(/\n/g, "<br>")
          : "Analysis complete."
      }</div>
      <div class="pg-actions">
        <button class="pg-btn pg-btn-primary" data-action="open-dashboard">
          📊 Full Dashboard
        </button>
        <button class="pg-btn pg-btn-secondary" data-action="close-panel">
          Dismiss
        </button>
      </div>
      <div class="pg-footer">B01821745 | UWS MSc IT with Data Analytics</div>
    `;
  }

  // Gmail CSP can block inline onclick handlers; bind actions programmatically.
  panel.querySelectorAll('[data-action="close-panel"]').forEach((btn) => {
    btn.addEventListener("click", () => {
      panel.remove();
    });
  });

  const dashboardBtn = panel.querySelector('[data-action="open-dashboard"]');
  if (dashboardBtn) {
    dashboardBtn.addEventListener("click", () => {
      window.open(`${API_BASE}/dashboard`, "_blank", "noopener");
    });
  }

  // Insert after email header or at top of email view
  const emailView = document.querySelector(".nH.if.aeN, .nH.hx, [role='main']");
  if (emailView) {
    emailView.insertBefore(panel, emailView.firstChild);
  } else {
    document.body.appendChild(panel);
  }
}

// ── Auto-detect email opens ───────────────────────────────
const observer = new MutationObserver(() => {
  clearTimeout(debounceTimer);
  debounceTimer = setTimeout(() => {
    injectButton();
    // Auto-analyse when a new email is opened
    const emailBody = document.querySelector(".a3s.aiL");
    if (emailBody) {
      const emailId = emailBody.closest("[data-message-id]")?.getAttribute("data-message-id");
      if (emailId && emailId !== currentEmailId) {
        currentEmailId = emailId;
        // Auto-analyse on email open (user can disable in settings)
        chrome.storage.sync.get(["autoAnalyse"], (s) => {
          if (s.autoAnalyse !== false) analyseCurrentEmail();
        });
      }
    }
  }, DEBOUNCE_MS);
});

observer.observe(document.body, { subtree: true, childList: true });
injectButton();

// ── Listen for messages from popup ───────────────────────
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.action === "analyse") {
    analyseCurrentEmail();
    sendResponse({ status: "analysing" });
  }
  if (msg.action === "getEmailText") {
    sendResponse(extractEmailText());
  }
  return true;
});
