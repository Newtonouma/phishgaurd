// background.js — PhishGuard Service Worker
// UWS MSc IT with Data Analytics | B01821745

chrome.runtime.onInstalled.addListener(() => {
  console.log("PhishGuard installed and ready.");
  // Set default settings
  chrome.storage.sync.set({ autoAnalyse: true });
});

// Keep service worker alive for message passing
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg?.action === "openDashboard" && msg.url) {
    chrome.tabs.create({ url: msg.url });
    sendResponse({ status: "opened" });
    return false;
  }

  // Forward any background-level messages if needed in future
  return true;
});
