/**
 * Defensive Browser Extension - Content Script Bridge (ISOLATED World)
 * Runs at document_start in all frames.
 * Bridges communication between the MAIN-world interceptor and background service worker.
 */

(function () {
  'use strict';

  const CHANNEL_MAIN = 'DEFENSIVE_EXTENSION_MAIN';
  const CHANNEL_BRIDGE = 'DEFENSIVE_EXTENSION_BRIDGE';

  // Listen to messages from the page context (MAIN world)
  window.addEventListener('message', async (event) => {
    if (event.source !== window || !event.data || event.data.source !== CHANNEL_MAIN) {
      return;
    }

    const { type, payload } = event.data;

    try {
      if (type === 'GET_CONFIG') {
        // Request policy config from background worker
        chrome.runtime.sendMessage({ action: 'GET_POLICY_CONFIG' }, (response) => {
          if (chrome.runtime.lastError || !response) return;
          window.postMessage({
            source: CHANNEL_BRIDGE,
            type: 'SYNC_CONFIG',
            config: response
          }, '*');
        });
      } else if (type === 'OPERATION_BLOCKED') {
        // Log blocked event in background worker
        chrome.runtime.sendMessage({
          action: 'LOG_BLOCKED_EVENT',
          event: payload
        });
      } else if (type === 'DEVICE_CONNECTED') {
        // Log connected device in background worker
        chrome.runtime.sendMessage({
          action: 'LOG_DEVICE_CONNECTED',
          device: payload
        });
      }
    } catch (e) {
      // Handle extension context invalidated
    }
  });

  // Listen for push notifications / policy updates from background worker
  try {
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      if (message.action === 'POLICY_UPDATED') {
        window.postMessage({
          source: CHANNEL_BRIDGE,
          type: 'SYNC_CONFIG',
          config: message.config
        }, '*');
        sendResponse({ success: true });
      }
    });
  } catch (e) {}

  // Initial config broadcast
  try {
    chrome.runtime.sendMessage({ action: 'GET_POLICY_CONFIG' }, (response) => {
      if (chrome.runtime.lastError || !response) return;
      window.postMessage({
        source: CHANNEL_BRIDGE,
        type: 'SYNC_CONFIG',
        config: response
      }, '*');
    });
  } catch (e) {}
})();
