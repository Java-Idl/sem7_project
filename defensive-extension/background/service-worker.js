/**
 * Defensive Browser Extension - Background Service Worker (MV3)
 * Manages configuration, persistent audit logs, device database,
 * enterprise policies (chrome.storage.managed), badge counters, and native companion messaging.
 */

const NATIVE_HOST_NAME = 'com.defensive.extension.host';
const MAX_AUDIT_LOGS = 1000;

// Default initial settings
const DEFAULT_CONFIG = {
  mode: 'Balanced', // Strict, Balanced, Permissive
  deviceOverrides: {},
  originAllowlist: [],
  blockedCount: 0,
  enableNotifications: true,
  enableNativeHost: true
};

// In-memory runtime state
let runtimeState = {
  config: { ...DEFAULT_CONFIG },
  devicesDatabase: [],
  connectedDevicesByTab: new Map(), // tabId -> Array<device>
  auditLogs: []
};

// Initialize extension storage and load devices database
async function initialize() {
  try {
    // 1. Load devices database
    const response = await fetch(chrome.runtime.getURL('data/devices.json'));
    const data = await response.json();
    runtimeState.devicesDatabase = data.devices || [];
  } catch (err) {
    console.warn('[ServiceWorker] Could not load data/devices.json:', err);
  }

  // 2. Load local storage
  const stored = await chrome.storage.local.get(['config', 'auditLogs', 'blockedCount']);
  if (stored.config) {
    runtimeState.config = { ...DEFAULT_CONFIG, ...stored.config };
  } else {
    await chrome.storage.local.set({ config: DEFAULT_CONFIG });
  }

  if (Array.isArray(stored.auditLogs)) {
    runtimeState.auditLogs = stored.auditLogs;
  }
  if (typeof stored.blockedCount === 'number') {
    runtimeState.config.blockedCount = stored.blockedCount;
  }

  // 3. Check chrome.storage.managed for enterprise policies
  try {
    if (chrome.storage.managed) {
      const managed = await chrome.storage.managed.get(null);
      if (managed && Object.keys(managed).length > 0) {
        runtimeState.managedPolicy = managed;
        console.log('[ServiceWorker] Enterprise Managed Policy loaded:', managed);
      }
    }
  } catch (e) {
    // Managed storage not supported or no admin policy installed
  }

  updateBadge();
}

initialize();

// Update extension action badge
function updateBadge() {
  const count = runtimeState.config.blockedCount || 0;
  if (count > 0) {
    chrome.action.setBadgeText({ text: count > 999 ? '999+' : count.toString() });
    chrome.action.setBadgeBackgroundColor({ color: '#ef4444' }); // Red badge
  } else {
    chrome.action.setBadgeText({ text: '' });
  }
}

// Forward telemetry to optional native messaging host (SIEM / OS logging)
function dispatchToNativeHost(event) {
  if (!runtimeState.config.enableNativeHost) return;

  try {
    chrome.runtime.sendNativeMessage(
      NATIVE_HOST_NAME,
      {
        action: 'LOG_SECURITY_ALERT',
        timestamp: new Date().toISOString(),
        event
      },
      (response) => {
        if (chrome.runtime.lastError) {
          // Native host not installed or inactive; gracefully ignore
          return;
        }
      }
    );
  } catch (e) {
    // Graceful fallback
  }
}

// Broadcast updated policy configuration to all open tabs
async function broadcastPolicyUpdate() {
  const tabs = await chrome.tabs.query({});
  for (const tab of tabs) {
    if (!tab.id) continue;
    try {
      chrome.tabs.sendMessage(tab.id, {
        action: 'POLICY_UPDATED',
        config: {
          mode: runtimeState.config.mode,
          deviceOverrides: runtimeState.config.deviceOverrides,
          originAllowlist: runtimeState.config.originAllowlist,
          managedPolicy: runtimeState.managedPolicy || null
        }
      }, () => {
        if (chrome.runtime.lastError) {} // Ignore tabs without content script
      });
    } catch (e) {}
  }
}

// Message listener from content bridge, popup, and options
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  const action = request.action;

  // 1. Content Script config request
  if (action === 'GET_POLICY_CONFIG') {
    sendResponse({
      mode: runtimeState.config.mode,
      deviceOverrides: runtimeState.config.deviceOverrides,
      originAllowlist: runtimeState.config.originAllowlist,
      devicesDatabase: runtimeState.devicesDatabase,
      managedPolicy: runtimeState.managedPolicy || null
    });
    return true;
  }

  // 2. Log blocked security attack event
  if (action === 'LOG_BLOCKED_EVENT') {
    const event = request.event || {};
    runtimeState.config.blockedCount = (runtimeState.config.blockedCount || 0) + 1;

    // Prepend to audit log
    runtimeState.auditLogs.unshift(event);
    if (runtimeState.auditLogs.length > MAX_AUDIT_LOGS) {
      runtimeState.auditLogs = runtimeState.auditLogs.slice(0, MAX_AUDIT_LOGS);
    }

    // Persist
    chrome.storage.local.set({
      blockedCount: runtimeState.config.blockedCount,
      auditLogs: runtimeState.auditLogs
    });

    updateBadge();
    dispatchToNativeHost(event);

    sendResponse({ success: true, count: runtimeState.config.blockedCount });
    return true;
  }

  // 3. Register connected device for tab
  if (action === 'LOG_DEVICE_CONNECTED') {
    const tabId = sender.tab ? sender.tab.id : 'unknown';
    const device = request.device || {};

    if (!runtimeState.connectedDevicesByTab.has(tabId)) {
      runtimeState.connectedDevicesByTab.set(tabId, []);
    }
    const currentList = runtimeState.connectedDevicesByTab.get(tabId);
    if (!currentList.some(d => d.vendorId === device.vendorId && d.productId === device.productId)) {
      currentList.push(device);
    }

    sendResponse({ success: true });
    return true;
  }

  // 4. Get UI state for popup
  if (action === 'GET_POPUP_STATE') {
    const tabId = request.tabId;
    const connectedDevices = runtimeState.connectedDevicesByTab.get(tabId) || [];
    sendResponse({
      mode: runtimeState.config.mode,
      blockedCount: runtimeState.config.blockedCount,
      originAllowlist: runtimeState.config.originAllowlist,
      deviceOverrides: runtimeState.config.deviceOverrides,
      connectedDevices,
      devicesDatabase: runtimeState.devicesDatabase,
      recentLogs: runtimeState.auditLogs.slice(0, 10)
    });
    return true;
  }

  // 5. Update global policy mode (Strict / Balanced / Permissive)
  if (action === 'SET_POLICY_MODE') {
    runtimeState.config.mode = request.mode || 'Balanced';
    chrome.storage.local.set({ config: runtimeState.config });
    broadcastPolicyUpdate();
    sendResponse({ success: true, mode: runtimeState.config.mode });
    return true;
  }

  // 6. Toggle site allowlist
  if (action === 'TOGGLE_ORIGIN_ALLOWLIST') {
    const origin = request.origin;
    if (!origin) return false;

    const list = runtimeState.config.originAllowlist || [];
    const index = list.indexOf(origin);
    if (index === -1) {
      list.push(origin);
    } else {
      list.splice(index, 1);
    }
    runtimeState.config.originAllowlist = list;
    chrome.storage.local.set({ config: runtimeState.config });
    broadcastPolicyUpdate();
    sendResponse({ success: true, isAllowed: index === -1, originAllowlist: list });
    return true;
  }

  // 7. Update per-device override
  if (action === 'SET_DEVICE_OVERRIDE') {
    const { deviceKey, override } = request; // override: "always_allow", "always_block", "follow_policy"
    if (override === 'follow_policy') {
      delete runtimeState.config.deviceOverrides[deviceKey];
    } else {
      runtimeState.config.deviceOverrides[deviceKey] = override;
    }
    chrome.storage.local.set({ config: runtimeState.config });
    broadcastPolicyUpdate();
    sendResponse({ success: true, deviceOverrides: runtimeState.config.deviceOverrides });
    return true;
  }

  // 8. Fetch audit logs (Options page)
  if (action === 'GET_AUDIT_LOGS') {
    sendResponse({ logs: runtimeState.auditLogs });
    return true;
  }

  // 9. Clear audit logs
  if (action === 'CLEAR_AUDIT_LOGS') {
    runtimeState.auditLogs = [];
    runtimeState.config.blockedCount = 0;
    chrome.storage.local.set({ auditLogs: [], blockedCount: 0, config: runtimeState.config });
    updateBadge();
    sendResponse({ success: true });
    return true;
  }

  // 10. Export settings
  if (action === 'EXPORT_SETTINGS') {
    sendResponse({
      config: runtimeState.config,
      exportDate: new Date().toISOString()
    });
    return true;
  }

  // 11. Import settings
  if (action === 'IMPORT_SETTINGS') {
    if (request.data && request.data.config) {
      runtimeState.config = { ...DEFAULT_CONFIG, ...request.data.config };
      chrome.storage.local.set({ config: runtimeState.config });
      updateBadge();
      broadcastPolicyUpdate();
      sendResponse({ success: true });
    } else {
      sendResponse({ success: false, error: 'Invalid settings format' });
    }
    return true;
  }
});

// Clean up connected devices when tabs are closed
chrome.tabs.onRemoved.addListener((tabId) => {
  runtimeState.connectedDevicesByTab.delete(tabId);
});
