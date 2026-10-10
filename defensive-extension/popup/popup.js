/**
 * Defensive Browser Extension - Popup Controller
 */

document.addEventListener('DOMContentLoaded', async () => {
  let currentTab = null;
  let currentOrigin = '';
  let popupState = null;

  const originDisplay = document.getElementById('originDisplay');
  const toggleOriginBtn = document.getElementById('toggleOriginBtn');
  const originBtnText = document.getElementById('originBtnText');
  const originBtnIcon = document.getElementById('originBtnIcon');
  const statusBadge = document.getElementById('statusBadge');
  const blockedCountEl = document.getElementById('blockedCount');
  const connectedCountEl = document.getElementById('connectedCount');
  const devicesListEl = document.getElementById('devicesList');
  const devicesCountBadge = document.getElementById('devicesCountBadge');
  const recentLogsListEl = document.getElementById('recentLogsList');
  const openOptionsBtn = document.getElementById('openOptionsBtn');
  const modeButtons = document.querySelectorAll('.mode-btn');

  // 1. Get active tab
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tabs && tabs.length > 0) {
      currentTab = tabs[0];
      if (currentTab.url) {
        try {
          const url = new URL(currentTab.url);
          currentOrigin = url.origin;
          originDisplay.textContent = currentOrigin.replace(/^https?:\/\//, '');
          originDisplay.title = currentOrigin;
        } catch (e) {
          originDisplay.textContent = 'Non-web page';
        }
      }
    }
  } catch (e) {
    originDisplay.textContent = 'Unknown origin';
  }

  // 2. Fetch state from service worker
  async function loadState() {
    return new Promise((resolve) => {
      chrome.runtime.sendMessage({
        action: 'GET_POPUP_STATE',
        tabId: currentTab ? currentTab.id : null
      }, (response) => {
        if (chrome.runtime.lastError || !response) {
          resolve(null);
        } else {
          resolve(response);
        }
      });
    });
  }

  // 3. Render state
  function renderUI(state) {
    if (!state) return;
    popupState = state;

    // A. Render Mode
    const mode = state.mode || 'Balanced';
    statusBadge.textContent = mode;
    statusBadge.className = `mode-badge ${mode.toLowerCase()}`;

    modeButtons.forEach(btn => {
      if (btn.dataset.mode === mode) {
        btn.classList.add('active');
      } else {
        btn.classList.remove('active');
      }
    });

    // B. Blocked Stats
    blockedCountEl.textContent = state.blockedCount || 0;

    // C. Origin Allowlist Button
    const isAllowed = (state.originAllowlist || []).includes(currentOrigin);
    if (isAllowed) {
      toggleOriginBtn.classList.add('allowed');
      originBtnText.textContent = 'Trusted';
      originBtnIcon.textContent = '✓';
    } else {
      toggleOriginBtn.classList.remove('allowed');
      originBtnText.textContent = 'Trust Site';
      originBtnIcon.textContent = '🛡️';
    }

    // D. Connected Peripherals
    const devices = state.connectedDevices || [];
    connectedCountEl.textContent = devices.length;
    devicesCountBadge.textContent = devices.length;

    if (devices.length === 0) {
      devicesListEl.innerHTML = '<div class="empty-state">No WebHID/Serial/MIDI devices active on this page.</div>';
    } else {
      devicesListEl.innerHTML = '';
      devices.forEach(dev => {
        const item = document.createElement('div');
        item.className = 'device-item';

        // Match against database
        const dbMatch = (state.devicesDatabase || []).find(d =>
          d.vendorId === dev.vendorId && d.productId === dev.productId
        );

        const risk = dbMatch ? dbMatch.riskLevel : (dev.riskLevel || 'HIGH');
        const devName = dev.productName || (dbMatch ? dbMatch.name : 'Unknown Device');
        const vidHex = dev.vendorId ? `0x${dev.vendorId.toString(16).padStart(4, '0')}` : 'N/A';
        const pidHex = dev.productId ? `0x${dev.productId.toString(16).padStart(4, '0')}` : 'N/A';

        item.innerHTML = `
          <div class="device-item-info">
            <span class="device-name" title="${escapeHtml(devName)}">${escapeHtml(devName)}</span>
            <span class="device-meta">VID: ${vidHex} | PID: ${pidHex}</span>
          </div>
          <span class="risk-tag ${risk.toLowerCase()}">${risk}</span>
        `;
        devicesListEl.appendChild(item);
      });
    }

    // E. Recent Blocked Events
    const recentLogs = (state.recentLogs || []).slice(0, 3);
    if (recentLogs.length === 0) {
      recentLogsListEl.innerHTML = '<div class="empty-state">No attacks blocked in this session.</div>';
    } else {
      recentLogsListEl.innerHTML = '';
      recentLogs.forEach(log => {
        const item = document.createElement('div');
        item.className = 'log-item';
        const timeStr = log.timestamp ? new Date(log.timestamp).toLocaleTimeString() : '';

        item.innerHTML = `
          <div class="log-item-header">
            <span>${escapeHtml(log.device || 'Peripheral')}</span>
            <span>${escapeHtml(timeStr)}</span>
          </div>
          <div class="log-item-reason">${escapeHtml(log.reason || 'Dangerous write blocked')}</div>
        `;
        recentLogsListEl.appendChild(item);
      });
    }
  }

  // 4. Mode Switcher Event Handlers
  modeButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      const newMode = btn.dataset.mode;
      chrome.runtime.sendMessage({
        action: 'SET_POLICY_MODE',
        mode: newMode
      }, (res) => {
        if (res && res.success) {
          if (popupState) popupState.mode = newMode;
          renderUI(popupState);
        }
      });
    });
  });

  // 5. Origin Allowlist Toggle
  toggleOriginBtn.addEventListener('click', () => {
    if (!currentOrigin || currentOrigin.startsWith('chrome')) return;
    chrome.runtime.sendMessage({
      action: 'TOGGLE_ORIGIN_ALLOWLIST',
      origin: currentOrigin
    }, (res) => {
      if (res && res.success) {
        if (popupState) {
          popupState.originAllowlist = res.originAllowlist;
        }
        renderUI(popupState);
      }
    });
  });

  // 6. Open Options Dashboard
  openOptionsBtn.addEventListener('click', () => {
    if (chrome.runtime.openOptionsPage) {
      chrome.runtime.openOptionsPage();
    } else {
      window.open(chrome.runtime.getURL('options/options.html'));
    }
  });

  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  // Initial Load
  const state = await loadState();
  renderUI(state);
});
