/**
 * Defensive Browser Extension - Options & Security Dashboard Controller
 */

document.addEventListener('DOMContentLoaded', async () => {
  let devicesDatabase = [];
  let currentConfig = {
    mode: 'Balanced',
    deviceOverrides: {},
    originAllowlist: [],
    blockedCount: 0
  };
  let auditLogs = [];

  // DOM Elements - Navigation
  const navItems = document.querySelectorAll('.nav-item');
  const tabPanes = document.querySelectorAll('.tab-pane');

  // DOM Elements - Overview
  const statBlockedTotal = document.getElementById('statBlockedTotal');
  const statCurrentMode = document.getElementById('statCurrentMode');
  const statModeDisplay = document.getElementById('statModeDisplay');
  const statDevicesInDb = document.getElementById('statDevicesInDb');
  const statOriginsTotal = document.getElementById('statOriginsTotal');
  const policyModeRadios = document.querySelectorAll('input[name="policyMode"]');
  const modeOptStrict = document.getElementById('modeOptStrict');
  const modeOptBalanced = document.getElementById('modeOptBalanced');
  const modeOptPermissive = document.getElementById('modeOptPermissive');

  // DOM Elements - Devices
  const deviceSearchInput = document.getElementById('deviceSearchInput');
  const deviceRiskFilter = document.getElementById('deviceRiskFilter');
  const devicesTableBody = document.getElementById('devicesTableBody');

  // DOM Elements - Allowlist
  const newOriginInput = document.getElementById('newOriginInput');
  const addOriginBtn = document.getElementById('addOriginBtn');
  const allowlistTableBody = document.getElementById('allowlistTableBody');

  // DOM Elements - Audit Log
  const logSearchInput = document.getElementById('logSearchInput');
  const logRiskFilter = document.getElementById('logRiskFilter');
  const auditTableBody = document.getElementById('auditTableBody');
  const clearLogsBtn = document.getElementById('clearLogsBtn');
  const exportLogsJsonBtn = document.getElementById('exportLogsJsonBtn');
  const exportLogsCsvBtn = document.getElementById('exportLogsCsvBtn');

  // DOM Elements - Estimator
  const estimatorConnectBtn = document.getElementById('estimatorConnectBtn');
  const estimatorAnalyzeBtn = document.getElementById('estimatorAnalyzeBtn');
  const mockDescriptorInput = document.getElementById('mockDescriptorInput');
  const scoreCircle = document.getElementById('scoreCircle');
  const scoreLabel = document.getElementById('scoreLabel');
  const scoreSub = document.getElementById('scoreSub');
  const threatBreakdown = document.getElementById('threatBreakdown');

  // DOM Elements - Enterprise
  const managedStatusIndicator = document.getElementById('managedStatusIndicator');
  const managedStatusTitle = document.getElementById('managedStatusTitle');
  const managedStatusDesc = document.getElementById('managedStatusDesc');
  const exportSettingsBtn = document.getElementById('exportSettingsBtn');
  const importSettingsBtn = document.getElementById('importSettingsBtn');
  const importFileInput = document.getElementById('importFileInput');
  const statusToast = document.getElementById('statusToast');

  // Toast message utility
  function showToast(msg, duration = 3000) {
    statusToast.textContent = msg;
    statusToast.classList.remove('hidden');
    setTimeout(() => {
      statusToast.classList.add('hidden');
    }, duration);
  }

  // 1. Tab Switching
  navItems.forEach(item => {
    item.addEventListener('click', () => {
      const target = item.dataset.tab;
      navItems.forEach(n => n.classList.remove('active'));
      tabPanes.forEach(p => p.classList.remove('active'));
      item.classList.add('active');
      const pane = document.getElementById(`tab-${target}`);
      if (pane) pane.classList.add('active');
    });
  });

  // 2. Fetch Devices Database & Configuration
  async function loadInitialData() {
    try {
      const res = await fetch(chrome.runtime.getURL('data/devices.json'));
      const data = await res.json();
      devicesDatabase = data.devices || [];
      statDevicesInDb.textContent = devicesDatabase.length;
    } catch (e) {
      console.warn('Failed to load data/devices.json:', e);
    }

    // Load config from background
    chrome.runtime.sendMessage({ action: 'GET_POLICY_CONFIG' }, (response) => {
      if (response) {
        currentConfig.mode = response.mode || 'Balanced';
        currentConfig.deviceOverrides = response.deviceOverrides || {};
        currentConfig.originAllowlist = response.originAllowlist || [];
        if (response.managedPolicy) {
          currentConfig.managedPolicy = response.managedPolicy;
        }
        updateOverviewUI();
        renderDevicesTable();
        renderAllowlistTable();
        updateEnterpriseStatus();
      }
    });

    // Load audit logs
    chrome.runtime.sendMessage({ action: 'GET_AUDIT_LOGS' }, (response) => {
      if (response && response.logs) {
        auditLogs = response.logs;
        statBlockedTotal.textContent = auditLogs.length;
        renderAuditTable();
      }
    });
  }

  // 3. Update Overview UI
  function updateOverviewUI() {
    statCurrentMode.textContent = currentConfig.mode;
    statModeDisplay.textContent = currentConfig.mode;
    statOriginsTotal.textContent = currentConfig.originAllowlist.length;

    policyModeRadios.forEach(radio => {
      radio.checked = radio.value === currentConfig.mode;
    });

    [modeOptStrict, modeOptBalanced, modeOptPermissive].forEach(opt => {
      if (opt) opt.classList.remove('active');
    });

    if (currentConfig.mode === 'Strict' && modeOptStrict) modeOptStrict.classList.add('active');
    if (currentConfig.mode === 'Balanced' && modeOptBalanced) modeOptBalanced.classList.add('active');
    if (currentConfig.mode === 'Permissive' && modeOptPermissive) modeOptPermissive.classList.add('active');
  }

  // 4. Policy Mode Change
  policyModeRadios.forEach(radio => {
    radio.addEventListener('change', () => {
      const newMode = radio.value;
      chrome.runtime.sendMessage({
        action: 'SET_POLICY_MODE',
        mode: newMode
      }, (res) => {
        if (res && res.success) {
          currentConfig.mode = newMode;
          updateOverviewUI();
          showToast(`Global policy mode changed to ${newMode}`);
        }
      });
    });
  });

  // 5. Render Devices Table with overrides
  function renderDevicesTable() {
    const search = (deviceSearchInput.value || '').toLowerCase();
    const risk = deviceRiskFilter.value;

    const filtered = devicesDatabase.filter(dev => {
      const matchSearch = dev.name.toLowerCase().includes(search) ||
        (dev.vendorId && dev.vendorId.toString(16).includes(search)) ||
        (dev.productId && dev.productId.toString(16).includes(search));
      const matchRisk = risk === 'ALL' || dev.riskLevel === risk;
      return matchSearch && matchRisk;
    });

    devicesTableBody.innerHTML = '';
    if (filtered.length === 0) {
      devicesTableBody.innerHTML = '<tr><td colspan="6" class="text-muted text-center" style="padding: 20px;">No matching peripherals found in vulnerability database.</td></tr>';
      return;
    }

    filtered.forEach(dev => {
      const tr = document.createElement('tr');
      const vidHex = dev.vendorId ? `0x${dev.vendorId.toString(16).padStart(4, '0')}` : 'N/A';
      const pidHex = dev.productId ? `0x${dev.productId.toString(16).padStart(4, '0')}` : 'N/A';
      const devKey = `${dev.vendorId}:${dev.productId}`;
      const currentOverride = currentConfig.deviceOverrides[devKey] || 'follow_policy';

      tr.innerHTML = `
        <td><strong>${escapeHtml(dev.name)}</strong></td>
        <td><code>${vidHex}:${pidHex}</code></td>
        <td>${escapeHtml(dev.protocol || 'HID')}</td>
        <td><span class="risk-tag ${dev.riskLevel.toLowerCase()}">${dev.riskLevel}</span></td>
        <td style="max-width: 280px; font-size: 11px; color: #94a3b8;">${escapeHtml(dev.description || dev.cve || 'Hardware macro write vulnerability')}</td>
        <td>
          <select class="form-select override-select" data-devkey="${devKey}">
            <option value="follow_policy" ${currentOverride === 'follow_policy' ? 'selected' : ''}>Follow Global Policy</option>
            <option value="always_block" ${currentOverride === 'always_block' ? 'selected' : ''}>Always Block</option>
            <option value="always_allow" ${currentOverride === 'always_allow' ? 'selected' : ''}>Always Allow (Bypass)</option>
          </select>
        </td>
      `;
      devicesTableBody.appendChild(tr);
    });

    // Wire up override change listeners
    document.querySelectorAll('.override-select').forEach(sel => {
      sel.addEventListener('change', () => {
        const devKey = sel.dataset.devkey;
        const override = sel.value;
        chrome.runtime.sendMessage({
          action: 'SET_DEVICE_OVERRIDE',
          deviceKey: devKey,
          override: override
        }, (res) => {
          if (res && res.success) {
            currentConfig.deviceOverrides = res.deviceOverrides;
            showToast(`Override updated for device ${devKey}: ${override}`);
          }
        });
      });
    });
  }

  deviceSearchInput.addEventListener('input', renderDevicesTable);
  deviceRiskFilter.addEventListener('change', renderDevicesTable);

  // 6. Origin Allowlist Management
  function renderAllowlistTable() {
    allowlistTableBody.innerHTML = '';
    const origins = currentConfig.originAllowlist || [];
    if (origins.length === 0) {
      allowlistTableBody.innerHTML = '<tr><td colspan="3" class="text-muted text-center" style="padding: 20px;">No origins allowlisted. Standard security inspection applies to all websites.</td></tr>';
      return;
    }

    origins.forEach(orig => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><code>${escapeHtml(orig)}</code></td>
        <td>Active</td>
        <td>
          <button class="btn btn-danger btn-sm remove-origin-btn" data-origin="${escapeHtml(orig)}">Remove</button>
        </td>
      `;
      allowlistTableBody.appendChild(tr);
    });

    document.querySelectorAll('.remove-origin-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const originToRemove = btn.dataset.origin;
        chrome.runtime.sendMessage({
          action: 'TOGGLE_ORIGIN_ALLOWLIST',
          origin: originToRemove
        }, (res) => {
          if (res && res.success) {
            currentConfig.originAllowlist = res.originAllowlist;
            statOriginsTotal.textContent = currentConfig.originAllowlist.length;
            renderAllowlistTable();
            showToast(`Removed origin: ${originToRemove}`);
          }
        });
      });
    });
  }

  addOriginBtn.addEventListener('click', () => {
    let raw = (newOriginInput.value || '').trim();
    if (!raw) return;
    try {
      const url = new URL(raw);
      raw = url.origin;
    } catch (e) {
      if (!raw.startsWith('http://') && !raw.startsWith('https://')) {
        raw = 'https://' + raw;
      }
    }

    if (currentConfig.originAllowlist.includes(raw)) {
      showToast('Origin is already in allowlist');
      return;
    }

    chrome.runtime.sendMessage({
      action: 'TOGGLE_ORIGIN_ALLOWLIST',
      origin: raw
    }, (res) => {
      if (res && res.success) {
        currentConfig.originAllowlist = res.originAllowlist;
        statOriginsTotal.textContent = currentConfig.originAllowlist.length;
        newOriginInput.value = '';
        renderAllowlistTable();
        showToast(`Added trusted origin: ${raw}`);
      }
    });
  });

  // 7. Audit Log Management
  function renderAuditTable() {
    const search = (logSearchInput.value || '').toLowerCase();
    const risk = logRiskFilter.value;

    const filtered = auditLogs.filter(log => {
      const matchSearch = (log.device || '').toLowerCase().includes(search) ||
        (log.origin || '').toLowerCase().includes(search) ||
        (log.reason || '').toLowerCase().includes(search) ||
        (log.method || '').toLowerCase().includes(search);
      const matchRisk = risk === 'ALL' || log.riskLevel === risk;
      return matchSearch && matchRisk;
    });

    auditTableBody.innerHTML = '';
    if (filtered.length === 0) {
      auditTableBody.innerHTML = '<tr><td colspan="6" class="text-muted text-center" style="padding: 24px;">No security interception events match current filters.</td></tr>';
      return;
    }

    filtered.forEach(log => {
      const tr = document.createElement('tr');
      const timeStr = log.timestamp ? new Date(log.timestamp).toLocaleString() : 'N/A';
      const riskClass = (log.riskLevel || 'HIGH').toLowerCase();

      tr.innerHTML = `
        <td style="white-space: nowrap; font-family: monospace; font-size: 11px;">${escapeHtml(timeStr)}</td>
        <td style="max-width: 160px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(log.origin || '')}"><code>${escapeHtml(log.origin || 'N/A')}</code></td>
        <td><strong>${escapeHtml(log.device || 'Peripheral')}</strong></td>
        <td><code>${escapeHtml(log.method || 'sendReport')}</code></td>
        <td style="max-width: 320px; font-size: 11px;">${escapeHtml(log.reason || '')}</td>
        <td><span class="risk-tag ${riskClass}">${escapeHtml(log.riskLevel || 'HIGH')}</span></td>
      `;
      auditTableBody.appendChild(tr);
    });
  }

  logSearchInput.addEventListener('input', renderAuditTable);
  logRiskFilter.addEventListener('change', renderAuditTable);

  clearLogsBtn.addEventListener('click', () => {
    if (!confirm('Are you sure you want to clear all recorded audit logs?')) return;
    chrome.runtime.sendMessage({ action: 'CLEAR_AUDIT_LOGS' }, (res) => {
      if (res && res.success) {
        auditLogs = [];
        statBlockedTotal.textContent = '0';
        renderAuditTable();
        showToast('Audit logs cleared');
      }
    });
  });

  exportLogsJsonBtn.addEventListener('click', () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(auditLogs, null, 2));
    const dl = document.createElement('a');
    dl.setAttribute('href', dataStr);
    dl.setAttribute('download', `peripheralshield-audit-logs-${Date.now()}.json`);
    dl.click();
  });

  exportLogsCsvBtn.addEventListener('click', () => {
    let csv = 'Timestamp,Origin,Device,Method,RiskLevel,Reason\n';
    auditLogs.forEach(l => {
      const ts = l.timestamp ? new Date(l.timestamp).toISOString() : '';
      csv += `"${ts}","${l.origin || ''}","${l.device || ''}","${l.method || ''}","${l.riskLevel || ''}","${(l.reason || '').replace(/"/g, '""')}"\n`;
    });
    const dataStr = 'data:text/csv;charset=utf-8,' + encodeURIComponent(csv);
    const dl = document.createElement('a');
    dl.setAttribute('href', dataStr);
    dl.setAttribute('download', `peripheralshield-audit-logs-${Date.now()}.csv`);
    dl.click();
  });

  // 8. Heuristic Threat Estimator (Ported from PeripheralInstinct tool.html)
  function evaluateDeviceDescriptor(device) {
    let score = 0;
    const factors = [];
    const collections = device.collections || [];

    // Factor 1: Vendor or Product defined collection (e.g. usagePage >= 0xFF00)
    const hasVendorPage = collections.some(c => c.usagePage >= 0xFF00);
    if (hasVendorPage) {
      score += 35;
      factors.push({ name: 'Vendor-Defined Usage Page (>= 0xFF00)', desc: 'Device exposes proprietary configuration endpoints.', severity: 'CRITICAL', pts: '+35' });
    }

    // Factor 2: Device can simulate Keyboard (usagePage 1, usage 6)
    const hasKeyboard = collections.some(c => c.usagePage === 1 && c.usage === 6);
    if (hasKeyboard) {
      score += 25;
      factors.push({ name: 'Keyboard Interface Present', desc: 'Device can send arbitrary simulated keystrokes to OS.', severity: 'HIGH', pts: '+25' });
    }

    // Factor 3: Device has Output or Feature reports allowing host-to-device writes
    let hasWritableReports = false;
    let totalOutputEndpoints = 0;
    collections.forEach(c => {
      if ((c.outputReports && c.outputReports.length > 0) || (c.featureReports && c.featureReports.length > 0)) {
        hasWritableReports = true;
        totalOutputEndpoints += (c.outputReports ? c.outputReports.length : 0) + (c.featureReports ? c.featureReports.length : 0);
      }
    });

    if (hasWritableReports) {
      score += 25;
      factors.push({ name: 'Writable Output/Feature Reports', desc: `Detected ${totalOutputEndpoints} writable reports for sending host commands.`, severity: 'HIGH', pts: '+25' });
    }

    // Factor 4: Known vulnerable VID in database
    const dbMatch = devicesDatabase.find(d => d.vendorId === device.vendorId);
    if (dbMatch) {
      score += 15;
      factors.push({ name: 'Known Vulnerable Vendor (Matched Database)', desc: `Vendor matches ${dbMatch.name} protocol family.`, severity: 'MEDIUM', pts: '+15' });
    }

    score = Math.min(100, score);
    return { score, factors };
  }

  function displayEstimatorResult(assessment) {
    scoreCircle.textContent = assessment.score;
    let color = '#10b981';
    let label = 'Low Threat';
    if (assessment.score >= 70) {
      color = '#ef4444';
      label = 'CRITICAL Threat';
    } else if (assessment.score >= 40) {
      color = '#f97316';
      label = 'HIGH Threat';
    } else if (assessment.score >= 20) {
      color = '#eab308';
      label = 'MEDIUM Threat';
    }

    scoreCircle.style.borderColor = color;
    scoreCircle.style.color = color;
    scoreLabel.textContent = `${assessment.score}/100 - ${label}`;
    scoreSub.textContent = assessment.score >= 40 ? 'High probability of programmable keystroke macro vulnerability.' : 'Standard input peripheral characteristics.';

    threatBreakdown.innerHTML = '';
    assessment.factors.forEach(f => {
      const item = document.createElement('div');
      item.className = 'threat-factor';
      item.innerHTML = `
        <div>
          <strong>${escapeHtml(f.name)}</strong>
          <div class="text-muted" style="font-size: 10px;">${escapeHtml(f.desc)}</div>
        </div>
        <div style="font-weight: 700; color: ${f.severity === 'CRITICAL' ? '#f87171' : '#fbbf24'};">${f.pts}</div>
      `;
      threatBreakdown.appendChild(item);
    });
  }

  estimatorAnalyzeBtn.addEventListener('click', () => {
    try {
      const parsed = JSON.parse(mockDescriptorInput.value);
      const assessment = evaluateDeviceDescriptor(parsed);
      displayEstimatorResult(assessment);
    } catch (e) {
      alert('Invalid JSON descriptor format: ' + e.message);
    }
  });

  estimatorConnectBtn.addEventListener('click', async () => {
    if (!navigator.hid) {
      alert('WebHID API not available in this browser window.');
      return;
    }
    try {
      const devices = await navigator.hid.requestDevice({ filters: [] });
      if (devices && devices.length > 0) {
        const dev = devices[0];
        mockDescriptorInput.value = JSON.stringify({
          vendorId: dev.vendorId,
          productId: dev.productId,
          productName: dev.productName,
          collections: dev.collections || []
        }, null, 2);
        const assessment = evaluateDeviceDescriptor(dev);
        displayEstimatorResult(assessment);
      }
    } catch (e) {
      console.warn('WebHID device selection cancelled or failed:', e);
    }
  });

  // 9. Enterprise Management & Backup
  function updateEnterpriseStatus() {
    if (currentConfig.managedPolicy) {
      managedStatusIndicator.classList.add('active');
      managedStatusTitle.textContent = 'Enterprise Managed Policy Active';
      managedStatusDesc.textContent = `Extension policies are enforced by enterprise administrator. Managed keys: ${Object.keys(currentConfig.managedPolicy).join(', ')}`;
    } else {
      managedStatusIndicator.classList.remove('active');
      managedStatusTitle.textContent = 'Unmanaged Local Instance';
      managedStatusDesc.textContent = 'Running with local browser configuration. Enterprise Managed Storage (chrome.storage.managed) is inactive.';
    }
  }

  exportSettingsBtn.addEventListener('click', () => {
    chrome.runtime.sendMessage({ action: 'EXPORT_SETTINGS' }, (res) => {
      if (res) {
        const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(res, null, 2));
        const dl = document.createElement('a');
        dl.setAttribute('href', dataStr);
        dl.setAttribute('download', `peripheralshield-config-backup-${Date.now()}.json`);
        dl.click();
      }
    });
  });

  importSettingsBtn.addEventListener('click', () => {
    importFileInput.click();
  });

  importFileInput.addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (event) => {
      try {
        const parsed = JSON.parse(event.target.result);
        chrome.runtime.sendMessage({
          action: 'IMPORT_SETTINGS',
          data: parsed
        }, (res) => {
          if (res && res.success) {
            showToast('Settings restored successfully! Reloading...');
            setTimeout(() => location.reload(), 1000);
          } else {
            alert('Import failed: ' + (res ? res.error : 'Unknown error'));
          }
        });
      } catch (err) {
        alert('Invalid JSON file: ' + err.message);
      }
    };
    reader.readAsText(file);
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

  // Run initial load
  await loadInitialData();
  // Run initial threat estimate on default JSON
  try {
    const initialDesc = JSON.parse(mockDescriptorInput.value);
    displayEstimatorResult(evaluateDeviceDescriptor(initialDesc));
  } catch (e) {}
});
