/**
 * Defensive Browser Extension - Main World API Interceptor
 * Injected at document_start in world: "MAIN" across all frames.
 *
 * Implements bypass-resistant wrapping of WebHID, WebSerial, and WebMIDI APIs.
 * Enforces security policy on all device interactions and freezes prototypes.
 */

(function () {
  'use strict';

  // Guard against double initialization
  if (window.__DEFENSIVE_EXTENSION_INITIALIZED__) {
    return;
  }
  window.__DEFENSIVE_EXTENSION_INITIALIZED__ = true;

  // 1. Capture pristine primitives before page scripts can mutate them
  const _apply = Function.prototype.apply;
  const _call = Function.prototype.call;
  const _defineProperty = Object.defineProperty;
  const _freeze = Object.freeze;
  const _getOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
  const _slice = Array.prototype.slice;
  const _Map = window.Map;
  const _Set = window.Set;
  const _Uint8Array = window.Uint8Array;
  const _Promise = window.Promise;
  const _TextDecoder = window.TextDecoder;
  const _performance = window.performance;
  const _postMessage = window.postMessage.bind(window);

  // Helper to freeze property
  function lockProperty(obj, prop, value) {
    try {
      _defineProperty(obj, prop, {
        value: value,
        writable: false,
        configurable: false,
        enumerable: true
      });
    } catch (e) {
      // Ignore if already locked
    }
  }

  // Active state synced from background via bridge
  const state = {
    mode: 'Balanced', // Strict, Balanced, Permissive
    deviceOverrides: {},
    originAllowlist: [],
    knownFeatureIndexes: new _Map(),
    blockedCount: 0,
    devicesDatabase: []
  };

  // Channel token for authenticating messages to the isolated bridge script
  const CHANNEL_SOURCE = 'DEFENSIVE_EXTENSION_MAIN';
  const BRIDGE_SOURCE = 'DEFENSIVE_EXTENSION_BRIDGE';

  // Listen for configuration sync from isolated world bridge
  window.addEventListener('message', (event) => {
    if (event.source !== window || !event.data || event.data.source !== BRIDGE_SOURCE) {
      return;
    }
    const msg = event.data;
    if (msg.type === 'SYNC_CONFIG') {
      if (msg.config) {
        state.mode = msg.config.mode || state.mode;
        state.deviceOverrides = msg.config.deviceOverrides || state.deviceOverrides;
        state.originAllowlist = msg.config.originAllowlist || state.originAllowlist;
        if (Array.isArray(msg.config.devicesDatabase)) {
          state.devicesDatabase = msg.config.devicesDatabase;
        }
      }
    }
  });

  // Notify bridge of security events
  function reportEvent(eventType, payload) {
    try {
      _postMessage({
        source: CHANNEL_SOURCE,
        type: eventType,
        payload: {
          ...payload,
          origin: window.location.origin,
          href: window.location.href,
          timestamp: Date.now()
        }
      }, '*');
    } catch (e) {
      // Ignore serialization issues
    }
  }

  // Display rich in-page security alert toast
  function showBlockedNotification(deviceName, operation, reason, riskLevel) {
    try {
      const existing = document.getElementById('defensive-ext-toast');
      if (existing) existing.remove();

      const toast = document.createElement('div');
      toast.id = 'defensive-ext-toast';
      toast.setAttribute('style', `
        position: fixed !important;
        top: 20px !important;
        right: 20px !important;
        z-index: 2147483647 !important;
        background: #111827 !important;
        color: #f9fafb !important;
        border: 2px solid ${riskLevel === 'CRITICAL' ? '#ef4444' : '#f59e0b'} !important;
        border-radius: 10px !important;
        padding: 16px 20px !important;
        max-width: 420px !important;
        box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5), 0 10px 10px -5px rgba(0, 0, 0, 0.3) !important;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif !important;
        font-size: 13px !important;
        line-height: 1.5 !important;
        animation: defExtSlideIn 0.3s cubic-bezier(0.16, 1, 0.3, 1) !important;
      `);

      toast.innerHTML = `
        <div style="font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 11px;">
          <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #1f2937; padding-bottom: 6px; margin-bottom: 8px;">
            <div style="font-weight: 700; letter-spacing: 0.05em; color: ${riskLevel === 'CRITICAL' ? '#f87171' : '#fbbf24'};">
              [SECURITY INTERCEPTION] ${riskLevel}
            </div>
            <button id="defExtToastClose" style="background: none; border: 1px solid #374151; color: #9ca3af; border-radius: 3px; font-size: 10px; padding: 1px 6px; cursor: pointer;">Dismiss</button>
          </div>
          <div style="color: #e5e7eb; margin-bottom: 4px;">
            <strong>Target:</strong> ${deviceName} (${operation})
          </div>
          <div style="color: #9ca3af; line-height: 1.4; background: #0b0f19; padding: 6px 8px; border-radius: 4px; border: 1px solid #1f2937;">
            ${reason}
          </div>
        </div>
      `;

      (document.body || document.documentElement).appendChild(toast);
      const closeBtn = document.getElementById('defExtToastClose');
      if (closeBtn) {
        closeBtn.onclick = () => toast.remove();
      }
      setTimeout(() => {
        if (toast.parentNode) toast.remove();
      }, 7000);
    } catch (e) {
      // Notification fail-safe
    }
  }

  // =========================================================================
  // 2. PARSERS & PROTOCOL INSPECTION LOGIC (Bundled for zero-latency sync evaluation)
  // =========================================================================

  function inspectHIDReport(reportId, data, device) {
    const vid = device.vendorId;
    const pid = device.productId;
    const name = device.productName || 'HID Device';

    // A. Check Global Strict Mode
    if (state.mode === 'Strict') {
      return {
        isDangerous: true,
        reason: `Strict Policy: All outgoing HID writes to ${name} are blocked.`,
        opType: 'strict_policy_block'
      };
    }

    // B. Check Manual Per-Device Override
    const devKey = `${vid}:${pid}`;
    if (state.deviceOverrides[devKey] === 'always_allow') {
      return { isDangerous: false, reason: 'Device allowed by manual override' };
    }
    if (state.deviceOverrides[devKey] === 'always_block') {
      return {
        isDangerous: true,
        reason: `Manual Device Override: Device ${name} (${devKey}) is set to Always Block`,
        opType: 'manual_override_blocked'
      };
    }

    // C. Origin Allowlist Check
    if (state.originAllowlist.includes(window.location.origin)) {
      return { isDangerous: false, reason: 'Origin allowlisted' };
    }

    if (!data || data.length < 2) return { isDangerous: false };

    // D. Logitech HID++ (VID 0x046d = 1133)
    if (vid === 1133 || vid === 0x046d) {
      // Unifying Receiver bootloader entry: [0xff, 0x80, 0xf0]
      if (data[0] === 0xff && data[1] === 0x80 && data[2] === 0xf0) {
        return {
          isDangerous: true,
          reason: 'Attempted to force Unifying Receiver into bootloader mode (CVE-2019-13055)',
          opType: 'logitech_bootloader_entry'
        };
      }
      // Unifying Receiver pairing key extraction: [0xff, 0x81, 0xd4]
      if (data[0] === 0xff && data[1] === 0x81 && data[2] === 0xd4) {
        return {
          isDangerous: true,
          reason: 'Attempted to dump memory/extract AES pairing keys via WebHID (CVE-2019-13055)',
          opType: 'logitech_key_extraction'
        };
      }
      // Unifying Receiver bootloader flashing opcodes
      if ((reportId === 0 || reportId === 16) && (data[0] === 144 || data[0] === 128 || data[0] === 192 || data[0] === 208)) {
        return {
          isDangerous: true,
          reason: 'Attempted to write firmware flash frames to Logitech bootloader',
          opType: 'logitech_firmware_flash'
        };
      }

      // Check dynamic feature index via device registry or global state
      const record = getDeviceRecord(device);
      const mappedFeature = record.knownFeatureIndexes.get(data[1]) || state.knownFeatureIndexes.get(data[1]);
      const functionId = data[2] >> 4;

      // HID++ 2.0 Feature 0x8100 (Onboard Memory / Profiles)
      if (mappedFeature === 0x8100) {
        if (functionId === 0x01 || functionId === 0x06 || functionId === 0x07 || functionId === 0x08 || functionId === 0x0c) {
          return {
            isDangerous: true,
            reason: `Blocked HID++ Onboard Memory write (Feature 0x8100, function 0x0${functionId.toString(16)})`,
            opType: 'hidpp_onboard_memory_write'
          };
        }
        if (functionId === 0x05) {
          return {
            isDangerous: true,
            reason: 'Blocked HID++ Onboard Macro execution command (Feature 0x8100, function 0x05)',
            opType: 'hidpp_macro_execution'
          };
        }
      }

      // HID++ 2.0 Feature 0x8061 (Special Keys / Button Remapping)
      if (mappedFeature === 0x8061) {
        if (functionId === 0x01 || functionId === 0x02 || functionId === 0x05) {
          return {
            isDangerous: true,
            reason: `Blocked HID++ Button Remapping modification (Feature 0x8061, function 0x0${functionId.toString(16)})`,
            opType: 'hidpp_button_remapping'
          };
        }
      }

      // HID++ 2.0 Feature 0x8110 (Button Spy / Click Sniffing)
      if (mappedFeature === 0x8110) {
        if (functionId === 0x01) {
          return {
            isDangerous: true,
            reason: 'Blocked HID++ Button Spy click sniffing activation (Feature 0x8110, function 0x01)',
            opType: 'hidpp_button_spy_activate'
          };
        }
      }

      // Heuristic signatures for unmapped/guessed feature indices
      if ((reportId === 0x11 || reportId === 17) && functionId === 0x06 && data.length >= 8 && data[3] === 0x00 && data[7] === 0xff) {
        return {
          isDangerous: true,
          reason: 'Heuristic Block: Detected HID++ 2.0 sector prepare write transaction pattern',
          opType: 'heuristic_hidpp2_sector_prepare'
        };
      }
      if ((reportId === 0x11 || reportId === 17) && functionId === 0x07 && data.length >= 19) {
        return {
          isDangerous: true,
          reason: 'Heuristic Block: Detected HID++ 2.0 sector chunk write pattern',
          opType: 'heuristic_hidpp2_sector_write'
        };
      }
      if (functionId === 0x08 && data.length >= 3 && data[1] > 0x03) {
        return {
          isDangerous: true,
          reason: 'Heuristic Block: Detected HID++ 2.0 sector write finalize pattern',
          opType: 'heuristic_hidpp2_sector_finalize'
        };
      }
      if (functionId === 0x05 && data.length >= 6 && data[1] > 0x03) {
        return {
          isDangerous: true,
          reason: 'Heuristic Block: Detected HID++ 2.0 direct macro execution trigger pattern',
          opType: 'heuristic_hidpp2_macro_run'
        };
      }

      // HID++ 1.0 writeMemory (subId 0x90, 0x91)
      if (data[1] === 0x90 || data[1] === 0x91) {
        return {
          isDangerous: true,
          reason: `Blocked HID++ 1.0 direct writeMemory command (subId 0x${data[1].toString(16)})`,
          opType: 'hidpp1_write_memory'
        };
      }
      // HID++ 1.0 reset sequence / profile load (subId 0x80 with register 0xa1 or 0x0f)
      if (data[1] === 0x80 && (data[2] === 0xa1 || data[2] === 0x0f)) {
        return {
          isDangerous: true,
          reason: 'Blocked HID++ 1.0 profile configuration write sequence',
          opType: 'hidpp1_config_write'
        };
      }
    }

    // E. CH57X Macropad (VID 0x1189 = 4489, PID 0x8890 = 34960)
    if ((vid === 4489 && pid === 34960) || name.toLowerCase().includes('ch57')) {
      if (reportId === 3 || reportId === 0) {
        if (data[0] === 0xa1) {
          return {
            isDangerous: true,
            reason: 'CH57X Key Update Start command (0xa1) detected: Attempting to reprogram macro keys',
            opType: 'ch57x_key_update_start'
          };
        }
        if (data[0] === 0xaa && data[1] === 0xaa) {
          return {
            isDangerous: true,
            reason: 'CH57X Key Update Finalize command (0xaa 0xaa) detected',
            opType: 'ch57x_key_update_end'
          };
        }
        // Macro header sequence (Key index + Layer)
        if (data[0] >= 1 && data[0] <= 24 && (data[1] & 0xf0) && data[2] > 0) {
          return {
            isDangerous: true,
            reason: `CH57X Macro definition upload (Key ${data[0]}, Layer 0x${(data[1] & 0xf0).toString(16)}) detected`,
            opType: 'ch57x_macro_header'
          };
        }
      }
    }

    // F. Zelotes T90 & Speedlink (Holtek/Sino Wealth)
    if (vid === 12538 || name.toLowerCase().includes('zelotes') || name.toLowerCase().includes('speedlink')) {
      if (data[0] === 0x18) {
        const cmd = data[1];
        if (cmd === 0x03 || cmd === 0x09 || cmd === 0x00 || cmd === 0x05 || cmd === 0x10) {
          return {
            isDangerous: true,
            reason: `Zelotes/Speedlink macro programming packet (0x18, opcode 0x0${cmd.toString(16)}) detected`,
            opType: 'zelotes_programming_opcode'
          };
        }
      }
    }

    // G. PCsensor USB Foot Switch (VID 0x3553 = 13651, PID 0xb001 = 45057)
    if (vid === 13651 || name.toLowerCase().includes('foot switch')) {
      if (data[0] === 0x01 && (data[1] === 0xc0 || data[1] === 0xc1 || data[1] === 0x81 || data[1] === 0x82)) {
        return {
          isDangerous: true,
          reason: `USB Foot Switch macro programming command (0x01 0x${data[1].toString(16)}) detected`,
          opType: 'foot_switch_reprogramming'
        };
      }
    }

    // H. Generic Holtek / 0x18 signature across any device
    if (data[0] === 0x18 && (data[1] === 0x03 || data[1] === 0x09 || data[1] === 0x10)) {
      return {
        isDangerous: true,
        reason: 'Generic Holtek/Sino Wealth macro programming sequence (0x18) detected',
        opType: 'holtek_generic_macro'
      };
    }

    // Safe by default
    return { isDangerous: false };
  }

  function inspectSerialWrite(chunk) {
    if (state.mode === 'Strict') {
      return { isDangerous: true, reason: 'Strict Policy: All WebSerial writes blocked.' };
    }
    if (state.originAllowlist.includes(window.location.origin)) {
      return { isDangerous: false };
    }

    let text = '';
    if (typeof chunk === 'string') {
      text = chunk;
    } else if (chunk && (chunk instanceof ArrayBuffer || ArrayBuffer.isView(chunk))) {
      try {
        const u8 = chunk instanceof ArrayBuffer ? new _Uint8Array(chunk) : new _Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength);
        text = new _TextDecoder('utf-8', { fatal: false }).decode(u8);
      } catch (e) {}
    }

    const trimmed = text.trim();
    if (/^AT\+CMGS/i.test(trimmed)) {
      return { isDangerous: true, reason: 'AT+CMGS command blocked: Attempted to send unauthorized SMS messages via modem', opType: 'serial_sms_block' };
    }
    if (/^AT\+CPIN/i.test(trimmed)) {
      return { isDangerous: true, reason: 'AT+CPIN command blocked: Attempted to access or manipulate SIM card PIN', opType: 'serial_pin_block' };
    }
    if (/^AT(\^|\+)FLASH/i.test(trimmed) || /^AT\+FUS/i.test(trimmed)) {
      return { isDangerous: true, reason: 'Modem firmware flashing command blocked', opType: 'serial_flash_block' };
    }

    return { isDangerous: false };
  }

  function inspectMIDIMessage(data) {
    if (state.originAllowlist.includes(window.location.origin)) {
      return { isDangerous: false };
    }
    if (!data || data.length === 0) return { isDangerous: false };

    // In Strict mode, block all SysEx
    if (state.mode === 'Strict' && data[0] === 0xf0) {
      return { isDangerous: true, reason: 'Strict Policy: All WebMIDI SysEx messages blocked.' };
    }

    // Novation Launchpad MK2 bootloader force / firmware flasher: [0xf0, 0x00, 0x20, 0x29, 0x00, 0x71, 0x00, 0x69, 0xf7]
    if (data[0] === 0xf0 && data[1] === 0x00 && data[2] === 0x20 && data[3] === 0x29) {
      if (data[4] === 0x00 && data[5] === 0x71) {
        return {
          isDangerous: true,
          reason: 'Novation Launchpad MK2 SysEx Bootloader entry / firmware flashing opcode (0x00 0x71) blocked',
          opType: 'launchpad_bootloader_block'
        };
      }
      if (data.length > 64) {
        return {
          isDangerous: true,
          reason: `Novation Launchpad bulk SysEx firmware payload chunk (${data.length} bytes) blocked`,
          opType: 'launchpad_firmware_chunk_block'
        };
      }
    }

    // Very large SysEx streams (>128 bytes)
    if (data[0] === 0xf0 && data.length > 128) {
      return {
        isDangerous: true,
        reason: `Large SysEx stream (${data.length} bytes) blocked: Potential rogue firmware flash attempt`,
        opType: 'large_sysex_blocked'
      };
    }

    return { isDangerous: false };
  }

  // =========================================================================
  // 3. API WRAPPING & PROXYING
  // =========================================================================

  // --- Vulnerable Peripheral Detection & Connection Defense ---
  function isVulnerableVendor(vid) {
    return vid === 0x046d || vid === 1133 ||   // Logitech
           vid === 0x1189 || vid === 4489 ||   // WCH CH57x
           vid === 0x30fa || vid === 12538 ||  // Zelotes
           vid === 0x3553 || vid === 13651 ||  // FootSwitch
           vid === 0x1e7d || vid === 7805 ||   // Roccat
           vid === 0x258a || vid === 9610;     // Redragon
  }

  function inspectHIDConnection(options) {
    const origin = window.location.origin;
    if (state.originAllowlist.includes(origin)) {
      return { isDangerous: false };
    }
    if (state.mode === 'Permissive') {
      return { isDangerous: false };
    }

    const filters = options && Array.isArray(options.filters) ? options.filters : [];
    let targetsVulnerable = false;
    let targetName = 'Programmable Peripheral';

    if (filters.length === 0) {
      targetsVulnerable = true;
      targetName = 'All Connected Peripherals (Unfiltered Request)';
    } else {
      for (const f of filters) {
        if (f && isVulnerableVendor(f.vendorId)) {
          targetsVulnerable = true;
          if (f.vendorId === 0x046d || f.vendorId === 1133) targetName = 'Logitech Gaming Peripheral';
          else if (f.vendorId === 0x1189 || f.vendorId === 4489) targetName = 'CH57X Macro Hardware';
          break;
        }
      }
    }

    if (targetsVulnerable) {
      return {
        isDangerous: true,
        reason: `Blocked untrusted origin '${origin}' from requesting access to ${targetName}`,
        opType: 'untrusted_connection_blocked'
      };
    }

    return { isDangerous: false };
  }

  // Multi-collection TLC Shared State Registry
  const deviceRegistry = new _Map();
  function getDeviceRecord(dev) {
    const vid = dev ? dev.vendorId : 0;
    const pid = dev ? dev.productId : 0;
    const key = `${vid}:${pid}`;
    if (!deviceRegistry.has(key)) {
      deviceRegistry.set(key, {
        knownFeatureIndexes: new _Map(),
        pendingQueries: new _Map(), // swId -> featureId
        devices: new _Set()
      });
    }
    const record = deviceRegistry.get(key);
    if (dev) record.devices.add(dev);
    return record;
  }

  function sniffInputReport(device, event) {
    try {
      if (!event || !event.data) return;
      const record = getDeviceRecord(device);
      const u8 = new _Uint8Array(event.data.buffer, event.data.byteOffset, event.data.byteLength);
      if (u8.length < 4) return;

      const devIdx = u8[0];
      const featIdx = u8[1];
      const fnSw = u8[2];
      const fnId = (fnSw >> 4) & 0x0F;
      const swId = fnSw & 0x0F;

      // Root feature (0x00) response to GetFeature(featureId)
      if (featIdx === 0x00 && fnId === 0x00) {
        const runtimeIdx = u8[3];
        const queriedFeatId = record.pendingQueries.get(swId);
        if (runtimeIdx !== 0 && queriedFeatId) {
          record.knownFeatureIndexes.set(runtimeIdx, queriedFeatId);
          state.knownFeatureIndexes.set(runtimeIdx, queriedFeatId);
          console.log(`[DEFENSIVE EXTENSION] Synchronized Feature 0x${queriedFeatId.toString(16)} -> Runtime Index 0x${runtimeIdx.toString(16)} across all collections for ${device.productName || 'Device'}`);
        }
      }
    } catch (e) {}
  }

  // --- WebHID Interception ---
  if (window.navigator && window.navigator.hid) {
    const origRequestDevice = window.navigator.hid.requestDevice;
    const origGetDevices = window.navigator.hid.getDevices;

    const wrapDevice = (device) => {
      if (!device || device.__DEFENSIVE_WRAPPED__) return device;

      const deviceName = device.productName || 'HID Device';
      const vid = device.vendorId;
      const pid = device.productId;
      const record = getDeviceRecord(device);

      // Wrap sendReport
      const origSendReport = device.sendReport;
      device.sendReport = async function (reportId, data) {
        const u8 = data instanceof _Uint8Array ? data : new _Uint8Array(data);
        const verdict = inspectHIDReport(reportId, u8, device);

        if (verdict.isDangerous) {
          state.blockedCount++;
          console.warn(`[DEFENSIVE EXTENSION] Blocked sendReport on ${deviceName}: ${verdict.reason}`);
          reportEvent('OPERATION_BLOCKED', {
            device: deviceName,
            vendorId: vid,
            productId: pid,
            method: 'sendReport',
            reportId,
            reason: verdict.reason,
            opType: verdict.opType,
            riskLevel: 'CRITICAL'
          });
          showBlockedNotification(deviceName, `sendReport(ID ${reportId})`, verdict.reason, 'CRITICAL');
          return _Promise.resolve(); // Drop silently or resolve to prevent script crash
        }

        // Track Root feature queries (GetFeature)
        if (u8.length >= 5 && u8[1] === 0x00 && ((u8[2] >> 4) === 0x00)) {
          const swId = u8[2] & 0x0F;
          const requestedFeatId = (u8[3] << 8) | (u8[4] || 0);
          record.pendingQueries.set(swId, requestedFeatId);
        }

        return _apply.call(origSendReport, this, arguments);
      };

      // Wrap sendFeatureReport
      const origSendFeatureReport = device.sendFeatureReport;
      device.sendFeatureReport = async function (reportId, data) {
        const u8 = data instanceof _Uint8Array ? data : new _Uint8Array(data);
        const verdict = inspectHIDReport(reportId, u8, device);

        if (verdict.isDangerous) {
          state.blockedCount++;
          console.warn(`[DEFENSIVE EXTENSION] Blocked sendFeatureReport on ${deviceName}: ${verdict.reason}`);
          reportEvent('OPERATION_BLOCKED', {
            device: deviceName,
            vendorId: vid,
            productId: pid,
            method: 'sendFeatureReport',
            reportId,
            reason: verdict.reason,
            opType: verdict.opType,
            riskLevel: 'CRITICAL'
          });
          showBlockedNotification(deviceName, `sendFeatureReport(ID ${reportId})`, verdict.reason, 'CRITICAL');
          return _Promise.resolve();
        }

        return _apply.call(origSendFeatureReport, this, arguments);
      };

      // Wrap open to ensure connection protection
      const origOpen = device.open;
      device.open = async function () {
        const origin = window.location.origin;
        if (!state.originAllowlist.includes(origin) && state.mode !== 'Permissive') {
          if (isVulnerableVendor(vid) || state.mode === 'Strict') {
            const reason = `Blocked untrusted origin '${origin}' from opening programmable device ${deviceName}`;
            state.blockedCount++;
            reportEvent('OPERATION_BLOCKED', {
              device: deviceName,
              vendorId: vid,
              productId: pid,
              method: 'open',
              reason,
              opType: 'untrusted_device_open_blocked',
              riskLevel: 'CRITICAL'
            });
            showBlockedNotification(deviceName, 'device.open()', reason, 'CRITICAL');
            throw new DOMException(reason, 'SecurityError');
          }
        }

        reportEvent('DEVICE_CONNECTED', {
          device: deviceName,
          vendorId: vid,
          productId: pid,
          type: 'HID'
        });
        return _apply.call(origOpen, this, arguments);
      };

      // Hook addEventListener for inputreport across collections
      const origAddEventListener = device.addEventListener;
      if (origAddEventListener) {
        device.addEventListener = function (type, listener, options) {
          if (type === 'inputreport') {
            const wrappedListener = function (event) {
              sniffInputReport(device, event);
              if (typeof listener === 'function') {
                return _apply.call(listener, this, arguments);
              } else if (listener && typeof listener.handleEvent === 'function') {
                return listener.handleEvent(event);
              }
            };
            return _apply.call(origAddEventListener, this, [type, wrappedListener, options]);
          }
          return _apply.call(origAddEventListener, this, arguments);
        };
      }

      // Ensure internal sniffer runs on this device collection
      try {
        if (origAddEventListener) {
          _apply.call(origAddEventListener, device, ['inputreport', function (event) {
            sniffInputReport(device, event);
          }]);
        }
      } catch (e) {}

      // Mark wrapped and lock device methods
      lockProperty(device, '__DEFENSIVE_WRAPPED__', true);
      lockProperty(device, 'sendReport', device.sendReport);
      lockProperty(device, 'sendFeatureReport', device.sendFeatureReport);
      lockProperty(device, 'open', device.open);
      if (origAddEventListener) {
        lockProperty(device, 'addEventListener', device.addEventListener);
      }

      return device;
    };

    window.navigator.hid.requestDevice = async function (options) {
      const connVerdict = inspectHIDConnection(options);
      if (connVerdict.isDangerous) {
        state.blockedCount++;
        reportEvent('OPERATION_BLOCKED', {
          device: 'WebHID Peripheral',
          method: 'requestDevice',
          reason: connVerdict.reason,
          opType: connVerdict.opType,
          riskLevel: 'CRITICAL'
        });
        showBlockedNotification('WebHID Connection Request', 'navigator.hid.requestDevice()', connVerdict.reason, 'CRITICAL');
        throw new DOMException(connVerdict.reason, 'SecurityError');
      }

      const devices = await _apply.call(origRequestDevice, this, arguments);
      return Array.isArray(devices) ? devices.map(wrapDevice) : devices;
    };
    lockProperty(window.navigator.hid, 'requestDevice', window.navigator.hid.requestDevice);

    window.navigator.hid.getDevices = async function () {
      const devices = await _apply.call(origGetDevices, this, arguments);
      return Array.isArray(devices) ? devices.map(wrapDevice) : devices;
    };
    lockProperty(window.navigator.hid, 'getDevices', window.navigator.hid.getDevices);

    // Freeze HIDDevice prototype methods
    if (window.HIDDevice && window.HIDDevice.prototype) {
      const origProtoSendReport = window.HIDDevice.prototype.sendReport;
      window.HIDDevice.prototype.sendReport = async function (reportId, data) {
        wrapDevice(this);
        return _apply.call(this.sendReport, this, arguments);
      };
      lockProperty(window.HIDDevice.prototype, 'sendReport', window.HIDDevice.prototype.sendReport);

      const origProtoSendFeatureReport = window.HIDDevice.prototype.sendFeatureReport;
      window.HIDDevice.prototype.sendFeatureReport = async function (reportId, data) {
        wrapDevice(this);
        return _apply.call(this.sendFeatureReport, this, arguments);
      };
      lockProperty(window.HIDDevice.prototype, 'sendFeatureReport', window.HIDDevice.prototype.sendFeatureReport);

      _freeze(window.HIDDevice.prototype);
    }
  }

  // --- WebSerial Interception ---
  if (window.navigator && window.navigator.serial) {
    const origRequestPort = window.navigator.serial.requestPort;
    const origGetPorts = window.navigator.serial.getPorts;

    const wrapSerialPort = (port) => {
      if (!port || port.__DEFENSIVE_WRAPPED__) return port;

      const info = typeof port.getInfo === 'function' ? port.getInfo() : {};
      const devName = `Serial Port (VID:${info.usbVendorId || 'N/A'} PID:${info.usbProductId || 'N/A'})`;

      // Intercept writable property getter
      const origWritableDesc = _getOwnPropertyDescriptor(window.SerialPort.prototype, 'writable');
      if (origWritableDesc && origWritableDesc.get) {
        const origGetWritable = origWritableDesc.get;

        _defineProperty(port, 'writable', {
          get: function () {
            const rawWritable = _call.call(origGetWritable, this);
            if (!rawWritable || rawWritable.__DEFENSIVE_WRAPPED__) return rawWritable;

            const origGetWriter = rawWritable.getWriter;
            rawWritable.getWriter = function () {
              const writer = _call.call(origGetWriter, this);
              const origWrite = writer.write;

              writer.write = async function (chunk) {
                const verdict = inspectSerialWrite(chunk);
                if (verdict.isDangerous) {
                  state.blockedCount++;
                  console.warn(`[DEFENSIVE EXTENSION] Blocked WebSerial write: ${verdict.reason}`);
                  reportEvent('OPERATION_BLOCKED', {
                    device: devName,
                    method: 'serial.write',
                    reason: verdict.reason,
                    riskLevel: 'CRITICAL'
                  });
                  showBlockedNotification(devName, 'serial.write()', verdict.reason, 'CRITICAL');
                  return _Promise.resolve(); // Drop write packet
                }
                return _apply.call(origWrite, this, arguments);
              };

              lockProperty(writer, 'write', writer.write);
              return writer;
            };

            lockProperty(rawWritable, 'getWriter', rawWritable.getWriter);
            lockProperty(rawWritable, '__DEFENSIVE_WRAPPED__', true);
            return rawWritable;
          },
          configurable: false,
          enumerable: true
        });
      }

      lockProperty(port, '__DEFENSIVE_WRAPPED__', true);
      return port;
    };

    window.navigator.serial.requestPort = async function () {
      const port = await _apply.call(origRequestPort, this, arguments);
      return wrapSerialPort(port);
    };
    lockProperty(window.navigator.serial, 'requestPort', window.navigator.serial.requestPort);

    window.navigator.serial.getPorts = async function () {
      const ports = await _apply.call(origGetPorts, this, arguments);
      return Array.isArray(ports) ? ports.map(wrapSerialPort) : ports;
    };
    lockProperty(window.navigator.serial, 'getPorts', window.navigator.serial.getPorts);

    if (window.SerialPort && window.SerialPort.prototype) {
      _freeze(window.SerialPort.prototype);
    }
  }

  // --- WebMIDI Interception ---
  if (window.navigator && window.navigator.requestMIDIAccess) {
    const origRequestMIDIAccess = window.navigator.requestMIDIAccess;

    const wrapMIDIOutput = (output) => {
      if (!output || output.__DEFENSIVE_WRAPPED__) return output;

      const origSend = output.send;
      output.send = function (data, timestamp) {
        const u8 = data instanceof _Uint8Array ? data : new _Uint8Array(data);
        const verdict = inspectMIDIMessage(u8);

        if (verdict.isDangerous) {
          state.blockedCount++;
          console.warn(`[DEFENSIVE EXTENSION] Blocked WebMIDI SysEx send on ${output.name || 'MIDI Output'}: ${verdict.reason}`);
          reportEvent('OPERATION_BLOCKED', {
            device: output.name || 'MIDI Output',
            method: 'MIDIOutput.send',
            reason: verdict.reason,
            riskLevel: 'CRITICAL'
          });
          showBlockedNotification(output.name || 'MIDI Controller', 'SysEx send()', verdict.reason, 'CRITICAL');
          return; // Drop message
        }

        return _apply.call(origSend, this, arguments);
      };

      lockProperty(output, 'send', output.send);
      lockProperty(output, '__DEFENSIVE_WRAPPED__', true);
      return output;
    };

    window.navigator.requestMIDIAccess = async function () {
      const midiAccess = await _apply.call(origRequestMIDIAccess, this, arguments);
      if (midiAccess && midiAccess.outputs) {
        for (const output of midiAccess.outputs.values()) {
          wrapMIDIOutput(output);
        }
        midiAccess.addEventListener('statechange', (e) => {
          if (e.port && e.port.type === 'output') {
            wrapMIDIOutput(e.port);
          }
        });
      }
      return midiAccess;
    };
    lockProperty(window.navigator, 'requestMIDIAccess', window.navigator.requestMIDIAccess);

    if (window.MIDIOutput && window.MIDIOutput.prototype) {
      const origProtoSend = window.MIDIOutput.prototype.send;
      window.MIDIOutput.prototype.send = function (data, timestamp) {
        wrapMIDIOutput(this);
        return _apply.call(this.send, this, arguments);
      };
      lockProperty(window.MIDIOutput.prototype, 'send', window.MIDIOutput.prototype.send);
      _freeze(window.MIDIOutput.prototype);
    }
  }

  // 4. Request initial policy configuration from isolated bridge
  _postMessage({
    source: CHANNEL_SOURCE,
    type: 'GET_CONFIG'
  }, '*');

  console.log('[DEFENSIVE EXTENSION] Secure API Interceptor active in MAIN world.');
})();
