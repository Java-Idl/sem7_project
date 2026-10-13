/**
 * Policy Engine Module
 * Evaluates operation permissions against global policy mode (Strict / Balanced / Permissive),
 * per-device overrides, per-origin allowlists, and protocol command parsers.
 */

import { HIDppParser } from './parsers/hidpp-parser.js';
import { CH57XParser } from './parsers/ch57x-parser.js';
import { ZelotesParser } from './parsers/zelotes-parser.js';
import { UnifyingParser } from './parsers/unifying-parser.js';
import { RoccatParser, RedragonParser, FootSwitchParser } from './parsers/other-parsers.js';
import { MIDIParser } from './parsers/midi-parser.js';
import { SerialParser } from './parsers/serial-parser.js';

export const POLICY_MODES = {
  STRICT: 'Strict',
  BALANCED: 'Balanced',
  PERMISSIVE: 'Permissive'
};

export class PolicyEngine {
  /**
   * @param {object} config - Configuration object
   */
  constructor(config = {}) {
    this.mode = config.mode || POLICY_MODES.BALANCED;
    this.deviceOverrides = config.deviceOverrides || {}; // key: "vid:pid" -> "always_allow" | "always_block" | "follow_policy"
    this.originAllowlist = new Set(config.originAllowlist || []); // Set of allowed origins (e.g. "https://trusted-site.com")
    this.managedPolicy = config.managedPolicy || null; // Enterprise admin policy
    this.knownFeatureIndexes = new Map(); // Dynamic mapping: featureIndex -> featureId (e.g. 0x8100)

    if (this.managedPolicy && (this.managedPolicy.enforceStrict || this.managedPolicy.mode === POLICY_MODES.STRICT)) {
      this.mode = POLICY_MODES.STRICT;
    }
  }

  /**
   * Updates configuration dynamically from storage.
   * @param {object} newConfig
   */
  updateConfig(newConfig) {
    if (newConfig.mode) this.mode = newConfig.mode;
    if (newConfig.deviceOverrides) this.deviceOverrides = newConfig.deviceOverrides;
    if (newConfig.originAllowlist) this.originAllowlist = new Set(newConfig.originAllowlist);
    if (newConfig.managedPolicy) {
      this.managedPolicy = newConfig.managedPolicy;
      if (this.managedPolicy.enforceStrict || this.managedPolicy.mode === POLICY_MODES.STRICT) {
        this.mode = POLICY_MODES.STRICT;
      }
    }
  }

  evaluateHIDOperation(classification, method, reportId, data, origin = '') {
    return this.evaluateHID(classification, method, reportId, data, origin);
  }

  /**
   * Evaluates a device connection request (navigator.hid.requestDevice).
   * Defends against untrusted origins requesting high-risk programmable hardware.
   * @param {string} origin - window.location.origin
   * @param {Array<object>} filters - HID device filters passed to requestDevice
   * @returns {{ allowed: boolean, reason: string, opType: string, riskLevel: string, shouldNotify: boolean }}
   */
  evaluateHIDConnection(origin = '', filters = []) {
    // 1. Check Origin Allowlist
    if (origin && this.originAllowlist.has(origin)) {
      return {
        allowed: true,
        reason: `Origin '${origin}' is explicitly trusted in user allowlist`,
        opType: 'origin_allowlisted',
        riskLevel: 'LOW',
        shouldNotify: false
      };
    }

    // 2. Strict Mode blocks all device requests
    if (this.mode === POLICY_MODES.STRICT) {
      return {
        allowed: false,
        reason: `Strict Mode active: Blocked WebHID requestDevice() from ${origin}`,
        opType: 'strict_mode_block_connection',
        riskLevel: 'CRITICAL',
        shouldNotify: true
      };
    }

    // 3. Permissive Mode allows all for audit logging
    if (this.mode === POLICY_MODES.PERMISSIVE) {
      return {
        allowed: true,
        reason: 'Permissive Mode: Device request permitted for audit monitoring',
        opType: 'permissive_connection_allowed',
        riskLevel: 'LOW',
        shouldNotify: false
      };
    }

    // 4. Balanced Mode: Check if requested filters target vulnerable programmable peripherals
    const vulnerableVendors = new Set([
      1133, 0x046d,  // Logitech
      4489, 0x1189,  // WCH CH57x
      12538, 0x30fa, // Zelotes
      13651, 0x3553, // FootSwitch
      7805, 0x1e7d,  // Roccat
      9610, 0x258a   // Redragon
    ]);

    let targetsVulnerable = false;
    let targetName = 'Programmable Peripheral';

    if (!Array.isArray(filters) || filters.length === 0) {
      targetsVulnerable = true;
      targetName = 'All Connected Peripherals (Unfiltered Request)';
    } else {
      for (const f of filters) {
        if (f && vulnerableVendors.has(f.vendorId)) {
          targetsVulnerable = true;
          if (f.vendorId === 1133 || f.vendorId === 0x046d) targetName = 'Logitech Gaming Peripheral';
          else if (f.vendorId === 4489 || f.vendorId === 0x1189) targetName = 'CH57X Macro Hardware';
          break;
        }
      }
    }

    if (targetsVulnerable) {
      return {
        allowed: false,
        reason: `Untrusted origin '${origin}' blocked from acquiring ${targetName}`,
        opType: 'untrusted_connection_blocked',
        riskLevel: 'CRITICAL',
        shouldNotify: true
      };
    }

    return {
      allowed: true,
      reason: 'Device filters do not target known programmable hardware',
      opType: 'benign_connection_allowed',
      riskLevel: 'LOW',
      shouldNotify: false
    };
  }

  /**
   * Registers a discovered HID feature index for a device (e.g. 0x8100 mapped to index 7).
   * @param {number} featureIndex
   * @param {number} featureId
   */
  registerFeatureIndex(featureIndex, featureId) {
    this.knownFeatureIndexes.set(featureIndex, featureId);
  }

  /**
   * Evaluates an outgoing WebHID operation.
   * @param {object} classification - Output of DeviceClassifier
   * @param {string} method - 'sendReport' | 'sendFeatureReport' | 'open'
   * @param {number} reportId - HID report ID
   * @param {Uint8Array} data - Report payload
   * @param {string} origin - Calling page origin (window.location.origin)
   * @returns {{ allowed: boolean, reason: string, opType: string, riskLevel: string, shouldNotify: boolean }}
   */
  evaluateHID(classification, method, reportId, data, origin = '') {
    const devInfo = classification?.deviceInfo || classification?.device || {};
    const vid = devInfo.vendorId;
    const pid = devInfo.productId;
    const devKey = `${vid}:${pid}`;
    const riskLevel = classification?.riskLevel || 'MEDIUM';

    // 1. Check Enterprise Managed Policy
    if (this.managedPolicy) {
      if (Array.isArray(this.managedPolicy.blockedDevices) && this.managedPolicy.blockedDevices.includes(devKey)) {
        return {
          allowed: false,
          reason: 'Blocked by Enterprise Administrator Policy',
          opType: 'enterprise_blocked',
          riskLevel: 'CRITICAL',
          shouldNotify: true
        };
      }
      if (Array.isArray(this.managedPolicy.allowedOrigins) && this.managedPolicy.allowedOrigins.includes(origin)) {
        return {
          allowed: true,
          reason: 'Permitted by Enterprise Origin Allowlist',
          opType: 'enterprise_origin_allowed',
          riskLevel: 'LOW',
          shouldNotify: false
        };
      }
    }

    // 2. Check Origin Allowlist
    if (origin && this.originAllowlist.has(origin)) {
      return {
        allowed: true,
        reason: `Origin '${origin}' is explicitly trusted in user allowlist`,
        opType: 'origin_allowlisted',
        riskLevel: 'LOW',
        shouldNotify: false
      };
    }

    // 3. Check Per-Device Override
    const devName = classification?.name || devInfo.name || 'Device';
    const deviceOverride = this.deviceOverrides[devKey];
    if (deviceOverride === 'always_block') {
      return {
        allowed: false,
        reason: `Device ${devName} (${devKey}) is manually set to Always Block`,
        opType: 'device_override_blocked',
        riskLevel: 'CRITICAL',
        shouldNotify: true
      };
    }
    if (deviceOverride === 'always_allow') {
      return {
        allowed: true,
        reason: `Device ${devName} (${devKey}) is manually set to Always Allow`,
        opType: 'device_override_allowed',
        riskLevel: 'LOW',
        shouldNotify: false
      };
    }

    // 4. Evaluate under Policy Mode: STRICT
    if (this.mode === POLICY_MODES.STRICT) {
      // In Strict mode, all write/feature reports are blocked
      return {
        allowed: false,
        reason: `Strict Mode active: Blocked all ${method} calls to ${classification.name}`,
        opType: 'strict_mode_block_all_writes',
        riskLevel,
        shouldNotify: true
      };
    }

    // 5. Handle device.open() gating
    if (method === 'open') {
      if (this.mode === POLICY_MODES.BALANCED) {
        const isVulnerable = vid === 1133 || vid === 0x046d || vid === 4489 || vid === 0x1189 || vid === 12538 || vid === 0x30fa || vid === 13651 || vid === 0x3553 || riskLevel === 'CRITICAL';
        if (isVulnerable && origin && !this.originAllowlist.has(origin)) {
          return {
            allowed: false,
            reason: `Untrusted origin '${origin}' blocked from opening programmable peripheral (${devName})`,
            opType: 'untrusted_device_open_blocked',
            riskLevel: 'CRITICAL',
            shouldNotify: true
          };
        }
      }
      return {
        allowed: true,
        reason: 'Device open permitted',
        opType: 'open_allowed',
        riskLevel: 'LOW',
        shouldNotify: false
      };
    }

    // 6. Evaluate Protocol-Specific Commands in BALANCED or PERMISSIVE
    let parserVerdict = { isDangerous: false, opType: 'safe' };

    // A. Logitech HID++
    if (vid === 1133 || vid === 0x046d) {
      // Check Unifying receiver bootloader / memory dump
      const unifyingRes = UnifyingParser.parseReport(reportId, data);
      if (unifyingRes.isDangerous) {
        parserVerdict = unifyingRes;
      } else {
        parserVerdict = HIDppParser.parseReport(reportId, data, this.knownFeatureIndexes);
      }
    }
    // B. CH57X Macropad
    else if (vid === 4489 || vid === 0x1189) {
      parserVerdict = CH57XParser.parseReport(reportId, data);
    }
    // C. Zelotes / Speedlink (Holtek)
    else if (vid === 12538 || vid === 0x30fa || classification.name.toLowerCase().includes('zelotes')) {
      parserVerdict = ZelotesParser.parseFeatureReport(reportId, data);
    }
    // D. Roccat Kone Aimo
    else if (vid === 7805 || vid === 0x1e7d) {
      parserVerdict = RoccatParser.parseFeatureReport(reportId, data);
    }
    // E. Redragon
    else if (vid === 9610 || vid === 0x258a) {
      parserVerdict = RedragonParser.parseFeatureReport(reportId, data);
    }
    // F. PCsensor USB Foot Switch
    else if (vid === 13651 || vid === 0x3553) {
      parserVerdict = FootSwitchParser.parseReport(reportId, data);
    }
    // G. Heuristic inspection for unknown device
    else {
      // Check for generic Zelotes/Speedlink 0x18 signature
      if (data && data[0] === 0x18) {
        parserVerdict = ZelotesParser.parseFeatureReport(reportId, data);
      }
      // Check if unknown device has high risk and is receiving large write packets (>32 bytes)
      else if ((riskLevel === 'CRITICAL' || riskLevel === 'HIGH') && data && data.length > 32) {
        parserVerdict = {
          isDangerous: true,
          reason: `High-risk unknown peripheral received large write report (${data.length} bytes)`,
          opType: 'heuristic_large_write_blocked'
        };
      }
    }

    // In PERMISSIVE mode, we warn & log but do not block
    if (this.mode === POLICY_MODES.PERMISSIVE) {
      return {
        allowed: true,
        reason: parserVerdict.isDangerous
          ? `[WARNING] ${parserVerdict.reason || 'Dangerous command allowed in Permissive Mode'}`
          : 'Permitted in Permissive Mode',
        opType: parserVerdict.opType || 'permissive_allowed',
        riskLevel,
        shouldNotify: parserVerdict.isDangerous
      };
    }

    // In BALANCED mode:
    if (parserVerdict.isDangerous) {
      return {
        allowed: false,
        reason: parserVerdict.reason || 'Blocked dangerous peripheral configuration operation',
        opType: parserVerdict.opType || 'dangerous_command_blocked',
        riskLevel: 'CRITICAL',
        shouldNotify: true
      };
    }

    // Default safe operation
    return {
      allowed: true,
      reason: 'Safe operation permitted',
      opType: parserVerdict.opType || 'safe_operation',
      riskLevel: 'SAFE',
      shouldNotify: false
    };
  }

  /**
   * Evaluates outgoing WebSerial write chunk.
   */
  evaluateSerial(classification, chunk, origin = '') {
    if (origin && this.originAllowlist.has(origin)) {
      return { allowed: true, reason: 'Origin allowlisted', opType: 'serial_allowed', shouldNotify: false };
    }

    if (this.mode === POLICY_MODES.STRICT) {
      return {
        allowed: false,
        reason: 'Strict Mode active: Blocked all WebSerial write operations',
        opType: 'strict_serial_blocked',
        riskLevel: 'CRITICAL',
        shouldNotify: true
      };
    }

    const res = SerialParser.parseWriteChunk(chunk);

    if (this.mode === POLICY_MODES.PERMISSIVE) {
      return {
        allowed: true,
        reason: res.isDangerous ? `[WARNING] ${res.reason}` : 'Permissive serial write',
        opType: res.opType,
        riskLevel: 'MEDIUM',
        shouldNotify: res.isDangerous
      };
    }

    if (res.isDangerous) {
      return {
        allowed: false,
        reason: res.reason,
        opType: res.opType,
        riskLevel: 'CRITICAL',
        shouldNotify: true
      };
    }

    return { allowed: true, reason: 'Safe serial command', opType: res.opType, riskLevel: 'SAFE', shouldNotify: false };
  }

  /**
   * Evaluates outgoing WebMIDI message.
   */
  evaluateMIDI(classification, data, origin = '') {
    if (origin && this.originAllowlist.has(origin)) {
      return { allowed: true, reason: 'Origin allowlisted', opType: 'midi_allowed', shouldNotify: false };
    }

    if (this.mode === POLICY_MODES.STRICT && data && data[0] === 0xf0) {
      return {
        allowed: false,
        reason: 'Strict Mode active: Blocked all WebMIDI SysEx messages',
        opType: 'strict_midi_sysex_blocked',
        riskLevel: 'CRITICAL',
        shouldNotify: true
      };
    }

    const res = MIDIParser.parseMessage(data);

    if (this.mode === POLICY_MODES.PERMISSIVE) {
      return {
        allowed: true,
        reason: res.isDangerous ? `[WARNING] ${res.reason}` : 'Permissive MIDI message',
        opType: res.opType,
        riskLevel: 'MEDIUM',
        shouldNotify: res.isDangerous
      };
    }

    if (res.isDangerous) {
      return {
        allowed: false,
        reason: res.reason,
        opType: res.opType,
        riskLevel: 'CRITICAL',
        shouldNotify: true
      };
    }

    return { allowed: true, reason: 'Musical MIDI message permitted', opType: res.opType, riskLevel: 'SAFE', shouldNotify: false };
  }
}
