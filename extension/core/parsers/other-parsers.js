/**
 * Parsers for Roccat Kone Aimo, Redragon, and PCsensor USB Foot Switch peripherals.
 */

export class RoccatParser {
  /**
   * Evaluates feature report for Roccat Kone Aimo devices.
   * Reports 8, 13, 14 are used for macro writing.
   */
  static parseFeatureReport(reportId, data) {
    if (!data) return { isDangerous: false };

    // Report 8 contains macro header / name ("My Macros", "My Macro") + keystroke codes
    if (reportId === 8) {
      // Check for macro text or non-trivial length
      const text = String.fromCharCode(...data.slice(0, 32));
      return {
        isDangerous: true,
        reason: `Roccat Feature Report 8 macro definition upload detected (${text.replace(/[\x00-\x1f\x7f-\xff]/g, '').trim() || 'Binary macro stream'})`,
        opType: 'roccat_macro_upload'
      };
    }

    // Report 13 sends raw macro chunks starting with 0x2e
    if (reportId === 13 && data[0] === 0x2e) {
      return {
        isDangerous: true,
        reason: 'Roccat Feature Report 13 macro sequence chunk (prefix 0x2e) detected',
        opType: 'roccat_macro_chunk'
      };
    }

    // Report 14 activates the macro profile
    if (reportId === 14 && data.length >= 4) {
      return {
        isDangerous: true,
        reason: 'Roccat Feature Report 14 profile / macro activation command detected',
        opType: 'roccat_profile_activate'
      };
    }

    return { isDangerous: false, opType: 'roccat_safe' };
  }
}

export class RedragonParser {
  /**
   * Evaluates feature reports for Redragon mice and keyboards.
   */
  static parseFeatureReport(reportId, data) {
    if (!data) return { isDangerous: false };

    // Mouse: Feature Report 4 (button remapping, size ~70 bytes)
    if (reportId === 4 && data.length >= 60) {
      return {
        isDangerous: true,
        reason: 'Redragon Feature Report 4 button remapping / macro configuration detected',
        opType: 'redragon_mouse_rebind'
      };
    }

    // Mouse: Feature Report 6 (macro keystroke array upload)
    if (reportId === 6 && data.length > 20) {
      return {
        isDangerous: true,
        reason: 'Redragon Feature Report 6 keystroke macro stream detected',
        opType: 'redragon_macro_upload'
      };
    }

    // Keyboard (K629): Feature Report 5 init (0x84, 0xd4)
    if (reportId === 5 && data[0] === 0x84 && data[1] === 0xd4) {
      return {
        isDangerous: true,
        reason: 'Redragon Keyboard Feature Report 5 macro programming init (0x84 0xd4) detected',
        opType: 'redragon_kb_init'
      };
    }

    // Keyboard (K629): Feature Report 6 macro matrix write (0x05, 0xdc or 0x04, 0xd4 or 0x08, 0xb8)
    if (reportId === 6 && (data[0] === 0x05 || data[0] === 0x04 || data[0] === 0x08)) {
      return {
        isDangerous: true,
        reason: `Redragon Keyboard Feature Report 6 matrix/macro write (opcode 0x${data[0].toString(16)} 0x${data[1].toString(16)}) detected`,
        opType: 'redragon_kb_macro'
      };
    }

    return { isDangerous: false, opType: 'redragon_safe' };
  }
}

export class FootSwitchParser {
  /**
   * Evaluates output report for PCsensor USB Foot Switch.
   */
  static parseReport(reportId, data) {
    if (!data || data.length < 2) return { isDangerous: false };

    // Report ID 0 with 0x01, 0xc0 -> macro programming init
    if (data[0] === 0x01 && data[1] === 0xc0) {
      return {
        isDangerous: true,
        reason: 'USB Foot Switch macro programming init command (0x01 0xc0) detected',
        opType: 'foot_switch_init'
      };
    }

    // Report ID 0 with 0x01, 0xc1 -> epilogue
    if (data[0] === 0x01 && data[1] === 0xc1) {
      return {
        isDangerous: true,
        reason: 'USB Foot Switch macro programming epilogue command (0x01 0xc1) detected',
        opType: 'foot_switch_epilogue'
      };
    }

    // Report ID 0 with 0x01, 0x81 / 0x82 -> activate macro
    if (data[0] === 0x01 && (data[1] === 0x81 || data[1] === 0x82)) {
      return {
        isDangerous: true,
        reason: `USB Foot Switch macro activation command (0x01 0x${data[1].toString(16)}) detected`,
        opType: 'foot_switch_activate'
      };
    }

    return { isDangerous: false, opType: 'foot_switch_safe' };
  }
}
