/**
 * Parser for WCH CH57X microcontrollers used in programmable macropads and keyboards.
 * Intercepts Report ID 3 update opcodes (0xa1, 0xaa) and macro key binding arrays.
 */

export class CH57XParser {
  /**
   * Evaluates outgoing report on CH57X device (VID 0x1189, PID 0x8890).
   * @param {number} reportId - HID report ID
   * @param {Uint8Array} data - Report data payload
   * @returns {{ isDangerous: boolean, reason?: string, opType?: string }}
   */
  static parseReport(reportId, data) {
    if (!data || data.length === 0) {
      return { isDangerous: false, opType: 'empty' };
    }

    // Handshake: 64-byte zero buffer -> SAFE
    let isAllZero = true;
    for (let i = 0; i < data.length; i++) {
      if (data[i] !== 0) {
        isAllZero = false;
        break;
      }
    }
    if (isAllZero) {
      return { isDangerous: false, opType: 'ch57x_hello_handshake' };
    }

    // CH57X communicates via Report ID 3
    if (reportId === 3 || reportId === 0) {
      const opcode = data[0];

      // 0xa1: Key Update Start (e.g. data[0] = 0xa1, data[1] = layer + 1)
      if (opcode === 0xa1) {
        const layer = (data[1] || 1) - 1;
        return {
          isDangerous: true,
          reason: `CH57X Key Update Start command (opcode 0xa1, Layer ${layer}) detected. Attempting to reprogram physical key bindings.`,
          opType: 'ch57x_key_update_start'
        };
      }

      // 0xaa: Key Update End (e.g. data[0] = 0xaa, data[1] = 0xaa)
      if (opcode === 0xaa && data[1] === 0xaa) {
        return {
          isDangerous: true,
          reason: 'CH57X Key Update Finalize/End command (opcode 0xaa 0xaa) detected.',
          opType: 'ch57x_key_update_end'
        };
      }

      // Macro header packet: data[0] = key (1-16), data[1] = layer + type (0x11, 0x12, 0x21, etc.), data[2] = sequence length
      const keyIndex = data[0];
      const layerType = data[1];
      const seqLen = data[2];

      // If key is between 1-16 and layerType matches known layers (0x10, 0x20, 0x30) + types (1: Keys, 2: Media, 3: Mouse)
      const layer = layerType & 0xf0;
      const type = layerType & 0x0f;
      if (keyIndex >= 1 && keyIndex <= 24 && (layer === 0x10 || layer === 0x20 || layer === 0x30) && (type >= 1 && type <= 3)) {
        return {
          isDangerous: true,
          reason: `CH57X Macro Header programming detected: Key ${keyIndex}, Layer 0x${layer.toString(16)}, Type ${type}, Length ${seqLen}.`,
          opType: 'ch57x_program_key_header'
        };
      }

      // Keystroke stream packet: data[3] = index, data[4] = modifier, data[5] = scancode
      if (data.length >= 6 && data[4] !== undefined && data[5] !== undefined && (data[4] > 0 || data[5] > 0)) {
        // High likelihood of macro payload chunk
        return {
          isDangerous: true,
          reason: `CH57X Macro Keystroke data packet (Modifier: 0x${data[4].toString(16)}, KeyCode: 0x${data[5].toString(16)}) detected.`,
          opType: 'ch57x_keystroke_payload'
        };
      }
    }

    return { isDangerous: false, opType: 'ch57x_unknown' };
  }
}
