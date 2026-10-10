/**
 * Parser for Logitech Unifying Receiver (CVE-2019-13055) and flash bootloader attacks.
 * Intercepts:
 * 1. Bootloader enter commands: [0xff, 0x80, 0xf0, 0x49, 0x43, 0x50] or [255, 129, 241, ...]
 * 2. Key/memory extraction commands: [0xff, 0x81, 0xd4, ...]
 * 3. Firmware flashing frames: report ID 0 or 16 starting with bootloader flash opcodes (144, 128, 192, 208)
 */

export class UnifyingParser {
  /**
   * Evaluates outgoing report on Logitech Unifying Receiver (PID 0xc52b, 0xaaac, etc.).
   * @param {number} reportId - HID report ID
   * @param {Uint8Array} data - Report data payload
   * @returns {{ isDangerous: boolean, reason?: string, opType?: string }}
   */
  static parseReport(reportId, data) {
    if (!data || data.length < 3) {
      return { isDangerous: false, opType: 'short_report' };
    }

    // 1. Bootloader trigger commands
    if (data[0] === 0xff && data[1] === 0x80 && data[2] === 0xf0) {
      return {
        isDangerous: true,
        reason: 'Attempted to force Logitech Unifying Receiver into flash bootloader mode (CVE-2019-13055)',
        opType: 'unifying_bootloader_command'
      };
    }

    if (data[0] === 255 && data[1] === 129 && data[2] === 241) {
      return {
        isDangerous: true,
        reason: 'Logitech Unifying flash bootloader restart command (255, 129, 241) detected',
        opType: 'unifying_bootloader_restart'
      };
    }

    // 2. Direct memory/AES key readout
    if (data[0] === 0xff && data[1] === 0x81 && data[2] === 0xd4) {
      const addrLSB = data[3] || 0;
      const addrMSB = data[4] || 0;
      const address = (addrMSB << 8) | addrLSB;
      return {
        isDangerous: true,
        reason: `Attempted to dump memory/extract AES pairing keys from address 0x${address.toString(16)} (CVE-2019-13055)`,
        opType: 'unifying_key_extraction'
      };
    }

    // 3. Firmware flash commands (sent on Report ID 0 or 16 in bootloader mode)
    // Common bootloader flashing opcodes: 144 (0x90), 128 (0x80), 192 (0xc0 - flash block data), 208 (0xd0 - flash sector/page write)
    const firstByte = data[0];
    if (reportId === 0 || reportId === 16) {
      if (firstByte === 144 || firstByte === 128 || firstByte === 192 || firstByte === 208) {
        return {
          isDangerous: true,
          reason: `Logitech flash bootloader write frame (opcode 0x${firstByte.toString(16)}, len ${data.length}) detected. Rogue firmware flash attempt.`,
          opType: 'unifying_firmware_flash'
        };
      }
    }

    return { isDangerous: false, opType: 'unifying_standard' };
  }
}
