/**
 * Parser for WebMIDI messages.
 * Intercepts dangerous System Exclusive (SysEx) messages targeting MIDI controllers
 * such as Novation Launchpad MK2 (manufacturer ID 0x00 0x20 0x29, bootloader opcode 0x71)
 * while allowing standard musical performance messages (Note On, Note Off, CC, Polyphonic Aftertouch).
 */

export class MIDIParser {
  /**
   * Evaluates outgoing MIDI message data.
   * @param {number[] | Uint8Array} data - MIDI message byte array
   * @returns {{ isDangerous: boolean, reason?: string, opType?: string, isSysEx: boolean }}
   */
  static parseMessage(data) {
    if (!data || data.length === 0) {
      return { isDangerous: false, isSysEx: false, opType: 'empty' };
    }

    const firstByte = data[0];

    // Standard Non-SysEx messages (0x80 - 0xef)
    // 0x80..0x8f: Note Off -> SAFE
    // 0x90..0x9f: Note On -> SAFE
    // 0xa0..0xaf: Polyphonic Key Pressure -> SAFE
    // 0xb0..0xbf: Control Change -> SAFE
    // 0xc0..0xcf: Program Change -> SAFE
    // 0xd0..0xdf: Channel Pressure -> SAFE
    // 0xe0..0xef: Pitch Bend Change -> SAFE
    if (firstByte >= 0x80 && firstByte <= 0xef) {
      return { isDangerous: false, isSysEx: false, opType: 'standard_midi_channel_voice' };
    }

    // System Real-Time messages (0xf8 - 0xff) -> Clock, Start, Continue, Stop, Active Sensing, Reset -> SAFE
    if (firstByte >= 0xf8 && firstByte <= 0xff) {
      return { isDangerous: false, isSysEx: false, opType: 'midi_realtime' };
    }

    // System Exclusive (SysEx): starts with 0xf0
    if (firstByte === 0xf0) {
      // 1. Check Novation Launchpad MK2 bootloader & firmware flasher
      // Launchpad MK2 bootloader trigger: [0xf0, 0x00, 0x20, 0x29, 0x00, 0x71, 0x00, 0x69, 0xf7]
      // Manufacturer ID: 0x00, 0x20, 0x29 (Novation)
      if (data.length >= 7 && data[1] === 0x00 && data[2] === 0x20 && data[3] === 0x29) {
        // Opcode 0x00 0x71 is bootloader force / firmware update start
        if (data[4] === 0x00 && data[5] === 0x71) {
          return {
            isDangerous: true,
            isSysEx: true,
            reason: 'Novation Launchpad MK2 SysEx command to force Bootloader mode / flash firmware (opcode 0x00 0x71) detected',
            opType: 'launchpad_bootloader_force'
          };
        }

        // Long SysEx packet with Novation header indicates firmware binary chunk
        if (data.length > 64) {
          return {
            isDangerous: true,
            isSysEx: true,
            reason: `Novation Launchpad MK2 bulk SysEx firmware payload chunk (${data.length} bytes) detected`,
            opType: 'launchpad_firmware_upload'
          };
        }
      }

      // 2. Generic Dangerous SysEx Heuristics:
      // SysEx packets larger than 128 bytes are typically firmware flashing streams or device dump overwrite
      if (data.length > 128) {
        return {
          isDangerous: true,
          isSysEx: true,
          reason: `Large SysEx stream (${data.length} bytes) detected. High risk of peripheral firmware overwriting.`,
          opType: 'large_sysex_bulk_write'
        };
      }

      // Check for Universal Non-Real Time SysEx Handshake / File Dump
      // 0xf0 0x7e (universal non-realtime), sub-ID 0x07 / 0x08 (sample dump / MIDI machine control / flash)
      if (data[1] === 0x7e && (data[3] === 0x06 || data[3] === 0x07 || data[3] === 0x08)) {
        return {
          isDangerous: true,
          isSysEx: true,
          reason: 'Universal Non-Real Time SysEx firmware/memory management request detected',
          opType: 'universal_sysex_flash_command'
        };
      }

      // Normal harmless short SysEx (e.g. RGB pad lighting update or inquiry)
      return {
        isDangerous: false,
        isSysEx: true,
        opType: 'short_sysex_allowed'
      };
    }

    return { isDangerous: false, isSysEx: false, opType: 'midi_common' };
  }
}
