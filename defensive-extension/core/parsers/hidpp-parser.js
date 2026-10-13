/**
 * Parser for Logitech HID++ 1.0 and HID++ 2.0/4.x protocols.
 * Evaluates whether a report packet attempts dangerous memory access,
 * onboard profile alteration, or firmware updates.
 */

export class HIDppParser {
  /**
   * Evaluates an outgoing HID report for Logitech devices.
   * @param {number} reportId - The HID report ID (e.g. 0x10 for SHORT, 0x11 for LONG)
   * @param {Uint8Array} data - The report data payload
   * @param {Map<number, number>} [knownFeatureIndexes] - Mapping of featureIndex -> featureId (e.g. 0x8100)
   * @returns {{ isDangerous: boolean, reason?: string, opType?: string, featureId?: number }}
   */
  static parseReport(reportId, data, knownFeatureIndexes = new Map()) {
    if (!data || data.length < 3) {
      return { isDangerous: false, opType: 'invalid_or_short' };
    }

    const byte0 = data[0]; // deviceIndex (often 0xff or 0x00/0x01)
    const byte1 = data[1]; // featureIndex (HID++ 2.0) OR subId (HID++ 1.0)
    const byte2 = data[2]; // (functionId << 4) | swId

    // 1. Check Unifying Receiver Bootloader / Memory Extraction
    // Bootloader command: [0xff, 0x80, 0xf0, 0x49, 0x43, 0x50]
    if (byte0 === 0xff && byte1 === 0x80 && byte2 === 0xf0) {
      return {
        isDangerous: true,
        reason: 'Attempted to force Logitech Unifying Receiver into bootloader mode (CVE-2019-13055)',
        opType: 'unifying_bootloader_entry'
      };
    }

    // Direct memory read/key dump command: [0xff, 0x81, 0xd4, addrLSB, addrMSB]
    if (byte0 === 0xff && byte1 === 0x81 && byte2 === 0xd4) {
      return {
        isDangerous: true,
        reason: 'Attempted to extract internal AES pairing keys/memory from Logitech Unifying Receiver (CVE-2019-13055)',
        opType: 'unifying_key_extraction'
      };
    }

    // Unifying bootloader reset command: [255, 129, 241, ...]
    if (byte0 === 0xff && byte1 === 0x81 && byte2 === 0xf1) {
      return {
        isDangerous: true,
        reason: 'Logitech bootloader reset sequence command detected',
        opType: 'unifying_bootloader_reset'
      };
    }

    // 2. Check HID++ 2.0 Feature Query & Setup
    // Feature Index 0x00, Function 0x00 is IRoot::GetFeature(featureId) -> SAFE
    if (byte1 === 0x00 && ((byte2 >> 4) === 0x00)) {
      const requestedFeatureId = (data[3] << 8) | (data[4] || 0);
      return {
        isDangerous: false,
        opType: 'root_get_feature',
        queriedFeatureId: requestedFeatureId
      };
    }

    // Feature Index 0x03, Function 0x01 is getDeviceName -> SAFE
    if (byte1 === 0x03 && ((byte2 >> 4) === 0x01)) {
      return { isDangerous: false, opType: 'get_device_name' };
    }

    // Check if the target featureIndex is mapped
    const mappedFeatureId = knownFeatureIndexes.get(byte1);
    const functionId = byte2 >> 4;

    // Feature 0x8100 (Onboard Memory / Profiles)
    if (mappedFeatureId === 0x8100) {
      if (functionId === 0x01 || functionId === 0x06 || functionId === 0x07 || functionId === 0x08 || functionId === 0x0c) {
        return {
          isDangerous: true,
          reason: `Dangerous HID++ 2.0 onboard memory modification: functionId 0x0${functionId.toString(16)} (Feature 0x8100)`,
          opType: 'hidpp2_write_onboard_memory',
          featureId: 0x8100
        };
      }
      if (functionId === 0x05) {
        return {
          isDangerous: true,
          reason: 'Dangerous HID++ 2.0 onboard macro execution command (Feature 0x8100 Fn 0x05)',
          opType: 'hidpp2_exec_macro',
          featureId: 0x8100
        };
      }
    }

    // Feature 0x8061 (Special Keys / Button Remapping)
    if (mappedFeatureId === 0x8061) {
      if (functionId === 0x01 || functionId === 0x02 || functionId === 0x05) {
        return {
          isDangerous: true,
          reason: `Dangerous HID++ 2.0 button remapping attempt: functionId 0x0${functionId.toString(16)} (Feature 0x8061)`,
          opType: 'hidpp2_button_remapping',
          featureId: 0x8061
        };
      }
    }

    // Feature 0x8110 (Button Spy / Click Sniffing)
    if (mappedFeatureId === 0x8110) {
      if (functionId === 0x01) {
        return {
          isDangerous: true,
          reason: 'Dangerous HID++ 2.0 Button Spy broadcast activation (Feature 0x8110 Fn 0x01)',
          opType: 'hidpp2_button_spy_activate',
          featureId: 0x8110
        };
      }
    }

    // Generic check for direct feature discovery packets
    // Feature 0x8100: [0xff, 0x00, 0x0a, 0x81, 0x00]
    if (data[3] === 0x81 && data[4] === 0x00) {
      return {
        isDangerous: false,
        opType: 'query_feature_0x8100_index',
        notes: 'Host is discovering feature index for Onboard Memory (0x8100)'
      };
    }
    // Feature 0x8061: [0xff, 0x00, 0x0a, 0x80, 0x61]
    if (data[3] === 0x80 && data[4] === 0x61) {
      return {
        isDangerous: false,
        opType: 'query_feature_0x8061_index',
        notes: 'Host is discovering feature index for Button Remapping (0x8061)'
      };
    }
    // Feature 0x8110: [0xff, 0x00, 0x0a, 0x81, 0x10]
    if (data[3] === 0x81 && data[4] === 0x10) {
      return {
        isDangerous: false,
        opType: 'query_feature_0x8110_index',
        notes: 'Host is discovering feature index for Button Spy (0x8110)'
      };
    }

    // Heuristic signature fallback for unmapped/guessed feature indices:
    // Sector prepare wire pattern: Report 0x11, function 0x06 with length boundary 0xFF at byte 7
    if ((reportId === 0x11 || reportId === 17) && functionId === 0x06 && data.length >= 8 && data[3] === 0x00 && data[7] === 0xff) {
      return {
        isDangerous: true,
        reason: 'Heuristic Match: Unmapped HID++ 2.0 sector prepare write transaction detected (Function 0x06)',
        opType: 'heuristic_hidpp2_sector_prepare'
      };
    }
    // Sector write block: Report 0x11, function 0x07 (16-byte transfer chunks)
    if ((reportId === 0x11 || reportId === 17) && functionId === 0x07 && data.length >= 19) {
      return {
        isDangerous: true,
        reason: 'Heuristic Match: Unmapped HID++ 2.0 sector chunk write detected (Function 0x07)',
        opType: 'heuristic_hidpp2_sector_write'
      };
    }
    // Sector finalize: function 0x08
    if (functionId === 0x08 && data.length >= 3 && data[1] > 0x03) {
      return {
        isDangerous: true,
        reason: 'Heuristic Match: Unmapped HID++ 2.0 sector write finalize detected (Function 0x08)',
        opType: 'heuristic_hidpp2_sector_finalize'
      };
    }

    // 3. Check HID++ 1.0 (e.g. G500s) dangerous subIds
    // subId 0x90: writeMemory header; subId 0x91: writeMemory payload
    if (byte1 === 0x90 || byte1 === 0x91) {
      return {
        isDangerous: true,
        reason: `HID++ 1.0 direct internal memory write: subId 0x${byte1.toString(16)}`,
        opType: 'hidpp1_write_memory'
      };
    }

    // subId 0x80: writeShort register; register 0xa1 0x01 = reset sequence
    if (byte1 === 0x80 && data[2] === 0xa1 && data[3] === 0x01) {
      return {
        isDangerous: true,
        reason: 'HID++ 1.0 memory write reset sequence initiated',
        opType: 'hidpp1_reset_sequence'
      };
    }

    // subId 0x82: writeLong register; register 0xa0 0x02 = fillPage
    if (byte1 === 0x82 && data[2] === 0xa0 && data[3] === 0x02) {
      return {
        isDangerous: true,
        reason: 'HID++ 1.0 fillPage internal profile overwrite',
        opType: 'hidpp1_fill_page'
      };
    }

    // subId 0x80: writeShort register 0x0f: loadProfileAddress / setFactoryProfile
    if (byte1 === 0x80 && data[2] === 0x0f) {
      return {
        isDangerous: true,
        reason: 'HID++ 1.0 profile address override (register 0x0F)',
        opType: 'hidpp1_load_profile_address'
      };
    }

    return { isDangerous: false, opType: 'hidpp_general' };
  }
}
