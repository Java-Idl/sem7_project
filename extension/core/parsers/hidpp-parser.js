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

    // Check if the target featureIndex is mapped to 0x8100 (Onboard Memory)
    const mappedFeatureId = knownFeatureIndexes.get(byte1);
    if (mappedFeatureId === 0x8100) {
      const functionId = byte2 >> 4;
      // 0x01 = setOnboardMode, 0x05 = readPage, 0x06 = startTransaction, 0x07 = writeBlock, 0x08 = endTransaction
      if (functionId === 0x01 || functionId === 0x06 || functionId === 0x07 || functionId === 0x08) {
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
          reason: 'HID++ 2.0 onboard memory page read (extracting profiles/macros)',
          opType: 'hidpp2_read_onboard_memory',
          featureId: 0x8100
        };
      }
    }

    // Generic check for direct feature 0x8100 discovery packet
    // e.g. [0xff, 0x00, 0x0a, 0x81, 0x00, 0x00]
    if (data[3] === 0x81 && data[4] === 0x00) {
      return {
        isDangerous: false,
        opType: 'query_feature_0x8100_index',
        notes: 'Host is discovering feature index for Onboard Memory (0x8100)'
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
