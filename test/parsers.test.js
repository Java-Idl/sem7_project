/**
 * Unit Tests: Peripheral Command & Protocol Parsers
 */

import { HIDppParser } from '../defensive-extension/core/parsers/hidpp-parser.js';
import { CH57XParser } from '../defensive-extension/core/parsers/ch57x-parser.js';
import { ZelotesParser } from '../defensive-extension/core/parsers/zelotes-parser.js';
import { UnifyingParser } from '../defensive-extension/core/parsers/unifying-parser.js';
import { RoccatParser, RedragonParser, FootSwitchParser } from '../defensive-extension/core/parsers/other-parsers.js';
import { MIDIParser } from '../defensive-extension/core/parsers/midi-parser.js';
import { SerialParser } from '../defensive-extension/core/parsers/serial-parser.js';

export function runParserTests(assert) {
  // =========================================================================
  // 1. Logitech HID++ Parser Tests
  // =========================================================================
  {
    // A. Unifying Receiver CVE-2019-13055 Bootloader Entry
    const bootloaderPayload = new Uint8Array([0xff, 0x80, 0xf0, 0x49, 0x43, 0x50]);
    const res1 = HIDppParser.parseReport(0x10, bootloaderPayload);
    assert(res1.isDangerous, true, 'HID++: Should block Unifying bootloader entry');
    assert(res1.opType, 'unifying_bootloader_entry', 'HID++: OpType should be unifying_bootloader_entry');

    // B. Unifying Receiver Key Dumping
    const keyDumpPayload = new Uint8Array([0xff, 0x81, 0xd4, 0x00, 0x10]);
    const res2 = HIDppParser.parseReport(0x10, keyDumpPayload);
    assert(res2.isDangerous, true, 'HID++: Should block AES key extraction');
    assert(res2.opType, 'unifying_key_extraction', 'HID++: OpType should be unifying_key_extraction');

    // C. HID++ 2.0 Feature 0x8100 Onboard Memory Write Transaction (Function 0x06)
    const featureMap = new Map([[0x07, 0x8100], [0x08, 0x8061], [0x09, 0x8110]]);
    const writePageStart = new Uint8Array([0x01, 0x07, 0x6a, 0x00, 0x02, 0x00]); // functionId 6 = writePage
    const res3 = HIDppParser.parseReport(0x11, writePageStart, featureMap);
    assert(res3.isDangerous, true, 'HID++: Should block Feature 0x8100 writePage transaction');

    // C2. HID++ 2.0 Feature 0x8100 Direct Macro Execution (Function 0x05)
    const execMacro = new Uint8Array([0x01, 0x07, 0x5a, 0x00, 0x06, 0x00]);
    const res3b = HIDppParser.parseReport(0x10, execMacro, featureMap);
    assert(res3b.isDangerous, true, 'HID++: Should block Feature 0x8100 direct macro execution');

    // C3. HID++ 2.0 Feature 0x8061 Button Remapping (Function 0x01)
    const setRemap = new Uint8Array([0x01, 0x08, 0x1a, 0x01, 0x00, 0x00]);
    const res3c = HIDppParser.parseReport(0x10, setRemap, featureMap);
    assert(res3c.isDangerous, true, 'HID++: Should block Feature 0x8061 button remapping');

    // C4. HID++ 2.0 Feature 0x8110 Button Spy Activation (Function 0x01)
    const spyActivate = new Uint8Array([0x01, 0x09, 0x1a, 0x01, 0x00]);
    const res3d = HIDppParser.parseReport(0x10, spyActivate, featureMap);
    assert(res3d.isDangerous, true, 'HID++: Should block Feature 0x8110 button spy activation');

    // C5. HID++ 2.0 Heuristic Block for unmapped sector prepare packet
    const rawPreparePacket = new Uint8Array([0x01, 0x0c, 0x6a, 0x00, 0x06, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00]);
    const res3e = HIDppParser.parseReport(0x11, rawPreparePacket, new Map()); // empty map!
    assert(res3e.isDangerous, true, 'HID++: Should heuristically block unmapped sector prepare packet');

    // D. HID++ 2.0 Safe Feature Query (GetFeature)
    const getFeature = new Uint8Array([0xff, 0x00, 0x0a, 0x81, 0x00]); // query feature 0x8100
    const res4 = HIDppParser.parseReport(0x10, getFeature);
    assert(res4.isDangerous, false, 'HID++: Should allow safe GetFeature query');

    // E. HID++ 1.0 writeMemory (subId 0x90, 0x91)
    const hidpp1Write = new Uint8Array([0x01, 0x90, 0x00, 0x01, 0x00, 0x00]);
    const res5 = HIDppParser.parseReport(0x11, hidpp1Write);
    assert(res5.isDangerous, true, 'HID++ 1.0: Should block writeMemory subId 0x90');
  }

  // =========================================================================
  // 2. CH57X Macropad Parser Tests
  // =========================================================================
  {
    // A. Key Update Start Command (0xa1)
    const keyUpdateStart = new Uint8Array(64);
    keyUpdateStart[0] = 0xa1;
    keyUpdateStart[1] = 0x01;
    const res1 = CH57XParser.parseReport(3, keyUpdateStart);
    assert(res1.isDangerous, true, 'CH57X: Should block Key Update Start opcode 0xa1');

    // B. Key Update End Command (0xaa)
    const keyUpdateEnd = new Uint8Array(64);
    keyUpdateEnd[0] = 0xaa;
    keyUpdateEnd[1] = 0xaa;
    const res2 = CH57XParser.parseReport(3, keyUpdateEnd);
    assert(res2.isDangerous, true, 'CH57X: Should block Key Update End opcode 0xaa');

    // C. Benign Hello Handshake
    const hello = new Uint8Array(64);
    const res3 = CH57XParser.parseReport(3, hello);
    assert(res3.isDangerous, false, 'CH57X: Should allow blank initialization report');
  }

  // =========================================================================
  // 3. Zelotes T90 & Speedlink Parser Tests
  // =========================================================================
  {
    // A. Macro bank setup opcode 0x03
    const macroStart = new Uint8Array(65);
    macroStart[0] = 0x18;
    macroStart[1] = 0x03;
    const res1 = ZelotesParser.parseFeatureReport(7, macroStart);
    assert(res1.isDangerous, true, 'Zelotes: Should block Feature 7 opcode 0x03 macro write');

    // B. Macro key sequence write opcode 0x09
    const keyPayload = new Uint8Array(65);
    keyPayload[0] = 0x18;
    keyPayload[1] = 0x09;
    const res2 = ZelotesParser.parseFeatureReport(7, keyPayload);
    assert(res2.isDangerous, true, 'Zelotes: Should block Feature 7 opcode 0x09 macro payload');
  }

  // =========================================================================
  // 4. USB Foot Switch Parser Tests
  // =========================================================================
  {
    // A. Foot Switch Macro Init
    const footInit = new Uint8Array([0x01, 0xc0, 0x00, 0x57, 0x04, 0x00, 0x00, 0x00]);
    const res1 = FootSwitchParser.parseReport(0, footInit);
    assert(res1.isDangerous, true, 'FootSwitch: Should block macro programming init 0x01 0xc0');

    // B. Foot Switch Epilogue / Activation
    const footActivate = new Uint8Array([0x01, 0x81, 0x08, 0x02, 0x00, 0x00, 0x00, 0x00]);
    const res2 = FootSwitchParser.parseReport(0, footActivate);
    assert(res2.isDangerous, true, 'FootSwitch: Should block macro activation 0x01 0x81');
  }

  // =========================================================================
  // 5. Roccat & Redragon Parser Tests
  // =========================================================================
  {
    // Roccat Feature Report 8 Write
    const roccatReport = new Uint8Array([0x08, 0x00, 0x01, 0x00]);
    const res1 = RoccatParser.parseFeatureReport(8, roccatReport);
    assert(res1.isDangerous, true, 'Roccat: Should block Feature Report 8 write');

    // Redragon Feature Report 6 Write
    const redragonReport = new Uint8Array([0x05, 0xdc, 0x00, 0x40]);
    const res2 = RedragonParser.parseFeatureReport(6, redragonReport);
    assert(res2.isDangerous, true, 'Redragon: Should block Feature Report 6 macro configuration write');
  }

  // =========================================================================
  // 6. WebMIDI SysEx Parser Tests
  // =========================================================================
  {
    // A. Launchpad MK2 Bootloader / Firmware SysEx frame
    const sysexFlash = new Uint8Array([0xf0, 0x00, 0x20, 0x29, 0x00, 0x71, 0x00, 0x01, 0xf7]);
    const res1 = MIDIParser.parseMessage(sysexFlash);
    assert(res1.isDangerous, true, 'MIDI: Should block Launchpad MK2 firmware write frame');

    // B. Normal Note On Event
    const noteOn = new Uint8Array([0x90, 0x3c, 0x7f]);
    const res2 = MIDIParser.parseMessage(noteOn);
    assert(res2.isDangerous, false, 'MIDI: Should allow normal musical Note On event');
  }

  // =========================================================================
  // 7. WebSerial AT Modem Parser Tests
  // =========================================================================
  {
    // A. SMS Send command
    const res1 = SerialParser.parseWriteChunk(new TextEncoder().encode('AT+CMGS="+123456789"\r'));
    assert(res1.isDangerous, true, 'Serial: Should block AT+CMGS SMS transmission');

    // B. SIM PIN entry
    const res2 = SerialParser.parseWriteChunk(new TextEncoder().encode('AT+CPIN="0000"\r\n'));
    assert(res2.isDangerous, true, 'Serial: Should block AT+CPIN access attempt');

    // C. Benign AT ping
    const res3 = SerialParser.parseWriteChunk(new TextEncoder().encode('AT\r\n'));
    assert(res3.isDangerous, false, 'Serial: Should allow safe AT handshake');
  }
}
