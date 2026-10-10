# Security Policy & Threat Model

## Threat Model & Attack Surface

PeripheralShield mitigates threats stemming from the exposure of low-level hardware communication APIs in the web browser (WebHID, WebSerial, WebMIDI).

### Attack Scenarios Mitigated
1. **BadUSB-over-WebHID:**
   - A user visits an attacker-controlled website or a site vulnerable to Cross-Site Scripting (XSS).
   - The page requests access to a plugged-in programmable mouse, keyboard, or macropad.
   - The malicious script sends vendor-specific HID reports that rewrite device non-volatile flash or EEPROM to remap button clicks into automated keystroke injection sequences (e.g., launching PowerShell / Terminal).
2. **Firmware & Key Extraction:**
   - Exploitation of bootloader endpoints (e.g., Logitech Unifying CVE-2019-13055) to dump AES link keys or flash rogue firmware into wireless transceivers.
3. **WebSerial Modem Abuse:**
   - Transmission of cellular AT commands (e.g. `AT+CMGS`) to send premium-rate SMS messages or exfiltrate local data over the cellular modem without user awareness.
4. **WebMIDI Controller Hijacking:**
   - Overwriting MIDI controller firmware memory through SysEx packets.

---

## Defensive Guarantees & Bypass Resistance

### 1. Prototype Immutability
- Interception hooks are installed in `world: "MAIN"` at `document_start` before any page scripts execute.
- Pristine ECMAScript reflection primitives (`Function.prototype.apply`, `Object.defineProperty`) are captured and held in private lexical scope.
- `HIDDevice.prototype`, `SerialPort.prototype`, and `MIDIOutput.prototype` are locked with `writable: false, configurable: false`, and sealed with `Object.freeze`.
- Any attempt by page scripts to reassign `navigator.hid.requestDevice`, delete properties, or monkey-patch prototypes will throw in strict mode or fail silently.

### 2. Stream Interception
- WebSerial writes occur through stream writers (`port.writable.getWriter().write(...)`). PeripheralShield intercepts the `writable` property getter on `SerialPort.prototype` to proxy the stream chunks inline before they reach OS device handles.

### 3. Synchronous Inline Evaluation
- The core protocol parsers evaluate signatures synchronously during the function invocation. There are no asynchronous race windows or delays where a script could queue a packet before the parser finishes.

---

## Reporting Vulnerabilities

If you discover a security bypass, prototype escape, or parser evasion in PeripheralShield, please submit a responsible disclosure report via GitHub Security Advisories or contact the maintainers directly.
