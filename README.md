# PeripheralShield - WebHID/Serial/MIDI Hardware Defense Extension

**PeripheralShield** is an enterprise-grade, bypass-resistant **Chromium Manifest V3 browser extension** designed to protect endpoint machines from unauthorized peripheral device reprogramming, rogue keystroke injection (BadUSB-over-WebHID), firmware tampering, and cellular modem exploitation.

The defensive rules, signature engines, and threat estimators in PeripheralShield are modeled directly on empirical hardware vulnerability research from the [CISPA PeripheralInstinct repository](https://github.com/cispa/PeripheralInstinct).

---

## Architecture Overview

Modern Chromium browsers expose powerful low-level hardware interfaces to web applications via **WebHID**, **WebSerial**, and **WebMIDI**. While designed for configurator web apps, these APIs can be abused by malicious pages to reprogram peripheral flash memory and onboard microcontrollers:

```
┌────────────────────────────────────────────────────────────────────────┐
│                          WEB PAGE (DOM)                                │
│   navigator.hid.sendReport()  /  port.writable.getWriter().write()    │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                         [ MAIN WORLD INTERCEPTION ]
                                    │
               ┌────────────────────▼────────────────────┐
               │    PeripheralShield API Interceptor     │
               │   - Native prototype frozen (freeze)    │
               │   - Writable & configurable: false      │
               │   - Synchronous signature evaluation    │
               └────────────────────┬────────────────────┘
                                    │
           ┌────────────────────────┴────────────────────────┐
           │                                                 │
 [ BLOCKED MALICIOUS PACKET ]                      [ PERMITTED BENIGN PACKET ]
           │                                                 │
           ▼                                                 ▼
 - Abort transmission                              - Call pristine native method
 - Display in-DOM security toast                   - Allow hardware communication
 - Notify isolated bridge                          
 - Log to persistent Audit Log & SIEM
```

### Bypass-Resistant Dual-World Design
1. **Main World Interceptor (`core/interceptor.js`):** Injected at `document_start` with `world: "MAIN"` across all frames. Captures pristine JavaScript primitives (`Function.prototype.apply`, `Object.defineProperty`) before any page scripts can tamper with them. Prototype methods (`HIDDevice.prototype.sendReport`, `SerialPort.prototype.writable`, `MIDIOutput.prototype.send`) are locked with `writable: false, configurable: false`, and prototypes are frozen (`Object.freeze`).
2. **Isolated World Bridge (`content/bridge.js`):** Runs in `world: "ISOLATED"`. Translates local `window.postMessage` telemetry into privileged `chrome.runtime.sendMessage` calls to the background service worker.
3. **Background Service Worker (`background/service-worker.js`):** Manages local storage, badge notification counters, enterprise policy enforcement (`chrome.storage.managed`), and Native Messaging SIEM forwarding.

---

## Protected Vulnerability Matrix

PeripheralShield contains dedicated protocol parsers modeled after the devices documented in `PeripheralInstinct`:

| Peripheral Device | Protocol / Interface | Vulnerability Vector | Defense Implemented |
| :--- | :--- | :--- | :--- |
| **Logitech G502 HERO / G203 / G305** | WebHID (HID++ 2.0 / 4.x) | Feature 0x8100 Onboard Memory overwrite to rebind buttons to simulated keystrokes (`Win+R`, `cmd.exe`) | Blocks Feature 0x8100 `writePage` (functions 0x01, 0x06, 0x07, 0x08) while permitting DPI reads and safe feature queries |
| **Logitech G500s** | WebHID (HID++ 1.0) | Direct memory writing via subId 0x90/0x91 and temporary profile loading | Blocks `writeMemory` chunks (subId 0x90, 0x91) and profile loading registers |
| **Logitech Unifying Receiver** | WebHID | CVE-2019-13055: AES pairing key memory readout (`0xff 0x81 0xd4`) and bootloader forcing (`0xff 0x80 0xf0`) | Neutralizes key dumping requests and drops unauthenticated firmware flashing blocks |
| **WCH CH57X Macro Keyboards** | WebHID | Report ID 3 vendor opcodes (`0xa1`, `0xaa`) silently reprogramming multi-step macro keystrokes | Drops `sendKeyUpdateStart` (`0xa1`) and `sendKeyUpdateEnd` (`0xaa`) while allowing hello handshake |
| **Zelotes T90 & Speedlink Decus** | WebHID (Holtek) | Feature Report 7 opcode `0x18` writing persistent keystroke sequences to profile memory | Intercepts Feature 7 opcodes `0x03`, `0x09`, `0x10`, and `0x05` |
| **PCsensor USB Foot Switch** | WebHID | Report 0 macro initialization (`0x01 0xc0`) and key activation scripting | Blocks macro initialization headers and activation triggers |
| **Roccat Kone Aimo 16K** | WebHID | Multi-report configuration sequence (Reports 8, 13, 14) remapping profile 2 | Blocks Feature Report 8 macro uploads and Feature Report 13 raw payloads |
| **Redragon K629 & M711** | WebHID | Feature Reports 5 and 6 writing keystroke macro chunks | Blocks Feature Report 6 macro script configuration packets |
| **Novation Launchpad MK2** | WebMIDI | SysEx firmware flasher frames (`0xf0 0x00 0x20 0x29 0x00 0x71 ... 0xf7`) | Intercepts bootloader flashing frames while permitting musical Note On/Off and CC events |
| **Fibocom L850-GL Cellular Modem** | WebSerial | Hayes AT commands sending unauthenticated SMS messages (`AT+CMGS`) or querying PIN (`AT+CPIN`) | Proxies write stream and drops dangerous AT commands while permitting diagnostic `AT` queries |
| **Unknown Programmable Peripherals** | WebHID Heuristic Fallback | Ported from `mitigation/tool.html`: compound keyboard interfaces with vendor-defined usage pages (>= 0xFF00) | Computes a live threat score (0-100) and blocks high-risk macro flash payloads |

---

## Directory Structure

```text
├── defensive-extension/              # Primary Chromium Extension
│   ├── manifest.json                 # Manifest V3 declaration
│   ├── background/
│   │   └── service-worker.js         # Storage, badge alerts, enterprise managed policy
│   ├── content/
│   │   └── bridge.js                 # Isolated-world bridge script
│   ├── core/
│   │   ├── interceptor.js            # Main-world bypass-resistant API interceptor
│   │   ├── policy-engine.js          # Strict / Balanced / Permissive policy evaluator
│   │   ├── device-classifier.js      # Device lookup and risk classification
│   │   ├── threat-estimator.js       # Heuristic HID collection risk evaluator
│   │   └── parsers/                  # Dedicated protocol parsers
│   │       ├── hidpp-parser.js
│   │       ├── ch57x-parser.js
│   │       ├── zelotes-parser.js
│   │       ├── unifying-parser.js
│   │       ├── other-parsers.js
│   │       ├── midi-parser.js
│   │       └── serial-parser.js
│   ├── data/
│   │   └── devices.json              # Catalog of known vulnerable peripherals & opcodes
│   ├── popup/                        # Extension toolbar popup UI
│   │   ├── popup.html
│   │   ├── popup.css
│   │   └── popup.js
│   ├── options/                      # Enterprise dashboard & audit log UI
│   │   ├── options.html
│   │   ├── options.css
│   │   └── options.js
│   └── icons/                        # 16px, 32px, 48px, 128px assets
├── native-host/                      # OS-Level SIEM companion host
│   ├── host.py                       # Python native messaging host
│   ├── host.js                       # Node.js native messaging host
│   ├── host.bat                      # Windows wrapper script
│   ├── com.defensive.extension.host.json # Chromium native host manifest
│   ├── install.bat / uninstall.bat   # Windows registry installer
│   ├── install.sh                    # Linux / macOS installer
│   └── README.md
├── test/                             # Automated test suite
│   ├── mock-devices.js               # Mock WebHID / Serial / MIDI devices
│   ├── parsers.test.js               # Protocol signature unit tests
│   ├── policy.test.js                # Policy engine & override tests
│   ├── classifier.test.js            # Classifier & threat estimator tests
│   └── run-tests.js                  # Test runner (61/61 passing)
├── testbed/                          # Interactive exploit verification workbench
│   ├── index.html                    # Hands-on simulation UI
│   ├── testbed.css
│   └── testbed.js
└── README.md
```

---

## Installation & Setup

### 1. Load Extension in Chromium
1. Open Google Chrome, Microsoft Edge, or Brave.
2. Navigate to `chrome://extensions/` (or `edge://extensions/`).
3. Enable **Developer mode** toggle in the top-right corner.
4. Click **Load unpacked** and select the `defensive-extension` directory.
5. Pin the **PeripheralShield** icon to your browser toolbar.

### 2. Optional: Install Native Messaging SIEM Host
To enable OS-level event logging into `~/.peripheralshield/security_alerts.jsonl`:
- **Windows:** Run `native-host\install.bat` as the current user.
- **Linux/macOS:** Run `chmod +x native-host/install.sh && ./native-host/install.sh`.

---

## Running the Automated Test Suite

PeripheralShield includes a complete zero-dependency unit test suite covering every protocol parser, override rule, and threat estimation factor:

```bash
node test/run-tests.js
```

Output:
```text
===================================================
  PeripheralShield Test Suite - Unit & Protocol Tests
===================================================

[1/3] Running Peripheral Protocol Parser Tests...
  ✓ HID++: Should block Unifying bootloader entry
  ✓ HID++: Should block AES key extraction
  ✓ HID++: Should block Feature 0x8100 writePage transaction
  ✓ HID++: Should allow safe GetFeature query
  ✓ HID++ 1.0: Should block writeMemory subId 0x90
  ✓ CH57X: Should block Key Update Start opcode 0xa1
  ✓ CH57X: Should block Key Update End opcode 0xaa
  ✓ Zelotes: Should block Feature 7 opcode 0x03 macro write
  ✓ FootSwitch: Should block macro programming init 0x01 0xc0
  ✓ Roccat: Should block Feature Report 8 write
  ✓ Redragon: Should block Feature Report 6 macro configuration write
  ✓ MIDI: Should block Launchpad MK2 firmware write frame
  ✓ Serial: Should block AT+CMGS SMS transmission
  ...
===================================================
ALL TESTS PASSED! (61 assertions in 2ms)
===================================================
```

---

## Interactive Exploit Verification Testbed

An interactive testbed is included in `testbed/index.html`. To run:
1. Serve the workspace locally:
   ```bash
   npx serve .
   # Or using python:
   python -m http.server 8000
   ```
2. Navigate to `http://localhost:8000/testbed/index.html` in your Chromium browser with PeripheralShield loaded.
3. Observe:
   - Green indicator confirming active MAIN-world protection.
   - Click any **Simulate Attack** button to verify that the dangerous payload is blocked, a red security notification appears on-screen, and an entry is logged.
   - Click any **Send Benign** button to verify that legitimate diagnostic reads continue to function smoothly.

---

## Enterprise Managed Storage (`chrome.storage.managed`)

In corporate environments deployed via Google Admin Console or Microsoft Intune, administrators can configure enterprise policies:

```json
{
  "mode": "Strict",
  "allowedOrigins": [
    "https://firmware-portal.corp.internal"
  ],
  "blockedDevices": [
    "1133:49291",
    "4489:34960"
  ],
  "enforceStrict": true
}
```
PeripheralShield automatically ingests `chrome.storage.managed` on startup and overrides local user settings.
