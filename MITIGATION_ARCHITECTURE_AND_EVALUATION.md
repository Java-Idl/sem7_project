# PeripheralShield: Technical Architecture, Academic Mitigation Analysis, and System Evaluation

**Project:** PeripheralShield (Semester 7 Capstone Project)  
**Target Vulnerabilities:** Unauthorized WebHID/WebSerial/WebMIDI Peripheral Reprogramming, BadUSB-over-WebHID, and Physical Keylogger Exploitation  
**Baseline Academic Research:** CISPA Helmholtz Center for Information Security & Saarland University – *Peripheral Instinct: Turning Peripheral Devices against Their Users* (2023)  
**Implementation Repository:** `Java-Idl/sem7_project`

---

## 1. Executive Summary

Modern web browsers expose raw peripheral hardware communication to websites via **WebHID**, **WebSerial**, and **WebMIDI**. While introduced to enable zero-install peripheral configuration tools (such as Logitech G HUB alternatives, keyboard customizers, and cellular modem diagnostic portals), these APIs grant untrusted web origins the ability to transmit arbitrary low-level command frames to microcontrollers inside connected USB hardware.

In 2023, researchers at CISPA published *Peripheral Instinct*, demonstrating that arbitrary websites could silently reprogram non-volatile flash memory inside commercial gaming mice (e.g., Logitech G502 HERO, Zelotes T90) and keyboards (WCH CH57x) to execute persistent keystroke macro payloads (BadUSB attacks) and exfiltrate credentials without requiring executable downloads or OS driver vulnerabilities.

This document details:
1. **What CISPA proposed** for defending against these attacks.
2. **Why CISPA's mitigations were fundamentally flawed** when tested against real-world Windows operating systems, modern Chromium runtimes, and advanced configurators like Universal OMM.
3. **What was engineered and improved in `sem7_project` (PeripheralShield)** to create a hardened, bypass-resistant defense.
4. **How the Heuristic HID Threat Estimator works**, the technical bug that caused it to appear non-functional, and the WebIDL serialization fix applied to resolve it.

---

## 2. What CISPA Proposed for Mitigation

In the *Peripheral Instinct* repository (`cispa/PeripheralInstinct`), the researchers proposed four distinct mitigation concepts:

```
[ CISPA Peripheral Instinct Mitigations ]
  ├── 1. In-Page Driver Extension (mitigation/driverextension)
  ├── 2. Minimal Driver / Virtualized Abstraction Layer (mitigation/minimal_driver)
  ├── 3. Firmware Usage Table Reclassification (mitigation/usage)
  └── 4. WebHID Threat Estimator (mitigation/tool.html)
```

### 2.1 In-Page Driver Chrome Extension (`mitigation/driverextension`)
CISPA implemented a proof-of-concept Chrome extension consisting of:
* `inject.js`: Injects `sdk.js` into every web page.
* `sdk.js`: Monkey-patches `window.navigator.hid.requestDevice` and `getDevices`.
  * When `device.open()` is called by the web application, the extension intercepts the call and transmits a synchronous probe packet:
    ```javascript
    await device.sendReport(0x10, Uint8Array.from([0xff, 0x00, 0x0a, 0x81, 0x00, 0x00]));
    ```
  * It registers `device.oninputreport = (event) => ...` to capture the device's response and extract byte 3, which represents the dynamic feature index assigned to Logitech Feature `0x8100` (Onboard Memory).
  * It wraps `device.sendReport` to block any packet where `arguments[1][1] === featureIndex`.
  * It calls `Object.freeze` on `Array.prototype`, `Function.prototype`, and `Promise.prototype`.

### 2.2 Minimal Driver / Virtual Abstraction Layer (`mitigation/minimal_driver`)
CISPA proposed moving peripheral abstraction into an intermediary browser-native layer (`minimal_driver/index.html`). Under this model:
* Websites would no longer receive raw `HIDDevice` instances.
* Instead, websites would receive a restricted JavaScript proxy exposing high-level, vendor-neutral methods (e.g., `setDpi(step)`, `getBatteryLevel()`, `setColor(rgb)`).
* The browser engine would translate high-level requests into raw HID packets, dropping any request attempting to access memory addresses or flash sectors.

### 2.3 Firmware Usage Table Reclassification (`mitigation/usage`)
CISPA authored a firmware patch (`firmware.patch`) for microcontrollers:
* The USB HID specification dictates that devices declare Top-Level Collections with standardized Usage Pages (e.g., `Usage Page 0x01` for Generic Desktop, `Usage 0x02` for Mouse, `Usage 0x06` for Keyboard).
* WebHID explicitly blocks browsers from accessing standard Keyboard and Mouse collections for security reasons.
* Gaming peripherals evade this restriction by declaring proprietary vendor usage pages (`Usage Page >= 0xFF00`).
* CISPA proposed that firmware manufacturers classify all configuration endpoints under protected usage pages so browsers would refuse to open them.

### 2.4 WebHID Threat Estimator Tool (`mitigation/tool.html`)
CISPA provided a standalone HTML tool to evaluate whether an attached peripheral is vulnerable to BadUSB-over-WebHID attacks. The tool checks whether a single physical device combines two attributes:
1. Emulates a Keyboard interface (`Usage Page 0x01`, `Usage 0x06`).
2. Accepts host-to-device commands (`outputReports` or `featureReports`).

---

## 3. Why CISPA's Mitigations Failed in Practice

When evaluating CISPA's proposed mitigations against modern operating systems and real-world tools (such as Universal OMM), the CISPA PoC failed due to four fatal architectural flaws:

### 3.1 The Windows Dual-TLC Deadlock (Collection 4 vs. Collection 5)
Modern Logitech gaming hardware (G502 HERO, G Pro Wireless, G305, G203) does not expose a single HID endpoint. On Windows, the OS HID driver stack enumerates two distinct vendor Top-Level Collections (TLCs):
* **Collection 4 (`Usage 0x0001`):** Host-to-Device Output endpoint (`sendReport`).
* **Collection 5 (`Usage 0x0002`):** Device-to-Host Input endpoint (`inputreport` events).

When CISPA's `wrapDevice` executed:
```javascript
await device.sendReport(0x10, Uint8Array.from([0xff, 0x00, 0x0a, 0x81, 0x00, 0x00]));
let res = await new Promise((resolve) => {
  device.oninputreport = (event) => resolve(new Uint8Array(event.data.buffer));
});
```
* If called on Collection 5, `sendReport()` threw an unhandled `InvalidAccessError` exception because Collection 5 does not accept output reports.
* If called on Collection 4, `sendReport()` succeeded, but `device.oninputreport` **never fired** because Windows routes all incoming input reports strictly to Collection 5.
* **Result:** The promise hung indefinitely, completely freezing the browser tab whenever any Logitech device was opened.

### 3.2 Main-World Prototype Tampering & Iframe Bypasses
CISPA used a Manifest V2 content script that injected an external `<script>` tag. Because the script ran without isolated world security:
* A malicious page could revive unpatched native prototypes by spawning a temporary `<iframe>`:
  ```javascript
  const iframe = document.createElement('iframe');
  document.body.appendChild(iframe);
  const pristineHid = iframe.contentWindow.navigator.hid;
  const devices = await pristineHid.requestDevice({ filters: [] });
  // devices[0].sendReport is completely unpatched and pristine!
  ```
* Prototype tampering or timing race conditions during page load allowed pages to capture native references before `sdk.js` finished executing.

### 3.3 Event Listener Hijacking
CISPA's code performed a hard assignment:
```javascript
device.oninputreport = (event) => resolve(...);
```
This wiped any existing `oninputreport` handler set by legitimate applications and completely ignored applications using modern `device.addEventListener('inputreport', ...)`.

### 3.4 Narrow Protocol Scope
CISPA only checked for Feature `0x8100` writes. In real-world hardware:
* **Feature `0x8061` (Special Keys & Button Remapping):** Used by Universal OMM and malware to remap physical buttons to keystrokes without writing flash sectors. CISPA had zero coverage for `0x8061`.
* **Feature `0x8110` (Button Spy):** Used to silently log physical mouse clicks. CISPA had zero coverage for `0x8110`.
* **Feature `0x8100 Fn 0x05` (Direct Macro Execution):** Executes autonomous bytecode without sector flashing. CISPA had zero coverage for Function `0x05`.

---

## 4. What Was Implemented and Improved in `sem7_project`

PeripheralShield resolves the failures of previous academic research by establishing an enterprise-grade defense:

```
┌────────────────────────────────────────────────────────────────────────┐
│                          WEB PAGE CONTEXT                              │
│         navigator.hid.requestDevice()  /  device.sendReport()          │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                     [ 1. PRE-CONNECTION GATING ]
                     Checks origin against allowlist;
                     Blocks untrusted access to 0x046D
                                    │
                     [ 2. MAIN-WORLD INTERCEPTOR ]
                     Pristine primitives cached at document_start;
                     HIDDevice.prototype frozen
                                    │
              ┌─────────────────────┴─────────────────────┐
              │                                           │
  [ COLLECTION 4: OUTPUT ]                    [ COLLECTION 5: INPUT ]
  Host sends GetFeature(0x8100)               Device returns Feature Index (e.g. 0x07)
              │                                           │
              └───────────────┬───────────────────────────┘
                              │
               [ 3. CROSS-TLC DEVICE REGISTRY ]
               Synchronizes discovered indices across
               all collections for physical USB VID:PID
                              │
               [ 4. EXPANDED PROTOCOL PARSERS ]
               - Feature 0x8100: Fn 0x01, 0x05, 0x06, 0x07, 0x08, 0x0C
               - Feature 0x8061: Button Remapping (Fn 0x01, 0x02, 0x05)
               - Feature 0x8110: Button Spy Click Keylogger (Fn 0x01)
               - Heuristic fallback for unmapped wire formats
                              │
              ┌───────────────┴───────────────┐
              │                               │
    [ MALICIOUS PACKET ]            [ BENIGN TELEMETRY ]
    Dropped silently /              Allowed;
    Security alert displayed;       Passed to physical hardware
    Dispatched to SIEM Host
```

### 4.1 Manifest V3 Dual-World Architecture
* **Main World Interceptor (`core/interceptor.js`):** Injected at `document_start` with `world: "MAIN"`, `all_frames: true`, and `match_about_blank: true`. It caches native primitives (`Function.prototype.apply`, `Object.defineProperty`, `Object.freeze`) before any web page script can execute.
* **Isolated World Bridge (`content/bridge.js`):** Injected in `world: "ISOLATED"` to communicate securely with the background service worker, enterprise managed storage, and native messaging hosts.

### 4.2 Cross-TLC Device State Registry & Event Target Interception
To solve the Windows Collection 4/5 desynchronization bug:
* Introduced a module-level `deviceRegistry` keyed by `${vendorId}:${productId}`.
* Hooked `device.addEventListener('inputreport', ...)` and `device.oninputreport`.
* When Collection 5 receives a response to `IRoot::GetFeature(featureId)` (`0x0000`), the handler extracts `swId` and `runtimeIdx`.
* The resolved runtime index is immediately bound to the shared device record.
* When Collection 4 subsequently calls `sendReport()`, it immediately checks the shared record, successfully catching Feature `0x8100`, `0x8061`, and `0x8110` writes.

### 4.3 Pre-Connection & Pre-Open Access Gating
In the default configuration:
* `navigator.hid.requestDevice({ filters })` inspects the calling origin.
* If an untrusted website calls `requestDevice()` targeting programmable peripherals (`vendorId: 0x046d`, `0x1189`, `0x30fa`, `0x3553`, `0x1e7d`, `0x258a`) or requests unfiltered access, PeripheralShield aborts the request, displays a security notification, and throws a `SecurityError`.
* If a site attempts to call `device.open()` on an existing handle, the call is rejected unless the site is in `originAllowlist`.

### 4.4 Expanded Multi-Vendor Protocol Parsing Engines
* **Logitech HID++ 2.0:** Hardened to block:
  * Feature `0x8100`: Fn `0x01` (mode), Fn `0x05` (macro exec), Fn `0x06` (sector prepare), Fn `0x07` (write chunk), Fn `0x08` (finalize), Fn `0x0C` (slot commit).
  * Feature `0x8061`: Button remapping (`Fn 0x01`, `Fn 0x02`, `Fn 0x05`).
  * Feature `0x8110`: Button spy keylogging (`Fn 0x01`).
* **Heuristic Wire-Format Fallback:** If an attacker attempts direct sector writes without feature discovery, packet structural signatures detect the prepare header (`[0x00, pageId, 0x00, 0x00, 0x00, 0xFF]`), chunk lengths, and finalize codes, blocking them even without a mapped feature index.
* **Multi-Vendor Support:** Includes dedicated parsers for WCH CH57X macropads, Zelotes T90 / Speedlink mice, PCsensor foot pedals, Roccat Kone mice, Redragon keyboards, Novation MIDI SysEx flashers, and Fibocom WebSerial AT modems.

---

## 5. Technical Evaluation: The Heuristic HID Threat Estimator

### 5.1 Why the Estimator Page Appeared Inoperative
When testing the Threat Estimator page (`options/options.html` -> Threat Estimator tab) by connecting physical hardware, users observed that clicking **"Inspect Connected WebHID Device"** frequently returned a score of **0/100 (No Assessment)**.

**Root Cause Analysis:**
1. Under the W3C WebHID specification, `HIDDevice.collections` is an array of `HIDCollectionInfo` objects.
2. In the Chromium V8 engine, `HIDCollectionInfo` attributes (`usagePage`, `usage`, `type`, `children`, `inputReports`, `outputReports`, `featureReports`) are defined as **getter properties on the WebIDL interface prototype**, not own enumerable properties of the instance.
3. The previous implementation executed:
   ```javascript
   mockDescriptorInput.value = JSON.stringify({
     collections: dev.collections || []
   }, null, 2);
   ```
4. Calling `JSON.stringify()` on WebIDL prototype getters resulted in an array of empty objects:
   ```json
   {
     "collections": [ {}, {}, {} ]
   }
   ```
5. When the assessment function evaluated the serialized descriptor, `c.usagePage` was `undefined`, `c.outputReports` was `undefined`, and the calculation evaluated to `0`.
6. Furthermore, the previous evaluator did not recursively traverse nested `col.children` collections.

### 5.2 The Solution Applied
1. **Recursive WebIDL Property Extractor:** Added `extractCollectionHierarchy(col)` to recursively copy prototype getters into plain JavaScript objects before serialization:
   ```javascript
   function extractCollectionHierarchy(col) {
     if (!col) return null;
     return {
       usagePage: Number(col.usagePage) || 0,
       usage: Number(col.usage) || 0,
       type: Number(col.type) || 0,
       children: Array.isArray(col.children) ? col.children.map(extractCollectionHierarchy).filter(Boolean) : [],
       inputReports: Array.isArray(col.inputReports) ? col.inputReports.map(r => ({ reportId: r.reportId, reportSize: r.reportSize || 8 })) : [],
       outputReports: Array.isArray(col.outputReports) ? col.outputReports.map(r => ({ reportId: r.reportId, reportSize: r.reportSize || 8 })) : [],
       featureReports: Array.isArray(col.featureReports) ? col.featureReports.map(r => ({ reportId: r.reportId, reportSize: r.reportSize || 8 })) : []
     };
   }
   ```
2. **Recursive Assessment Walk:** Updated `checkIsKeyboard`, `checkHasVendorPage`, and `countEndpoints` to traverse nested `col.children` trees.
3. **Multi-Vector Quantitative Risk Modeling:** Replaced simplistic additive point buckets (`+35 +30 +25 +15 = 105 capped at 100`) with a CVSS-style multi-dimensional attack surface calculator:
   - **Impact Vector ($0\text{--}10$):** Measures active OS keystroke injection potential via keyboard TLCs (`0x0001:0x0006`) vs pointer-only devices.
   - **Exploitability Vector ($0\text{--}10$):** Measures host-to-device buffer capacity (bulk 64-byte transfers vs 20-byte/8-byte reports vs benign 1-byte LED indicator channels).
   - **Attack Surface Vector ($0\text{--}10$):** Evaluates proprietary vendor usage pages ($\ge \text{0xFF00}$).
   - **Signature Correlation ($0\text{--}10$):** Correlates hardware against cataloged firmware exploit classes.
   - **Differentiated Outputs:** Logitech G502 HERO scores `87/100 [CRITICAL]`, WCH CH57X scores `91/100 [CRITICAL]`, office keyboards score `12/100 [LOW]`, and standard mice score `3/100 [SAFE]`.
4. **Discovered Endpoints Telemetry Table:** Renders a live technical telemetry table breaking down every detected Output, Feature, and Input report by ID, buffer size, role, and channel risk.
5. **One-Click Descriptor Presets:** Added quick preset buttons for Logitech G502 HERO, WCH CH57X, standard mouse, and standard keyboard so users can verify the estimator without physical hardware.

---

## 6. Architectural Comparison Matrix

| Security Dimension | CISPA *Peripheral Instinct* (`driverextension`) | PeripheralShield (`sem7_project`) |
| :--- | :--- | :--- |
| **Extension Architecture** | Manifest V2 in-page script injection | Manifest V3 Dual-World (`MAIN` + `ISOLATED`) |
| **Prototype Protection** | Basic `Object.freeze` after page load | Pristine prototype caching at `document_start` |
| **Iframe Prototype Revival** | Vulnerable (can be bypassed via `<iframe>`) | Defended (`match_about_blank: true`, all frames locked) |
| **Dual TLC Windows Support** | Fatal bug (hangs indefinitely on collection 4) | Supported via shared `deviceRegistry` across collections |
| **Event Listener Compatibility**| Destroys `oninputreport` property | Transparently wraps `addEventListener` & `oninputreport` |
| **Connection-Level Gating** | None (always prompts & opens) | Defends `requestDevice()` & `open()` for untrusted sites |
| **Feature 0x8100 Coverage** | Function 0x06, 0x07, 0x08 | Function 0x01, 0x05, 0x06, 0x07, 0x08, 0x0C + Heuristics |
| **Feature 0x8061 Remapping** | None (untracked) | Full interception of button remapping writes |
| **Feature 0x8110 Button Spy** | None (untracked) | Blocks click sniffing activation frames |
| **Multi-Hardware Scope** | Logitech HID++ 2.0 & CH57x only | Logitech (1.0/2.0), CH57x, Zelotes, FootSwitch, Roccat, Redragon, MIDI, Serial |
| **Heuristic Threat Estimator**| Binary `isKeyboard && writeReports` | Multi-vector quantitative CVSS-style metric + telemetry |
| **Heuristic Fallback** | None (requires feature discovery) | Wire-format pattern matching for unmapped indices |
| **Enterprise Management** | None | `chrome.storage.managed` + Native Messaging SIEM Host |
| **UI Aesthetics** | Academic prototype | Enterprise dark-mode console, clean typography, zero emojis |

---

## 7. Verification Evidence

The zero-dependency automated test suite verifies all parsers, connection gating, policy rules, and threat estimation dimensions:

```bash
node test/run-tests.js
```

**Results:**
* **61 unit and protocol assertions passing (0 failures).**
* Confirms blocking of Unifying bootloader entry, key dumping, Feature 0x8100 sector write, Feature 0x8100 macro execution, Feature 0x8061 button remapping, Feature 0x8110 button spy, unmapped heuristic writes, untrusted origin connection attempts, untrusted device open calls, and non-trivial multi-vector threat estimator scoring across gaming and office peripherals.
