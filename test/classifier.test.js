/**
 * Unit Tests: Device Classifier & Heuristic Threat Estimator
 */

import { DeviceClassifier } from '../defensive-extension/core/device-classifier.js';
import { ThreatEstimator } from '../defensive-extension/core/threat-estimator.js';
import { MockHIDDevice } from './mock-devices.js';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const devicesJsonPath = path.resolve(__dirname, '../defensive-extension/data/devices.json');
const devicesData = JSON.parse(fs.readFileSync(devicesJsonPath, 'utf8')).devices;

export function runClassifierTests(assert) {
  const classifier = new DeviceClassifier(devicesData);

  // =========================================================================
  // 1. Known Vulnerable Device Identification
  // =========================================================================
  {
    // A. Logitech G502 HERO (VID 0x046d = 1133, PID 0xc08b = 49291)
    const g502 = new MockHIDDevice({
      vendorId: 1133,
      productId: 49291,
      productName: 'Logitech G502 HERO Gaming Mouse'
    });
    const c1 = classifier.classifyHIDDevice(g502);
    assert(c1.isKnown, true, 'Classifier: Should identify Logitech G502 HERO as known');
    assert(c1.riskLevel, 'CRITICAL', 'Classifier: G502 HERO risk level should be CRITICAL');
    assert(c1.protocol.includes('HID++'), true, 'Classifier: G502 HERO protocol should be HID++');

    // B. WCH CH57X Macropad (VID 0x1189 = 4489, PID 0x8890 = 34960)
    const ch57x = new MockHIDDevice({
      vendorId: 4489,
      productId: 34960,
      productName: 'CH57X Macro Keyboard'
    });
    const c2 = classifier.classifyHIDDevice(ch57x);
    assert(c2.isKnown, true, 'Classifier: Should identify CH57X macropad as known');
    assert(c2.riskLevel, 'CRITICAL', 'Classifier: CH57X risk level should be CRITICAL');
    assert(c2.protocol.includes('CH57'), true, 'Classifier: CH57X protocol should be CH57x');

    // C. Zelotes T90 Gaming Mouse (VID 0x30fa = 12538, PID 0x1140 = 4416)
    const zelotes = new MockHIDDevice({
      vendorId: 12538,
      productId: 4416,
      productName: 'Zelotes T90 Gaming Mouse'
    });
    const c3 = classifier.classifyHIDDevice(zelotes);
    assert(c3.isKnown, true, 'Classifier: Should identify Zelotes T90 as known');
    assert(c3.protocol.includes('Holtek'), true, 'Classifier: Zelotes protocol should be Holtek');
  }

  // =========================================================================
  // 2. Heuristic Threat Estimator Fallback for Unknown Devices
  // =========================================================================
  {
    // Unknown device with Keyboard collection (Usage 1:6) AND Vendor-defined page (0xff00) AND Output reports
    const unknownSuspiciousDevice = new MockHIDDevice({
      vendorId: 0x9999,
      productId: 0x8888,
      productName: 'Mysterious USB Peripheral',
      collections: [
        {
          usagePage: 0x01,
          usage: 0x06, // Keyboard
          inputReports: [{ reportId: 1, reportSize: 8 }]
        },
        {
          usagePage: 0xff00, // Vendor Defined
          usage: 0x01,
          outputReports: [{ reportId: 2, reportSize: 64 }],
          featureReports: [{ reportId: 3, reportSize: 64 }]
        }
      ]
    });

    const assessment = ThreatEstimator.analyzeDevice(unknownSuspiciousDevice);
    assert(assessment.isVulnerable, true, 'ThreatEstimator: Device with keyboard + vendor page + output reports must be flagged as vulnerable');
    assert(assessment.isKeyboard, true, 'ThreatEstimator: Should detect keyboard collection');
    assert(assessment.hasVendorPages, true, 'ThreatEstimator: Should detect vendor-defined usage page');
    assert(assessment.hasOutputReports, true, 'ThreatEstimator: Should detect host-to-device output report endpoints');
    assert(assessment.score >= 70, true, 'ThreatEstimator: Threat score must be >= 70 for keystroke injection capable hardware');

    // Heuristic Classification in DeviceClassifier
    const fallbackClass = classifier.classifyHIDDevice(unknownSuspiciousDevice);
    assert(fallbackClass.isKnown, false, 'Classifier: Unknown device should not be marked isKnown');
    assert(fallbackClass.riskLevel, 'CRITICAL', 'Classifier: Heuristic should rate high-threat unknown device as CRITICAL');
  }
}
