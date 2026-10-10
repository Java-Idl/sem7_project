/**
 * Device Classifier Module
 * Identifies connected peripherals using the known vulnerable device database
 * and applies heuristic fallback classification for unknown hardware.
 */

import { ThreatEstimator } from './threat-estimator.js';

export class DeviceClassifier {
  /**
   * @param {Array<object>} [knownDevices] - Array of device definitions from devices.json
   */
  constructor(knownDevices = []) {
    this.knownDevices = knownDevices;
    this.deviceMap = new Map();
    this.initDatabase(knownDevices);
  }

  /**
   * Index known devices by VID:PID key and product name substrings.
   * @param {Array<object>} devices
   */
  initDatabase(devices) {
    this.knownDevices = devices || [];
    this.deviceMap.clear();

    for (const dev of this.knownDevices) {
      if (dev.vendorId !== undefined && dev.productId !== undefined) {
        const key = `${dev.vendorId}:${dev.productId}`;
        this.deviceMap.set(key, dev);
      }
    }
  }

  /**
   * Classifies an HID device.
   * @param {object} hidDevice - WebHID device object (or mock)
   * @returns {{
   *   isKnown: boolean,
   *   deviceInfo: object,
   *   riskLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'SAFE',
   *   riskScore: number,
   *   protocol: string,
   *   category: string,
   *   name: string,
   *   threatReport?: object
   * }}
   */
  classifyHIDDevice(hidDevice) {
    if (!hidDevice) {
      return {
        isKnown: false,
        deviceInfo: null,
        riskLevel: 'LOW',
        riskScore: 0,
        protocol: 'Unknown',
        category: 'Unknown',
        name: 'Unknown Device'
      };
    }

    const vid = hidDevice.vendorId;
    const pid = hidDevice.productId;
    const productName = hidDevice.productName || 'Unnamed Device';
    const key = `${vid}:${pid}`;

    // 1. Direct VID:PID lookup
    if (this.deviceMap.has(key)) {
      const known = this.deviceMap.get(key);
      return {
        isKnown: true,
        deviceInfo: known,
        riskLevel: known.riskLevel,
        riskScore: known.riskLevel === 'CRITICAL' ? 95 : known.riskLevel === 'HIGH' ? 80 : 50,
        protocol: known.protocol,
        category: known.category,
        name: known.name || productName
      };
    }

    // 2. Fallback Substring Matching on Product Name (e.g. "G502", "G203", "G305", "CH57", "Zelotes")
    const genericWords = new Set(['usb', 'gaming', 'mouse', 'keyboard', 'device', 'custom', 'switch', 'pad', 'controller', 'optical', 'wired', 'wireless', 'peripheral', 'peripherals', 'macro']);
    const lowerName = productName.toLowerCase();
    for (const known of this.knownDevices) {
      if (known.name) {
        const words = known.name.toLowerCase().split(/\s+/).filter(w => w.length >= 3 && !genericWords.has(w));
        if (words.length > 0 && words.some(w => lowerName.includes(w))) {
          return {
            isKnown: true,
            deviceInfo: known,
            riskLevel: known.riskLevel,
            riskScore: 85,
            protocol: known.protocol,
            category: known.category,
            name: productName
          };
        }
      }
    }

    // 3. Fallback Heuristics for Unknown Devices via ThreatEstimator
    const threatReport = ThreatEstimator.analyzeDevice(hidDevice);
    let riskLevel = threatReport.threatLevel;
    let category = 'Generic HID Peripheral';

    if (threatReport.isKeyboard) {
      category = 'Compound Keyboard / HID';
    }

    return {
      isKnown: false,
      deviceInfo: {
        vendorId: vid,
        productId: pid,
        name: productName,
        category,
        protocol: threatReport.hasVendorPages ? 'Vendor-Defined HID' : 'Standard HID',
        riskLevel,
        dangerousOperations: threatReport.vulnerabilities,
        safeOperations: ['Device Enumeration', 'Input Reports']
      },
      riskLevel,
      riskScore: threatReport.score,
      protocol: threatReport.hasVendorPages ? 'Vendor-Defined HID' : 'Standard HID',
      category,
      name: productName,
      threatReport
    };
  }

  /**
   * Classifies a WebSerial port.
   * @param {object} serialPort - SerialPort instance
   * @returns {object}
   */
  classifySerialPort(serialPort) {
    const info = typeof serialPort?.getInfo === 'function' ? serialPort.getInfo() : (serialPort?._info || {});
    const vid = info.usbVendorId;
    const pid = info.usbProductId;

    // Check Fibocom / LTE modems (VID 0x2cb7 = 11447)
    if (vid === 11447 || vid === 0x2cb7) {
      return {
        isKnown: true,
        riskLevel: 'CRITICAL',
        riskScore: 90,
        protocol: 'Hayes AT / LTE Modem',
        category: 'Cellular Modem',
        name: 'Fibocom L850-GL / LTE Modem'
      };
    }

    // Generic serial port
    return {
      isKnown: false,
      riskLevel: 'HIGH', // Serial ports have high risk because of raw bus write capabilities
      riskScore: 75,
      protocol: 'WebSerial UART',
      category: 'Serial Interface',
      name: `Serial Device (VID:${vid || 'N/A'} PID:${pid || 'N/A'})`
    };
  }

  /**
   * Classifies a WebMIDI output.
   * @param {object} midiOutput - MIDIOutput instance
   * @returns {object}
   */
  classifyMIDIOutput(midiOutput) {
    const name = midiOutput?.name || 'MIDI Output Port';
    const lowerName = name.toLowerCase();

    if (lowerName.includes('launchpad') || lowerName.includes('focusrite') || lowerName.includes('novation')) {
      return {
        isKnown: true,
        riskLevel: 'CRITICAL',
        riskScore: 95,
        protocol: 'WebMIDI / SysEx Bootloader',
        category: 'MIDI Controller',
        name: 'Novation Launchpad Controller'
      };
    }

    return {
      isKnown: false,
      riskLevel: 'MEDIUM',
      riskScore: 45,
      protocol: 'Standard WebMIDI',
      category: 'MIDI Device',
      name
    };
  }
}
