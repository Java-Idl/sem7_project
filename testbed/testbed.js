/**
 * PeripheralShield Interactive Exploit & Defense Testbed
 */

document.addEventListener('DOMContentLoaded', () => {
  const extensionStatus = document.getElementById('extensionStatus');
  const consoleBox = document.getElementById('consoleBox');
  const btnClearLog = document.getElementById('btnClearLog');
  const connectedDeviceStatus = document.getElementById('connectedDeviceStatus');

  let physicalHIDDevice = null;
  let physicalSerialPort = null;

  function log(msg, type = 'info') {
    const line = document.createElement('div');
    line.className = `log-line ${type}`;
    const timestamp = new Date().toLocaleTimeString();
    line.textContent = `[${timestamp}] ${msg}`;
    consoleBox.appendChild(line);
    consoleBox.scrollTop = consoleBox.scrollHeight;
  }

  btnClearLog.addEventListener('click', () => {
    consoleBox.innerHTML = '';
    log('Log cleared.', 'info');
  });

  // Check if Defensive Extension is Active
  function checkExtension() {
    let isActive = false;
    if (window.__DEFENSIVE_EXTENSION_INITIALIZED__) {
      isActive = true;
    } else if (window.HIDDevice && Object.isFrozen(window.HIDDevice.prototype)) {
      isActive = true;
    }

    if (isActive) {
      extensionStatus.textContent = '🛡️ PeripheralShield Active (Protected)';
      extensionStatus.className = 'ext-status-pill active';
      log('PeripheralShield MAIN-world interceptor detected! Native prototypes frozen.', 'success');
    } else {
      extensionStatus.textContent = '⚠️ Unprotected Browser (Extension Inactive)';
      extensionStatus.className = 'ext-status-pill inactive';
      log('Warning: Extension not loaded in this tab. Attacks will not be intercepted unless extension is installed and enabled.', 'warn');
    }
  }

  checkExtension();
  setTimeout(checkExtension, 800);

  // Helper Mock HID Device constructor that runs through the intercepted window.HIDDevice prototype
  function createTestHIDDevice(vendorId, productId, productName) {
    let dev;
    if (window.HIDDevice) {
      dev = Object.create(window.HIDDevice.prototype);
    } else {
      dev = {};
    }
    dev.vendorId = vendorId;
    dev.productId = productId;
    dev.productName = productName;
    dev.opened = true;
    dev.collections = [];

    // Mock sendReport fallback if running without physical hardware
    if (!dev.sendReport) {
      dev.sendReport = async (reportId, data) => {
        log(`[Device TX] sendReport(${reportId}, [${Array.from(data).slice(0, 6).join(', ')}...]) executed! (UNBLOCKED)`, 'warn');
      };
    }
    if (!dev.sendFeatureReport) {
      dev.sendFeatureReport = async (reportId, data) => {
        log(`[Device TX] sendFeatureReport(${reportId}, [${Array.from(data).slice(0, 6).join(', ')}...]) executed! (UNBLOCKED)`, 'warn');
      };
    }
    return dev;
  }

  // =========================================================================
  // 1. Attack Vectors
  // =========================================================================

  // A. Logitech G502 HID++ 2.0 Macro Write
  document.getElementById('btnAttackLogitech').addEventListener('click', async () => {
    log('--- Launching Vector: Logitech HID++ 2.0 Onboard Macro Overwrite ---', 'info');
    const dev = physicalHIDDevice || createTestHIDDevice(0x046d, 0xc08b, 'Logitech G502 HERO Gaming Mouse');
    // Function 0x06 = writePage transaction start on Feature 0x8100
    const attackPayload = new Uint8Array([0x01, 0x07, 0x6a, 0x00, 0x02, 0x00, 0x00, 0x00]);
    try {
      await dev.sendReport(0x11, attackPayload);
      log('ATTACK TRANSMITTED: HID++ writePage frame sent to device without error!', 'warn');
    } catch (e) {
      log(`DEFENSE INTERCEPTED: Attack blocked by PeripheralShield! Error: ${e.message}`, 'blocked');
    }
  });

  document.getElementById('btnBenignLogitech').addEventListener('click', async () => {
    log('--- Sending Benign: Logitech GetFeature Query ---', 'info');
    const dev = physicalHIDDevice || createTestHIDDevice(0x046d, 0xc08b, 'Logitech G502 HERO Gaming Mouse');
    const benignPayload = new Uint8Array([0xff, 0x00, 0x0a, 0x81, 0x00]); // query feature 0x8100
    try {
      await dev.sendReport(0x10, benignPayload);
      log('BENIGN QUERY PERMITTED: GetFeature executed successfully.', 'success');
    } catch (e) {
      log(`Error: ${e.message}`, 'warn');
    }
  });

  // B. CH57X Macropad
  document.getElementById('btnAttackCH57X').addEventListener('click', async () => {
    log('--- Launching Vector: WCH CH57X Silent Macro Reprogramming ---', 'info');
    const dev = physicalHIDDevice || createTestHIDDevice(0x1189, 0x8890, 'CH57X Macro Keyboard');
    const keyUpdateStart = new Uint8Array(64);
    keyUpdateStart[0] = 0xa1; // sendKeyUpdateStart
    keyUpdateStart[1] = 0x01;
    try {
      await dev.sendReport(3, keyUpdateStart);
      log('ATTACK TRANSMITTED: CH57X Key Update Start (0xa1) sent to macropad!', 'warn');
    } catch (e) {
      log(`DEFENSE INTERCEPTED: CH57X Macro reprogramming blocked! Error: ${e.message}`, 'blocked');
    }
  });

  document.getElementById('btnBenignCH57X').addEventListener('click', async () => {
    log('--- Sending Benign: CH57X Hello Handshake ---', 'info');
    const dev = physicalHIDDevice || createTestHIDDevice(0x1189, 0x8890, 'CH57X Macro Keyboard');
    const hello = new Uint8Array(64); // all zeroes
    try {
      await dev.sendReport(3, hello);
      log('BENIGN HANDSHAKE PERMITTED: 64-byte zero frame allowed.', 'success');
    } catch (e) {
      log(`Error: ${e.message}`, 'warn');
    }
  });

  // C. Logitech Unifying Receiver
  document.getElementById('btnAttackUnifying').addEventListener('click', async () => {
    log('--- Launching Vector: Unifying Receiver AES Key Dump (CVE-2019-13055) ---', 'info');
    const dev = physicalHIDDevice || createTestHIDDevice(0x046d, 0xc52b, 'Logitech Unifying Receiver');
    const keyDumpPayload = new Uint8Array([0xff, 0x81, 0xd4, 0x00, 0x10]);
    try {
      await dev.sendReport(0x10, keyDumpPayload);
      log('ATTACK TRANSMITTED: Key dump memory request sent to receiver!', 'warn');
    } catch (e) {
      log(`DEFENSE INTERCEPTED: Logitech Unifying memory dump blocked! Error: ${e.message}`, 'blocked');
    }
  });

  // D. Zelotes T90 Mouse
  document.getElementById('btnAttackZelotes').addEventListener('click', async () => {
    log('--- Launching Vector: Zelotes T90 Holtek Feature 7 Macro Flash ---', 'info');
    const dev = physicalHIDDevice || createTestHIDDevice(0x30fa, 0x1140, 'Zelotes T90 Gaming Mouse');
    const macroStart = new Uint8Array(65);
    macroStart[0] = 0x18;
    macroStart[1] = 0x03; // opcode 0x03: macro block start
    try {
      await dev.sendFeatureReport(7, macroStart);
      log('ATTACK TRANSMITTED: Feature Report 7 macro block sent to mouse!', 'warn');
    } catch (e) {
      log(`DEFENSE INTERCEPTED: Zelotes/Speedlink macro write blocked! Error: ${e.message}`, 'blocked');
    }
  });

  // E. Foot Switch
  document.getElementById('btnAttackFoot').addEventListener('click', async () => {
    log('--- Launching Vector: USB Foot Switch Scripting ---', 'info');
    const dev = physicalHIDDevice || createTestHIDDevice(0x3553, 0xb001, 'USB Foot Switch');
    const footInit = new Uint8Array([0x01, 0xc0, 0x00, 0x57, 0x04, 0x00, 0x00, 0x00]);
    try {
      await dev.sendReport(0, footInit);
      log('ATTACK TRANSMITTED: Foot switch macro initialization frame sent!', 'warn');
    } catch (e) {
      log(`DEFENSE INTERCEPTED: USB Foot switch macro programming blocked! Error: ${e.message}`, 'blocked');
    }
  });

  // F. WebMIDI SysEx
  document.getElementById('btnAttackMIDI').addEventListener('click', async () => {
    log('--- Launching Vector: Novation Launchpad MK2 SysEx Firmware Overwrite ---', 'info');
    const sysexFlash = new Uint8Array([0xf0, 0x00, 0x20, 0x29, 0x00, 0x71, 0x00, 0x01, 0xf7]);
    if (window.MIDIOutput && window.MIDIOutput.prototype) {
      const mockMidi = Object.create(window.MIDIOutput.prototype);
      mockMidi.name = 'Launchpad MK2 Bootloader';
      if (!mockMidi.send) {
        mockMidi.send = (data) => log('ATTACK TRANSMITTED: SysEx frame dispatched!', 'warn');
      }
      try {
        mockMidi.send(sysexFlash);
        log('ATTACK TRANSMITTED: Launchpad firmware flashing frame dispatched!', 'warn');
      } catch (e) {
        log(`DEFENSE INTERCEPTED: SysEx bootloader flasher blocked! Error: ${e.message}`, 'blocked');
      }
    } else {
      log('WebMIDI API not supported by browser environment.', 'warn');
    }
  });

  document.getElementById('btnBenignMIDI').addEventListener('click', async () => {
    log('--- Sending Benign: Musical Note On (Middle C) ---', 'info');
    const noteOn = new Uint8Array([0x90, 0x3c, 0x7f]);
    if (window.MIDIOutput && window.MIDIOutput.prototype) {
      const mockMidi = Object.create(window.MIDIOutput.prototype);
      mockMidi.name = 'MIDI Keyboard Output';
      if (!mockMidi.send) {
        mockMidi.send = () => log('Musical note transmitted.', 'success');
      }
      try {
        mockMidi.send(noteOn);
        log('BENIGN NOTE PERMITTED: Musical Note On message allowed.', 'success');
      } catch (e) {
        log(`Error: ${e.message}`, 'warn');
      }
    }
  });

  // G. WebSerial Hayes Modem
  document.getElementById('btnAttackSerial').addEventListener('click', async () => {
    log('--- Launching Vector: Hayes Modem SMS Exfiltration (AT+CMGS) ---', 'info');
    if (window.SerialPort && window.SerialPort.prototype) {
      const mockPort = Object.create(window.SerialPort.prototype);
      mockPort.opened = true;
      try {
        const writer = mockPort.writable ? mockPort.writable.getWriter() : {
          write: async () => log('ATTACK TRANSMITTED: AT+CMGS written to serial port!', 'warn')
        };
        await writer.write(new TextEncoder().encode('AT+CMGS="+123456789"\r'));
        log('ATTACK TRANSMITTED: AT+CMGS SMS transmission written to port!', 'warn');
      } catch (e) {
        log(`DEFENSE INTERCEPTED: AT+CMGS modem write blocked! Error: ${e.message}`, 'blocked');
      }
    } else {
      log('WebSerial API not supported by browser environment.', 'warn');
    }
  });

  document.getElementById('btnBenignSerial').addEventListener('click', async () => {
    log('--- Sending Benign: Modem AT Ping Handshake ---', 'info');
    if (window.SerialPort && window.SerialPort.prototype) {
      const mockPort = Object.create(window.SerialPort.prototype);
      mockPort.opened = true;
      try {
        const writer = mockPort.writable ? mockPort.writable.getWriter() : {
          write: async () => log('Benign AT ping written.', 'success')
        };
        await writer.write(new TextEncoder().encode('AT\r\n'));
        log('BENIGN SERIAL WRITE PERMITTED: Safe AT ping allowed.', 'success');
      } catch (e) {
        log(`Error: ${e.message}`, 'warn');
      }
    }
  });

  // =========================================================================
  // 2. Physical Hardware Connection Handlers
  // =========================================================================
  document.getElementById('btnConnectPhysicalHID').addEventListener('click', async () => {
    if (!navigator.hid) {
      alert('WebHID is not supported in this browser.');
      return;
    }
    try {
      const devices = await navigator.hid.requestDevice({ filters: [] });
      if (devices && devices.length > 0) {
        physicalHIDDevice = devices[0];
        if (!physicalHIDDevice.opened) {
          await physicalHIDDevice.open();
        }
        connectedDeviceStatus.innerHTML = `<strong>Connected HID:</strong> ${physicalHIDDevice.productName} (VID: 0x${physicalHIDDevice.vendorId.toString(16)} | PID: 0x${physicalHIDDevice.productId.toString(16)})`;
        log(`Physical hardware connected: ${physicalHIDDevice.productName}`, 'success');
      }
    } catch (e) {
      log(`Physical device connection cancelled or error: ${e.message}`, 'warn');
    }
  });

  document.getElementById('btnConnectPhysicalSerial').addEventListener('click', async () => {
    if (!navigator.serial) {
      alert('WebSerial is not supported in this browser.');
      return;
    }
    try {
      physicalSerialPort = await navigator.serial.requestPort();
      await physicalSerialPort.open({ baudRate: 115200 });
      connectedDeviceStatus.innerHTML = '<strong>Connected Serial:</strong> WebSerial Port Open (115200 baud)';
      log('Physical WebSerial port opened.', 'success');
    } catch (e) {
      log(`Serial port error: ${e.message}`, 'warn');
    }
  });
});
