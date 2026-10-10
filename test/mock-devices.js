/**
 * Mock Device Test Harness for WebHID, WebSerial, and WebMIDI
 */

export class MockHIDDevice {
  constructor(options = {}) {
    this.vendorId = options.vendorId || 0x1189;
    this.productId = options.productId || 0x8890;
    this.productName = options.productName || 'Mock Peripheral';
    this.collections = options.collections || [];
    this.opened = false;
    this.sentReports = [];
    this.sentFeatureReports = [];
  }

  async open() {
    this.opened = true;
  }

  async close() {
    this.opened = false;
  }

  async sendReport(reportId, data) {
    if (!this.opened) throw new Error('Device not opened');
    this.sentReports.push({ reportId, data: new Uint8Array(data) });
  }

  async sendFeatureReport(reportId, data) {
    if (!this.opened) throw new Error('Device not opened');
    this.sentFeatureReports.push({ reportId, data: new Uint8Array(data) });
  }
}

export class MockSerialPort {
  constructor(options = {}) {
    this.vendorId = options.vendorId || 0x2cb7;
    this.productId = options.productId || 0x0001;
    this.opened = false;
    this.writtenChunks = [];
    
    const self = this;
    this.writable = {
      getWriter() {
        return {
          async write(chunk) {
            if (!self.opened) throw new Error('Port not open');
            self.writtenChunks.push(chunk);
          },
          async close() {},
          releaseLock() {}
        };
      }
    };
  }

  async open() {
    this.opened = true;
  }

  async close() {
    this.opened = false;
  }
}

export class MockMIDIOutput {
  constructor(name = 'Mock MIDI Controller') {
    this.name = name;
    this.sentMessages = [];
  }

  send(data, timestamp) {
    this.sentMessages.push({ data: new Uint8Array(data), timestamp });
  }
}
