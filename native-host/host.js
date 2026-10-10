#!/usr/bin/env node
/**
 * PeripheralShield - Native Messaging Companion Host (Node.js)
 * Alternative Node.js implementation for logging peripheral security alerts to SIEM JSONL.
 */

const fs = require('fs');
const path = require('path');
const os = require('os');

const LOG_DIR = path.join(os.homedir(), '.peripheralshield');
const LOG_FILE = path.join(LOG_DIR, 'security_alerts.jsonl');

if (!fs.existsSync(LOG_DIR)) {
  fs.mkdirSync(LOG_DIR, { recursive: true });
}

function appendLog(entry) {
  try {
    fs.appendFileSync(LOG_FILE, JSON.stringify(entry) + '\n', 'utf8');
  } catch (err) {
    console.error('Failed to append log:', err);
  }
}

appendLog({
  event_type: 'HOST_STARTED_NODEJS',
  timestamp: new Date().toISOString(),
  pid: process.pid
});

function sendMessage(msg) {
  const jsonStr = JSON.stringify(msg);
  const len = Buffer.byteLength(jsonStr, 'utf8');
  const header = Buffer.alloc(4);
  header.writeUInt32LE(len, 0);
  process.stdout.write(header);
  process.stdout.write(jsonStr);
}

let buffer = Buffer.alloc(0);

process.stdin.on('readable', () => {
  let chunk;
  while ((chunk = process.stdin.read()) !== null) {
    buffer = Buffer.concat([buffer, chunk]);
    while (buffer.length >= 4) {
      const msgLen = buffer.readUInt32LE(0);
      if (buffer.length < 4 + msgLen) {
        break; // Wait for full message
      }
      const rawMsg = buffer.slice(4, 4 + msgLen);
      buffer = buffer.slice(4 + msgLen);

      try {
        const msg = JSON.parse(rawMsg.toString('utf8'));
        if (msg.action === 'LOG_SECURITY_ALERT') {
          appendLog({
            event_type: 'PERIPHERAL_EXPLOIT_BLOCKED',
            host_received_at: new Date().toISOString(),
            payload: msg.event || {}
          });
          sendMessage({ status: 'LOGGED', log_path: LOG_FILE });
        } else if (msg.action === 'PING') {
          sendMessage({ status: 'PONG', timestamp: new Date().toISOString() });
        } else {
          sendMessage({ status: 'ACK', received_action: msg.action });
        }
      } catch (e) {
        sendMessage({ status: 'ERROR', error: e.message });
      }
    }
  }
});

process.stdin.on('end', () => {
  process.exit(0);
});
