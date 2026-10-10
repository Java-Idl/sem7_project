/**
 * Parser for WebSerial write streams.
 * Intercepts dangerous AT commands targeting cellular/LTE modems (e.g. Fibocom L850-GL):
 * - AT+CMGS (send SMS)
 * - AT+CPIN (PIN unlock/manipulate)
 * - AT+CFUN (radio mode reset)
 * - Firmware/bootloader flash commands (AT^FLASH, AT+FUS, Intel/Qualcomm Sahara/EDL headers)
 * Allows safe diagnostic and query commands (AT, AT+CSQ, AT+CGMI, AT+CGMM).
 */

export class SerialParser {
  /**
   * Decodes and inspects data written to a SerialPort.
   * @param {ArrayBuffer | TypedArray | string} chunk - Data written to serial port
   * @returns {{ isDangerous: boolean, reason?: string, opType?: string, command?: string }}
   */
  static parseWriteChunk(chunk) {
    if (!chunk) return { isDangerous: false, opType: 'empty' };

    let text = '';
    let uint8Array = null;

    if (typeof chunk === 'string') {
      text = chunk;
    } else if (chunk instanceof ArrayBuffer) {
      uint8Array = new Uint8Array(chunk);
      text = new TextDecoder('utf-8', { fatal: false }).decode(uint8Array);
    } else if (ArrayBuffer.isView(chunk)) {
      uint8Array = new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength);
      text = new TextDecoder('utf-8', { fatal: false }).decode(uint8Array);
    }

    const trimmed = text.trim();

    // 1. Dangerous AT commands
    const DANGEROUS_AT_PATTERNS = [
      {
        regex: /^AT\+CMGS/i,
        reason: 'AT+CMGS command detected: Attempted to send unauthorized SMS messages via modem',
        type: 'modem_send_sms'
      },
      {
        regex: /^AT\+CPIN/i,
        reason: 'AT+CPIN command detected: Attempted to access or manipulate SIM card security PIN',
        type: 'modem_sim_pin'
      },
      {
        regex: /^AT\+CFUN\s*=\s*[04]/i,
        reason: 'AT+CFUN radio shutdown/airplane mode command detected: Attempted to disable device connectivity',
        type: 'modem_radio_disable'
      },
      {
        regex: /^AT(\^|\+)FLASH/i,
        reason: 'Modem firmware flashing command (AT^FLASH) detected',
        type: 'modem_firmware_flash'
      },
      {
        regex: /^AT\+FUS/i,
        reason: 'Modem firmware update service (AT+FUS) command detected',
        type: 'modem_firmware_update'
      },
      {
        regex: /^AT\+CSIM/i,
        reason: 'Direct APDU transmission to SIM card (AT+CSIM) detected',
        type: 'modem_raw_sim_apdu'
      },
      {
        regex: /^ATD[\d+*#]+/i,
        reason: 'Voice/data dialing command (ATD) detected: Attempting to dial external number',
        type: 'modem_dial_number'
      }
    ];

    for (const pat of DANGEROUS_AT_PATTERNS) {
      if (pat.regex.test(trimmed)) {
        return {
          isDangerous: true,
          reason: pat.reason,
          opType: pat.type,
          command: trimmed
        };
      }
    }

    // 2. Binary bootloader / firmware upload detection (e.g. Qualcomm EDL / Sahara / Intel XMM flashing)
    if (uint8Array && uint8Array.length > 32) {
      // Qualcomm Sahara Hello command packet (Command ID 0x01, Magic 0x02)
      if (uint8Array[0] === 0x01 && uint8Array[4] === 0x02) {
        return {
          isDangerous: true,
          reason: 'Qualcomm Sahara emergency download / firmware flashing protocol handshake detected',
          opType: 'serial_edl_flashing'
        };
      }

      // Check Intel XMM / Fibocom FastBoot / Download protocol magic
      if (uint8Array[0] === 0x7e && uint8Array[uint8Array.length - 1] === 0x7e) {
        return {
          isDangerous: true,
          reason: 'HDLC-framed serial firmware download frame detected',
          opType: 'serial_hdlc_firmware_frame'
        };
      }
    }

    // Safe AT commands: AT, AT+CSQ (signal), AT+CGMI (manufacturer), AT+CGMM (model), AT+CGMR (revision)
    return {
      isDangerous: false,
      opType: 'serial_safe_data',
      command: trimmed
    };
  }
}
