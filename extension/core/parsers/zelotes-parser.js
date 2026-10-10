/**
 * Parser for Zelotes T90 and Speedlink (Holtek / Sino Wealth) gaming mice.
 * Intercepts Feature Report 7 programming packets starting with 0x18 and dangerous sub-commands.
 */

export class ZelotesParser {
  /**
   * Evaluates feature report packet for Zelotes T90 / Speedlink devices.
   * Protocol format:
   * req[0] = 0x18
   * req[1] = cmd (0x03, 0x09, 0x00, 0x05, 0x10)
   * req[2] = index
   * req[3] = offset
   * req[4] = page
   * req[5] = data byte
   * req[6] = end marker
   * @param {number} reportId - Feature report ID
   * @param {Uint8Array} data - Feature report payload
   * @returns {{ isDangerous: boolean, reason?: string, opType?: string }}
   */
  static parseFeatureReport(reportId, data) {
    if (!data || data.length < 2) {
      return { isDangerous: false, opType: 'short_feature_report' };
    }

    // Usually Feature Report 7, but check byte 0x18 signature regardless of reportId
    const isReport7 = reportId === 7;
    const isPacket18 = data[0] === 0x18;

    if (isPacket18) {
      const cmd = data[1];

      switch (cmd) {
        case 0x03:
          return {
            isDangerous: true,
            reason: `Zelotes/Speedlink macro data packet write (0x18, cmd: 0x03, offset: ${data[3]}, page: ${data[4]}, data: 0x${(data[5] || 0).toString(16)})`,
            opType: 'zelotes_write_macro_packet'
          };
        case 0x09:
          return {
            isDangerous: true,
            reason: `Zelotes/Speedlink macro block finish command (0x18, cmd: 0x09, offset: ${data[3]}, page: ${data[4]})`,
            opType: 'zelotes_end_block'
          };
        case 0x00:
          return {
            isDangerous: true,
            reason: `Zelotes/Speedlink macro finalize command (0x18, cmd: 0x00, offset: ${data[3]}, page: ${data[4]})`,
            opType: 'zelotes_finalize'
          };
        case 0x05:
          return {
            isDangerous: true,
            reason: 'Zelotes/Speedlink endConfigureButtons command (0x18, cmd: 0x05)',
            opType: 'zelotes_end_configure_buttons'
          };
        case 0x10:
          return {
            isDangerous: true,
            reason: 'Zelotes/Speedlink endProgramming command (0x18, cmd: 0x10)',
            opType: 'zelotes_end_programming'
          };
        default:
          return {
            isDangerous: true,
            reason: `Zelotes/Speedlink proprietary programming packet with opcode 0x${cmd.toString(16)}`,
            opType: 'zelotes_custom_cmd'
          };
      }
    }

    // Check if data starts with 0x07 0x18 (when report ID is prefixed)
    if (data[0] === 0x07 && data[1] === 0x18) {
      return {
        isDangerous: true,
        reason: 'Zelotes/Speedlink reportId-prefixed 0x18 programming packet detected',
        opType: 'zelotes_prefixed_packet'
      };
    }

    return { isDangerous: false, opType: 'zelotes_non_programming' };
  }
}
