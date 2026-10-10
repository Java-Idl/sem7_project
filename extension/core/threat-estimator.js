/**
 * WebHID Threat Estimator
 * Reusable analysis module ported and enhanced from mitigation/tool.html.
 * Evaluates device collections to determine whether an HID device can be abused
 * to reprogram macros or emit unauthenticated keystrokes (BadUSB over WebHID).
 */

export class ThreatEstimator {
  /**
   * Recursively extracts all Output Reports from HID collection hierarchy.
   * @param {Array<object>} collections
   * @returns {Set<object>}
   */
  static getOutputReports(collections) {
    const result = new Set();
    if (!collections || !Array.isArray(collections)) return result;

    for (const col of collections) {
      if (col && Array.isArray(col.outputReports)) {
        for (const report of col.outputReports) {
          result.add(report);
        }
      }
      if (col && Array.isArray(col.children) && col.children.length > 0) {
        const childResults = this.getOutputReports(col.children);
        for (const report of childResults) {
          result.add(report);
        }
      }
    }
    return result;
  }

  /**
   * Recursively extracts all Feature Reports from HID collection hierarchy.
   * @param {Array<object>} collections
   * @returns {Set<object>}
   */
  static getFeatureReports(collections) {
    const result = new Set();
    if (!collections || !Array.isArray(collections)) return result;

    for (const col of collections) {
      if (col && Array.isArray(col.featureReports)) {
        for (const report of col.featureReports) {
          result.add(report);
        }
      }
      if (col && Array.isArray(col.children) && col.children.length > 0) {
        const childResults = this.getFeatureReports(col.children);
        for (const report of childResults) {
          result.add(report);
        }
      }
    }
    return result;
  }

  /**
   * Checks whether the device implements a Keyboard collection (Usage Page 0x01, Usage 0x06).
   * @param {Array<object>} collections
   * @returns {boolean}
   */
  static deviceIsKeyboard(collections) {
    if (!collections || !Array.isArray(collections)) return false;

    return collections.reduce((res, col) => {
      if (!col) return res;
      const isDirectKeyboard = (col.usagePage === 0x01 && col.usage === 0x06);
      const isChildKeyboard = col.children ? this.deviceIsKeyboard(col.children) : false;
      return res || isDirectKeyboard || isChildKeyboard;
    }, false);
  }

  /**
   * Checks for vendor-defined usage pages (usagePage >= 0xff00).
   * @param {Array<object>} collections
   * @returns {boolean}
   */
  static hasVendorDefinedUsagePage(collections) {
    if (!collections || !Array.isArray(collections)) return false;

    return collections.some(col => {
      if (!col) return false;
      if (col.usagePage && col.usagePage >= 0xff00) return true;
      if (col.children && Array.isArray(col.children)) {
        return this.hasVendorDefinedUsagePage(col.children);
      }
      return false;
    });
  }

  /**
   * Analyzes an HID device object and returns comprehensive threat assessment.
   * @param {object} device - An HIDDevice instance
   * @returns {{
   *   isVulnerable: boolean,
   *   threatLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'SAFE',
   *   score: number,
   *   summary: string,
   *   isKeyboard: boolean,
   *   hasOutputReports: boolean,
   *   hasFeatureReports: boolean,
   *   hasVendorPages: boolean,
   *   outputReportCount: number,
   *   featureReportCount: number,
   *   outputReports: Array<object>,
   *   featureReports: Array<object>,
   *   vulnerabilities: Array<string>
   * }}
   */
  static analyzeDevice(device) {
    const collections = device?.collections || [];
    const isKeyboard = this.deviceIsKeyboard(collections);
    const outputReportsSet = this.getOutputReports(collections);
    const featureReportsSet = this.getFeatureReports(collections);
    const hasVendorPages = this.hasVendorDefinedUsagePage(collections);

    const outputReports = Array.from(outputReportsSet);
    const featureReports = Array.from(featureReportsSet);
    const hasOutputReports = outputReports.length > 0;
    const hasFeatureReports = featureReports.length > 0;

    const vulnerabilities = [];
    let score = 0;

    if (isKeyboard) {
      score += 40;
      vulnerabilities.push('Implements HID Keyboard interface capable of injecting OS keystrokes.');
    }

    if (hasOutputReports) {
      score += 25;
      vulnerabilities.push(`Accepts host Output Reports (${outputReports.length} endpoints discovered) for command execution.`);
    }

    if (hasFeatureReports) {
      score += 25;
      vulnerabilities.push(`Accepts host Feature Reports (${featureReports.length} endpoints discovered) for hardware configuration.`);
    }

    if (hasVendorPages) {
      score += 15;
      vulnerabilities.push('Exposes proprietary vendor-defined Usage Pages (>= 0xFF00) capable of undocumented flash programming.');
    }

    // Determine vulnerability verdict
    const isVulnerable = isKeyboard && (hasOutputReports || hasFeatureReports);

    let threatLevel = 'SAFE';
    if (score >= 80) threatLevel = 'CRITICAL';
    else if (score >= 60) threatLevel = 'HIGH';
    else if (score >= 30) threatLevel = 'MEDIUM';
    else if (score > 0) threatLevel = 'LOW';

    let summary = '';
    if (isVulnerable) {
      summary = 'LIKELY VULNERABLE: Device implements keyboard functionality and accepts host configuration/output commands. A malicious web page could reprogram this device to execute keystroke payloads.';
    } else if (hasVendorPages && (hasOutputReports || hasFeatureReports)) {
      summary = 'SUSPICIOUS: Device has vendor-defined programming endpoints. Potential risk if companion firmware has keyboard capabilities.';
    } else {
      summary = 'LOW THREAT: Device does not combine keyboard emulation with write/configuration interfaces.';
    }

    return {
      isVulnerable,
      threatLevel,
      score: Math.min(100, score),
      summary,
      isKeyboard,
      hasOutputReports,
      hasFeatureReports,
      hasVendorPages,
      outputReportCount: outputReports.length,
      featureReportCount: featureReports.length,
      outputReports,
      featureReports,
      vulnerabilities
    };
  }

  /**
   * Formats report usage details for debugging or UI display.
   * @param {object} report
   * @returns {string}
   */
  static formatReportUsage(report) {
    if (!report) return '';
    let usages = '';
    if (Array.isArray(report.items)) {
      for (const item of report.items) {
        if (Array.isArray(item.usages)) {
          for (const usage of item.usages) {
            const pageHex = ((usage >> 16) & 0xffff).toString(16).padStart(4, '0');
            const usageHex = (usage & 0xffff).toString(16).padStart(4, '0');
            usages += `0x${pageHex} 0x${usageHex}, `;
          }
        }
      }
    }
    const rId = (report.reportId || 0).toString(16).padStart(2, '0');
    return `Report ID: 0x${rId}, Usage: ${usages.replace(/,\s*$/, '') || 'None'}`;
  }
}
