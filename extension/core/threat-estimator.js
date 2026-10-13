/**
 * WebHID Threat Estimator
 * Quantitative Peripheral Risk & Attack Surface Analyzer.
 * Ported and enhanced from PeripheralInstinct mitigation research.
 *
 * Evaluates HID collections, usage pages, endpoints, report sizes, and
 * protocol architectures using a multi-vector vulnerability model:
 *   - Impact (Keystroke Injection Potential)
 *   - Exploitability (Host-to-Device Control Plane & Buffer Depth)
 *   - Attack Surface (Vendor & Proprietary Collections)
 *   - Signature Correlation (Known Hardware Firmware Vulnerabilities)
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
   * Recursively extracts all Input Reports from HID collection hierarchy.
   * @param {Array<object>} collections
   * @returns {Set<object>}
   */
  static getInputReports(collections) {
    const result = new Set();
    if (!collections || !Array.isArray(collections)) return result;

    for (const col of collections) {
      if (col && Array.isArray(col.inputReports)) {
        for (const report of col.inputReports) {
          result.add(report);
        }
      }
      if (col && Array.isArray(col.children) && col.children.length > 0) {
        const childResults = this.getInputReports(col.children);
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
   * Checks whether the device implements a Pointer / Mouse collection (Usage Page 0x01, Usage 0x01 or 0x02).
   * @param {Array<object>} collections
   * @returns {boolean}
   */
  static deviceIsMouse(collections) {
    if (!collections || !Array.isArray(collections)) return false;

    return collections.some(col => {
      if (!col) return false;
      if (col.usagePage === 0x01 && (col.usage === 0x02 || col.usage === 0x01)) return true;
      if (Array.isArray(col.children)) return this.deviceIsMouse(col.children);
      return false;
    });
  }

  /**
   * Checks whether the device implements Consumer Control (Usage Page 0x0C, Usage 0x01).
   * @param {Array<object>} collections
   * @returns {boolean}
   */
  static deviceHasConsumerControl(collections) {
    if (!collections || !Array.isArray(collections)) return false;

    return collections.some(col => {
      if (!col) return false;
      if (col.usagePage === 0x0c && col.usage === 0x01) return true;
      if (Array.isArray(col.children)) return this.deviceHasConsumerControl(col.children);
      return false;
    });
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
   * Calculates maximum report buffer size across a collection of reports.
   * @param {Array<object>} reports
   * @returns {number}
   */
  static getMaxReportSize(reports) {
    if (!reports || reports.length === 0) return 0;
    let max = 0;
    for (const r of reports) {
      const size = Number(r.reportSize) || 8;
      if (size > max) max = size;
    }
    return max;
  }

  /**
   * Analyzes an HID device object using a multi-vector attack surface model.
   * @param {object} device - An HIDDevice instance or mock descriptor
   * @param {object|null} dbRecord - Optional matched database record
   * @returns {object} Threat assessment report
   */
  static analyzeDevice(device, dbRecord = null) {
    const collections = device?.collections || [];
    const isKeyboard = this.deviceIsKeyboard(collections);
    const isMouse = this.deviceIsMouse(collections);
    const hasConsumer = this.deviceHasConsumerControl(collections);
    const hasVendorPages = this.hasVendorDefinedUsagePage(collections);

    const outputReports = Array.from(this.getOutputReports(collections));
    const featureReports = Array.from(this.getFeatureReports(collections));
    const inputReports = Array.from(this.getInputReports(collections));

    const outCount = outputReports.length;
    const featCount = featureReports.length;
    const totalWritable = outCount + featCount;
    const maxWritableSize = this.getMaxReportSize([...outputReports, ...featureReports]);

    // Check if writable reports are purely constrained 1-byte LED indicators
    const isLedOnlyChannel = (totalWritable === 1 && maxWritableSize <= 1 && !hasVendorPages);

    // 1. Vector: Keystroke Injection Potential (Impact, 0 - 10)
    let impactScore = 1.0;
    let impactDesc = 'Non-interactive peripheral. Negligible OS keystroke delivery capability.';
    let impactSeverity = 'SAFE';

    if (isKeyboard) {
      impactScore = hasConsumer ? 9.2 : 8.8;
      impactDesc = 'Direct HID Keyboard collection present (Usage 0x01:0x06). Device can emit simulated OS keystrokes without authorization.';
      impactSeverity = 'CRITICAL';
    } else if (isMouse) {
      impactScore = hasConsumer ? 4.2 : 2.2;
      impactDesc = 'Pointer/Mouse interface only. Direct keystroke injection is unachievable without companion firmware re-enumeration.';
      impactSeverity = 'LOW';
    }

    // 2. Vector: Host Control Plane & Buffer Depth (Exploitability, 0 - 10)
    let exploitabilityScore = 0.0;
    let exploitabilityDesc = 'Read-only HID peripheral. No Output or Feature report endpoints exposed for host-to-device command injection.';
    let exploitabilitySeverity = 'SAFE';

    if (totalWritable === 0) {
      exploitabilityScore = 0.0;
    } else if (isLedOnlyChannel) {
      exploitabilityScore = 1.2;
      exploitabilityDesc = 'Constrained 1-byte LED status channel. Incapable of carrying programmable firmware or macro payloads.';
      exploitabilitySeverity = 'LOW';
    } else {
      let base = 6.2;
      if (maxWritableSize > 32) {
        base = 8.5; // Bulk memory frames (e.g. 64-byte CH57x blocks)
      } else if (maxWritableSize > 8) {
        base = 7.5; // Extended protocol frames (e.g. 20-byte HID++ long)
      }
      base += Math.min(totalWritable, 3) * 0.4;
      exploitabilityScore = Math.min(9.5, Number(base.toFixed(1)));
      exploitabilitySeverity = exploitabilityScore >= 8.0 ? 'CRITICAL' : 'HIGH';
      exploitabilityDesc = `Detected ${totalWritable} writable report endpoint(s) (${outCount} Output, ${featCount} Feature). Max buffer depth: ${maxWritableSize} bytes. Host can dispatch unconstrained control packets.`;
    }

    // 3. Vector: Attack Surface & Proprietary Protocol Scope (0 - 10)
    let attackSurfaceScore = 1.5;
    let attackSurfaceDesc = 'Standard Desktop HID usage pages only. Operates under standard operating system interface constraints.';
    let attackSurfaceSeverity = 'LOW';

    if (hasVendorPages) {
      let base = 7.6;
      if (totalWritable > 1) base += 0.8;
      attackSurfaceScore = Math.min(9.2, Number(base.toFixed(1)));
      attackSurfaceSeverity = 'HIGH';
      attackSurfaceDesc = 'Proprietary vendor-defined Usage Pages (>= 0xFF00) detected. Endpoints operate outside standard OS drivers, exposing raw controller registers.';
    }

    // 4. Vector: Hardware Signature & Catalog Correlation (0 - 10)
    let profileScore = 1.0;
    let profileDesc = 'Generic peripheral profile without cataloged firmware vulnerability record.';
    let profileSeverity = 'SAFE';

    const vid = Number(device?.vendorId) || 0;
    const isLogitech = (vid === 1133 || vid === 0x046d);
    const isWch = (vid === 4489 || vid === 0x1189);
    const hasKnownVendor = isLogitech || isWch || Boolean(dbRecord);

    if (hasKnownVendor) {
      profileScore = 8.6;
      profileSeverity = 'CRITICAL';
      const name = dbRecord?.name || (isLogitech ? 'Logitech HID++ Macro Controller' : 'WCH CH57x Direct Flash Controller');
      profileDesc = `Vendor signature matches cataloged reprogrammable architecture: ${name}.`;
    } else if (hasVendorPages && isKeyboard) {
      profileScore = 6.0;
      profileSeverity = 'MEDIUM';
      profileDesc = 'Unknown vendor peripheral exhibiting composite keyboard and proprietary configuration attributes.';
    }

    // Calculate Composite Risk Score (0 - 100)
    let score = 0;
    if (exploitabilityScore === 0) {
      score = Math.round(impactScore * 0.4);
    } else {
      const weightedBase =
        (0.44 * (impactScore * (exploitabilityScore / 10)) * 10) +
        (0.34 * exploitabilityScore * 10) +
        (0.14 * attackSurfaceScore * 10) +
        (0.08 * profileScore * 10);
      score = Math.round(weightedBase * 1.08);
      // Clamp between 1 and 96 to preserve mathematical credibility
      score = Math.max(1, Math.min(96, score));
    }

    // Determine vulnerability verdict
    const isVulnerable = isKeyboard && totalWritable > 0 && !isLedOnlyChannel;

    let threatLevel = 'SAFE';
    if (score >= 80) threatLevel = 'CRITICAL';
    else if (score >= 60) threatLevel = 'HIGH';
    else if (score >= 30) threatLevel = 'MEDIUM';
    else if (score >= 10) threatLevel = 'LOW';

    let summary = '';
    if (isVulnerable) {
      summary = `High risk: Peripheral combines OS keystroke injection capabilities with writable host command endpoints (${outCount} Output, ${featCount} Feature). Malicious web applications can dispatch unauthenticated frames to reprogram device behavior.`;
    } else if (hasVendorPages && totalWritable > 0) {
      summary = 'Moderate risk: Peripheral exposes proprietary write endpoints but lacks direct keyboard injection capabilities. Potential firmware tampering surface.';
    } else if (isKeyboard) {
      summary = 'Low risk: Standard keyboard input interface with minimal or read-only host write channel. No rogue keystroke injection vector identified.';
    } else {
      summary = 'Safe peripheral: Standard non-keyboard input device without unauthenticated host-to-device programming endpoints.';
    }

    const vulnerabilities = [];
    if (isKeyboard) {
      vulnerabilities.push('HID Keyboard interface capable of synthesizing unauthenticated OS keystrokes.');
    }
    if (totalWritable > 0 && !isLedOnlyChannel) {
      vulnerabilities.push(`Accepts host-to-device command reports (${outCount} Output, ${featCount} Feature, max ${maxWritableSize}B buffer).`);
    }
    if (hasVendorPages) {
      vulnerabilities.push('Exposes proprietary vendor-defined Usage Pages (>= 0xFF00) capable of undocumented register writes.');
    }
    if (hasKnownVendor) {
      vulnerabilities.push('Hardware correlates with known reprogrammable vendor firmware architecture.');
    }

    // Structure vector dimensions for detailed reporting
    const vectors = [
      {
        id: 'impact',
        name: 'Keystroke Injection Potential (Impact)',
        score: impactScore,
        max: 10,
        severity: impactSeverity,
        finding: impactDesc,
        evidence: isKeyboard ? 'Usage Page 0x01, Usage 0x06 (Keyboard TLC)' : (isMouse ? 'Usage Page 0x01, Usage 0x02 (Mouse TLC)' : 'Non-Input TLC')
      },
      {
        id: 'exploitability',
        name: 'Control Plane & Writable Channels (Exploitability)',
        score: exploitabilityScore,
        max: 10,
        severity: exploitabilitySeverity,
        finding: exploitabilityDesc,
        evidence: totalWritable > 0 ? `${outCount} Output, ${featCount} Feature (Max: ${maxWritableSize}B)` : 'Read-Only (0 Writable Endpoints)'
      },
      {
        id: 'surface',
        name: 'Vendor & Proprietary Interface Exposure (Attack Surface)',
        score: attackSurfaceScore,
        max: 10,
        severity: attackSurfaceSeverity,
        finding: attackSurfaceDesc,
        evidence: hasVendorPages ? 'Usage Page >= 0xFF00 Present' : 'Standard USB HID Desktop Usages'
      },
      {
        id: 'signature',
        name: 'Hardware Profile & Vulnerability Correlation',
        score: profileScore,
        max: 10,
        severity: profileSeverity,
        finding: profileDesc,
        evidence: hasKnownVendor ? `VID: 0x${vid.toString(16).padStart(4, '0')} (Cataloged)` : 'Generic / Unmatched VID'
      }
    ];

    // Detail discovered endpoints for telemetry
    const endpointList = [];
    outputReports.forEach(r => {
      const size = Number(r.reportSize) || 8;
      endpointList.push({
        type: 'Output Report',
        reportId: r.reportId !== undefined ? `0x${Number(r.reportId).toString(16).padStart(2, '0')}` : '0x00',
        reportSize: `${size} bytes`,
        riskLevel: size > 8 ? 'CRITICAL' : 'HIGH',
        role: size > 32 ? 'Bulk Data / Firmware Transfer' : 'Host Command Dispatch'
      });
    });
    featureReports.forEach(r => {
      const size = Number(r.reportSize) || 8;
      endpointList.push({
        type: 'Feature Report',
        reportId: r.reportId !== undefined ? `0x${Number(r.reportId).toString(16).padStart(2, '0')}` : '0x00',
        reportSize: `${size} bytes`,
        riskLevel: 'MEDIUM',
        role: 'Hardware Register / Configuration'
      });
    });
    inputReports.forEach(r => {
      const size = Number(r.reportSize) || 8;
      endpointList.push({
        type: 'Input Report',
        reportId: r.reportId !== undefined ? `0x${Number(r.reportId).toString(16).padStart(2, '0')}` : '0x00',
        reportSize: `${size} bytes`,
        riskLevel: 'SAFE',
        role: 'Peripheral State Ingest'
      });
    });

    return {
      isVulnerable,
      threatLevel,
      score,
      summary,
      isKeyboard,
      isMouse,
      hasOutputReports: outCount > 0,
      hasFeatureReports: featCount > 0,
      hasVendorPages,
      outputReportCount: outCount,
      featureReportCount: featCount,
      maxWritableSize,
      outputReports,
      featureReports,
      vulnerabilities,
      vectors,
      endpoints: endpointList
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
