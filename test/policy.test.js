/**
 * Unit Tests: Policy Engine & Access Decision Matrix
 */

import { PolicyEngine, POLICY_MODES } from '../defensive-extension/core/policy-engine.js';

export function runPolicyTests(assert) {
  const mockLogitechClassification = {
    isKnownVulnerable: true,
    protocol: 'HID++',
    device: { vendorId: 0x046d, productId: 0xc08b, name: 'Logitech G502 HERO' },
    riskLevel: 'CRITICAL'
  };

  const dangerousHIDppData = new Uint8Array([0x01, 0x90, 0x00, 0x01, 0x00, 0x00]); // writeMemory
  const safeHIDppData = new Uint8Array([0xff, 0x00, 0x0a, 0x81, 0x00]); // GetFeature

  // 1. Balanced Mode (Default)
  {
    const engine = new PolicyEngine({ mode: POLICY_MODES.BALANCED });
    
    // Dangerous write should be blocked
    const dec1 = engine.evaluateHIDOperation(mockLogitechClassification, 'sendReport', 0x11, dangerousHIDppData, 'https://evil-site.com');
    assert(dec1.allowed, false, 'Balanced Mode: Should block dangerous writeMemory operation');
    assert(dec1.shouldNotify, true, 'Balanced Mode: Should trigger user security alert');

    // Safe read should be allowed
    const dec2 = engine.evaluateHIDOperation(mockLogitechClassification, 'sendReport', 0x10, safeHIDppData, 'https://evil-site.com');
    assert(dec2.allowed, true, 'Balanced Mode: Should allow safe GetFeature operation');
  }

  // 2. Strict Mode
  {
    const engine = new PolicyEngine({ mode: POLICY_MODES.STRICT });
    
    // Both safe and dangerous writes blocked
    const dec1 = engine.evaluateHIDOperation(mockLogitechClassification, 'sendReport', 0x10, safeHIDppData, 'https://evil-site.com');
    assert(dec1.allowed, false, 'Strict Mode: Should block even safe writes under zero-trust policy');
  }

  // 3. Permissive Mode
  {
    const engine = new PolicyEngine({ mode: POLICY_MODES.PERMISSIVE });
    
    // Dangerous write allowed with audit alert
    const dec1 = engine.evaluateHIDOperation(mockLogitechClassification, 'sendReport', 0x11, dangerousHIDppData, 'https://evil-site.com');
    assert(dec1.allowed, true, 'Permissive Mode: Should allow write for audit-only tracing');
    assert(dec1.shouldNotify, true, 'Permissive Mode: Should still record audit notification');
  }

  // 4. Origin Allowlist Override
  {
    const engine = new PolicyEngine({
      mode: POLICY_MODES.STRICT,
      originAllowlist: ['https://trusted-site.com']
    });

    const dec1 = engine.evaluateHIDOperation(mockLogitechClassification, 'sendReport', 0x11, dangerousHIDppData, 'https://trusted-site.com');
    assert(dec1.allowed, true, 'Allowlist: Trusted origin should bypass policy blocks');
  }

  // 5. Per-Device Overrides
  {
    const engine = new PolicyEngine({
      mode: POLICY_MODES.BALANCED,
      deviceOverrides: {
        '1133:49291': 'always_block',
        '4489:34960': 'always_allow'
      }
    });

    // 1133:49291 (0x046d:0xc08b) set to always_block
    const dec1 = engine.evaluateHIDOperation(mockLogitechClassification, 'sendReport', 0x10, safeHIDppData, 'https://evil-site.com');
    assert(dec1.allowed, false, 'Override: Device set to always_block should reject even safe operations');

    // 4489:34960 (CH57X) set to always_allow
    const ch57xClassification = {
      isKnownVulnerable: true,
      protocol: 'CH57X',
      device: { vendorId: 4489, productId: 34960, name: 'CH57X Keyboard' }
    };
    const keyUpdateStart = new Uint8Array([0xa1, 0x01]);
    const dec2 = engine.evaluateHIDOperation(ch57xClassification, 'sendReport', 3, keyUpdateStart, 'https://evil-site.com');
    assert(dec2.allowed, true, 'Override: Device set to always_allow should permit operations');
  }

  // 6. Enterprise Managed Policy
  {
    const engine = new PolicyEngine({
      mode: POLICY_MODES.BALANCED,
      managedPolicy: {
        enforceStrict: true
      }
    });

    assert(engine.mode, POLICY_MODES.STRICT, 'Enterprise: Managed enforceStrict should override mode to Strict');
  }

  // 7. Connection Defense Tests (Untrusted Origin WebHID Access)
  {
    const engine = new PolicyEngine({
      mode: POLICY_MODES.BALANCED,
      originAllowlist: ['https://trusted-site.com']
    });

    // Untrusted origin requesting Logitech mouse (0x046d) should be BLOCKED
    const blockedConn = engine.evaluateHIDConnection('https://universal-omm-fake.com', [{ vendorId: 0x046d }]);
    assert(blockedConn.allowed, false, 'Connection: Untrusted origin requesting Logitech device must be blocked');
    assert(blockedConn.opType, 'untrusted_connection_blocked', 'Connection: OpType should be untrusted_connection_blocked');

    // Trusted origin requesting Logitech mouse should be ALLOWED
    const allowedConn = engine.evaluateHIDConnection('https://trusted-site.com', [{ vendorId: 0x046d }]);
    assert(allowedConn.allowed, true, 'Connection: Allowlisted origin requesting Logitech device must be permitted');

    // Untrusted origin requesting benign device (e.g. non-vulnerable vendor)
    const benignConn = engine.evaluateHIDConnection('https://other-site.com', [{ vendorId: 0x1234 }]);
    assert(benignConn.allowed, true, 'Connection: Non-programmable vendor filter should be permitted');

    // Untrusted origin attempting to open vulnerable device
    const openDec = engine.evaluateHID(mockLogitechClassification, 'open', 0, null, 'https://universal-omm-fake.com');
    assert(openDec.allowed, false, 'Open: Untrusted origin blocked from opening programmable Logitech mouse');
  }
}
