/**
 * PeripheralShield - Automated Unit Test Runner
 */

import { runParserTests } from './parsers.test.js';
import { runPolicyTests } from './policy.test.js';
import { runClassifierTests } from './classifier.test.js';

let passed = 0;
let failed = 0;
const errors = [];

function assert(actual, expected, message) {
  if (actual === expected) {
    passed++;
    console.log(`  \x1b[32m✓\x1b[0m ${message}`);
  } else {
    failed++;
    const errMsg = `FAIL: ${message} (Expected: ${JSON.stringify(expected)}, Actual: ${JSON.stringify(actual)})`;
    console.error(`  \x1b[31m✗\x1b[0m ${errMsg}`);
    errors.push(errMsg);
  }
}

console.log('\n\x1b[1m\x1b[34m===================================================\x1b[0m');
console.log('\x1b[1m\x1b[34m  PeripheralShield Test Suite - Unit & Protocol Tests\x1b[0m');
console.log('\x1b[1m\x1b[34m===================================================\x1b[0m\n');

const startTime = Date.now();

try {
  console.log('\x1b[1m[1/3] Running Peripheral Protocol Parser Tests...\x1b[0m');
  runParserTests(assert);
  console.log('');

  console.log('\x1b[1m[2/3] Running Policy Engine & Override Tests...\x1b[0m');
  runPolicyTests(assert);
  console.log('');

  console.log('\x1b[1m[3/3] Running Device Classifier & Threat Estimator Tests...\x1b[0m');
  runClassifierTests(assert);
  console.log('');
} catch (e) {
  console.error('\x1b[31mFATAL TEST EXCEPTION:\x1b[0m', e);
  failed++;
}

const duration = Date.now() - startTime;

console.log('\x1b[1m\x1b[34m---------------------------------------------------\x1b[0m');
if (failed === 0) {
  console.log(`\x1b[1m\x1b[32mALL TESTS PASSED! (${passed} assertions in ${duration}ms)\x1b[0m`);
  console.log('\x1b[1m\x1b[34m===================================================\x1b[0m\n');
  process.exit(0);
} else {
  console.error(`\x1b[1m\x1b[31mTESTS FAILED: ${failed} failed, ${passed} passed (${duration}ms)\x1b[0m`);
  errors.forEach(err => console.error(`  - ${err}`));
  console.log('\x1b[1m\x1b[34m===================================================\x1b[0m\n');
  process.exit(1);
}
