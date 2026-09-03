// The drift-vs-regression triage.
//
// This is the highest-consequence pure function in the engine, and it is the one
// that has already been wrong: a disclosure regression was classified as
// FAIL_CONTRACT — "Watson's map is wrong" — which is how a real privacy finding
// gets waved through (Phase-1 defect W4).
//
// Both directions of misclassification are tested, because they fail differently:
// calling drift a product defect burns the reviewer's trust, and calling a product
// defect drift hides it.

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { classifyFailure, evaluate, SECURITY_RULES } from '../src/checks.mjs';

const noFindings = [];
const corroborating = [{ rule: 'unexpected-5xx', severity: 'blocking' }];

describe('classifyFailure', () => {
  test('a missing HANDLE is contract drift, not a broken product', () => {
    for (const action of ['click', 'fill', 'select']) {
      const v = classifyFailure(
        { action, message: 'locator.click: Timeout 15000ms exceeded.' },
        noFindings,
      );
      assert.equal(v.verdict, 'FAIL_CONTRACT', `${action} target miss`);
    }
  });

  test('a failed BEHAVIORAL assertion is a product failure', () => {
    // W4: wait_for_text and expect_count_at_most used to sit in the addressing set.
    // wait_for_text asserts what the app SAYS; expect_count_at_most cannot even fail
    // on a missing handle, since a selector matching nothing counts zero.
    for (const action of ['wait_for_text', 'expect_count_at_most', 'expect_text', 'expect_api']) {
      const v = classifyFailure(
        { action, message: 'locator.waitFor: Timeout 15000ms exceeded.' },
        noFindings,
      );
      assert.equal(v.verdict, 'FAIL_PRODUCT', `${action} must accuse the product`);
    }
  });

  test('the exact W4 regression: a missing suppression notice is a PRODUCT failure', () => {
    const v = classifyFailure(
      { action: 'wait_for_text', message: 'locator.waitFor: Timeout 15000ms exceeded.' },
      noFindings,
    );
    assert.equal(v.verdict, 'FAIL_PRODUCT');
    assert.match(v.reason, /behavioral assertion/);
  });

  test('a runtime signal overrides drift — corroborated failures accuse the product', () => {
    const v = classifyFailure(
      { action: 'click', message: 'locator.click: Timeout 15000ms exceeded.' },
      corroborating,
    );
    assert.equal(v.verdict, 'FAIL_PRODUCT');
    assert.equal(v.corroborated, true);
  });

  test('a route that does not exist is drift, not a denial failure', () => {
    const v = classifyFailure(
      { action: 'expect_denied', message: 'expected /api/x to be denied (401/403), got 404' },
      noFindings,
    );
    assert.equal(v.verdict, 'FAIL_CONTRACT');
  });

  test('an addressing step failing for a NON-target reason still accuses the product', () => {
    // A click that fails because the server 500ed mid-navigation is not drift.
    const v = classifyFailure(
      { action: 'click', message: 'net::ERR_CONNECTION_REFUSED' },
      noFindings,
    );
    assert.equal(v.verdict, 'FAIL_PRODUCT');
  });
});

// ----------------------------------------------------------------------------
// SECURITY RULES ARE NOT SUBJECT TO THE CONTRACT.
//
// Found by the exact-HEAD confirmation review (its N4) and reproduced before
// fixing. `severityOf` already forced these to `blocking` whatever a contract
// said, so the intent was clear — but `isEnabled` did not, and enablement is
// what decides whether the finding exists at all. Measured on evidence carrying
// a real 500:
//
//     undeclared                    -> unexpected-5xx:blocking
//     severity: off                 -> NO FINDING
//     except_features: [thisOne]    -> NO FINDING
//     applies_to_features: [other]  -> NO FINDING
//
// Three ways to silence a rule whose severity could not be lowered. Not
// pull-request-exploitable — invariants come from the BASE contract — but
// `.watson/invariants.yaml` in nsc-eval states that these cannot be switched
// off, and a claim in a shipped file is either true or it is a defect.
//
// Emptying `SECURITY_RULES` entirely also left the whole suite green, so the
// membership was unpinned too.
describe('security rules cannot be switched off by a contract', () => {
  // Independent literal, deliberately. An assertion that iterates the set under
  // test shrinks with it — the same trap as CONFIG_AUTHORITY and
  // ENGINE_OWNED_ENV. Changing the engine must change only one side of this.
  const EXPECTED_SECURITY_RULES = ['unauthorized-route-200', 'unexpected-5xx', 'wrong-season-context'];

  const withFiveHundred = { requests: [{ url: 'http://x/api/a', status: 500, method: 'GET' }],
    console: [], failed: [], texts: [], pageErrors: [] };
  const rules = (invariants) => evaluate({ featureId: 'j', evidence: withFiveHundred, invariants, pageText: '' })
    .map((f) => `${f.rule}:${f.severity}`);

  test('the set is exactly these rules', () => {
    assert.deepEqual([...SECURITY_RULES].sort(), [...EXPECTED_SECURITY_RULES].sort());
  });

  test('an undeclared security rule still fires, and fires blocking', () => {
    assert.deepEqual(rules([]), ['unexpected-5xx:blocking']);
  });

  for (const [label, declaration] of [
    ['severity: off', { rule: 'unexpected-5xx', severity: 'off' }],
    ['except_features naming this feature', { rule: 'unexpected-5xx', severity: 'blocking', except_features: ['j'] }],
    ['applies_to_features naming another', { rule: 'unexpected-5xx', severity: 'blocking', applies_to_features: ['other'] }],
    ['severity downgraded to advisory', { rule: 'unexpected-5xx', severity: 'advisory' }],
  ]) {
    test(`${label} does not silence it`, () => {
      assert.deepEqual(rules([declaration]), ['unexpected-5xx:blocking'],
        'a contract switched off a rule the engine calls non-negotiable');
    });
  }

  test('an ADVISORY rule is still tunable — this is not a blanket override', () => {
    // The point is a bounded exception, not "the contract is ignored". A contract
    // that legitimately silences a style rule for one journey must still work, or
    // the mechanism becomes something people route around.
    const noisy = { requests: [], console: [{ type: 'error', text: 'boom' }], failed: [], texts: [], pageErrors: [] };
    const run = (invariants) => evaluate({ featureId: 'j', evidence: noisy, invariants, pageText: '' })
      .map((f) => `${f.rule}:${f.severity}`);
    assert.deepEqual(run([{ rule: 'console-errors', severity: 'advisory' }]), ['console-errors:advisory']);
    assert.deepEqual(run([{ rule: 'console-errors', severity: 'off' }]), []);
    assert.deepEqual(run([{ rule: 'console-errors', severity: 'advisory', except_features: ['j'] }]), []);
  });
});
