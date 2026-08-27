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
import { classifyFailure } from '../src/checks.mjs';

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
