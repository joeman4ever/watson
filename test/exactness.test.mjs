// Exact-HEAD claims, and the obligation model.
//
// W2, now a permanent invariant: a run may only make a claim ABOUT A PRODUCT
// REVISION when the checkout it drove actually is that revision. Reporting the
// dirt was not enough — a dirty run must not be able to say PASS.

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { checkFor, PRODUCT_CLAIMS, downgradeForInexactHead } from '../src/result.mjs';
import { isAuthorized } from '../src/driver.mjs';

describe('the two-axis verdict model', () => {
  test('only FAIL_PRODUCT accuses the product', () => {
    assert.equal(checkFor('FAIL_PRODUCT', { shadow: false }).obligation, 'failed');
    for (const v of ['FAIL_CONTRACT', 'BLOCKED_ENVIRONMENT', 'INDETERMINATE']) {
      assert.equal(checkFor(v, { shadow: false }).obligation, 'not_satisfied', v);
    }
  });

  test('an unmet obligation is never silently satisfiable', () => {
    // "A runtime-relevant HEAD cannot merge merely because Watson was unable to
    // verify it." A blocked run is not a pass.
    assert.notEqual(checkFor('BLOCKED_ENVIRONMENT', { shadow: false }).obligation, 'satisfied');
  });

  test('shadow mode makes every conclusion informational', () => {
    assert.equal(checkFor('FAIL_PRODUCT', { shadow: true }).conclusion, 'neutral');
  });
});

describe('exact-HEAD is required for a product claim (W2)', () => {
  test('the three product claims are the ones that need exactness', () => {
    assert.deepEqual(
      [...PRODUCT_CLAIMS].sort(),
      ['FAIL_PRODUCT', 'PASS', 'PASS_WITH_ADVISORIES'],
    );
  });

  test('a clean checkout leaves a product claim intact', () => {
    const wt = { clean: true, exact_head: true, contract_dirty: false, dirty_count: 0 };
    assert.equal(downgradeForInexactHead('PASS', wt).verdict, 'PASS');
  });

  test('a DIRTY checkout cannot produce a PASS', () => {
    const wt = { clean: false, exact_head: false, contract_dirty: false, dirty_count: 3 };
    const r = downgradeForInexactHead('PASS', wt);
    assert.equal(r.verdict, 'INDETERMINATE');
    assert.match(r.reason, /not the revision it reports/);
  });

  test('a dirty checkout cannot produce a FAIL_PRODUCT either', () => {
    // Accusing a commit of a defect you did not observe on that commit is the same
    // error as absolving it, and costs more.
    const wt = { clean: false, exact_head: false, contract_dirty: false, dirty_count: 1 };
    assert.equal(downgradeForInexactHead('FAIL_PRODUCT', wt).verdict, 'INDETERMINATE');
  });

  test('a dirty CONTRACT says so specifically', () => {
    const wt = { clean: false, exact_head: false, contract_dirty: true, dirty_count: 1 };
    const r = downgradeForInexactHead('PASS', wt);
    assert.equal(r.verdict, 'INDETERMINATE');
    assert.match(r.reason, /contract/i);
  });

  test('non-product verdicts pass through untouched', () => {
    // FAIL_CONTRACT and BLOCKED_ENVIRONMENT are claims about Watson and the
    // environment, not about the product revision, so exactness does not gate them.
    const wt = { clean: false, exact_head: false, contract_dirty: false, dirty_count: 9 };
    for (const v of ['FAIL_CONTRACT', 'BLOCKED_ENVIRONMENT']) {
      assert.equal(downgradeForInexactHead(v, wt).verdict, v, v);
    }
  });

  test('an unknown working-tree state is treated as inexact, not as clean', () => {
    // `git status` failing is not evidence of cleanliness.
    const r = downgradeForInexactHead('PASS', { clean: null, exact_head: false });
    assert.equal(r.verdict, 'INDETERMINATE');
  });
});

describe('isAuthorized', () => {
  test('2xx and 304 are authorized; 401/403 are not', () => {
    for (const s of [200, 201, 204, 299, 304]) assert.equal(isAuthorized(s), true, String(s));
    for (const s of [401, 403]) assert.equal(isAuthorized(s), false, String(s));
  });

  test('a cached repeat navigation does not read as unauthenticated', () => {
    // The false failure that cost a bring-up: asserting strictly on 200.
    assert.equal(isAuthorized(304), true);
  });
});
