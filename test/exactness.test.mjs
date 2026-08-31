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

/** Minimal run record: only the fields `buildEnvelope` needs to produce a result. */
function baseRun() {
  return {
    runId: 'wtsn-test', watsonVersion: '0.0.0-test', repository: 'demo',
    headSha: 'c'.repeat(40), verdict: 'PASS', shadow: true,
    workingTree: { clean: true, exact_head: true },
    productFingerprint: `sha256:${'0'.repeat(64)}`,
    contractFingerprint: `sha256:${'0'.repeat(64)}`,
    features: [], findings: [], timings: {},
  };
}

describe('engine provenance — which verifier produced the result', () => {
  test('a result carries the engine commit and its cleanliness', async () => {
    const { buildEnvelope } = await import('../src/result.mjs');
    const sha = 'a'.repeat(40);
    const env = buildEnvelope({
      ...baseRun(), engine: { commit: sha, clean: true },
    });
    assert.equal(env.watson.commit, sha);
    assert.equal(env.watson.clean, true);
  });

  test('an undeterminable engine records nulls rather than guessing', async () => {
    const { buildEnvelope } = await import('../src/result.mjs');
    const env = buildEnvelope({ ...baseRun(), engine: { commit: null, clean: null } });
    assert.equal(env.watson.commit, null);
    assert.equal(env.watson.clean, null);
  });

  test('a DIRTY engine still reports its sha, flagged — the pair is the point', async () => {
    // A sha from a modified tree is a more convincing lie than no sha at all, so
    // the two travel together and neither is reported without the other.
    const { buildEnvelope } = await import('../src/result.mjs');
    const env = buildEnvelope({
      ...baseRun(), engine: { commit: 'b'.repeat(40), clean: false },
    });
    assert.equal(env.watson.clean, false, 'a dirty engine must be visible, not silently trusted');
    assert.equal(env.watson.commit, 'b'.repeat(40));
  });

  test('engineProvenance resolves this engine’s real commit from its own checkout', async () => {
    const { engineProvenance } = await import('../src/fingerprint.mjs');
    const p = engineProvenance(new URL('..', import.meta.url).pathname);
    assert.match(p.commit, /^[0-9a-f]{40}$/, 'must resolve a real sha in a git checkout');
    assert.equal(typeof p.clean, 'boolean');
  });

  test('engineProvenance fails closed on a non-repository', async () => {
    const { engineProvenance } = await import('../src/fingerprint.mjs');
    assert.deepEqual(engineProvenance('/'), { commit: null, clean: null });
  });
});
