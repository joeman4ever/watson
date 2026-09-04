// Exact-HEAD claims, and the obligation model.
//
// W2, now a permanent invariant: a run may only make a claim ABOUT A PRODUCT
// REVISION when the checkout it drove actually is that revision. Reporting the
// dirt was not enough — a dirty run must not be able to say PASS.

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { checkFor, PRODUCT_CLAIMS, downgradeForInexactHead } from '../src/result.mjs';
import { isAuthorized } from '../src/driver.mjs';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import { buildManifest } from '../src/manifest.mjs';

const CLI = fileURLToPath(new URL('../src/cli.mjs', import.meta.url));
const SHA = '1'.repeat(40);

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

// ----------------------------------------------------------------------------
// D2 — THE END-OF-RUN RE-MEASURE MUST ACTUALLY EXECUTE.
//
// The exact-HEAD confirmation found that the whole W2 block in `finish()` could
// be disabled — `if (run.repoRoot && run.verdict)` → `if (false && …)` — with
// the entire suite green. Its only guard asserted the SOURCE CONTAINS
// `downgradeForInexactHead(`, which a dead branch still satisfies. The
// downgrade itself is well covered above; what nothing covered is that it is
// reached with a FRESH measurement.
//
// Why that matters: `product/` is mounted read-write into the container running
// the product's own code, so the tree can change WHILE the run is in flight. If
// the re-measure stops happening, `product_identity` silently reverts to the
// start-of-run value and a tree that went dirty mid-run becomes invisible — to
// the engine AND to the trusted validator, which reads that same field.
//
// So this drives the real CLI as a process, with a contract whose own install
// command writes a file into the product tree and then fails. That is a
// deterministic mid-run change: the manifest was built before it, the run stops
// at install, and `finish()` still runs.
describe('D2: the exact-head re-measure runs at the END of the run, not once at the start', () => {
  const build = (installCmd) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'watson-w2-'));
    const w = path.join(dir, '.watson');
    fs.mkdirSync(path.join(w, 'features'), { recursive: true });
    fs.mkdirSync(path.join(w, 'fixtures'), { recursive: true });
    fs.writeFileSync(path.join(w, 'config.yaml'), [
      'contract_version: 4',
      'generated_roots: []',
      'identity: { issuer: "https://watson.local/x", client_id: "c" }',
      'injected_by_engine: []',
      `install: ${JSON.stringify([installCmd])}`,
      'provision: []', 'build: []',
      'env: {}', 'browser: {}', 'engine: {}',
      'launch:',
      '  command: "true"',
      '  health_path: /api/health',
      '  readiness_path: /api/health/db',
      '  fixture_profile: p',
      '  expect_seasons: 2',
    ].join('\n'));
    fs.writeFileSync(path.join(w, 'identities.yaml'), 'identities: []\n');
    fs.writeFileSync(path.join(w, 'invariants.yaml'), 'invariants: []\n');
    fs.writeFileSync(path.join(w, 'fixtures', 'profiles.yaml'), 'profiles:\n  p:\n    command: "true"\n');
    fs.writeFileSync(path.join(w, 'features', 'j1.md'),
      ['---', 'id: j1', 'title: j1', 'status: mapped', 'personas: [A]', 'profiles: [poc]',
        'steps:', '  - goto: /', '---', '', 'b'].join('\n'));

    // The manifest is built BEFORE the run, from the pristine tree — which is
    // exactly the trusted side's ordering.
    const mf = path.join(dir, '..', `w2-manifest-${path.basename(dir)}.json`);
    fs.writeFileSync(mf, JSON.stringify(buildManifest(dir, { sha: SHA })));

    const out = path.join(dir, 'result.json');
    try {
      execFileSync(process.execPath, [CLI, 'verify', '--repo', dir, '--out', out,
        '--sha', SHA, '--manifest', mf], { stdio: ['ignore', 'pipe', 'pipe'], timeout: 60_000 });
    } catch { /* a non-product verdict exits non-zero */ }
    return { dir, result: JSON.parse(fs.readFileSync(out, 'utf8')) };
  };

  test('a tree that is pristine at start and dirty at the end is reported as CHANGED MID-RUN', () => {
    const { dir, result } = build("sh -c 'echo tainted > MID_RUN.txt; exit 1'");
    // The premise, asserted: the mid-run write really happened.
    assert.ok(fs.existsSync(path.join(dir, 'MID_RUN.txt')),
      'the install command did not write into the product tree; the premise of this test is gone');

    const wt = result.product_identity ?? result.working_tree;
    assert.equal(wt.at_start_exact_head, true, 'the tree was not pristine at start-up');
    assert.equal(wt.changed_mid_run, true, 'the end-of-run re-measure did not observe the change');
    assert.equal(wt.exact_head, false, 'the run still claims it drove the exact commit');
    assert.equal(wt.dirty_count, 1);
    assert.ok(wt.dirty_paths.some((p) => p.includes('MID_RUN.txt')),
      `the changed file is not named: ${JSON.stringify(wt.dirty_paths)}`);
  });

  test('a run whose tree never changes is NOT flagged — the signal has to mean something', () => {
    const { dir, result } = build('sh -c "exit 1"');
    assert.ok(!fs.existsSync(path.join(dir, 'MID_RUN.txt')));
    const wt = result.product_identity ?? result.working_tree;
    assert.equal(wt.at_start_exact_head, true);
    assert.equal(wt.changed_mid_run, false);
    assert.equal(wt.exact_head, true);
    assert.equal(wt.dirty_count, 0);
  });

  test('and the gate downgrades on what the re-measure found', () => {
    // The join. The two halves are separately covered — the re-measure observes
    // (above) and `downgradeForInexactHead` downgrades (earlier in this file) —
    // and this states the connection they exist for: a mid-run change forces
    // `exact_head: false` INTO the gate, so a PASS-shaped verdict cannot survive
    // it. `finish()` passes `{ ...at_end, exact_head: false }` when
    // `changed_mid_run`, which is what makes that true even for a run whose
    // end-state measurement alone might look exact.
    const changed = { exact_head: false, dirty_count: 1, dirty_paths: ['MID_RUN.txt (unexpected)'] };
    for (const v of ['PASS', 'PASS_WITH_ADVISORIES']) {
      assert.equal(downgradeForInexactHead(v, changed).verdict, 'INDETERMINATE', v);
    }
  });
});
