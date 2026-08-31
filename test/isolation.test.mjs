// The trust boundary between the verifier and the thing it verifies.
//
// Watson runs the product's own install, build, launch and seed commands. Under
// the threat model that matters — a pull request whose code may be hostile —
// those commands are written by the author whose work Watson is judging. The
// tests here are the negative controls for the two properties that stops being
// a verifier without:
//
//   1. product code cannot forge, overwrite or influence the result;
//   2. product code cannot inherit the credentials of whatever invoked Watson.
//
// Where a control needs real privilege separation it says so and asserts the
// FAIL-CLOSED behaviour instead when it cannot have it. It never silently skips:
// a security test that quietly does nothing is worse than no test, because the
// green tick is read as proof.

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

import { workingTreeState } from '../src/fingerprint.mjs';
import { buildEnvelope, downgradeForInexactHead, writeResult } from '../src/result.mjs';
import {
  scrubEnv, SCRUBBED_ENV_KEYS, productExecution, resetProductExecution, runStep,
} from '../src/environment.mjs';
import { browserSandbox } from '../src/driver.mjs';

const IS_ROOT = typeof process.getuid === 'function' && process.getuid() === 0;
const HAS_SETPRIV = (() => {
  try { execFileSync('setpriv', ['--help'], { stdio: 'ignore' }); return true; } catch { return false; }
})();

function tmpdir(label) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `watson-${label}-`));
}

function gitRepo() {
  const dir = tmpdir('repo');
  const git = (...a) => execFileSync('git', a, { cwd: dir, encoding: 'utf8' }).trim();
  git('init', '-q', '-b', 'main');
  git('config', 'user.email', 'watson@example.invalid');
  git('config', 'user.name', 'watson-test');
  fs.writeFileSync(path.join(dir, 'app.js'), 'console.log(1);\n');
  git('add', '-A');
  git('commit', '-qm', 'initial');
  return { dir, git, head: () => git('rev-parse', 'HEAD') };
}

describe('exact-HEAD is an identity claim, not a cleanliness claim', () => {
  test('a clean tree at the reported commit is exact', () => {
    const r = gitRepo();
    const st = workingTreeState(r.dir, r.head());
    assert.equal(st.clean, true);
    assert.equal(st.head_matches, true);
    assert.equal(st.exact_head, true);
  });

  test('a clean tree at a DIFFERENT commit is not exact', () => {
    // The forgery this closes: modify the product, commit the modification, and
    // `git status` is clean again. Cleanliness alone would have called this
    // exact-HEAD and let a product claim through for a commit that was never
    // driven.
    const r = gitRepo();
    const reported = r.head();
    fs.writeFileSync(path.join(r.dir, 'app.js'), 'console.log("tampered");\n');
    r.git('commit', '-aqm', 'tampered by the code under verification');
    const after = r.head();
    assert.notEqual(after, reported);

    const st = workingTreeState(r.dir, reported);
    assert.equal(st.clean, true, 'the tree really is clean — that is the point');
    assert.equal(st.head_matches, false);
    assert.equal(st.exact_head, false);
    assert.match(st.note, /not the reported/);
  });

  test('no expectation named means unknown, and unknown is not a failure', () => {
    const r = gitRepo();
    const st = workingTreeState(r.dir);
    assert.equal(st.head_matches, null);
    assert.equal(st.exact_head, true);
  });

  test('a product claim on a mismatched HEAD is withheld', () => {
    for (const verdict of ['PASS', 'PASS_WITH_ADVISORIES', 'FAIL_PRODUCT']) {
      const g = downgradeForInexactHead(verdict, {
        clean: true, exact_head: false, head_matches: false, head_sha: 'a'.repeat(40),
      });
      assert.equal(g.verdict, 'INDETERMINATE', `${verdict} must not survive a HEAD mismatch`);
      assert.match(g.reason, /is at a{40}, not the reported commit/);
    }
  });
});

describe('the canonical result is named by the caller, never discovered', () => {
  test('--out writes the same object to the exact path given', () => {
    const runDir = tmpdir('run');
    const out = path.join(tmpdir('evidence'), 'nested', 'result.json');
    // Built through the real envelope builder rather than hand-rolled: the point
    // of --out is that the canonical file is the SAME object the run produced,
    // and a hand-made stub could satisfy that trivially.
    const envelope = buildEnvelope({
      runId: 'run-test', watsonVersion: '0.0.0-test', repository: 'product',
      headSha: 'b'.repeat(40), baseSha: null, profile: 'poc', shadow: true,
      verdict: 'PASS', verdictReason: 'nothing to report',
      dbName: 'n/a', baseUrl: 'n/a', fixtureProfile: 'poc', browser: 'chromium',
      viewports: ['1280x800'], features: [], findings: [],
      doctor: { ok: true, probes: [] },
      selection: { method: 'impact', applicable: true, selected: [], setup: [], deferred: [] },
      qualitySignals: {}, timings: {}, evidence: { bundle: 'runs/run-test' },
      startedAt: new Date().toISOString(), finishedAt: new Date().toISOString(),
      workingTree: { clean: true, exact_head: true },
    });
    const { jsonPath } = writeResult(runDir, envelope, out);
    assert.equal(
      fs.readFileSync(out, 'utf8'),
      fs.readFileSync(jsonPath, 'utf8'),
      'the canonical copy must be the SAME object the run wrote, not a re-derivation',
    );
    const written = JSON.parse(fs.readFileSync(out, 'utf8'));
    assert.equal(written.verdict, 'PASS');
    assert.equal(written.head_sha, 'b'.repeat(40));
  });
});

describe('product code does not inherit the credentials of the invoking CI', () => {
  test('every scrubbed key is removed, and nothing else is', () => {
    const env = { PATH: '/usr/bin', DATABASE_URL: 'postgres://x', KEEP_ME: '1' };
    for (const k of SCRUBBED_ENV_KEYS) env[k] = 'sensitive';
    const out = scrubEnv(env);
    for (const k of SCRUBBED_ENV_KEYS) assert.equal(k in out, false, `${k} survived the scrub`);
    assert.equal(out.PATH, '/usr/bin');
    assert.equal(out.DATABASE_URL, 'postgres://x');
    assert.equal(out.KEEP_ME, '1');
  });

  test('the list covers credentials AND the runner command channels', () => {
    // Named individually because the second group is the one that gets forgotten:
    // GITHUB_ENV and GITHUB_PATH are files the runner reads back after a step, so
    // anything able to append to them injects state into the TRUSTED side.
    for (const k of ['ACTIONS_RUNTIME_TOKEN', 'GITHUB_TOKEN', 'GITHUB_ENV', 'GITHUB_PATH', 'GITHUB_OUTPUT']) {
      assert.ok(SCRUBBED_ENV_KEYS.includes(k), `${k} must be scrubbed`);
    }
  });

  test('a product command cannot read a scrubbed variable', async () => {
    const dir = tmpdir('scrub');
    await runStep('printf %s "${ACTIONS_RUNTIME_TOKEN:-ABSENT}" > seen.txt', {
      cwd: dir,
      env: { ...process.env, ACTIONS_RUNTIME_TOKEN: 'a-live-bearer-token' },
      label: 'scrub-control',
    });
    assert.equal(fs.readFileSync(path.join(dir, 'seen.txt'), 'utf8'), 'ABSENT');
  });
});

describe('privilege separation is opt-in and fail-closed', () => {
  test('unset means no separation — local development is not a boundary', () => {
    assert.deepEqual(productExecution({}), { drop: false });
  });

  for (const [why, environ] of [
    ['a non-numeric uid', { WATSON_PRODUCT_UID: 'nobody', WATSON_PRODUCT_GID: '65534', WATSON_PRODUCT_HOME: '/tmp' }],
    ['a missing gid', { WATSON_PRODUCT_UID: '65534', WATSON_PRODUCT_HOME: '/tmp' }],
    ['a missing home', { WATSON_PRODUCT_UID: '65534', WATSON_PRODUCT_GID: '65534' }],
  ]) {
    test(`asking for separation with ${why} refuses rather than degrading`, () => {
      assert.throws(() => productExecution(environ), /must run unprivileged/);
    });
  }
});

// ---------------------------------------------------------------------------
// THE CONTROL THAT MATTERS. Everything above tests a decision; this tests the
// boundary itself, by having a product-authored command try to do the three
// things a hostile PR would actually want to do.
//
// It needs real privilege separation, which needs root. When that is not
// available the control asserts the fail-closed contract instead and SAYS so, so
// that a green run is never mistaken for a proof it did not perform.
// ---------------------------------------------------------------------------
describe('a product command cannot forge, overwrite, or reach the evidence', () => {
  const capable = IS_ROOT && HAS_SETPRIV;

  test(capable
    ? 'evidence and engine are unreachable from the dropped uid'
    : 'NOT PROVEN HERE (needs root + setpriv) — the fail-closed contract is asserted instead', async () => {
    if (!capable) {
      assert.throws(
        () => productExecution({ WATSON_PRODUCT_UID: '65534', WATSON_PRODUCT_GID: '65534', WATSON_PRODUCT_HOME: '/tmp' }),
        /must run unprivileged/,
        'without root the engine must REFUSE, never fall back to running product code as itself',
      );
      return;
    }

    const root = tmpdir('boundary');
    const evidence = path.join(root, 'evidence');
    const engine = path.join(root, 'engine');
    const product = path.join(root, 'product');
    const home = path.join(root, 'product-home');
    for (const d of [evidence, engine, product, home]) fs.mkdirSync(d);
    // mkdtemp is 0700: without this the dropped uid cannot even traverse into the
    // layout, and every attempt below would "fail" for the wrong reason.
    fs.chmodSync(root, 0o755);

    // The trusted layout: evidence is private to the verifier, the engine is
    // readable but not writable, the product tree belongs to the product.
    fs.writeFileSync(path.join(evidence, 'result.json'), JSON.stringify({ verdict: 'FAIL_PRODUCT' }));
    fs.writeFileSync(path.join(engine, 'result.mjs'), 'export const REAL = true;\n');
    fs.chmodSync(evidence, 0o700);
    fs.chmodSync(engine, 0o755);
    fs.chmodSync(path.join(engine, 'result.mjs'), 0o644);
    execFileSync('chown', ['-R', '65534:65534', product, home]);

    resetProductExecution();
    const policy = productExecution({
      WATSON_PRODUCT_UID: '65534', WATSON_PRODUCT_GID: '65534', WATSON_PRODUCT_HOME: home,
    });
    assert.equal(policy.drop, true);

    const attempt = async (label, cmd) => {
      const outFile = path.join(product, `${label}.out`);
      await runStep(`{ ${cmd} ; } > ${JSON.stringify(outFile)} 2>&1 ; echo "exit=$?" >> ${JSON.stringify(outFile)}`, {
        cwd: product, env: { PATH: process.env.PATH, HOME: home }, label, policy,
      });
      return fs.readFileSync(outFile, 'utf8');
    };

    // 0. The control's own control: the dropped command really did drop.
    const who = await attempt('whoami', 'id -u');
    assert.match(who, /^65534/, `the product command did not actually drop privilege: ${who}`);

    // 1. Forge a passing verdict at the canonical path.
    const forge = await attempt('forge', `printf '{"verdict":"PASS"}' > ${JSON.stringify(path.join(evidence, 'result.json'))}`);
    assert.match(forge, /exit=[1-9]/, `writing the canonical result must fail: ${forge}`);
    assert.equal(
      JSON.parse(fs.readFileSync(path.join(evidence, 'result.json'), 'utf8')).verdict,
      'FAIL_PRODUCT',
      'the real verdict was overwritten',
    );

    // 2. Plant a second, newer result for a mtime-ordered harness to pick up.
    const plant = await attempt('plant', `printf '{"verdict":"PASS"}' > ${JSON.stringify(path.join(evidence, 'result-2.json'))}`);
    assert.match(plant, /exit=[1-9]/, `planting a result must fail: ${plant}`);
    assert.deepEqual(fs.readdirSync(evidence), ['result.json']);

    // 3. Rewrite the verifier so that it reports whatever the product wants.
    const patch = await attempt('patch', `printf 'export const REAL = false;' > ${JSON.stringify(path.join(engine, 'result.mjs'))}`);
    assert.match(patch, /exit=[1-9]/, `patching the engine must fail: ${patch}`);
    assert.equal(fs.readFileSync(path.join(engine, 'result.mjs'), 'utf8'), 'export const REAL = true;\n');

    resetProductExecution();
  });
});

describe('the run says which protections it actually had', () => {
  test('browser sandbox state follows the uid, and is reported rather than assumed', () => {
    // Chromium will not start as root with its sandbox on. Watson is root only
    // where it must drop privilege to run product code as another user, so the
    // two protections trade against each other and the result must say which one
    // this run had — not leave a reader to guess from the environment.
    assert.equal(browserSandbox(), !IS_ROOT);
  });
});
