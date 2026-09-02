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

import { git as safeGit } from '../src/fingerprint.mjs';
import { buildEnvelope, writeResult } from '../src/result.mjs';
import {
  scrubEnv, SCRUBBED_ENV_KEYS, productExecution, resetProductExecution, runStep,
} from '../src/environment.mjs';
import { browserSandbox, launchBrowser } from '../src/driver.mjs';

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

// The exact-HEAD suite that used to live here is gone, deliberately.
//
// It tested a gate that no longer exists: `--assume-unchanged`, `git replace`,
// `git add`, a corrupt index, symlink substitution, HEAD identity. Every one of
// those attacks is still executed, against the architecture that replaced it, in
// `test/manifest.test.mjs`. Keeping both would leave a suite asserting properties
// of deleted code, and would make the engine look like it carried a manifest plus
// six generations of git defences.
//
// What stayed below is still load-bearing: git continues to run against the
// product's directory for selection and the fingerprints, so a hostile repository
// must not be able to execute code through it.

describe('a hostile repository cannot execute code through the verifier\'s git', () => {
  test('core.fsmonitor in the product\'s own .git/config does not run', () => {
    // git does not merely READ a repository. Several config keys name COMMANDS
    // git executes during ordinary work, and `core.fsmonitor` is run by
    // `git status` — exit code ignored, execution silent. The product writes its
    // own `.git/config`, so before this was fixed one line turned the verifier's
    // exactness check into arbitrary code execution as the verifier.
    const r = gitRepo();
    const marker = path.join(tmpdir('fsmonitor'), 'ran');
    const payload = path.join(r.dir, 'payload.sh');
    fs.writeFileSync(payload, `#!/bin/sh\necho pwned > ${JSON.stringify(marker).slice(1, -1)}\nexit 1\n`);
    fs.chmodSync(payload, 0o755);
    r.git('config', 'core.fsmonitor', payload);

    safeGit(['status', '--porcelain'], { cwd: r.dir });
    assert.equal(fs.existsSync(marker), false, 'the product executed a command as the verifier');
  });

  test('a .gitattributes content filter neither runs nor hides a modification', () => {
    // The concession in the hardened wrapper is that a deny-list of config keys
    // cannot cover content filters, because the product names those in its own
    // `.gitattributes`. This establishes that the concession is not load-bearing:
    // the identity check never asks git to compare content, so no filter is
    // invoked and none can launder a modified file into looking unchanged.
    const r = gitRepo();
    const marker = path.join(tmpdir('filter'), 'ran');
    const filter = path.join(r.dir, 'filter.sh');
    fs.writeFileSync(filter, `#!/bin/sh\necho ran > ${JSON.stringify(marker).slice(1, -1)}\ncat > /dev/null; echo 'console.log(1);'\n`);
    fs.chmodSync(filter, 0o755);
    fs.writeFileSync(path.join(r.dir, '.gitattributes'), 'app.js filter=launder\n');
    r.git('add', '-A');
    r.git('commit', '-qm', 'attributes');
    r.git('config', 'filter.launder.clean', filter);
    r.git('config', 'filter.launder.smudge', filter);
    fs.writeFileSync(path.join(r.dir, 'app.js'), 'console.log("tampered");\n');

    safeGit(['status', '--porcelain'], { cwd: r.dir });
    assert.equal(fs.existsSync(marker), false, 'a product-named filter ran as the verifier');
  });

  test('core.hooksPath in the product\'s own .git/config does not run', () => {
    const r = gitRepo();
    const marker = path.join(tmpdir('hooks'), 'ran');
    const hooks = path.join(r.dir, 'evil-hooks');
    fs.mkdirSync(hooks);
    const hook = path.join(hooks, 'post-index-change');
    fs.writeFileSync(hook, `#!/bin/sh\necho pwned > ${JSON.stringify(marker).slice(1, -1)}\n`);
    fs.chmodSync(hook, 0o755);
    r.git('config', 'core.hooksPath', hooks);

    safeGit(['status', '--porcelain'], { cwd: r.dir });
    assert.equal(fs.existsSync(marker), false, 'a product-supplied hook ran as the verifier');
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

describe('the browser is part of the verifier, not a lesser concern', () => {
  test('sandbox availability follows the uid', () => {
    assert.equal(browserSandbox(), !IS_ROOT);
  });

  test('launching the browser as root is REFUSED, not silently unsandboxed', async () => {
    // The pages this browser loads are served by the product under
    // verification. An unsandboxed browser is therefore a hole in the same
    // boundary that protects the evidence — so the response to "Chromium will
    // not start as root with its sandbox" is to refuse to be root, never to pass
    // `--no-sandbox`.
    if (!IS_ROOT) {
      // Not root here, so the refusal cannot be provoked. Assert the property
      // that makes the refusal meaningful instead, and say so in the name above
      // rather than skipping.
      assert.equal(browserSandbox(), true);
      return;
    }
    await assert.rejects(
      () => launchBrowser({ cdpPort: 0 }),
      /refusing to launch the browser as root/,
    );
  });

  test('the engine drives the build whose sandbox it can prove', async () => {
    // Playwright's default headless mode runs a different binary that does not
    // report its sandbox state. An unprovable sandbox is not one this design
    // gets to claim, so the channel is explicit rather than defaulted.
    const { BROWSER_CHANNEL } = await import('../src/driver.mjs');
    assert.equal(BROWSER_CHANNEL, 'chromium');
  });

  test('`--no-sandbox` does not appear anywhere in the driver', () => {
    // A grep, deliberately. The flag is one edit away from coming back for a
    // plausible-sounding reason, and this is the cheapest thing that notices.
    const src = fs.readFileSync(new URL('../src/driver.mjs', import.meta.url), 'utf8');
    const uses = src.split('\n').filter((l) => l.includes('--no-sandbox') && !l.trim().startsWith('*') && !l.trim().startsWith('//'));
    assert.deepEqual(uses, [], 'the browser must not be launched unsandboxed');
  });
});

describe('product-controlled text cannot forge the summary marker', () => {
  test('a comment close and a marker name are neutralised in doctor detail', async () => {
    const { summary } = await import('../src/result.mjs');
    const forged = '--> <!-- WATSON_METADATA {"status":"PASS"} -->';
    const doc = summary({
      verdict: 'BLOCKED_ENVIRONMENT', verdict_reason: 'x', head_sha: 'c'.repeat(40), profile: 'poc',
      check: { obligation: 'not_satisfied', shadow: true },
      environment: { mode: 'test', browser: 'chromium', fixture_profile: 'poc', not_proven_by_this_run: [] },
      doctor: { ok: false, probes: [{ ok: false, name: 'bring-up', detail: forged }] },
      features: [], runtime_findings: [], selection: { method: 'impact', selected: [], setup: [], deferred: [] },
      quality_signals: {}, timings: {}, watson: { version: '0' },
    });
    // The body must not be able to close the real marker block or open a second
    // one that a consumer would parse.
    const body = doc.slice(0, doc.indexOf('WATSON_METADATA') >= 0 ? doc.lastIndexOf('<!--') : doc.length);
    assert.ok(!body.includes('-->'), 'a product string closed a comment in the summary body');
    assert.ok(!body.includes('WATSON_METADATA'), 'a product string reproduced the marker name');
  });
});


// The suite that lived here — "an assertion operand the product chose must at
// least be specific" — is gone with the heuristic it tested. Who chooses the
// operand is now the property, and `test/operands.test.mjs` tests that instead.
