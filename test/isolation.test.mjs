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
import { validateBrowserOwnership, validateEnvOwnership, ENGINE_OWNED_ENV } from '../src/contract.mjs';
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

// SCOPE. This file covers the EXECUTION boundary only: privilege separation,
// credential scrubbing, evidence protection, and the fact that a hostile
// repository cannot execute code through the verifier's own git.
//
// It deliberately does not test product IDENTITY. That gate lives in
// `test/exactness.test.mjs` and is unchanged by this slice — it is replaced
// wholesale in the verification-policy slice that follows (ADR-049), and
// splitting it across two suites in the meantime would leave neither readable.
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

  // A `.gitattributes` content filter is the one thing the hardened wrapper's
  // deny-list provably cannot cover: filters are named by the product's own
  // attributes file, so there is no finite set of `-c` overrides that stops them.
  //
  // The test that used to sit here asserted the concession was "not load-bearing"
  // and PASSED BY ACCIDENT. It tampered with `console.log(1);` (15 bytes) by
  // writing `console.log("tampered");` (25 bytes); git decides "modified" from
  // stat data when the size differs and never converts the content, so the filter
  // never ran. At equal length it runs — reproduced, as uid 0:
  //
  //     shipped tampering (15 -> 25 bytes):  filter ran? no
  //     equal length      (15 -> 15 bytes):  filter ran? YES  ("ran as uid 0")
  //
  // It is closed here by construction rather than by another deny-list entry: no
  // trusted-side call reads the working tree any more, because product identity
  // comes from the manifest. This test asserts that property directly, so it fails
  // the moment someone reintroduces a working-tree read — which is the only way
  // the filter vector can come back.
  test('no trusted-side git call reads the working tree', () => {
    // Verbs that make git convert file content (and therefore run a clean filter).
    // `status`, `diff` without two commits, `add`, `stash`, `checkout`, `archive`
    // of a worktree — all read what is on disk.
    const WORKTREE_READING = /git\(\[\s*'(status|add|stash|checkout|commit)'/;
    for (const file of ['../src/fingerprint.mjs', '../src/contract.mjs', '../src/cli.mjs',
      '../src/environment.mjs', '../src/exec.mjs']) {
      const src = fs.readFileSync(new URL(file, import.meta.url), 'utf8');
      assert.doesNotMatch(src, WORKTREE_READING,
        `${file} runs a working-tree-reading git verb against a product-controlled tree; `
        + 'a `.gitattributes` filter would execute as the verifier');
    }
  });

  test('the surviving git verbs are object-store reads only', () => {
    const src = fs.readFileSync(new URL('../src/fingerprint.mjs', import.meta.url), 'utf8');
    const verbs = [...src.matchAll(/git\(\[\s*'([a-z-]+)'/g)].map((m) => m[1]);
    assert.ok(verbs.length > 0, 'expected to find git invocations');
    const OBJECT_STORE = new Set(['rev-parse', 'merge-base', 'diff', 'ls-tree', 'cat-file', 'archive']);
    const worktree = verbs.filter((v) => !OBJECT_STORE.has(v));
    assert.deepEqual(worktree, [], `non-object-store git verbs reached the product tree: ${worktree.join(', ')}`);
  });

  test('the governing contract cannot be read out of the product\'s .git', () => {
    // ADR-049 F3, structurally. `loadContractAt` used `git archive` against a
    // repository mounted read-write into the product container, and D1 turned
    // that from descriptive into verdict-bearing. The base contract now arrives
    // as a trusted materialisation, and the way to keep it that way is for the
    // module that loads contracts to have no git at all — not for a reviewer to
    // notice the next time somebody adds one back.
    const src = fs.readFileSync(new URL('../src/contract.mjs', import.meta.url), 'utf8');
    // Comments explain why the absence matters; code is what must be absent.
    const code = src.split('\n').filter((l) => !/^\s*(\/\/|\*|\/\*)/.test(l)).join('\n');
    assert.doesNotMatch(code, /\bgit\(/, 'src/contract.mjs invokes git');
    assert.doesNotMatch(code, /execFileSync|spawnSync|child_process/, 'src/contract.mjs spawns a process');
  });

  test('governance decides authority from what the TRUSTED side supplied, not from the product', () => {
    // The whole decision has to be a function of `baseSupplied` — an argument the
    // trusted caller passes — and never of anything read out of the product tree.
    const src = fs.readFileSync(new URL('../src/governance.mjs', import.meta.url), 'utf8');
    const code = src.split('\n').filter((l) => !/^\s*(\/\/|\*|\/\*)/.test(l)).join('\n');
    assert.doesNotMatch(code, /require\(|import\s|readFileSync|existsSync|execFileSync|process\.env/,
      'governance.mjs reads something other than its arguments');
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
    //
    // ON ITS OWN THIS TEST IS NEARLY WORTHLESS, and it is worth being precise
    // about why rather than deleting it. It passed for the entire life of the
    // project while every browser Watson launched carried `--no-sandbox`,
    // because Playwright was adding the flag and this only looks at OUR source.
    // The absence of a string in a file is not a property of a process. The two
    // tests below are what make the claim, and the container proof is what
    // establishes it against a real browser.
    const src = fs.readFileSync(new URL('../src/driver.mjs', import.meta.url), 'utf8');
    const uses = src.split('\n').filter((l) => l.includes('--no-sandbox') && !l.trim().startsWith('*') && !l.trim().startsWith('//'));
    assert.deepEqual(uses, [], 'the browser must not be launched unsandboxed');
  });

  test('launchBrowser passes `chromiumSandbox: true` to Playwright', async () => {
    // THE DEFECT THIS PINS. playwright-core, at the exact version this
    // repository pins, contains:
    //
    //     if (options.chromiumSandbox !== true) chromeArguments.push('--no-sandbox');
    //
    // so omitting the option is not "leaving the default alone", it is asking
    // for an unsandboxed browser. Measured as an unprivileged user: without the
    // option, `chrome://sandbox` reports `Layer 1 Sandbox: None` and every
    // renderer carries `--no-sandbox`; with it, `Layer 1 Sandbox: Namespace` and
    // none does.
    //
    // The option is intercepted rather than inferred, so this fails if the call
    // stops passing it, whatever the source happens to look like.
    const { chromium } = await import('playwright');
    const real = chromium.launch;
    let seen = null;
    chromium.launch = async (opts) => { seen = opts; throw new Error('intercepted'); };
    try {
      await launchBrowser({ cdpPort: 0 }).catch(() => {});
    } finally {
      chromium.launch = real;
    }
    if (IS_ROOT) {
      // launchBrowser refuses before it ever calls launch(), which is its own
      // (separately tested) property. Nothing to intercept.
      assert.equal(seen, null);
      return;
    }
    assert.ok(seen, 'launchBrowser did not call chromium.launch');
    assert.equal(seen.chromiumSandbox, true);
  });

  test('the pinned Playwright really does add `--no-sandbox` without it', async () => {
    // R4, applied to a dependency: who controls this input? The claim above is
    // about playwright-core's behaviour, so it is checked against playwright-core
    // rather than believed. If an upgrade changes the default, this fails and the
    // comment above stops being true — which is the point.
    const url = new URL('../node_modules/playwright-core/lib/server/chromium/chromium.js', import.meta.url);
    const src = fs.readFileSync(url, 'utf8');
    assert.match(src, /options\.chromiumSandbox !== true.*--no-sandbox/,
      'playwright-core no longer gates --no-sandbox on chromiumSandbox; re-read the launch path');
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

// The contract must not be able to choose what the VERIFIER executes.
//
// Both of these were reproduced by a review as arbitrary code execution as the
// verifier, from product-repo content, on the side of the boundary that holds the
// evidence, the engine source and the signing key.
describe('the product cannot choose the verifier\'s binaries', () => {
  test('a contract naming a browser executable is REFUSED, not ignored', () => {
    const problems = validateBrowserOwnership({ browser: { executable_path: '/tmp/evil.sh' } });
    assert.equal(problems.length, 1);
    assert.match(problems[0], /verifier chooses what it executes/);
    assert.match(problems[0], /WATSON_CHROMIUM/, 'says where the path is supposed to come from');
  });

  test('the launch site reads the trusted environment and nothing else', () => {
    // Grep rather than execute: launching a browser needs one, and the property
    // is about which SOURCE the path comes from.
    const cli = fs.readFileSync(new URL('../src/cli.mjs', import.meta.url), 'utf8');
    const launch = cli.slice(cli.indexOf('drive.launchBrowser('), cli.indexOf('drive.launchBrowser(') + 400);
    assert.match(launch, /executablePath: process\.env\.WATSON_CHROMIUM/);
    assert.doesNotMatch(launch, /contract\.config/, 'the contract must not reach the browser launch');
  });

  test('PATH is engine-owned, so a contract cannot redirect a bare program name', () => {
    // `spawn` resolves a bare name against the CHILD's environment. The engine
    // spawns `setpriv` around every product command, so a contract-supplied PATH
    // chose which one ran — while the preflight validated a different binary.
    assert.ok(ENGINE_OWNED_ENV.includes('PATH'));
    const problems = validateEnvOwnership({ env: { PATH: '/tmp/evil/bin:/usr/bin' } });
    assert.equal(problems.length, 1);
    assert.match(problems[0], /PATH/);
  });

  test('the privilege wrapper is invoked by absolute path, never by name', () => {
    const exec = fs.readFileSync(new URL('../src/exec.mjs', import.meta.url), 'utf8');
    assert.doesNotMatch(exec, /file: 'setpriv'/, 'a bare name is resolved by the child environment');
    assert.match(exec, /file: policy\.setpriv/);
    assert.match(exec, /path\.isAbsolute\(setpriv\)/, 'and it is checked to be absolute');
  });
});
