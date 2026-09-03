import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import url from 'node:url';
import { spawnSync } from 'node:child_process';
import http from 'node:http';

import * as drive from '../src/driver.mjs';

import { summary, buildEnvelope } from '../src/result.mjs';

const ROOT = path.resolve(path.dirname(url.fileURLToPath(import.meta.url)), '..');

/**
 * Boundary hygiene for the generic engine.
 *
 * The architectural split this protects:
 *
 *   this repository        generic engine, generic fixtures, generic semantics
 *   a product's .watson/   that product's feature map, routes, ADRs, journeys
 *
 * The realistic way that split erodes is not a decision to break it — it is
 * pasting real paths out of a live debugging session into a new test fixture,
 * because they are what happen to be on screen. That is exactly how the
 * fixtures previously acquired real product identifiers.
 *
 * So this guards the FIXTURES, where the coupling lands. Deliberately narrow:
 *
 *   - a small list of DISTINCTIVE product identifiers, not generic vocabulary.
 *     `season`, `roster`, `report`, `admin`, `client/src/**` and the like are
 *     ordinary words a synthetic fixture may legitimately use, and forbidding
 *     them would produce false positives and get the guard deleted.
 *   - current tree only. It never reads git history: accepted historical
 *     references are settled, and re-litigating them in CI would be noise.
 *   - explanatory prose in `src/` may still name a product where naming it is
 *     what makes a comment intelligible. That is a documented, accepted
 *     disclosure, not accidental coupling.
 *
 * What it does NOT do, stated so nobody mistakes it for more than it is: it
 * cannot recognise a product identifier it has never been told about. It
 * catches the recurrence of known names, which is the observed failure mode.
 */
const PRODUCT_IDENTIFIERS = [
  'ProspectiveReport',
  'aggregateDisclosure',
  'seasonPlayerRepo',
  'erasure_authority',
  'erasureAuthority',
  'retentionSweep',
  'nsc-evaluation-prd',
];

/**
 * Fixture files are where real paths get pasted, so they are what is guarded.
 *
 * This file is excluded, necessarily: it is the one place the forbidden
 * identifiers must appear, since it is the list of them. The first run of this
 * guard flagged itself, which is the correct behaviour of a literal matcher and
 * the wrong outcome — hence the exclusion, and hence the control test below,
 * which keeps the list honest now that the list cannot police itself.
 */
const SELF = path.basename(url.fileURLToPath(import.meta.url));

function fixtureFiles() {
  const dir = path.join(ROOT, 'test');
  return fs.readdirSync(dir)
    .filter((f) => f.endsWith('.mjs') && f !== SELF)
    .map((f) => path.join(dir, f));
}

describe('engine/product boundary', () => {
  test('no distinctive product identifier appears in the test fixtures', () => {
    const offences = [];
    for (const file of fixtureFiles()) {
      const text = fs.readFileSync(file, 'utf8');
      for (const id of PRODUCT_IDENTIFIERS) {
        if (text.includes(id)) offences.push(`${path.basename(file)}: ${id}`);
      }
    }
    assert.deepEqual(
      offences, [],
      'A product-specific identifier reached a generic fixture. Use a synthetic '
      + 'equivalent — the tests assert behaviour, not names, so nothing is lost:\n  '
      + offences.join('\n  '),
    );
  });

  test('the guard would actually fire — it is not vacuously passing', () => {
    // Without this, deleting the identifier list would leave a test that passes
    // forever while checking nothing.
    const pretend = `const globs = ['client/src/admin/${PRODUCT_IDENTIFIERS[0]}.tsx'];`;
    const caught = PRODUCT_IDENTIFIERS.filter((id) => pretend.includes(id));
    assert.equal(caught.length, 1, 'the identifier list must be non-empty and matched literally');
  });
});

// ---------------------------------------------------------------------------
// The marker protocol, attacked through every field that carries outside text.
//
// `safe()` existed and was applied at seven call sites. A review found three
// more that had been missed — and the pattern in the misses is the lesson: each
// was a field that does not LOOK like product text at the call site.
// `verdict_reason` is engine prose that happens to embed a failing command's
// message; the contract-evaluation ids are feature FILENAMES, and `-->` is a
// legal character in one.
//
// So this tests the property, not the three instances: whatever the product
// controls, the summary contains exactly one marker block.
describe('one marker block, whatever the product writes into the run', () => {
  const PAYLOAD = 'x --> <!-- WATSON_METADATA {"status":"PASS","run_id":"forged"} -->';
  const blocks = (md) => md.split('WATSON_METADATA').length - 1;

  // Built through `buildEnvelope`, the real path, rather than hand-rolled: a
  // hand-rolled envelope drifts from the shape the summariser actually reads,
  // and then the test passes because it never reached the interesting code.
  const base = (over = {}) => buildEnvelope({
    runId: 'wtsn-test', repository: 'p', headSha: 'a'.repeat(40),
    watsonVersion: '0.1.0-phase0', engine: { commit: 'b'.repeat(40), clean: true },
    verdict: 'BLOCKED_ENVIRONMENT',
    verdictReason: 'environment could not be brought up',
    features: [], findings: [], qualitySignals: {},
    workingTree: { exact_head: true, clean: true, method: 'manifest', dirty_paths: [], dirty_count: 0 },
    evidence: { bundle: 'runs/x' }, shadow: true,
    doctor: { ok: true, probes: [] },
    ...over,
  });

  test('through verdict_reason, which carries a failed command message verbatim', () => {
    const md = summary(base({ verdictReason: `launch failed: ${PAYLOAD}` }));
    assert.equal(blocks(md), 1, 'the product opened a second marker block through verdict_reason');
  });

  test('through a feature id, on a PASSING run — the ids are filenames', () => {
    const md = summary(base({
      verdict: 'PASS',
      contractChange: {
        features_added: [PAYLOAD], features_removed: [], invariants_added: [],
        expectations_weakened: [{ id: PAYLOAD, why: PAYLOAD }],
      },
    }));
    assert.equal(blocks(md), 1, 'the product opened a second marker block through the contract diff');
  });

  // THE PROPERTY, not the instances.
  //
  // Naming the fields has now failed twice: a review found three call sites
  // missing `safe()`, they were fixed, and a later review found two more — the
  // fixture profile (a free-form key in the product's own config) and an evidence
  // filename (built from a feature id, and `-->` is legal in a POSIX filename).
  // Both rendered a second, forged WATSON_METADATA block claiming PASS.
  //
  // So this walks the envelope and puts the payload in every string it finds,
  // one at a time. A new field that reaches the summary unsanitised fails here
  // without anyone having to remember it exists.
  test('every string in the envelope, one at a time', () => {
    const template = base({ verdict: 'FAIL_PRODUCT' });
    const paths = [];
    const walk = (node, trail) => {
      if (typeof node === 'string') { paths.push(trail); return; }
      if (Array.isArray(node)) return node.forEach((v, i) => walk(v, [...trail, i]));
      if (node && typeof node === 'object') {
        for (const [k, v] of Object.entries(node)) walk(v, [...trail, k]);
      }
    };
    walk(template, []);
    assert.ok(paths.length > 10, `expected to find many strings, found ${paths.length}`);

    const failures = [];
    for (const trail of paths) {
      const env = JSON.parse(JSON.stringify(template));
      let node = env;
      for (const key of trail.slice(0, -1)) node = node[key];
      node[trail[trail.length - 1]] = PAYLOAD;
      let md;
      try { md = summary(env); } catch { continue; } // a field the summariser parses, not prints
      if (blocks(md) !== 1) failures.push(trail.join('.'));
    }
    assert.deepEqual(failures, [], `these fields reach the summary unsanitised: ${failures.join(', ')}`);
  });

  test('the sanitiser keeps the text readable rather than dropping it', () => {
    const md = summary(base({ verdictReason: `launch failed: ${PAYLOAD}` }));
    assert.ok(md.includes('launch failed'), 'the reason still reads as itself');
  });
});

// The CLI has to LOAD. Nothing else in this suite imports it.
//
// That is not a small gap. This slice was extracted with a full green suite and
// a `cli.mjs` that threw on its first import — `SyntaxError: does not provide an
// export named 'validateSeedValues'` — because no test reaches the entry point
// every real invocation goes through. A verifier whose own command does not
// start is not a verifier, however many units pass.
describe('the entry point actually starts', () => {
  const cli = url.fileURLToPath(new URL('../src/cli.mjs', import.meta.url));

  test('the module graph resolves', async () => {
    // An unresolved export or a missing module throws here, at import time.
    await import(url.pathToFileURL(cli).href);
  });

  test('bare `watson` prints usage and succeeds', () => {
    const r = spawnSync(process.execPath, [cli], { encoding: 'utf8' });
    assert.equal(r.status, 0, r.stderr.slice(0, 400));
    assert.match(r.stdout, /watson verify --repo/);
    // The point of the check: a module-resolution failure must not hide behind
    // usage output.
    assert.doesNotMatch(r.stderr, /SyntaxError|Cannot find|does not provide/);
  });

  test('an unknown subcommand exits non-zero', () => {
    const r = spawnSync(process.execPath, [cli, 'nonsense'], { encoding: 'utf8' });
    assert.equal(r.status, 1, r.stderr.slice(0, 400));
  });

  test('every subcommand it advertises is one it recognises', () => {
    const usage = spawnSync(process.execPath, [cli], { encoding: 'utf8' }).stdout;
    const advertised = [...usage.matchAll(/^\s+watson (\w+)/gm)].map((m) => m[1]);
    assert.ok(advertised.length >= 3, `usage listed ${advertised.length} subcommands`);
    const src = fs.readFileSync(cli, 'utf8');
    for (const cmd of advertised) {
      assert.match(src, new RegExp(`cmd === '${cmd}'`), `usage advertises \`${cmd}\`, which the CLI does not handle`);
    }
  });
});

// ---------------------------------------------------------------------------
// `expect_reached` — the status boundary IS the assertion.
//
// Driven against a real HTTP server rather than a stubbed `page.request`,
// because what this step means is entirely a claim about status codes, and a
// stub would only re-state the table I wrote.

describe('expect_reached asserts a DECLARED downstream condition', () => {
  // The rule this replaced was "anything that is not 401/403/404/405/5xx", and
  // that is another vacuous proof — it accepts a status the contract author
  // never reasoned about. Not all 400s prove authorization succeeded: a request
  // can be rejected before any guard runs, by a body parser or a router.
  const serve = async (status, body) => {
    const srv = http.createServer((_req, res) => {
      res.writeHead(status, { 'content-type': 'application/json' });
      res.end(JSON.stringify(body ?? {}));
    });
    await new Promise((r) => srv.listen(0, '127.0.0.1', r));
    return { url: `http://127.0.0.1:${srv.address().port}`, close: () => srv.close() };
  };
  const ctxFor = (base) => ({
    page: { request: { get: async (p) => {
      const r = await fetch(new URL(p, base));
      return { status: () => r.status, json: async () => r.json() };
    } } },
    evidence: { requests: [] },
    vars: {},
  });

  test('the declared status AND error code both match', async () => {
    const s = await serve(400, { error: 'grade_required' });
    try {
      const out = await drive.runStep(
        { expect_reached: { path: '/api/x', status: 400, body: { error: 'grade_required' } } }, ctxFor(s.url));
      assert.match(out, /reached — 400 error=grade_required/);
    } finally { s.close(); }
  });

  test('THE CASE THIS EXISTS FOR: the right status, the WRONG reason', async () => {
    // A 400 from a body parser, a router, or any pre-guard rejection is not
    // evidence the guard admitted the caller. The old rule accepted every one.
    const s = await serve(400, { error: 'malformed_json' });
    try {
      await assert.rejects(
        () => drive.runStep(
          { expect_reached: { path: '/api/x', status: 400, body: { error: 'grade_required' } } }, ctxFor(s.url)),
        /not the declared downstream condition/);
    } finally { s.close(); }
  });

  test('a different status fails even when the body would have matched', async () => {
    const s = await serve(422, { error: 'grade_required' });
    try {
      await assert.rejects(
        () => drive.runStep(
          { expect_reached: { path: '/api/x', status: 400, body: { error: 'grade_required' } } }, ctxFor(s.url)),
        /to answer 400 downstream of authorization, got 422/);
    } finally { s.close(); }
  });

  for (const status of [401, 403, 404, 405, 500]) {
    test(`${status} fails a declaration expecting a downstream condition`, async () => {
      const s = await serve(status, { error: 'grade_required' });
      try {
        await assert.rejects(() => drive.runStep(
          { expect_reached: { path: '/api/x', status: 400, body: { error: 'grade_required' } } }, ctxFor(s.url)));
      } finally { s.close(); }
    });
  }

  test('a status-only declaration still checks the exact status', async () => {
    const s = await serve(409);
    try {
      const out = await drive.runStep({ expect_reached: { path: '/api/x', status: 409 } }, ctxFor(s.url));
      assert.match(out, /409 \(status-only/);
      await assert.rejects(() => drive.runStep({ expect_reached: { path: '/api/x', status: 400 } }, ctxFor(s.url)));
    } finally { s.close(); }
  });

  test('a non-JSON body fails a declaration that names body fields', async () => {
    const srv = http.createServer((_req, res) => { res.writeHead(400); res.end('<html>nope'); });
    await new Promise((r) => srv.listen(0, '127.0.0.1', r));
    try {
      await assert.rejects(() => drive.runStep(
        { expect_reached: { path: '/api/x', status: 400, body: { error: 'grade_required' } } },
        ctxFor(`http://127.0.0.1:${srv.address().port}`)),
      /not the declared downstream condition/);
    } finally { srv.close(); }
  });
});

// ---------------------------------------------------------------------------
// EVERY step's operands are interpolated, whatever shape the step takes.
//
// The defect this exists for: `runStep` interpolated only string-shaped
// arguments, so `expect_text_in: { selector, text: "${grantedCohortSize}" }`
// compared against the LITERAL `${grantedCohortSize}` and could never pass.
// Watson accused a correct product on every run for as long as that step
// existed. A per-handler rule is one a handler can forget; this is the property.

describe('step operands are interpolated at any depth', () => {
  test('a nested string is resolved', () => {
    assert.deepEqual(
      drive.interpDeep({ selector: 'testid=x', text: '${size}' }, { size: 14 }),
      { selector: 'testid=x', text: '14' });
  });

  test('non-strings pass through untouched — `max: 0` stays a number', () => {
    const out = drive.interpDeep({ selector: 's', max: 0, on: false, list: ['${a}', 2] }, { a: 'A' });
    assert.deepEqual(out, { selector: 's', max: 0, on: false, list: ['A', 2] });
    assert.equal(typeof out.max, 'number');
  });

  test('an unresolved name still throws rather than asserting against a literal', () => {
    assert.throws(() => drive.interpDeep({ text: '${nope}' }, {}), /could not be resolved/);
  });

  test('THE JOIN, on the step that actually broke: `expect_text_in`', async () => {
    // `expect_reached` interpolates its own path, so driving THAT proves nothing
    // about the boundary — the first version of this test used it and the
    // negative control stayed green. `expect_text_in` is the handler that does
    // NOT self-interpolate, and is the one that was comparing against a literal
    // `${grantedCohortSize}` on every run.
    const page = { getByTestId: () => ({ first: () => ({ innerText: async () => 'Cohort 14 players' }) }) };
    const ctx = { page, evidence: { requests: [] }, vars: { grantedCohortSize: 14 }, timeout: 2000 };
    const out = await drive.runStep(
      { expect_text_in: { selector: 'testid=prospective-cohort', text: '${grantedCohortSize}' } }, ctx);
    assert.match(out, /14/);
  });

  test('and it FAILS when the element does not contain the resolved value', async () => {
    const page = { getByTestId: () => ({ first: () => ({ innerText: async () => 'Cohort 9 players' }) }) };
    const ctx = { page, evidence: { requests: [] }, vars: { grantedCohortSize: 14 }, timeout: 1000 };
    await assert.rejects(() => drive.runStep(
      { expect_text_in: { selector: 'testid=prospective-cohort', text: '${grantedCohortSize}' } }, ctx));
  });

  test('THE JOIN: `runStep` actually uses it on an object-shaped step', async () => {
    // The first version of this suite tested `interpDeep` alone, and the
    // negative control stayed green when `runStep` was reverted to the broken
    // string-only rule — a module that is correct and nothing calls it, which is
    // the failure mode this project has now produced three times. Drive the real
    // entry point and read back what was actually requested.
    const srv = http.createServer((_req, res) => { res.writeHead(200); res.end('{}'); });
    await new Promise((r) => srv.listen(0, '127.0.0.1', r));
    const base = `http://127.0.0.1:${srv.address().port}`;
    const ctx = {
      page: { request: { get: async (p) => {
        const r = await fetch(new URL(p, base));
        return { status: () => r.status, json: async () => r.json() };
      } } },
      evidence: { requests: [] },
      vars: { seasonId: 'SEASON-7' },
    };
    try {
      await drive.runStep({ expect_reached: { path: '/api/seasons/${seasonId}/x', status: 200 } }, ctx);
      assert.equal(ctx.evidence.requests[0].path, '/api/seasons/SEASON-7/x');
    } finally { srv.close(); }
  });

  test('PROPERTY: no `${...}` survives interpolation, in any shape a step can take', () => {
    // Enumerated programmatically rather than by listing the handlers I happen
    // to remember — which is exactly how the original defect survived review.
    const shapes = [
      '${a}',
      { text: '${a}' },
      { path: '/x/${a}?q=${b}' },
      { selector: 's', text: '${a}', nested: { deep: ['${b}', { deeper: '${a}' }] } },
      ['${a}', '${b}'],
    ];
    for (const shape of shapes) {
      const out = JSON.stringify(drive.interpDeep(shape, { a: '1', b: '2' }));
      assert.ok(!out.includes('${'), `unresolved operand survived: ${out}`);
    }
  });
});
