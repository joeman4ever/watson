import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import url from 'node:url';

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

  test('the sanitiser keeps the text readable rather than dropping it', () => {
    const md = summary(base({ verdictReason: `launch failed: ${PAYLOAD}` }));
    assert.ok(md.includes('launch failed'), 'the reason still reads as itself');
  });
});
