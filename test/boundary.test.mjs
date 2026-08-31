import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import url from 'node:url';

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
