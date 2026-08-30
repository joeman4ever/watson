import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { classifyConsoleErrors, DENIAL_STATUSES } from '../src/checks.mjs';

const P = '/api/seasons/S1/players';
const Q = '/api/seasons/S1/audit-log';

const resourceError = (path, status) => ({
  type: 'error',
  text: `Failed to load resource: the server responded with a status of ${status} (Forbidden)`,
  resourcePath: path,
});
const declared = (...paths) => paths.map((path) => ({ path, status: 403, method: 'GET' }));

/** Every case states what must SURVIVE, because this logic removes findings. */
describe('expected-denial correlation — suppression', () => {
  test('a declared 403 on the declared path is neutralised and retained', () => {
    const { product, expected } = classifyConsoleErrors([resourceError(P, 403)], declared(P));
    assert.equal(product.length, 0, 'must not remain a product finding');
    assert.equal(expected.length, 1, 'must be retained as evidence');
    assert.equal(expected[0].classification, 'expected_denial_console');
    assert.equal(expected[0].status, 403);
    assert.equal(expected[0].resourcePath, P, 'the retained record keeps its attribution');
  });

  test('401 is neutralised too, where the contract treats it as a denial', () => {
    assert.ok(DENIAL_STATUSES.includes(401));
    const { product } = classifyConsoleErrors([resourceError(P, 401)], declared(P));
    assert.equal(product.length, 0);
  });

  test('several declared denials are each neutralised independently', () => {
    const { product, expected } = classifyConsoleErrors(
      [resourceError(P, 403), resourceError(Q, 403)], declared(P, Q));
    assert.equal(product.length, 0);
    assert.equal(expected.length, 2);
  });
});

describe('expected-denial correlation — what must SURVIVE', () => {
  test('an undeclared 403 survives, even alongside a declared one', () => {
    const other = '/api/seasons/S1/secrets';
    const { product, expected } = classifyConsoleErrors(
      [resourceError(P, 403), resourceError(other, 403)], declared(P));
    assert.equal(product.length, 1, 'only the declared path may be neutralised');
    assert.equal(product[0].resourcePath, other);
    assert.equal(expected.length, 1);
  });

  test('a 500 on a DECLARED path survives — status is read from the event itself', () => {
    // The journey declared this path denied, and a probe did observe 403. If the
    // product then 500s on the same path in-page, that is a server error, not an
    // expected artifact. Reading the status from the console message rather than
    // from the probe's response is what keeps these apart.
    const { product } = classifyConsoleErrors([resourceError(P, 500)], declared(P));
    assert.equal(product.length, 1);
  });

  test('a 404 on a declared path survives', () => {
    const { product } = classifyConsoleErrors([resourceError(P, 404)], declared(P));
    assert.equal(product.length, 1);
  });

  test('a product console.error survives — it is not a resource-load failure', () => {
    const entry = { type: 'error', text: 'TypeError: cannot read x of undefined', resourcePath: '/roster' };
    const { product } = classifyConsoleErrors([entry], declared(P));
    assert.equal(product.length, 1);
  });

  test('a resource-load error with no attributable URL survives', () => {
    const entry = { ...resourceError(P, 403), resourcePath: null };
    const { product } = classifyConsoleErrors([entry], declared(P));
    assert.equal(product.length, 1, 'no attribution means no neutralisation');
  });

  test('nothing is neutralised when the journey declared nothing', () => {
    const { product } = classifyConsoleErrors([resourceError(P, 403)], []);
    assert.equal(product.length, 1);
  });

  test('a path that merely resembles a declared one survives', () => {
    // Matching is exact. A prefix or query-string variant is a different request.
    for (const near of [`${P}?page=2`, `${P}/extra`, '/api/seasons/S2/players']) {
      const { product } = classifyConsoleErrors([resourceError(near, 403)], declared(P));
      assert.equal(product.length, 1, `${near} must not match ${P}`);
    }
  });

  test('a warning is never neutralised and never counted as an error', () => {
    const warn = { type: 'warning', text: 'Failed to load resource: the server responded with a status of 403', resourcePath: P };
    const { product, expected } = classifyConsoleErrors([warn], declared(P));
    assert.equal(expected.length, 0, 'only errors are candidates');
    assert.equal(product.length, 0, 'warnings are not console errors');
  });
});

describe('page errors are structurally out of reach', () => {
  test('classifyConsoleErrors never sees pageErrors, so an exception cannot be neutralised', () => {
    // pageErrors are a separate Playwright event stream and are concatenated
    // AFTER classification. This pins that separation rather than describing it.
    const src = String(classifyConsoleErrors);
    assert.ok(!src.includes('pageError'), 'the classifier must not touch page errors');
  });
});
