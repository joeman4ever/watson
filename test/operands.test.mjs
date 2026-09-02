// Who chooses the value that makes an assertion true.
//
// Three rounds of review converged on this being the only property that closes
// the class rather than raising its cost:
//
//   The thing being tested cannot choose the value that makes the verifier's
//   assertion true.
//
// The heuristic this replaces could never establish it. `http`, `Sign` and `Home`
// are all syntactically plausible and all make a substring assertion true against
// a generic error page. No predicate over a string separates "a real season name"
// from "a string chosen because it appears on the failure page" — the difference
// is not in the string, it is in who picked it.

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  assertionVars, validateAssertionOperands, fixtureValues, fixtureValueEnv,
} from '../src/contract.mjs';

const feature = (id, steps) => ({ id, __file: `${id}.yaml`, steps });

describe('proof operands and input operands are different things', () => {
  test('only assertion steps contribute', () => {
    const f = feature('f', [
      { goto: '/seasons/${seasonId}' },
      { fill: '#name', value: '${typedName}' },
      { click: '${buttonSelector}' },
      { expect_text: '${seasonName}' },
    ]);
    // `goto`, `fill` and `click` are things Watson does TO the product. Nothing
    // rests on their operands, so the product may well have chosen them.
    assert.deepEqual([...assertionVars(f)], ['seasonName']);
  });

  test('wait_for_text counts as proof', () => {
    // It asserts what the application eventually says. A journey that waits for
    // a string the product chose has proved that the product can echo itself.
    const f = feature('f', [{ wait_for_text: '${label}' }]);
    assert.deepEqual([...assertionVars(f)], ['label']);
  });

  test('nested operands are found', () => {
    const f = feature('f', [{ expect_json: { path: '/api/x', body: { name: '${seasonName}' } } }]);
    assert.deepEqual([...assertionVars(f)], ['seasonName']);
  });
});

describe('the contract may not let the product choose its own proof', () => {
  const profile = { emits: ['seasonName', 'sessionId'], verifier_chosen: ['seasonName'] };

  test('an assertion on a verifier-chosen value is allowed', () => {
    const problems = validateAssertionOperands([feature('a', [{ expect_text: '${seasonName}' }])], profile);
    assert.deepEqual(problems, []);
  });

  test('an assertion on a product-emitted value is REFUSED', () => {
    const problems = validateAssertionOperands([feature('b', [{ expect_url_contains: '${sessionId}' }])], profile);
    assert.equal(problems.length, 1);
    assert.match(problems[0], /verifier_chosen/);
    assert.match(problems[0], /choosing the value that makes its own test pass/);
  });

  test('a product-emitted value may still be INPUT', () => {
    // The rule constrains proof, not use. A journey may navigate to an id the
    // product assigned; it may not treat that id as evidence.
    const problems = validateAssertionOperands([
      feature('c', [{ goto: '/sessions/${sessionId}' }, { expect_text: '${seasonName}' }]),
    ], profile);
    assert.deepEqual(problems, []);
  });

  test('engine-supplied names are available without being declared', () => {
    assert.deepEqual(validateAssertionOperands([feature('d', [{ expect_text: '${runId}' }])], profile), []);
  });

  test('a profile that declares nothing refuses every assertion operand', () => {
    // Fail-closed: an absent declaration is not permission.
    const problems = validateAssertionOperands([feature('e', [{ expect_text: '${seasonName}' }])], { emits: ['seasonName'] });
    assert.equal(problems.length, 1);
  });
});

describe('the values the verifier supplies', () => {
  test('are deterministic per run, so a re-run reproduces them', () => {
    assert.deepEqual(fixtureValues('run-1', ['a', 'b']), fixtureValues('run-1', ['a', 'b']));
  });

  test('differ between runs and between names', () => {
    assert.notEqual(fixtureValues('run-1', ['a']).a, fixtureValues('run-2', ['a']).a);
    const v = fixtureValues('run-1', ['a', 'b']);
    assert.notEqual(v.a, v.b);
  });

  test('are specific enough that a substring assertion means something', () => {
    // The failure this exists to prevent is an operand like "Sign" matching a
    // generic error page. Sixteen hex characters do not appear by accident.
    const v = fixtureValues('run-1', ['seasonName']).seasonName;
    assert.match(v, /^watson-seasonName-[0-9a-f]{16}$/);
    const errorPage = 'Something went wrong. Please try again. Sign in. Home.';
    assert.equal(errorPage.includes(v), false);
  });

  test('reach the fixture through the environment, under a name it can find', () => {
    assert.deepEqual(
      fixtureValueEnv({ seasonName: 'x', 'session-id': 'y' }),
      { WATSON_FIXTURE_SEASONNAME: 'x', WATSON_FIXTURE_SESSION_ID: 'y' },
    );
  });

  test('are unpredictable to a product that cannot see the run id', () => {
    // Not random — deterministic from an identity the verifier owns. Flakiness
    // bought nothing; unpredictability is what the property needs.
    const seen = new Set();
    for (let i = 0; i < 200; i++) seen.add(fixtureValues(`run-${i}`, ['n']).n);
    assert.equal(seen.size, 200);
  });
});
