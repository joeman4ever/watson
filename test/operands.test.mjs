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
  assertionVars, validateAssertionOperands, fixtureValues, fixtureValueEnv, normaliseChosen, validateDenialAddresses,
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

  test('a path is an address, not proof', () => {
    // `expect_denied: { path: ".../groups/${g}" }` asserts an authorization
    // OUTCOME. A product choosing `g` cannot make "denied" true by choosing it —
    // it would have to make the endpoint actually deny, which is the behaviour
    // under test. A nonexistent group returns 404, which the engine classifies as
    // FAIL_CONTRACT rather than a pass.
    const f = feature('f', [
      { expect_denied: { path: '/api/seasons/${seasonId}/groups/${groupId}' } },
      { expect_allowed: { path: '/api/seasons/${seasonId}/groups/${groupId}/scores' } },
      { expect_api: { path: '/api/seasons/${seasonId}/x' } },
    ]);
    assert.deepEqual([...assertionVars(f)], []);
  });

  test('but the BODY of a json assertion is proof', () => {
    const f = feature('f', [
      { expect_json: { path: '/api/x/${addressId}', contains: { name: '${seasonName}' } } },
    ]);
    assert.deepEqual([...assertionVars(f)], ['seasonName']);
  });

  test('a selector is PROOF, because a selector can name content', () => {
    // This test used to assert the opposite, and was wrong. `locator()` resolves
    // `text=...` through `page.getByText`, so
    //     expect_count_at_least: { selector: "text=${sessionName}", min: 1 }
    // is `expect_text: "${sessionName}"` with the ownership rule looking the
    // other way. A review found it by executing it.
    //
    // Counted for EVERY selector rather than only content-matching ones: the
    // prefix can itself come from a variable, and a rule that has to parse the
    // selector to decide whether it matters is a rule with a next bypass in it.
    // It costs nothing real — a structural selector has no variables in it.
    const f = feature('f', [
      { expect_text_in: { selector: 'text=${scopedByContent}', text: '${cohortSize}' } },
      { expect_count_at_most: { selector: 'testid=${structural}', max: 0 } },
    ]);
    assert.deepEqual([...assertionVars(f)].sort(), ['cohortSize', 'scopedByContent', 'structural']);
  });

  test('the equivalent assertion is classified the same way whichever form it takes', () => {
    // The property, rather than the instance: writing an assertion as a selector
    // must not launder its operand.
    const viaText = feature('f', [{ expect_text: '${sessionName}' }]);
    const viaSelector = feature('f', [{ expect_count_at_least: { selector: 'text=${sessionName}', min: 1 } }]);
    assert.deepEqual([...assertionVars(viaText)], [...assertionVars(viaSelector)]);
  });

  test('a scoped text assertion counts as proof', () => {
    // `expect_text_in` is an assertion, so its operand is subject to the same
    // rule. Adding a step type and forgetting to classify it is how a hole
    // reopens quietly.
    const f = feature('f', [{ expect_text_in: { selector: 'testid=stat', text: '${cohortSize}' } }]);
    assert.deepEqual([...assertionVars(f)], ['cohortSize']);
  });

  test('every assertion step in the driver is classified', async () => {
    // The two lists are edited by hand and drift silently: a step that asserts
    // but is missing from ASSERTION_STEPS lets the product choose its operand
    // again. Anything named `expect_*` or `wait_for_*` must be in it.
    const { STEPS, ASSERTION_STEPS } = await import('../src/driver.mjs');
    const looksLikeAssertion = STEPS.filter((s) => /^(expect|wait_for)_/.test(s));
    const missing = looksLikeAssertion.filter((s) => !ASSERTION_STEPS.has(s)
      // These two assert about the page as a whole, with no operand a fixture
      // could supply — there is nothing for the product to choose.
      && !['expect_no_uuid', 'expect_no_overflow'].includes(s));
    assert.deepEqual(missing, [], `unclassified assertion steps: ${missing.join(', ')}`);
  });

  test('nested operands are found', () => {
    const f = feature('f', [{ expect_json: { path: '/api/x', body: { name: '${seasonName}' } } }]);
    assert.deepEqual([...assertionVars(f)], ['seasonName']);
  });
});

describe('the contract may not let the product choose its own proof', () => {
  const profile = { emits: ['seasonName', 'sessionId'], verifier_chosen: [{ seasonName: 'text' }] };

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

describe('a verifier-chosen value still has to fit the column it lands in', () => {
  test('a uuid shape produces something a uuid column accepts', () => {
    // Handing the fixture `watson-primarySeasonId-3f2a…` where a uuid belongs
    // fails at the insert and reads as a broken world — a verifier-chosen value
    // is only useful if the product can actually store it.
    const v = fixtureValues('run-1', [{ seasonId: 'uuid' }]).seasonId;
    assert.match(v, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  });

  test('an integer shape is small, because the fixture has to create that many rows', () => {
    for (let i = 0; i < 50; i++) {
      const n = fixtureValues(`run-${i}`, [{ cohort: 'integer' }]).cohort;
      assert.ok(Number.isInteger(n) && n >= 3 && n <= 9, `${n} is not a usable cohort size`);
    }
  });

  test('every shape stays deterministic and distinct', () => {
    const a = fixtureValues('run-1', [{ x: 'uuid' }, { y: 'text' }, { z: 'integer' }]);
    assert.deepEqual(a, fixtureValues('run-1', [{ x: 'uuid' }, { y: 'text' }, { z: 'integer' }]));
    assert.notEqual(a.x, fixtureValues('run-2', [{ x: 'uuid' }]).x);
  });

  test('a bare list still means text, so the simple case stays simple', () => {
    assert.deepEqual(normaliseChosen(['a', 'b']), [['a', 'text', null, null], ['b', 'text', null, null]]);
  });

  test('a closed domain is picked FROM, not invented', () => {
    // Some values cannot be invented. nsc-eval constrains a school grade to
    // PK, K, 1..12 with a database CHECK mirroring its own domain module, so a
    // verifier-generated string fails at the insert. Refusing to let the
    // verifier choose at all would hand the fixture back the decision this
    // mechanism exists to take away — it could pick whichever member makes an
    // assertion most vacuous. So the contract declares the domain and the
    // verifier picks the member.
    const GRADES = ['PK', 'K', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12'];
    const spread = new Set();
    for (let i = 0; i < 200; i++) {
      const v = fixtureValues(`run-${i}`, [{ grade: { enum: GRADES } }]).grade;
      assert.ok(GRADES.includes(v), `${v} is outside the declared domain`);
      spread.add(v);
    }
    assert.ok(spread.size > 5, 'the pick should range over the domain, not stick to one member');
    assert.equal(fixtureValues('r', [{ g: { enum: GRADES } }]).g, fixtureValues('r', [{ g: { enum: GRADES } }]).g);
  });

  test('a declared range keeps a verifier-chosen number inside product semantics', () => {
    // Some numbers are not free. nsc-eval seeds a cohort that must be ABOVE its
    // disclosure threshold so the journey observes a reportable aggregate. A
    // verifier that picked 4 would produce a SUPPRESSED cohort, the journey would
    // see a suppression notice where it expected a count, and Watson would report
    // FAIL_PRODUCT against a product that behaved correctly. A false accusation is
    // the most expensive kind of wrong a verifier can be.
    const seen = new Set();
    for (let i = 0; i < 300; i++) {
      const v = fixtureValues(`run-${i}`, [{ cohort: { integer: { min: 12, max: 18 } } }]).cohort;
      assert.ok(Number.isInteger(v) && v >= 12 && v <= 18, `${v} escaped the declared range`);
      seen.add(v);
    }
    assert.equal(seen.size, 7, 'the pick should use the whole range');
  });

  test('an unusable range is refused', () => {
    assert.throws(() => fixtureValues('r', [{ c: { integer: { min: 9, max: 2 } } }]), /not a usable range/);
  });

  test('names sharing a pool never collide', () => {
    // Five grades from one fourteen-member domain. Hashing each name
    // independently makes a collision a matter of luck, and a journey whose
    // "granted" and "ungranted" grades are the same value does not test an
    // authorization boundary — it tests nothing, non-deterministically.
    const G = ['PK', 'K', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12'];
    const names = ['grantedGrade', 'ungrantedGrade', 'revokedGrade', 'expiredGrade', 'suppressedGrade'];
    const decl = names.map((n) => ({ [n]: { enum: G, pool: 'grades' } }));
    for (let i = 0; i < 500; i++) {
      const v = fixtureValues(`run-${i}`, decl);
      assert.equal(new Set(Object.values(v)).size, names.length, `collision on run-${i}: ${JSON.stringify(v)}`);
      for (const n of names) assert.ok(G.includes(v[n]));
    }
  });

  test('a pool larger than its domain is refused, not silently truncated', () => {
    const decl = ['a', 'b', 'c'].map((n) => ({ [n]: { enum: ['x', 'y'], pool: 'p' } }));
    assert.throws(() => fixtureValues('r', decl), /needs 3 distinct values but its domain has 2/);
  });

  test('one pool means one set', () => {
    const decl = [{ a: { enum: ['x'], pool: 'p' } }, { b: { enum: ['y'], pool: 'p' } }];
    assert.throws(() => fixtureValues('r', decl), /two different domains/);
  });

  test('an empty domain is refused rather than silently yielding undefined', () => {
    assert.throws(() => fixtureValues('r', [{ g: { enum: [] } }]), /no values to choose from/);
  });

  test('an unknown shape is refused rather than guessed', () => {
    assert.throws(() => fixtureValues('r', [{ x: 'timestamptz' }]), /does not generate/);
  });
});

describe('the usability check does not reject values a product legitimately emits', () => {
  test('short domain values pass', async () => {
    // A regression I introduced and then removed: while the check was still
    // pretending to be a defence it carried a four-character floor, which
    // rejects a school grade of "5" and a displayed threshold of 10. A usability
    // check that fails valid contracts is not a usability check.
    const { degenerateOperand } = await import('../src/contract.mjs');
    for (const v of ['5', '7', 10, 0, 'U8']) {
      assert.equal(degenerateOperand(v), null, `${JSON.stringify(v)} is a legitimate fixture value`);
    }
  });

  test('it still catches what it is actually for', async () => {
    // Its remaining job is small and real: an empty or non-scalar value produces
    // a confusing failure three steps later.
    const { degenerateOperand } = await import('../src/contract.mjs');
    for (const v of ['', '   ', null, undefined, {}, []]) {
      assert.ok(degenerateOperand(v), `${JSON.stringify(v)} should be reported at the source`);
    }
  });
});

// A denial proves nothing unless the thing denied exists. This is the check that
// replaced a FALSE justification: `expect_denied.path` was exempted from the
// ownership rule on the grounds that a nonexistent id would 404 into
// FAIL_CONTRACT. nsc-eval's authorization layer answers 403 for anything outside
// the caller's scope, with no existence check — deliberately, so it is not an
// existence oracle. So the exemption needed a different guarantee, not a better
// excuse.
describe('a denial has to be denying something', () => {
  const f = (steps) => ({ id: 'x', __file: 'x.md', steps });

  test('the attack the review demonstrated: a decoy id nothing can resolve', () => {
    // A product where EVERY evaluator can open EVERY group passes this journey,
    // because the group named was never created.
    const problems = validateDenialAddresses([f([
      { expect_denied: { path: '/api/seasons/${s}/groups/${unassignedGroupId}/scoring-workspace' } },
    ])], { preconditions: [{ as: 'W-EVALUATOR', get: '/api/seasons/${s}/x', expect: { authorized: true } }] });
    assert.equal(problems.length, 1);
    assert.match(problems[0], /unassignedGroupId/);
    assert.match(problems[0], /denies everything AND by one that denies nothing/);
  });

  test('reaching it positively in the same feature satisfies it', () => {
    assert.deepEqual(validateDenialAddresses([f([
      { expect_allowed: { path: '/api/seasons/${s}/groups/${g}/scoring-workspace' } },
      { expect_denied: { path: '/api/seasons/${s}/groups/${g}/my-scores' } },
    ])], {}), []);
  });

  test('a precondition that RESOLVES it satisfies it — the only option when this identity must not', () => {
    assert.deepEqual(validateDenialAddresses(
      [f([{ expect_denied: { path: '/api/seasons/${s}/groups/${g}/scoring-workspace' } }])],
      { preconditions: [{ as: 'W-ADMIN', get: '/api/seasons/${s}/groups/${g}/scoring-workspace', expect: { authorized: true } }] },
    ), []);
  });

  test('a precondition that expects a DENIAL does not satisfy it', () => {
    // Two denials are not an existence proof. This is the shape that would have
    // let the check be satisfied by restating the thing being tested.
    const problems = validateDenialAddresses(
      [f([{ expect_denied: { path: '/api/seasons/${s}/groups/${g}/scoring-workspace' } }])],
      { preconditions: [{ as: 'W-EVALUATOR', get: '/api/seasons/${s}/groups/${g}/x', expect: { authorized: false } }] },
    );
    assert.equal(problems.length, 1);
  });
});
