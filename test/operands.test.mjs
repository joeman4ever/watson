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
  assertionVars, validateAssertionOperands, fixtureValues, fixtureValueEnv, normaliseChosen, validateDenialProofs, reconcileFixtureValues, routeOf, withDependencies,
} from '../src/contract.mjs';
import { rollUp } from '../src/result.mjs';

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

// The four denial-proof classes.
//
// A denial is the easiest assertion to satisfy by accident: 403 comes back from a
// product that denies correctly, one that denies everything, and one asked about
// something that does not exist. The three are indistinguishable at the status
// line, so what a denial must PROVE depends on which claim it is making — and the
// claim is declared, never inferred from a variable's name.
describe('denial-proof classes', () => {
  const f = (steps) => ({ id: 'x', __file: 'x.md', steps });
  const profile = {
    verifier_chosen: ['grantedGrade', 'ungrantedGrade', 'revokedGrade'],
    preconditions: [
      { as: 'W-ADMIN', get: '/api/seasons/${s}/groups/${provenGroupId}', expect: { authorized: true } },
      { as: 'W-P', get: '/api/x?grade=${revokedGrade}', expect: { authorized: false } },
    ],
  };

  test('an undeclared class fails closed', () => {
    const p = validateDenialProofs([f([{ expect_denied: { path: '/api/a/${g}' } }])], profile);
    assert.equal(p.length, 1);
    assert.match(p[0], /does not declare which kind of denial/);
    assert.match(p[0], /is not a weak proof, it is no proof/);
  });

  test('an unrecognised class fails closed rather than defaulting', () => {
    const p = validateDenialProofs([f([{ expect_denied: { path: '/api/a' }, proof: 'vibes' }])], profile);
    assert.equal(p.length, 1);
    assert.match(p[0], /unknown denial-proof class/);
  });

  test('entity_existence: a decoy id is refused, a proven one is accepted', () => {
    const decoy = validateDenialProofs(
      [f([{ expect_denied: { path: '/api/a/${decoyId}' }, proof: 'entity_existence' }])], profile);
    assert.equal(decoy.length, 1);
    assert.match(decoy[0], /denies exactly like one that does/);

    const proven = validateDenialProofs(
      [f([{ expect_denied: { path: '/api/a/${provenGroupId}' }, proof: 'entity_existence' }])], profile);
    assert.deepEqual(proven, []);
  });

  test('domain_negative: needs a verifier-chosen value and a working sibling', () => {
    const noSibling = validateDenialProofs(
      [f([{ expect_denied: { path: '/api/x?grade=${ungrantedGrade}' }, proof: { class: 'domain_negative' } }])], profile);
    assert.match(noSibling[0], /must name the known-positive `sibling`/);

    // The sibling has to actually be exercised, or the capability itself is unproven.
    const unexercised = validateDenialProofs(
      [f([{ expect_denied: { path: '/api/x?grade=${ungrantedGrade}' }, proof: { class: 'domain_negative', sibling: 'grantedGrade' } }])],
      profile);
    assert.match(unexercised[0], /never positively exercised/);

    const good = validateDenialProofs([f([
      { expect_api: { path: '/api/x?grade=${grantedGrade}' } },
      { expect_denied: { path: '/api/x?grade=${ungrantedGrade}' }, proof: { class: 'domain_negative', sibling: 'grantedGrade' } },
    ])], profile);
    assert.deepEqual(good, []);
  });

  test('state_transition: a never-granted value is not a substitute for a revoked one', () => {
    // `revokedGrade` is only ever resolved by a precondition that EXPECTS A DENIAL,
    // which is not evidence the grant ever existed.
    const p = validateDenialProofs(
      [f([{ expect_denied: { path: '/api/x?grade=${revokedGrade}' }, proof: 'state_transition' }])], profile);
    assert.equal(p.length, 1);
    assert.match(p[0], /was ALLOWED before the transition/);
  });

  test('capability: with no positive assertion anywhere, every denial is free', () => {
    const noControl = validateDenialProofs(
      [f([{ expect_denied: { path: '/api/seasons/x/audit-log' }, proof: 'capability' }])], profile);
    assert.equal(noControl.length, 1);
    assert.match(noControl[0], /satisfied by a product that denies everything/);
  });

  test('capability: THE ROUTE ITSELF must succeed for someone, not merely some route', () => {
    // This rule used to be "the feature contains a positive step". Measured
    // against nsc-eval's map, 48 of 58 denials were on routes NOTHING positively
    // exercised — a product answering 403 for all sixteen of those routes, to
    // every identity, passed every one. A positive on a DIFFERENT route does not
    // establish that this route exists or is reachable by anybody.
    const wrongRoute = validateDenialProofs([f([
      { expect_allowed: { path: '/api/seasons/x/my-scores' } },
      { expect_denied: { path: '/api/seasons/x/audit-log' }, proof: 'capability' },
    ])], profile);
    assert.equal(wrongRoute.length, 1);
    assert.match(wrongRoute[0], /no journey in this run reaches successfully/);

    const rightRoute = validateDenialProofs([f([
      { expect_allowed: { path: '/api/seasons/x/audit-log' } },
      { expect_denied: { path: '/api/seasons/x/audit-log' }, proof: 'capability' },
    ])], profile);
    assert.deepEqual(rightRoute, []);
  });

  test('capability: the control may live in ANOTHER journey of the same run', () => {
    // The identity that legitimately holds a capability is usually in a different
    // journey from the one proving it is denied: the administrator reads the
    // audit log, the no-role persona is denied it. Requiring both in one feature
    // meant an unsatisfiable rule, or journeys rewritten to suit the checker.
    const control = f([{ expect_allowed: { path: '/api/seasons/x/audit-log' } }]);
    control.id = 'admin-controls';
    const denial = f([{ expect_denied: { path: '/api/seasons/x/audit-log' }, proof: 'capability' }]);
    assert.deepEqual(validateDenialProofs([control, denial], profile), []);
  });

  test('capability: a control in a DESELECTED journey does not count', () => {
    // `validateDenialProofs` is given the run PLAN, not the whole map. A control
    // impact selection dropped is a control that does not execute, and crediting
    // it would make the rule a loophole rather than a check.
    const denial = f([{ expect_denied: { path: '/api/seasons/x/audit-log' }, proof: 'capability' }]);
    const p = validateDenialProofs([denial], profile);
    assert.equal(p.length, 1);
  });

  test('capability: the query string is not part of the route', () => {
    // `?grade=granted` and `?grade=ungranted` are the same capability answering
    // differently about two values — which is what `domain_negative` is for.
    const p = validateDenialProofs([f([
      { expect_api: { path: '/api/x/report?grade=${grantedGrade}' } },
      { expect_denied: { path: '/api/x/report?other=1' }, proof: 'capability' },
    ])], profile);
    assert.deepEqual(p, []);
  });
});

// Reconciling what the fixture built with what the verifier chose, against the
// SHAPES the engine actually produces.
//
// Every other test here used strings, and the `integer` shape returns a number.
// `reconcileFixtureValues` stringified one side of the comparison and not the
// other, so `"13" !== 13` made every integer-shaped value report as ignored — on
// every run, against a fixture that had done exactly what it was told. Found by
// the first local end-to-end run, not by the unit suite.
describe('reconciling the fixture against the verifier', () => {
  test('an integer-shaped value the fixture used correctly is NOT flagged', () => {
    const chosen = fixtureValues('wtsn-x', [{ grantedCohortSize: { integer: { min: 12, max: 18 } } }]);
    assert.equal(typeof chosen.grantedCohortSize, 'number');
    assert.deepEqual(reconcileFixtureValues({ grantedCohortSize: chosen.grantedCohortSize }, chosen).ignored, []);
  });

  test('a fixture that really did use a different number IS flagged', () => {
    const chosen = fixtureValues('wtsn-x', [{ grantedCohortSize: { integer: { min: 12, max: 18 } } }]);
    const { ignored } = reconcileFixtureValues({ grantedCohortSize: chosen.grantedCohortSize + 1 }, chosen);
    assert.equal(ignored.length, 1);
  });

  test('OMITTING a chosen value is caught, not just contradicting one', () => {
    // The omission matters most where it is least visible. A fixture that never
    // grants-then-revokes the verifier's `revokedGrade` still passes "the revoked
    // grant is denied", because a never-granted grade denies identically.
    const chosen = fixtureValues('wtsn-x', ['grantedGrade', 'revokedGrade']);
    const { ignored } = reconcileFixtureValues({ grantedGrade: chosen.grantedGrade }, chosen);
    assert.equal(ignored.length, 1);
    assert.match(ignored[0], /revokedGrade/);
  });

  test('the verifier\'s value wins whatever the fixture said', () => {
    const chosen = fixtureValues('wtsn-x', ['primarySeasonName']);
    const { vars } = reconcileFixtureValues({ primarySeasonName: 'something else' }, chosen);
    assert.equal(vars.primarySeasonName, chosen.primarySeasonName);
  });
});

describe('a route is a template, not a URL', () => {
  test('the same route on a different season is the same route', () => {
    // Otherwise a denial on a season the admin does not administer demands a
    // positive control ON THAT SEASON — which could only be built by granting
    // the access the journey exists to prove is absent.
    assert.equal(routeOf('/api/seasons/${foreignSeasonId}/players'),
                 routeOf('/api/seasons/${primarySeasonId}/players'));
  });

  test('different routes stay different', () => {
    assert.notEqual(routeOf('/api/seasons/${x}/players'), routeOf('/api/seasons/${x}/results'));
  });

  test('the query string is still dropped', () => {
    assert.equal(routeOf('/api/x?grade=${g}'), routeOf('/api/x'));
  });

  test('a cross-season capability denial is satisfied by the same route elsewhere', () => {
    const control = feature('control', [{ expect_api: { path: '/api/seasons/${primarySeasonId}/reporting/prospective?grade=${grantedGrade}' } }]);
    const denial = feature('denial', [{ expect_denied: { path: '/api/seasons/${secondarySeasonId}/reporting/prospective?grade=${grantedGrade}' }, proof: 'capability' }]);
    const p = validateDenialProofs([control, denial], {
      preconditions: [{ as: 'W-ADMIN', get: '/api/seasons/${secondarySeasonId}/players', expect: { authorized: true } }],
    });
    assert.deepEqual(p, []);
  });
});

describe('expect_reached: the route answered this identity', () => {
  const denial = (path, cls) => feature('d', [{ expect_denied: { path }, proof: cls }]);

  test('it satisfies a capability control', () => {
    const control = feature('ctl', [{ expect_reached: { path: '/api/seasons/${primarySeasonId}/reporting/session-comparison' } }]);
    const d = denial('/api/seasons/${primarySeasonId}/reporting/session-comparison', 'capability');
    const p = validateDenialProofs([control, d], {
      preconditions: [{ as: 'A', get: '/api/seasons/${primarySeasonId}/x', expect: { authorized: true } }],
    });
    assert.deepEqual(p, []);
  });

  test('it does NOT satisfy entity_existence — a 400 says nothing about the entity', () => {
    // The distinction that keeps this from being a general-purpose loophole: a
    // 400 for a missing query parameter proves the guard admitted the caller,
    // and proves nothing whatever about the season in the URL.
    const control = feature('ctl', [{ expect_reached: { path: '/api/seasons/${foreignSeasonId}/x' } }]);
    const d = denial('/api/seasons/${foreignSeasonId}/x', 'entity_existence');
    const p = validateDenialProofs([control, d], { preconditions: [] });
    assert.equal(p.length, 1);
    assert.match(p[0], /nothing proves/);
  });
});

describe('a selected journey is never demoted to setup', () => {
  // OBSERVED, NOT THEORISED. Adding `depends_on: [prospective-report-boundary]`
  // to another journey turned a real FAIL_PRODUCT into a run reporting
  // PASS_WITH_ADVISORIES: the dependency edge was walked first, `seen` stopped
  // the second visit, and the journey was labelled `setup` — a role the roll-up
  // used to exclude. 320 passing tests did not see it; one real run did.
  const f = (id, deps) => ({ id, __file: `${id}.md`, steps: [], ...(deps ? { depends_on: deps } : {}) });

  test('a journey that is both selected and a dependency stays `verified`', () => {
    const dep = f('control');
    const main = f('main', ['control']);
    const plan = withDependencies([main, dep], [main, dep]);
    assert.equal(plan.find((p) => p.feature.id === 'control').role, 'verified');
  });

  test('order does not decide the role', () => {
    const dep = f('control');
    const main = f('main', ['control']);
    for (const selected of [[main, dep], [dep, main]]) {
      const plan = withDependencies(selected, [main, dep]);
      assert.deepEqual(plan.map((p) => p.role), ['verified', 'verified'], JSON.stringify(plan.map((p) => p.feature.id)));
    }
  });

  test('a dependency that was NOT selected is still setup', () => {
    const dep = f('control');
    const main = f('main', ['control']);
    const plan = withDependencies([main], [main, dep]);
    assert.equal(plan.find((p) => p.feature.id === 'control').role, 'setup');
    assert.equal(plan.find((p) => p.feature.id === 'main').role, 'verified');
  });
});

describe('the roll-up counts every feature that ran', () => {
  test('a setup feature that FAILED is not dropped from the verdict', () => {
    // It used to be: the roll-up ran over `verified` only, so a failing setup
    // journey aborted its dependants and the run reported PASS over whatever had
    // already executed. Two under-verifications in one.
    assert.equal(rollUp([
      { verdict: 'PASS', role: 'verified' },
      { verdict: 'FAIL_PRODUCT', role: 'setup' },
    ]), 'FAIL_PRODUCT');
  });
});
