// Trusted precondition evidence.
//
// The property under test is narrow and worth stating exactly: these proofs
// establish that the entity the verifier named EXISTS in the run's own synthetic
// database, independently of the fixture's word for it. They do not establish
// that the product behaves correctly, and they do not establish anything about a
// product that chooses to behave differently when it recognises a value — that is
// outside the Phase-1 claim.

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  validateProofDeclarations, existenceSql, runTrustedProofs, proveProbeCanFail, impossibleLike,
  PROOF_TYPES, PROOF_SOURCES,
} from '../src/proofs.mjs';

const CHOSEN = ['primarySeasonId', 'foreignSeasonId', 'revokedGrade'];

describe('proof declarations', () => {
  test('an absent `proofs` block is allowed — the mechanism is opt-in per profile', () => {
    assert.deepEqual(validateProofDeclarations({}, CHOSEN), []);
  });

  test('an unknown type or source fails closed rather than defaulting', () => {
    const p = validateProofDeclarations(
      { proofs: [{ type: 'vibes', source: 'trust me', subject: 'primarySeasonId' }] }, CHOSEN);
    assert.ok(p.some((x) => /unknown proof type/.test(x)));
    assert.ok(p.some((x) => /unknown proof source/.test(x)));
  });

  test('a proof about a value the FIXTURE chose is refused', () => {
    // Otherwise the proof establishes the fixture's own claim, which is the thing
    // this mechanism exists to stop.
    const p = validateProofDeclarations(
      { proofs: [{ type: 'entity_exists', source: 'trusted_setup', subject: 'sessionId', probe: { table: 'session', column: 'id' } }] },
      CHOSEN);
    assert.equal(p.length, 1);
    assert.match(p[0], /not declared in `verifier_chosen`/);
  });

  test('probe identifiers must be plain — no quoting, no injection surface', () => {
    for (const bad of ['season"; DROP TABLE season; --', 'public.season', 'Season', '', 'a'.repeat(80)]) {
      const p = validateProofDeclarations(
        { proofs: [{ type: 'entity_exists', source: 'trusted_setup', subject: 'foreignSeasonId', probe: { table: bad, column: 'id' } }] },
        CHOSEN);
      assert.ok(p.some((x) => /probe `table` must be a plain lowercase identifier/.test(x)), `accepted: ${bad}`);
    }
  });

  test('a state_transition proof must require the transition column', () => {
    // Without it the proof establishes that the row exists, not that the
    // transition happened — and a never-granted value satisfies that.
    const p = validateProofDeclarations(
      { proofs: [{ type: 'state_transition', source: 'trusted_setup', subject: 'revokedGrade', probe: { table: 'prospective_coach_grant', column: 'grade_canonical' } }] },
      CHOSEN);
    assert.equal(p.length, 1);
    assert.match(p[0], /must require the transition column/);
  });

  test('a well-formed declaration passes', () => {
    assert.deepEqual(validateProofDeclarations({
      proofs: [
        { type: 'entity_exists', source: 'trusted_setup', subject: 'foreignSeasonId', probe: { table: 'season', column: 'id' } },
        { type: 'state_transition', source: 'trusted_setup', subject: 'revokedGrade', probe: { table: 'prospective_coach_grant', column: 'grade_canonical', requires: { revoked_at: 'not_null' } } },
        { type: 'entity_exists', source: 'application_read', subject: 'primarySeasonId', via: { as: 'W-ADMIN', get: '/api/seasons/${primarySeasonId}' } },
      ],
    }, CHOSEN), []);
  });
});

describe('the query a trusted proof runs', () => {
  test('is a parameterised existence read, with the value never interpolated', () => {
    const sql = existenceSql({ table: 'season', column: 'id' });
    assert.equal(sql, 'SELECT 1 FROM season WHERE id = $1 LIMIT 1');
  });

  test('carries the transition predicate when one is required', () => {
    const sql = existenceSql({ table: 'prospective_coach_grant', column: 'grade_canonical', requires: { revoked_at: 'not_null' } });
    assert.equal(sql, 'SELECT 1 FROM prospective_coach_grant WHERE grade_canonical = $1 AND revoked_at IS NOT NULL LIMIT 1');
  });

  test('refuses to build anything from an unvalidated identifier', () => {
    assert.throws(() => existenceSql({ table: 'season; DROP TABLE x', column: 'id' }), /unvalidated identifier/);
    assert.throws(() => existenceSql({ table: 'season', column: 'id', requires: { 'x; --': 'not_null' } }), /unsafe column/);
    assert.throws(() => existenceSql({ table: 'season', column: 'id', requires: { ok: 'whatever' } }), /unknown predicate/);
  });
});

describe('running the proofs', () => {
  const profile = {
    proofs: [
      { type: 'entity_exists', source: 'trusted_setup', subject: 'foreignSeasonId', probe: { table: 'season', column: 'id' } },
      // application_read proofs are not this function's job.
      { type: 'entity_exists', source: 'application_read', subject: 'primarySeasonId', via: { as: 'W-ADMIN', get: '/x' } },
    ],
  };

  test('a row that exists establishes the proof', async () => {
    const query = async () => ({ rows: [{ '?column?': 1 }] });
    const ev = await runTrustedProofs(query, profile, { foreignSeasonId: 'abc' });
    assert.equal(ev.length, 1, 'only the trusted_setup proof runs here');
    assert.equal(ev[0].established, true);
  });

  test('THE CASE THIS EXISTS FOR: the fixture echoed the id, the row is absent', async () => {
    // Reconciliation is satisfied — the fixture reported back exactly the value it
    // was given. The entity was never created. Without this proof the journey
    // asserts a denial against nothing.
    const query = async () => ({ rows: [] });
    const ev = await runTrustedProofs(query, profile, { foreignSeasonId: 'abc' });
    assert.equal(ev[0].established, false);
    assert.match(ev[0].detail, /no row in season/);
  });

  test('a probe that throws is not established', async () => {
    const query = async () => { throw new Error('relation "season" does not exist'); };
    const ev = await runTrustedProofs(query, profile, { foreignSeasonId: 'abc' });
    assert.equal(ev[0].established, false);
    assert.match(ev[0].detail, /probe failed/);
  });

  test('a missing value is not established, rather than skipped', async () => {
    const query = async () => ({ rows: [{ x: 1 }] });
    const ev = await runTrustedProofs(query, profile, {});
    assert.equal(ev[0].established, false);
    assert.match(ev[0].detail, /no value/);
  });
});

describe('the probe is shown capable of answering NO', () => {
  // The failure mode that matters is not a probe that wrongly says no — that
  // fails the run loudly. It is a probe that says YES unconditionally, in which
  // case every proof passes and the mechanism is decoration.
  test('a probe that discriminates passes its own control', async () => {
    const query = async (_sql, [v]) => ({ rows: v === 'real-value' ? [{ x: 1 }] : [] });
    const r = await proveProbeCanFail(query, { table: 'season', column: 'id' });
    assert.equal(r.ok, true);
  });

  test('a probe that always says yes FAILS its own control', async () => {
    const query = async () => ({ rows: [{ x: 1 }] });
    const r = await proveProbeCanFail(query, { table: 'season', column: 'id' });
    assert.equal(r.ok, false);
    assert.match(r.detail, /it proves nothing/);
  });
});

describe('the control value is type-compatible with the column', () => {
  // Found by running the whole thing against a real database, not by these tests:
  // `watson-absent-<uuid>` is not a uuid, so Postgres raises rather than answering,
  // the control fails, and — because it fails closed — every run declaring a proof
  // over a uuid column would have been blocked.
  test('a uuid subject gets a uuid the run does not contain', () => {
    const v = impossibleLike('11111111-1111-4111-8111-111111111111');
    assert.match(v, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    assert.notEqual(v, '11111111-1111-4111-8111-111111111111');
  });

  test('an integer subject gets an integer, inside int4', () => {
    const v = impossibleLike('7');
    assert.match(v, /^\d+$/);
    assert.ok(Number(v) > 1_000_000 && Number(v) < 2_147_483_647, v);
  });

  test('anything else keeps the marked sentinel', () => {
    assert.match(impossibleLike('watson-seasonName-abc'), /^watson-absent-/);
    assert.match(impossibleLike(undefined), /^watson-absent-/);
  });

  test('it is fresh every call — the product cannot pre-create a row for it', () => {
    const seen = new Set();
    for (let i = 0; i < 50; i += 1) seen.add(impossibleLike('11111111-1111-4111-8111-111111111111'));
    assert.equal(seen.size, 50);
  });
});

describe('the vocabulary is closed', () => {
  test('types and sources are the declared sets', () => {
    assert.deepEqual([...PROOF_TYPES], ['entity_exists', 'state_transition']);
    assert.deepEqual([...PROOF_SOURCES], ['application_read', 'trusted_setup']);
  });
});

// ---------------------------------------------------------------------------
// The proofs are load-bearing, or they are decoration.
//
// The module above is correct in isolation. That is not the property that
// matters. These tests are about the three joins that make it count:
//
//   1. `validateDenialProofs` credits a proof as evidence an entity exists.
//   2. `doctor` EXECUTES that proof and fails the run when it is not established.
//   3. The credit in (1) is only ever extended for a proof that (2) executes.
//
// Break any one and the mechanism becomes a declaration the product writes about
// itself, which is what it exists to stop.

import { validateDenialProofs, provenSubjects } from '../src/contract.mjs';
import { doctor } from '../src/environment.mjs';

const deniedFeature = (cls) => [{
  __file: 'f.yaml',
  steps: [{ expect_denied: { path: '/api/seasons/${foreignSeasonId}' }, proof: cls }],
}];

describe('a declared proof is credited as existence evidence', () => {
  const withProof = (proof) => ({
    verifier_chosen: [{ foreignSeasonId: 'uuid' }],
    proofs: [proof],
  });

  test('WITHOUT a proof, an entity_existence denial is refused', () => {
    const p = validateDenialProofs(deniedFeature('entity_existence'), { verifier_chosen: [{ foreignSeasonId: 'uuid' }] });
    assert.equal(p.length, 1);
    assert.match(p[0], /nothing proves/);
  });

  test('WITH a trusted_setup existence proof, it is accepted', () => {
    const p = validateDenialProofs(deniedFeature('entity_existence'), withProof(
      { type: 'entity_exists', source: 'trusted_setup', subject: 'foreignSeasonId', probe: { table: 'season', column: 'id' } },
    ));
    assert.deepEqual(p, []);
  });

  test('an `application_read` proof is NOT credited — nothing executes it', () => {
    // It describes a read the product exposes. That is a precondition, and gets
    // credited when one is actually declared and run. Crediting the description
    // alone would accept a claim in place of evidence.
    const p = validateDenialProofs(deniedFeature('entity_existence'), withProof(
      { type: 'entity_exists', source: 'application_read', subject: 'foreignSeasonId', via: { as: 'W-ADMIN', get: '/x' } },
    ));
    assert.equal(p.length, 1);
    assert.match(p[0], /nothing proves/);
  });

  test('an existence proof does NOT satisfy a state_transition denial', () => {
    // The row being there says nothing about the transition, and a value that was
    // never granted satisfies it identically.
    const p = validateDenialProofs(deniedFeature('state_transition'), withProof(
      { type: 'entity_exists', source: 'trusted_setup', subject: 'foreignSeasonId', probe: { table: 'season', column: 'id' } },
    ));
    assert.equal(p.length, 1);
    assert.match(p[0], /was ALLOWED before the transition/);
  });

  test('a state_transition proof that tests the transition column does', () => {
    const p = validateDenialProofs(deniedFeature('state_transition'), withProof(
      { type: 'state_transition', source: 'trusted_setup', subject: 'foreignSeasonId', probe: { table: 'g', column: 'id', requires: { revoked_at: 'not_null' } } },
    ));
    assert.deepEqual(p, []);
  });

  test('provenSubjects keeps existence and transition apart', () => {
    const s = provenSubjects({
      proofs: [
        { type: 'entity_exists', source: 'trusted_setup', subject: 'a', probe: { table: 't', column: 'c' } },
        { type: 'state_transition', source: 'trusted_setup', subject: 'b', probe: { table: 't', column: 'c', requires: { revoked_at: 'not_null' } } },
      ],
    });
    assert.deepEqual([...s.exists].sort(), ['a', 'b']);
    assert.deepEqual([...s.transitioned], ['b']);
  });
});

describe('doctor discharges the obligation the credit was extended against', () => {
  // `doctor` is exercised through its real signature. Only the probes that reach
  // the network are stubbed away; the database read is the thing under test, and
  // it runs against a real connection string that names a database that is not
  // this run's — which is the interlock below.
  const profile = {
    proofs: [{
      type: 'entity_exists', source: 'trusted_setup', subject: 'foreignSeasonId',
      probe: { table: 'season', column: 'id' },
    }],
  };
  const args = {
    baseUrl: 'http://127.0.0.1:1', dbName: 'watson_run_x',
    databaseUrl: 'postgres://u:p@127.0.0.1:5432/watson_run_x',
    fixtureProfile: profile, vars: { foreignSeasonId: 'abc' },
  };
  const named = (r, prefix) => r.probes.filter((p) => p.name.startsWith(prefix));

  test('it refuses to read a database this run did not create', async () => {
    // The production-safety interlock is not weakened to run a proof. Watson
    // reads its own database or it reads none.
    const r = await doctor({ ...args, databaseUrl: 'postgres://u:p@10.0.0.9:5432/nsc_production' });
    const t = named(r, 'trusted-proof');
    assert.equal(t.length, 1);
    assert.equal(t[0].ok, false);
    assert.match(t[0].detail, /did not create/);
    assert.equal(r.ok, false);
  });

  test('an unreachable database is a failed proof, never a skipped one', async () => {
    // Nothing here can connect. The point is that the absence of evidence is
    // recorded as absence of evidence, and doctor is not ok.
    const r = await doctor(args);
    assert.equal(r.ok, false);
    assert.ok(named(r, 'trusted-proof').length === 1 || named(r, 'proof ').length === 1);
  });

  test('a profile with no proofs adds no proof probes', async () => {
    const r = await doctor({ ...args, fixtureProfile: { preconditions: [] } });
    assert.deepEqual(named(r, 'trusted-proof'), []);
    assert.deepEqual(named(r, 'proof'), []);
  });
});
