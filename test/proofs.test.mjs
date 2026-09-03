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
  validateProofDeclarations, existenceSql, runTrustedProofs, proveProbeCanFail,
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

describe('the vocabulary is closed', () => {
  test('types and sources are the declared sets', () => {
    assert.deepEqual([...PROOF_TYPES], ['entity_exists', 'state_transition']);
    assert.deepEqual([...PROOF_SOURCES], ['application_read', 'trusted_setup']);
  });
});
