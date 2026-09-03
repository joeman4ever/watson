// Trusted precondition evidence: proving the world the journeys assert on was
// actually built.
//
// WHY THIS EXISTS.
//
// The verifier chooses the values its assertions rest on and hands them to the
// fixture (ADR-049 D4). The fixture reports back what it built, and the engine
// checks the report against what it supplied. That catches a fixture which
// contradicts a value, or silently never uses one.
//
// It does not catch the case that matters most. An untrusted fixture echoing an
// id back proves that it RECEIVED the id — nothing more. The entity behind it may
// not exist, and a denial asserted against an entity that does not exist is
// satisfied by a product that denies correctly, by one that denies everything, and
// by one asked about nothing at all. That was F1.
//
// So the world gets proven independently of the fixture's word for it:
//
//     trusted verifier chooses the operand
//         ↓
//     fixture receives it as input and builds its world
//         ↓
//     TRUSTED proof establishes the semantic world the journey needs
//         ↓
//     journey runs, asserting on the verifier-owned operand
//
// WHO CONTROLS WHAT (ADR-049, and the engineering rule that every trust-boundary
// input gets this analysis written down):
//
//     VALUE          the operand being proven
//       controlled by  the trusted verifier (`verifier_chosen`)
//       not by         the fixture, the product, the pull request
//
//     PROBE SHAPE    which table and column an existence proof reads
//       controlled by  the BASE contract — trusted, reviewed, on the default
//                      branch, and not editable by the pull request under test
//       not by         the head contract
//
//     DATABASE       what the probe reads
//       controlled by  the engine, which created this synthetic per-run database
//       not by         the product, beyond the rows its own fixture wrote
//
// Watson still does not author SQL semantics. It builds ONE query shape — a
// parameterised existence read — from a base-governed declaration of table and
// column. The product does not gain an endpoint it would not otherwise have, and
// no identity is invented to make an assertion reachable.

import { randomUUID } from 'node:crypto';

/** Proof types a contract may declare. Unknown types fail closed. */
export const PROOF_TYPES = Object.freeze(['entity_exists', 'state_transition']);

/**
 * Where a proof's evidence comes from.
 *
 * `application_read` is preferred wherever the product exposes an authorized
 * read: it proves the entity exists AND is reachable through the product's own
 * code path, which is strictly more than a row check.
 *
 * `trusted_setup` exists for the entities a product deliberately gives no read
 * path. `foreignSeasonId` is the case: it is administered by nobody, which is the
 * property that makes least-privilege testable, so no persona can resolve it and
 * no application read can exist. Inventing an administering identity to satisfy
 * the framework would change the topology under test.
 */
export const PROOF_SOURCES = Object.freeze(['application_read', 'trusted_setup']);

// A Postgres identifier the engine is willing to interpolate. Deliberately
// narrower than what Postgres accepts: no quoting, no schema qualification, no
// case sensitivity to reason about. The declaration is trusted, and this is still
// checked — a trusted source is not a reason to skip validation, it is a reason
// the validation should never fire.
const SAFE_IDENTIFIER = /^[a-z_][a-z0-9_]{0,62}$/;

/** Column predicates a `state_transition` proof may require. */
export const REQUIRE_PREDICATES = Object.freeze(['not_null', 'null', 'in_past', 'in_future']);

/**
 * Problems with a profile's `proofs` block. Pure; runs before anything is
 * provisioned.
 */
export function validateProofDeclarations(fixtureProfile, verifierChosenNames = []) {
  const problems = [];
  const proofs = fixtureProfile?.proofs;
  if (proofs === undefined) return problems;
  if (!Array.isArray(proofs)) return ['fixtures: `proofs` must be a list'];

  const chosen = new Set(verifierChosenNames);
  for (const [i, p] of proofs.entries()) {
    const at = `fixtures: proofs[${i}]`;
    if (!p || typeof p !== 'object') { problems.push(`${at} is not a mapping`); continue; }

    if (!PROOF_TYPES.includes(p.type)) {
      problems.push(`${at}: unknown proof type \`${p.type ?? '(none)'}\` (expected ${PROOF_TYPES.join(', ')})`);
    }
    if (!PROOF_SOURCES.includes(p.source)) {
      problems.push(`${at}: unknown proof source \`${p.source ?? '(none)'}\` (expected ${PROOF_SOURCES.join(', ')})`);
    }
    if (!p.subject || typeof p.subject !== 'string') {
      problems.push(`${at}: needs a \`subject\` naming the value being proven`);
    } else if (!chosen.has(p.subject)) {
      // A proof about a value the product chose proves the product's own claim.
      problems.push(
        `${at}: \`${p.subject}\` is not declared in \`verifier_chosen\`. A proof about a value the `
        + 'fixture chose establishes the fixture\'s own claim, which is what this mechanism exists to stop.',
      );
    }

    if (p.source === 'trusted_setup') {
      const probe = p.probe ?? null;
      if (!probe || typeof probe !== 'object') {
        problems.push(`${at}: \`trusted_setup\` needs a \`probe\` naming the table and column to read`);
      } else {
        for (const key of ['table', 'column']) {
          if (!SAFE_IDENTIFIER.test(String(probe[key] ?? ''))) {
            problems.push(
              `${at}: probe \`${key}\` must be a plain lowercase identifier, got \`${probe[key] ?? '(none)'}\``,
            );
          }
        }
        for (const [col, pred] of Object.entries(probe.requires ?? {})) {
          if (!SAFE_IDENTIFIER.test(col)) {
            problems.push(`${at}: probe requires an unsafe column name \`${col}\``);
          }
          if (!REQUIRE_PREDICATES.includes(pred)) {
            problems.push(`${at}: unknown predicate \`${pred}\` on \`${col}\` (expected ${REQUIRE_PREDICATES.join(', ')})`);
          }
        }
      }
      if (p.type === 'state_transition' && !Object.keys(p.probe?.requires ?? {}).length) {
        problems.push(
          `${at}: a \`state_transition\` proof must require the transition column — otherwise it establishes `
          + 'that the row exists, not that the transition happened, and a never-granted value satisfies it.',
        );
      }
    }

    if (p.source === 'application_read' && !p.via?.get) {
      problems.push(`${at}: \`application_read\` needs \`via: { as, get }\` naming the authorized read`);
    }
  }
  return problems;
}

/** The SQL a `trusted_setup` proof runs. Exported so a test can read it. */
export function existenceSql(probe) {
  if (!SAFE_IDENTIFIER.test(String(probe?.table ?? '')) || !SAFE_IDENTIFIER.test(String(probe?.column ?? ''))) {
    throw new Error('existenceSql: refusing to build a query from an unvalidated identifier');
  }
  const clauses = [`${probe.column} = $1`];
  for (const [col, pred] of Object.entries(probe.requires ?? {})) {
    if (!SAFE_IDENTIFIER.test(col)) throw new Error(`existenceSql: unsafe column \`${col}\``);
    if (pred === 'not_null') clauses.push(`${col} IS NOT NULL`);
    else if (pred === 'null') clauses.push(`${col} IS NULL`);
    else if (pred === 'in_past') clauses.push(`${col} < now()`);
    else if (pred === 'in_future') clauses.push(`${col} > now()`);
    else throw new Error(`existenceSql: unknown predicate \`${pred}\``);
  }
  return `SELECT 1 FROM ${probe.table} WHERE ${clauses.join(' AND ')} LIMIT 1`;
}

/**
 * Run the trusted proofs and return evidence records.
 *
 * `query` is injected rather than a pool being constructed here, so this is
 * testable and so the caller decides which connection the proof reads — the
 * engine's own, never one the product supplied.
 *
 * A proof that throws is NOT established. Fail-closed matters more here than
 * anywhere: an unestablished proof means the world the journey asserts on was
 * not shown to exist, and the honest outcome is a blocked environment rather
 * than a product verdict.
 */
export async function runTrustedProofs(query, fixtureProfile, vars) {
  const evidence = [];
  for (const p of (fixtureProfile?.proofs ?? []).filter((x) => x?.source === 'trusted_setup')) {
    const value = vars?.[p.subject];
    const record = {
      type: p.type, subject: p.subject, source: 'trusted_setup',
      established: false, detail: null,
    };
    if (value === undefined || value === null || String(value) === '') {
      record.detail = `no value for \`${p.subject}\` to prove`;
      evidence.push(record);
      continue;
    }
    try {
      const { rows } = await query(existenceSql(p.probe), [String(value)]);
      record.established = rows.length > 0;
      record.detail = record.established
        ? `${p.probe.table}.${p.probe.column} = the verifier's value${Object.keys(p.probe.requires ?? {}).length ? `, with ${Object.entries(p.probe.requires).map(([c, k]) => `${c} ${k}`).join(' and ')}` : ''}`
        : `no row in ${p.probe.table} where ${p.probe.column} is the verifier's value`;
    } catch (err) {
      record.detail = `probe failed: ${String(err.message ?? err).slice(0, 200)}`;
    }
    evidence.push(record);
  }
  return evidence;
}

/**
 * A value of the same SHAPE as `like` that the run's database does not contain.
 *
 * The shape matters, and finding out why cost a live run. The control below used
 * to ask every probe about `watson-absent-<uuid>`. Against a `uuid` column
 * Postgres does not answer that question at all — it raises `invalid input syntax
 * for type uuid` — so the control failed, and because it fails closed, it would
 * have blocked every run declaring a proof over a uuid column. The proofs
 * themselves were green in both directions; only executing the whole thing
 * against a real database showed the control was unusable.
 *
 * The control has to run the SAME query the proof runs, so casting the column or
 * the parameter is not an option: a control over a different query shape does not
 * control the proof. It has to be a type-compatible value instead.
 *
 * WHO CONTROLS THIS VALUE: the verifier. The shape is read from the verifier's
 * own chosen value, and the value itself is freshly random per call — the product
 * never sees it, cannot predict it, and cannot create a row for it.
 */
export function impossibleLike(like) {
  const s = String(like ?? '');
  // A random v4 uuid. It "cannot exist" at 2^-122, which is a smaller risk than
  // any other part of this system.
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(s)) return randomUUID();
  // Large but inside int4, so a narrow integer column answers rather than
  // erroring. The fixture seeds small counts; nothing in a per-run synthetic
  // database reaches this range.
  if (/^\d+$/.test(s)) return String(1_000_000_000 + Math.floor(Math.random() * 1_000_000_000));
  return `watson-absent-${randomUUID()}`;
}

/**
 * A negative control the engine can run against its own probe.
 *
 * The danger with an existence probe is not that it says no when it should say
 * yes — that fails the run loudly. It is that it says YES unconditionally, in
 * which case every proof passes and the mechanism is decoration. So the engine
 * asks the same probe about a value that cannot exist, and requires the answer
 * to be no.
 *
 * `like` is the verifier's real value for this subject, used only for its shape.
 */
export async function proveProbeCanFail(query, probe, like) {
  const impossible = impossibleLike(like);
  try {
    const { rows } = await query(existenceSql(probe), [impossible]);
    return { ok: rows.length === 0, detail: rows.length === 0
      ? 'the probe answers NO for a value that cannot exist'
      : 'the probe answered YES for a value that cannot exist — it proves nothing' };
  } catch (err) {
    return { ok: false, detail: `control failed: ${String(err.message ?? err).slice(0, 200)}` };
  }
}
