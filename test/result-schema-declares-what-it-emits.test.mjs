import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildEnvelope, coverageFrom } from '../src/result.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SCHEMA = JSON.parse(fs.readFileSync(path.join(ROOT, 'schemas/watson-result.schema.json'), 'utf8'));

/**
 * THE GAP THIS CLOSES.
 *
 * `product_identity`, `selection`, `governing_contract`, `not_attempted` and
 * `doctor` were emitted by the engine and ABSENT from the published schema.
 * `additionalProperties` is unset at the top level, so they validated — but
 * they were undeclared, meaning any consumer reading them depended on
 * undocumented behaviour that could change without a version bump. For a
 * merge gate reading `exact_head` to decide whether a product claim is
 * admissible, that is not acceptable.
 *
 * There was no test of any kind over this schema, which is exactly how the gap
 * persisted. This file is the missing one, and it is deliberately written
 * against the ENGINE rather than against captured fixtures: a fixture test
 * passes forever once the fixture stops being regenerated, and the failure
 * mode here is drift between what the engine emits and what the schema says.
 */

/** A full envelope through the real path, with every optional surface populated. */
function fullEnvelope(over = {}) {
  return buildEnvelope({
    runId: 'wtsn-test',
    repository: 'owner/product',
    headSha: 'a'.repeat(40),
    baseSha: 'b'.repeat(40),
    pullRequest: 42,
    watsonVersion: '0.1.0',
    engine: { commit: 'c'.repeat(40), clean: true },
    verdict: 'PASS',
    verdictReason: '9 feature(s) met their proof',
    shadow: true,
    workingTree: {
      exact_head: true, head_matches: true, clean: true, contract_dirty: false,
      changed_mid_run: false, at_start_exact_head: true,
      dirty_paths: [], dirty_count: 0, generated_roots: [], generated_count: 0,
      head_sha: 'a'.repeat(40), expected_sha: 'a'.repeat(40),
      method: 'manifest', counts: {}, note: 'matches',
    },
    governance: {
      authority: 'base', product_claims_permitted: true,
      head_only_features: [], sha: 'd'.repeat(40), fingerprint: 'sha256:x', note: 'base governs',
    },
    selection: {
      method: 'impact', profile: 'poc', applicable: true, escalated: true,
      reason: 'escalated', escalation_reasons: ['p: r (unmapped_runtime)'],
      changed_paths: ['p'],
      classifications: [
        { path: 'a.ts', class: 'unmapped_runtime', reason: 'claimed by no feature', features: [] },
        { path: 'b.sql', class: 'cross_cutting', reason: 'declared cross-cutting', features: [] },
        { path: 'c.ts', class: 'unclassified', reason: 'matched no selection rule', features: [] },
        { path: 'd.ts', class: 'mapped', reason: 'mapped', features: ['f1'] },
      ],
      selected: [], setup: [], deferred: [],
    },
    features: [{ id: 'f1', verdict: 'PASS', role: 'verified', steps: [], evidence: {} }],
    findings: [{ rule: 'unexpected-4xx', severity: 'advisory', feature: 'f1', summary: 's', required_action: 'a', detail: [] }],
    qualitySignals: {},
    notAttempted: [],
    doctor: { ok: true, probes: [] },
    evidence: { bundle: 'runs/x' },
    timings: { total_ms: 1 },
    contractScope: ['.watson'],
    ...over,
  });
}

describe('the schema declares what the engine actually emits', () => {
  test('EVERY top-level key the engine emits is declared', () => {
    const emitted = Object.keys(fullEnvelope());
    const declared = new Set(Object.keys(SCHEMA.properties));
    const undeclared = emitted.filter((k) => !declared.has(k));
    assert.deepEqual(
      undeclared, [],
      `emitted but undeclared: ${undeclared.join(', ')} — a consumer reading these ` +
      `would depend on undocumented behaviour that can change without a version bump`,
    );
  });

  test('every REQUIRED top-level property is actually emitted', () => {
    const env = fullEnvelope();
    for (const key of SCHEMA.required ?? []) {
      assert.ok(key in env, `schema requires \`${key}\` but the engine does not emit it`);
    }
  });

  /**
   * The enum is the point: `features[].verdict` was `{"type": "string"}`, which
   * accepts "definitely fine" as readily as "PASS".
   */
  test('features[].verdict enumerates exactly the nine verdicts, no more and no fewer', () => {
    const declared = SCHEMA.properties.features.items.properties.verdict.enum;
    const expected = [
      'PASS', 'PASS_WITH_ADVISORIES', 'NOT_APPLICABLE', 'FAIL_PRODUCT', 'FAIL_CONTRACT',
      'BLOCKED_ENVIRONMENT', 'INDETERMINATE', 'STALE_CONTRACT', 'CONTRACT_CHANGE_REVIEW_REQUIRED',
    ];
    assert.deepEqual([...declared].sort(), [...expected].sort());
    assert.deepEqual([...SCHEMA.properties.verdict.enum].sort(), [...expected].sort());
  });

  test('the gate-critical fields are declared, individually', () => {
    // Named one by one rather than as a set, so a deletion says WHICH.
    for (const key of ['product_identity', 'selection', 'governing_contract', 'not_attempted', 'doctor', 'coverage']) {
      assert.ok(SCHEMA.properties[key], `\`${key}\` must be declared — a merge gate reads it`);
    }
    assert.ok(SCHEMA.properties.product_identity.required.includes('exact_head'));
    assert.ok(SCHEMA.properties.product_identity.required.includes('changed_mid_run'));
    assert.ok(SCHEMA.properties.governing_contract.required.includes('authority'));
    assert.ok(SCHEMA.properties.selection.required.includes('classifications'));
  });

  test('runtime_findings items are described rather than left as a bare array', () => {
    const items = SCHEMA.properties.runtime_findings.items;
    assert.ok(items?.properties?.severity?.enum, 'severity must be an enum — advisory cannot block');
    assert.deepEqual([...items.properties.severity.enum].sort(), ['advisory', 'blocking']);
  });
});

describe('coverage — facts for a gate, not policy', () => {
  test('splits classified paths by class', () => {
    const c = fullEnvelope().coverage;
    assert.deepEqual(c.classified_paths.unmapped_runtime, ['a.ts']);
    assert.deepEqual(c.classified_paths.cross_cutting, ['b.sql']);
    assert.deepEqual(c.classified_paths.unclassified, ['c.ts']);
    assert.equal(c.counts.unmapped_runtime, 1);
    assert.equal(c.classified_total, 4, 'counts every classification, including mapped');
  });

  /**
   * `unclassified` means the selector COULD NOT DECIDE; `cross_cutting` means
   * the path was DECLARED to affect everything. A gate may reasonably treat
   * uncertainty more conservatively than a declaration, and cannot if they
   * arrive merged.
   */
  test('unclassified is kept distinct from cross_cutting', () => {
    const c = coverageFrom({
      classifications: [
        { path: 'x', class: 'unclassified' },
        { path: 'y', class: 'cross_cutting' },
      ],
    }, []);
    assert.deepEqual(c.classified_paths.unclassified, ['x']);
    assert.deepEqual(c.classified_paths.cross_cutting, ['y']);
  });

  test('counts only journeys that actually verified', () => {
    const c = coverageFrom({ classifications: [] }, [
      { id: 'a', role: 'verified' }, { id: 'b', role: 'verified' }, { id: 'c', role: 'declared' },
    ]);
    assert.equal(c.mapped_verified, 2);
  });

  /**
   * A gate must be able to tell "nothing was unmapped" from "nothing was
   * classified at all". Both give unmapped_runtime = 0; only classified_total
   * separates them.
   */
  test('distinguishes nothing-unmapped from nothing-classified', () => {
    const nothingUnmapped = coverageFrom({ classifications: [{ path: 'a', class: 'mapped' }] }, []);
    const nothingClassified = coverageFrom({ classifications: [] }, []);
    assert.equal(nothingUnmapped.counts.unmapped_runtime, 0);
    assert.equal(nothingClassified.counts.unmapped_runtime, 0);
    assert.equal(nothingUnmapped.classified_total, 1);
    assert.equal(nothingClassified.classified_total, 0);
  });

  test('survives a missing or malformed selection rather than throwing', () => {
    // A run that died before selection still has to produce a readable envelope.
    for (const sel of [null, undefined, {}, { classifications: null }]) {
      const c = coverageFrom(sel, []);
      assert.equal(c.classified_total, 0);
      assert.equal(c.counts.unmapped_runtime, 0);
    }
  });

  /**
   * THE BOUNDARY. Whether unmapped coverage is "meaningful", and whether a human
   * must dispose of it, depend on the consuming repository's ignore globs and
   * chosen conservatism — policy read from that repo's base branch. A verifier
   * emitting those flags would be asserting a merge rule.
   */
  test('reports no policy verdict — no `meaningful`, no `disposition_required`', () => {
    const c = fullEnvelope().coverage;
    assert.ok(!('meaningful' in c), 'meaningful is policy, not a verifier fact');
    assert.ok(!('disposition_required' in c), 'disposition_required is policy, not a verifier fact');
  });

  test('an unknown class is ignored rather than silently bucketed', () => {
    // Forward compatibility: a new CLASS value must not land in `unclassified`
    // and be mistaken for "the selector could not decide".
    const c = coverageFrom({ classifications: [{ path: 'z', class: 'brand_new_class' }] }, []);
    assert.equal(c.counts.unclassified, 0);
    assert.equal(c.classified_total, 1, 'still counted in the total, so the gate sees a discrepancy');
  });
});
