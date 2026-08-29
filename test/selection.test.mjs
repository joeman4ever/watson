import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  CLASS, assertIgnorableRules, classifyPath, globToRegExp, selectByImpact,
} from '../src/selection.mjs';

/** The rules as nsc-eval declares them. Kept close to the real contract so these
 *  cases exercise the shape the product actually ships, not a convenient one. */
const RULES = {
  runtime_roots: ['client/src/**', 'server/src/**'],
  cross_cutting: [
    'package.json', 'package-lock.json', '*/package.json',
    'tsconfig*.json', '*/tsconfig*.json',
    'server/migrations/**',
    '.watson/**',
  ],
  ignorable: ['docs/**', '*.md', '.github/**', 'LICENSE', '.gitignore'],
  adr_dir: 'docs/adr',
};

const FEATURES = [
  {
    id: 'prospective-report-boundary', status: 'mapped', profiles: ['poc', 'smoke'],
    adrs: ['ADR-005', 'ADR-036'],
    source_globs: [
      'client/src/admin/ProspectiveReport.tsx',
      'server/src/reporting/aggregateDisclosure.ts',
    ],
  },
  {
    id: 'admin-roster-manage', status: 'mapped', profiles: ['poc', 'smoke'],
    adrs: ['ADR-008'],
    source_globs: ['client/src/admin/Roster.tsx'],
  },
  {
    id: 'evaluator-tier-boundary', status: 'mapped', profiles: ['smoke'],
    adrs: ['ADR-019'],
    source_globs: ['server/src/assignments/**'],
  },
  { id: 'draft-thing', status: 'draft', profiles: ['smoke'], source_globs: ['client/src/poc/**'] },
];

const ids = (r) => r.features.map((f) => f.id).sort();

describe('glob translation', () => {
  test('`**` crosses separators, `*` does not, and `.` stays literal', () => {
    assert.ok(globToRegExp('server/src/**').test('server/src/a/b/c.ts'));
    assert.ok(!globToRegExp('client/src/*.tsx').test('client/src/a/b.tsx'));
    assert.ok(globToRegExp('client/src/*.tsx').test('client/src/App.tsx'));
    // The bug this pins: a literal dot must not become "any character".
    assert.ok(!globToRegExp('tsconfig.json').test('tsconfigXjson'));
  });

  test('`a/**/b` also matches `a/b`', () => {
    assert.ok(globToRegExp('docs/**/x.md').test('docs/x.md'));
    assert.ok(globToRegExp('docs/**/x.md').test('docs/a/b/x.md'));
  });
});

describe('the anti-self-approval guard on ignorable rules', () => {
  test('refuses an ignorable rule that reaches into runtime code', () => {
    assert.throws(
      () => assertIgnorableRules(['client/src/**'], ['client/src/**', 'server/src/**']),
      /may not cover runtime code/,
    );
  });

  test('refuses a rule that merely overlaps a runtime root', () => {
    // `client/**` is broader than the root, so it swallows runtime code too.
    assert.throws(() => assertIgnorableRules(['client/**'], ['client/src/**']), /may not cover runtime code/);
  });

  test('accepts genuinely non-runtime rules', () => {
    assert.doesNotThrow(() => assertIgnorableRules(RULES.ignorable, RULES.runtime_roots));
  });

  test('selectByImpact refuses to run at all under a poisoned contract', () => {
    assert.throws(
      () => selectByImpact({
        features: FEATURES, changedPaths: ['client/src/admin/Roster.tsx'], profile: 'poc',
        rules: { ...RULES, ignorable: [...RULES.ignorable, 'client/src/**'] },
      }),
      /may not cover runtime code/,
    );
  });
});

describe('path classification', () => {
  const c = (p) => classifyPath(p, {
    features: FEATURES, ignorable: RULES.ignorable, crossCutting: RULES.cross_cutting,
    runtimeRoots: RULES.runtime_roots, adrDir: RULES.adr_dir,
  });

  test('cross-cutting beats a source_globs match', () => {
    // Even if a feature claimed a migration, the schema is read by every journey.
    assert.equal(c('server/migrations/0023_erasure_authority.sql').class, CLASS.CROSS_CUTTING);
  });

  test('an ADR selects the features that cite it', () => {
    const r = c('docs/adr/ADR-005-minor-data-policy.md');
    assert.equal(r.class, CLASS.GOVERNANCE);
    assert.deepEqual(r.features, ['prospective-report-boundary']);
  });

  test('an ADR nothing cites selects nothing and does not escalate', () => {
    const r = c('docs/adr/ADR-041-least-privilege-erasure-authority.md');
    assert.equal(r.class, CLASS.GOVERNANCE);
    assert.deepEqual(r.features, []);
  });

  test('unmapped runtime code is unmapped_runtime, not ignorable', () => {
    assert.equal(c('server/src/privacy/retentionSweep.ts').class, CLASS.UNMAPPED_RUNTIME);
  });

  test('an unrecognised path is unclassified, never ignorable', () => {
    assert.equal(c('infra/terraform/main.tf').class, CLASS.UNCLASSIFIED);
  });
});

// ---------------------------------------------------------------------------
// The six controlled cases.
// ---------------------------------------------------------------------------

describe('controlled case 1 — docs-only change is positively NOT_APPLICABLE', () => {
  test('skips, and says why', () => {
    const r = selectByImpact({
      features: FEATURES, profile: 'poc', rules: RULES,
      changedPaths: ['README.md', 'docs/watson/phase-1-log.md', '.github/workflows/ci.yml'],
    });
    assert.equal(r.applicable, false);
    assert.equal(r.escalated, false);
    assert.deepEqual(r.features, []);
    assert.match(r.reason, /positively established as non-runtime/);
    assert.ok(r.classifications.every((x) => x.class === CLASS.IGNORABLE));
  });
});

describe('controlled case 2 — a mapped source file selects exactly its feature', () => {
  test('one feature, not the whole profile', () => {
    const r = selectByImpact({
      features: FEATURES, profile: 'poc', rules: RULES,
      changedPaths: ['client/src/admin/ProspectiveReport.tsx'],
    });
    assert.equal(r.applicable, true);
    assert.equal(r.escalated, false);
    assert.deepEqual(ids(r), ['prospective-report-boundary']);
  });

  test('a draft feature is never selected even when it claims the path', () => {
    const r = selectByImpact({
      features: FEATURES, profile: 'poc', rules: RULES,
      changedPaths: ['client/src/poc/Thing.tsx'],
    });
    // A draft feature's claim is intent, not capability. The path is therefore
    // unclaimed by anything runnable, so it escalates rather than skipping — and
    // the draft feature is not in the resulting selection either way.
    assert.equal(r.applicable, true);
    assert.equal(r.escalated, true);
    assert.ok(!ids(r).includes('draft-thing'), 'a draft feature must never be selected');
    assert.match(r.escalation_reasons[0], /claimed by no feature/);
  });
});

describe('controlled case 3 — unmapped runtime code escalates, it does not skip', () => {
  test('escalates to the smoke profile and names the reason', () => {
    const r = selectByImpact({
      features: FEATURES, profile: 'poc', rules: RULES,
      changedPaths: ['server/src/privacy/retentionSweep.ts'],
    });
    assert.equal(r.applicable, true);
    assert.equal(r.escalated, true);
    assert.deepEqual(ids(r), ['admin-roster-manage', 'evaluator-tier-boundary', 'prospective-report-boundary']);
    assert.match(r.escalation_reasons[0], /claimed by no feature/);
  });

  test('one unmapped file escalates a diff that is otherwise fully mapped', () => {
    const r = selectByImpact({
      features: FEATURES, profile: 'poc', rules: RULES,
      changedPaths: ['client/src/admin/ProspectiveReport.tsx', 'server/src/privacy/retentionSweep.ts'],
    });
    assert.equal(r.escalated, true);
    assert.ok(r.features.length > 1, 'a single unbounded path must widen the whole run');
  });
});

describe('controlled case 4 — cross-cutting change escalates without matching any glob', () => {
  test('a migration escalates', () => {
    const r = selectByImpact({
      features: FEATURES, profile: 'poc', rules: RULES,
      changedPaths: ['server/migrations/0023_erasure_authority.sql'],
    });
    assert.equal(r.escalated, true);
    assert.equal(r.applicable, true);
  });

  test('a lockfile escalates', () => {
    const r = selectByImpact({
      features: FEATURES, profile: 'poc', rules: RULES, changedPaths: ['package-lock.json'],
    });
    assert.equal(r.escalated, true);
  });

  test('editing the contract escalates, so selection rules verify their own change', () => {
    const r = selectByImpact({
      features: FEATURES, profile: 'poc', rules: RULES,
      changedPaths: ['.watson/config.yaml'],
    });
    assert.equal(r.escalated, true);
    assert.equal(r.applicable, true);
  });
});

describe('controlled case 5 — absent diff information never yields a skip', () => {
  test('no base SHA falls back to profile selection', () => {
    const r = selectByImpact({ features: FEATURES, profile: 'poc', rules: RULES, changedPaths: null });
    assert.equal(r.method, 'profile');
    assert.equal(r.applicable, true);
    assert.deepEqual(ids(r), ['admin-roster-manage', 'prospective-report-boundary']);
    assert.match(r.reason, /no base SHA/);
  });

  test('an empty diff is a positive fact and may skip', () => {
    const r = selectByImpact({ features: FEATURES, profile: 'poc', rules: RULES, changedPaths: [] });
    assert.equal(r.applicable, false);
    assert.match(r.reason, /no files changed/);
  });
});

describe('controlled case 6 — nsc-eval#448, the real diff', () => {
  // The regression this exists to prevent: #448 is 3 ADR/doc files plus a
  // migration plus a test. A selector that weighed "mostly docs" would skip a
  // change that rewrites foreign keys on every evaluation table. The correct
  // answer is NOT NOT_APPLICABLE, and this asserts that directly rather than
  // asserting whichever answer the implementation happens to give.
  const PR_448 = [
    'docs/adr/ADR-013-evaluation-domain-persistence-model.md',
    'docs/adr/ADR-040-owner-privacy-readiness-decisions.md',
    'docs/adr/ADR-041-least-privilege-erasure-authority.md',
    'server/migrations/0023_erasure_authority.sql',
    'server/src/__tests__/erasureAuthority.integration.test.ts',
  ];

  test('is applicable — a schema migration is never skippable', () => {
    const r = selectByImpact({ features: FEATURES, profile: 'poc', rules: RULES, changedPaths: PR_448 });
    assert.equal(r.applicable, true, 'PR #448 must not be classified NOT_APPLICABLE');
    assert.equal(r.escalated, true);
  });

  test('names the migration as the escalating path', () => {
    const r = selectByImpact({ features: FEATURES, profile: 'poc', rules: RULES, changedPaths: PR_448 });
    assert.ok(
      r.escalation_reasons.some((x) => x.includes('0023_erasure_authority.sql')),
      `expected the migration to be named; got ${JSON.stringify(r.escalation_reasons)}`,
    );
  });

  test('stays applicable even with the migration removed, because the test file is unmapped runtime', () => {
    // Guards against someone later "fixing" this by special-casing migrations.
    const r = selectByImpact({
      features: FEATURES, profile: 'poc', rules: RULES,
      changedPaths: PR_448.filter((p) => !p.startsWith('server/migrations/')),
    });
    assert.equal(r.applicable, true);
  });
});

describe('exit code follows the obligation, not the verdict', () => {
  test('every satisfied-obligation verdict would exit 0', async () => {
    const { checkFor } = await import('../src/result.mjs');
    // The regression: NOT_APPLICABLE discharges the verification duty. Keying
    // the exit code on the verdict made it exit 1 and read as a CI failure.
    for (const v of ['PASS', 'PASS_WITH_ADVISORIES', 'NOT_APPLICABLE']) {
      assert.equal(checkFor(v).obligation, 'satisfied', `${v} must satisfy the obligation`);
    }
    for (const v of ['FAIL_PRODUCT', 'FAIL_CONTRACT', 'BLOCKED_ENVIRONMENT', 'INDETERMINATE']) {
      assert.notEqual(checkFor(v).obligation, 'satisfied', `${v} must not satisfy the obligation`);
    }
  });
});
