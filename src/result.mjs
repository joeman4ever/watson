// The result contract: what Watson learned, and whether the obligation was met.
//
// TWO AXES, deliberately. A single axis cannot both be trustworthy and be a
// merge gate:
//
//   verdict            = what Watson learned about the product
//   check.obligation   = whether the required verification obligation was met
//
// Collapsing them produces one of two failures: an unverifiable HEAD merges
// because Watson could not run, or an environment fault is misreported as a
// broken product. Only FAIL_PRODUCT asserts the product is broken. The
// "not_satisfied" states say something weaker and more honest — Watson did not
// establish that this HEAD behaves correctly.
//
// PHASE-3 INVARIANT: a runtime-relevant HEAD cannot merge merely because Watson
// was unable to verify it.

import fs from 'node:fs';
import path from 'node:path';

export const SCHEMA_VERSION = 'watson-result/v1';
export const MARKER_SCHEMA = 'watson-marker/v1';

/** verdict -> obligation. The GitHub conclusion follows the Checks API. */
const OBLIGATION = {
  PASS: ['satisfied', 'success'],
  PASS_WITH_ADVISORIES: ['satisfied', 'success'],
  NOT_APPLICABLE: ['satisfied', 'success'],
  FAIL_PRODUCT: ['failed', 'failure'],
  FAIL_CONTRACT: ['not_satisfied', 'action_required'],
  BLOCKED_ENVIRONMENT: ['not_satisfied', 'action_required'],
  INDETERMINATE: ['not_satisfied', 'action_required'],
  STALE_CONTRACT: ['not_satisfied', 'action_required'],
  CONTRACT_CHANGE_REVIEW_REQUIRED: ['not_satisfied', 'action_required'],
};

export function checkFor(verdict, { shadow = true } = {}) {
  const [obligation, conclusion] = OBLIGATION[verdict] ?? ['not_satisfied', 'action_required'];
  // In shadow mode every conclusion is informational.
  return { obligation, conclusion: shadow ? 'neutral' : conclusion, shadow };
}

/** Roll per-feature verdicts into the run verdict. Worst outcome wins. */
export function rollUp(features) {
  const has = (v) => features.some((f) => f.verdict === v);
  if (!features.length) return 'NOT_APPLICABLE';
  if (has('FAIL_PRODUCT')) return 'FAIL_PRODUCT';
  if (has('FAIL_CONTRACT')) return 'FAIL_CONTRACT';
  if (has('INDETERMINATE')) return 'INDETERMINATE';
  if (has('PASS_WITH_ADVISORIES')) return 'PASS_WITH_ADVISORIES';
  return 'PASS';
}

export function buildEnvelope(run) {
  const verdict = run.verdict;
  return {
    schema_version: SCHEMA_VERSION,
    run_id: run.runId,
    watson: { version: run.watsonVersion, commit: run.watsonCommit ?? null },

    repository: run.repository,
    pull_request: run.pullRequest ?? null,
    head_sha: run.headSha,
    base_sha: run.baseSha ?? null,

    // Recorded ALWAYS; NOT consulted for carry-forward in phase 0/1.
    product_fingerprint: run.productFingerprint,
    contract_fingerprint: run.contractFingerprint,
    carried_forward_from: null,

    contract_change: !!run.contractChange,
    contract_evaluation: run.contractChange ?? {
      model: 'head-product-x-head-contract',
      base_contract_available: false,
    },

    profile: run.profile,
    verdict,
    verdict_reason: run.verdictReason,
    check: checkFor(verdict, { shadow: run.shadow !== false }),

    environment: {
      mode: 'local-ephemeral',
      base_url: run.baseUrl,
      browser: run.browser,
      viewports: run.viewports,
      database: run.dbName,
      fixture_profile: run.fixtureProfile,
      node: process.version,
      admin_mfa_enforced: false,
      // Stated in every result, not buried in docs: a verifier silent about its
      // blind spots invites people to assume it has none.
      not_proven_by_this_run: [
        'WorkOS hosted login',
        'Magic Auth delivery',
        'cookie/session lifetime',
        'session sealing and rotation',
        'Admin-MFA step-up',
      ],
      auth_seam: 'bearer-local-jwks',
    },

    selection: run.selection,
    doctor: run.doctor,
    features: run.features,
    runtime_findings: run.findings,
    quality_signals: run.qualitySignals,
    evidence: run.evidence,
    timings: run.timings,
    started_at: run.startedAt,
    finished_at: run.finishedAt,
  };
}

export function marker(env) {
  // Follows the six marker rules already proven in this workflow: exactly one
  // block, last in the message, full 40-char lowercase hex, SHA must exist in
  // the repo, schema version matches. Uses its OWN literal so Sherlock's parser
  // (which knows only `claude` and `reviewer`) ignores it rather than
  // mis-parsing it.
  const payload = {
    schema: MARKER_SCHEMA,
    agent: 'watson',
    status: env.verdict,
    obligation: env.check.obligation,
    verified_head: env.head_sha,
    product_fingerprint: env.product_fingerprint,
    profile: env.profile,
    run_id: env.run_id,
  };
  return `<!-- WATSON_METADATA\n${JSON.stringify(payload, null, 2)}\n-->`;
}

const ICON = { PASS: '✓', PASS_WITH_ADVISORIES: '✓', FAIL_PRODUCT: '✗', FAIL_CONTRACT: '⚠', BLOCKED_ENVIRONMENT: '⚠', INDETERMINATE: '?', NOT_APPLICABLE: '–' };

export function summary(env) {
  const L = [];
  L.push(`## Watson — ${env.verdict}`);
  L.push('');
  L.push(`**${env.verdict_reason}**`);
  L.push('');
  L.push(`| | |`);
  L.push(`| --- | --- |`);
  L.push(`| Verified HEAD | \`${env.head_sha}\` |`);
  L.push(`| Profile | \`${env.profile}\` |`);
  L.push(`| Check obligation | **${env.check.obligation}**${env.check.shadow ? ' _(shadow — informational)_' : ''} |`);
  L.push(`| Environment | ${env.environment.mode} · ${env.environment.browser} |`);
  L.push(`| Fixture | \`${env.environment.fixture_profile}\` |`);
  L.push('');

  if (env.doctor && !env.doctor.ok) {
    L.push('### Doctor failed — the environment was not worth driving');
    for (const p of env.doctor.probes) L.push(`- ${p.ok ? '✓' : '✗'} **${p.name}** — ${p.detail}`);
    L.push('');
  }

  if (env.features.length) {
    L.push('### Features');
    L.push('');
    L.push('| | Feature | Role | Steps | Time |');
    L.push('| --- | --- | --- | --- | --- |');
    for (const f of env.features) {
      L.push(`| ${ICON[f.verdict] ?? '·'} ${f.verdict} | ${f.title} | ${f.role} | ${f.steps.filter((s) => s.result === 'ok').length}/${f.steps.length} | ${(f.duration_ms / 1000).toFixed(1)}s |`);
    }
    L.push('');
  }

  const blocking = env.runtime_findings.filter((f) => f.severity === 'blocking');
  const advisory = env.runtime_findings.filter((f) => f.severity !== 'blocking');
  if (blocking.length) {
    L.push('### Blocking findings');
    for (const f of blocking) {
      L.push(`- **${f.summary}** _(${f.rule}, ${f.feature})_`);
      if (f.required_action) L.push(`  - Required: ${f.required_action}`);
    }
    L.push('');
  }
  for (const f of env.features.filter((x) => x.verdict === 'FAIL_PRODUCT')) {
    const bad = f.steps.find((s) => s.result === 'fail');
    if (!bad) continue;
    L.push(`### Failure detail — ${f.title}`);
    L.push(`Step ${bad.n} (\`${bad.action}\`): ${bad.observed}`);
    if (bad.expected) L.push(`Expected: ${bad.expected}`);
    if (f.evidence?.length) L.push(`Evidence: ${f.evidence.map((e) => `\`${e}\``).join(', ')}`);
    L.push('');
  }
  if (advisory.length) {
    L.push('### Advisories');
    for (const f of advisory) L.push(`- ${f.summary} _(${f.rule}, ${f.feature})_`);
    L.push('');
  }

  const q = env.quality_signals;
  L.push(`**Signals** — console errors ${q.console_errors} · warnings ${q.console_warnings} · 5xx ${q.http_5xx} · unexpected 4xx ${q.unexpected_4xx} · failed requests ${q.failed_requests} · raw UUIDs ${q.raw_uuid_visible}`);
  L.push('');

  if (env.contract_change) {
    L.push('### ⚠ This PR changes the verification contract');
    const ce = env.contract_evaluation;
    if (ce.expectations_weakened?.length) {
      L.push('Expectations **weakened**:');
      for (const w of ce.expectations_weakened) L.push(`- \`${w.id}\` — ${w.why}`);
    }
    if (ce.features_removed?.length) L.push(`Features removed: ${ce.features_removed.map((f) => `\`${f}\``).join(', ')}`);
    if (ce.features_added?.length) L.push(`Features added: ${ce.features_added.map((f) => `\`${f}\``).join(', ')}`);
    if (ce.invariants_added?.length) L.push(`Invariants added: ${ce.invariants_added.map((f) => `\`${f}\``).join(', ')}`);
    if (ce.base_contract_available === false) {
      L.push('The base contract could not be read, so only the FACT of a change is reported — review the `.watson/` diff directly.');
    } else if (!ce.expectations_weakened?.length && !ce.features_removed?.length) {
      // Say this explicitly. A bare heading with nothing under it reads as
      // "something was weakened and Watson could not name it".
      L.push('No expectation was removed or weakened: every feature, step and invariant present at the base is still present and still in scope.');
    }
    L.push('');
    L.push('_A PR must not be able to weaken its own verification expectation and thereby manufacture its own PASS. Sherlock is the independent reviewer of whether this change is legitimate. Watson REPORTS this in Phase 0/1; it does not gate on it._');
    L.push('');
  }

  L.push(`_Not proven by this run: ${env.environment.not_proven_by_this_run.join(' · ')}._`);
  L.push('');
  L.push(marker(env));
  return L.join('\n');
}

export function writeResult(runDir, env) {
  const jsonPath = path.join(runDir, 'result.json');
  const mdPath = path.join(runDir, 'summary.md');
  fs.writeFileSync(jsonPath, JSON.stringify(env, null, 2));
  fs.writeFileSync(mdPath, summary(env));
  return { jsonPath, mdPath };
}
