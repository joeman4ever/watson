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

/**
 * The three verdicts that are CLAIMS ABOUT A PRODUCT REVISION.
 *
 * Everything else says something about Watson (FAIL_CONTRACT), the environment
 * (BLOCKED_ENVIRONMENT), or the run's own inability to conclude — none of which
 * asserts anything about the commit.
 */
export const PRODUCT_CLAIMS = new Set(['PASS', 'PASS_WITH_ADVISORIES', 'FAIL_PRODUCT']);

/**
 * Verdicts an UNGOVERNED run may not reach.
 *
 * Wider than `PRODUCT_CLAIMS`, and the difference is the whole point.
 * `NOT_APPLICABLE` is not a statement about Watson — it says *this revision
 * needed no verification*, which is a claim about the revision, decided by the
 * contract's `selection` rules.
 *
 * When nothing governs the run those rules come from the PULL REQUEST. A head
 * contract declaring `ignorable: ["**"]` with empty `runtime_roots` then makes
 * every change non-runtime, the run drives zero journeys, and it reports
 * `NOT_APPLICABLE` with `obligation: satisfied` — indistinguishable from a
 * correct skip, while the product chose the semantics that produced it.
 *
 * Demonstrated by independent adversarial review with a full engine run: a diff
 * touching `identity/enforcement.ts`, an auth guard and a repository was
 * "positively established as non-runtime", 0 journeys, exit 0, and the trusted
 * validator accepted it.
 */
export const WITHHELD_WITHOUT_GOVERNANCE = new Set([...PRODUCT_CLAIMS, 'NOT_APPLICABLE']);

/**
 * A product claim requires that the source driven actually IS the revision
 * reported (Phase-1 defect W2, now a standing invariant).
 *
 * WHAT THIS ESTABLISHES, worded carefully because the looser version is easy to
 * write and is wrong:
 *
 *   At the verifier's measurement point, the materialised committed product
 *   source matched the reported product HEAD X.
 *
 * NOT: the bytes loaded into the running process are nothing but the committed
 * bytes. Generated build output is outside the measurement, the
 * source is measured at two instants rather than continuously, and nothing here
 * binds the artefact that was actually launched to the commit. Those are real
 * and separate, tracked as C4, and required to be closed or consciously accepted
 * before Watson becomes a required merge check.
 *
 * Reporting the dirt was not enough. Every result carries a 40-char SHA and two
 * fingerprints computed from git, while the contract that executed and the product
 * that was built came from the working tree — so on a dirty checkout a PASS is a
 * statement about a commit that was never run. Observed rather than reasoned about:
 * a feature file written mid-campaign was picked up by runs already in flight, all
 * reporting the same SHA.
 *
 * FAIL_PRODUCT is downgraded for the same reason PASS is, and it matters more.
 * Accusing a commit of a defect that was never observed on it is the same error as
 * absolving one, and it costs more to unwind.
 *
 * An UNKNOWN tree state (git unavailable) is treated as inexact. Not being able to
 * check is not evidence of cleanliness.
 */
export function downgradeForInexactHead(verdict, workingTree) {
  if (!PRODUCT_CLAIMS.has(verdict)) return { verdict, reason: null };
  if (workingTree?.exact_head === true) return { verdict, reason: null };

  const what = workingTree?.head_matches === false
    // Checked first: a clean tree at the WRONG commit would otherwise fall through
    // to the dirt wording and describe the least important thing that is wrong.
    ? `the checkout is at ${workingTree.head_sha ?? 'an unknown commit'}, not the reported commit`
    : workingTree?.contract_dirty
      ? 'the CONTRACT that executed is not the one at the reported SHA'
      : workingTree?.clean === null
        ? 'the checkout could not be compared against the reported SHA'
        : 'the checkout is not the revision it reports';
  return {
    verdict: 'INDETERMINATE',
    reason:
      `${verdict} withheld: ${what}. A verdict about a commit requires that the commit ` +
      'is what was actually driven.',
  };
}

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
  // A feature that ended BLOCKED_ENVIRONMENT did not verify anything, and used
  // to fall through to PASS because nothing named it here. Found by the
  // run-level property test, not by any test of this function.
  if (has('BLOCKED_ENVIRONMENT')) return 'BLOCKED_ENVIRONMENT';
  if (has('INDETERMINATE')) return 'INDETERMINATE';
  if (has('PASS_WITH_ADVISORIES')) return 'PASS_WITH_ADVISORIES';
  return 'PASS';
}

/**
 * The RUN-LEVEL verdict: what the whole run may claim, given what executed and
 * what was planned.
 *
 * Extracted from `cli.mjs` so the property below is testable where it actually
 * holds. Two defects lived in that inline code, both of them silent
 * under-verification on the verdict path:
 *
 *   - a failing SETUP journey was excluded from the roll-up, so a prerequisite
 *     failure aborted its dependants and the run reported PASS over whatever had
 *     already executed;
 *   - the aborted dependants vanished entirely, so the run reported on a subset
 *     without saying it was a subset.
 *
 * THE PROPERTY, stated once and enforced here:
 *
 *     a prerequisite failure cannot make verification coverage disappear
 *     while the run reports PASS or PASS_WITH_ADVISORIES.
 *
 * It holds for every failure kind, not only FAIL_PRODUCT — a dependency that
 * fails its contract or its environment leaves its dependants just as unable to
 * execute meaningfully.
 */
export function runVerdict({ executed = [], plan = [], applicable = true } = {}) {
  // SELECTED, APPLICABLE, AND NOTHING TO RUN IS A CONTRACT FAULT.
  //
  // `rollUp([])` answers `NOT_APPLICABLE`, which is right for a run that
  // decided up front there was nothing to verify — and wrong for one that
  // decided there WAS and then found no journeys: an escalation profile with no
  // members, a profile fallback matching nothing. That run drove nothing and
  // would report a satisfied obligation. Same defect class as an ungoverned
  // `NOT_APPLICABLE`; named here rather than left to the caller.
  if (applicable && !plan.length) {
    return {
      verdict: 'FAIL_CONTRACT',
      reason: 'the run was applicable but the contract selected no journeys at all — '
        + 'nothing was verified, and that is a contract fault rather than a skip',
      notAttempted: [],
    };
  }
  const verdict = rollUp(executed);

  const attempted = new Set(executed.map((f) => f.id));
  const notAttempted = plan
    .filter((p) => p.role === 'verified' && !attempted.has(p.feature?.id ?? p.id))
    .map((p) => p.feature?.id ?? p.id);

  const failed = executed.filter((f) => f.verdict === 'FAIL_PRODUCT');
  const drift = executed.filter((f) => f.verdict === 'FAIL_CONTRACT');

  // A selected journey that produced no result at all cannot be spoken for, so a
  // verdict that DISCHARGES THE OBLIGATION becomes INDETERMINATE.
  //
  // Not "PASS-shaped". That was the set, and it let the one case it was written
  // for slip past: `rollUp([])` returns NOT_APPLICABLE, which is not PASS-shaped,
  // so a run where NOTHING executed and journeys were selected came back as
  //
  //     NOT_APPLICABLE | obligation satisfied | "1 selected journey(s) never ran (j1)"
  //
  // — a verdict and a reason that contradict each other, discharging the
  // verification duty over journeys that did not run. Found by the exact-HEAD
  // confirmation review (its N5) and reproduced above before this changed.
  //
  // The right membership test is the one the obligation table already makes:
  // PASS, PASS_WITH_ADVISORIES and NOT_APPLICABLE all report `satisfied`, and
  // none of them may stand over a journey that never ran. It is the same
  // correction as `WITHHELD_WITHOUT_GOVERNANCE` — the wider set, for the same
  // reason: NOT_APPLICABLE says *this revision needed no runtime verification*,
  // which is a claim, not an abstention.
  //
  // FAIL_PRODUCT is deliberately NOT here even though it is a product claim: a
  // run that established a real failure keeps it. The failure is evidence, the
  // incompleteness is additional, and converting the finding into INDETERMINATE
  // would hide it. `PRODUCT_CLAIMS` includes FAIL_PRODUCT and is the wrong set.
  const DISCHARGES_OBLIGATION = new Set(['PASS', 'PASS_WITH_ADVISORIES', 'NOT_APPLICABLE']);
  if (notAttempted.length && DISCHARGES_OBLIGATION.has(verdict)) {
    return {
      verdict: 'INDETERMINATE',
      reason: `${notAttempted.length} selected journey(s) never ran (${notAttempted.join(', ')}), `
        + 'so this run cannot speak for them',
      notAttempted,
    };
  }
  return {
    verdict,
    reason: failed.length
      ? `${failed.length} of ${executed.length} feature(s) failed their proof`
      : drift.length
        ? `${drift.length} feature(s) could not be verified — the map names something that no longer exists`
        : notAttempted.length
          ? `${notAttempted.length} selected journey(s) never ran (${notAttempted.join(', ')})`
          : `${executed.length} feature(s) met their proof`,
    notAttempted,
  };
}

export function buildEnvelope(run) {
  const verdict = run.verdict;
  return {
    schema_version: SCHEMA_VERSION,
    run_id: run.runId,
    watson: {
      version: run.watsonVersion,
      commit: run.engine?.commit ?? run.watsonCommit ?? null,
      // False means the engine had uncommitted changes, so `commit` names a
      // revision the running code is not. Null means it could not be determined.
      clean: run.engine?.clean ?? null,
    },

    repository: run.repository,
    pull_request: run.pullRequest ?? null,
    head_sha: run.headSha,
    base_sha: run.baseSha ?? null,
    // Whether the checkout actually matched the SHA above.
    // `product_identity` because that is what it is. It was `working_tree` when
    // the answer came from `git status`; `working_tree` stays as an alias so a
    // consumer reading it does not silently start seeing `undefined` — which, on
    // a field that gates product claims, would read as "not exact" and turn every
    // run INDETERMINATE.
    product_identity: run.workingTree ?? null,
    working_tree: run.workingTree ?? null,

    // THE MANIFEST THAT ESTABLISHED IDENTITY, recorded in the envelope.
    //
    // `cli.mjs` computed this and never emitted it, so the trusted validator's
    // `d.manifest?.sha !== expect.headSha` check could not fire: the key was
    // always undefined and the `&&` short-circuited. A second silently-skipped
    // trusted-side check, found by the fixture canary that was written after
    // the first one (`schema` vs `schema_version`) was found by review.
    //
    // It is also provenance worth having on its own: which manifest, describing
    // how many entries, spoke for this run's product identity.
    manifest: run.manifest ?? null,

    // Recorded ALWAYS; NOT consulted for carry-forward in phase 0/1.
    product_fingerprint: run.productFingerprint,
    contract_fingerprint: run.contractFingerprint,
    // What that fingerprint covered. `.watson/` plus everything the contract
    // NAMES but does not contain — the fixture script, the package scripts, the
    // lockfile, the migrations (ADR-049 D2). Recorded because a digest whose
    // scope is invisible cannot be checked by the person reading it.
    contract_scope: run.contractScope ?? null,
    // The fingerprint pins the exact contract BYTES, which is the stronger fact.
    // The declared version is recorded beside it because it is what the engine
    // negotiated against — a reader comparing two observations wants to know the
    // contract generation changed, not only that some byte did.
    contract_version: run.contractVersion ?? null,
    carried_forward_from: null,

    // THREE STATES, AND THE ENVELOPE MUST CARRY ALL THREE.
    //
    // This was `!!run.contractChange`, and `contractChange` now returns a
    // TRUTHY object for an unavailable comparison — so an unobtainable base
    // reported `contract_change: true`. That is the exact collapse the D1
    // disposition forbids ("unavailable → changed"), reintroduced one layer
    // above the function that was fixed to prevent it. Caught by reading the
    // envelope rather than the function.
    //
    // `contract_change` now means what its documented semantics say and nothing
    // wider: verdict-bearing contract material in the EVALUATED HEAD differs
    // from the GOVERNING TRUSTED BASE. It is not a claim about who authored the
    // difference — see `contract_comparison`.
    contract_change: run.contractChange?.comparison !== 'unavailable' && !!run.contractChange,
    // The state itself, named, so a reader never has to infer it from a boolean
    // that cannot express three things.
    contract_comparison: run.contractChange
      ? (run.contractChange.comparison === 'unavailable' ? 'unavailable' : 'diverged')
      : 'equivalent',
    // THE THIRD COLLAPSE, and the one that shipped.
    //
    // This default was `{ model: 'head-product-x-head-contract',
    // base_contract_available: false }` for every run where `contractChange`
    // returned null — and since D1, null means BOTH trusted sides were read and
    // AGREED. So the field asserted the base was unavailable in exactly the case
    // where it demonstrably was available, on every base-governed run with an
    // unchanged contract. `base_contract_available` must be factual in both
    // directions; a false negative is as much a lie as a false positive, and it
    // is the one that was being emitted.
    //
    // The `model` string was wrong for the same reason — `result.mjs`'s own
    // `governing_contract` comment already says `head-product-x-head-contract`
    // "under D1 is simply false" for a governed run.
    contract_evaluation: run.contractChange ?? {
      model: run.governance?.authority === 'base' ? 'trusted-base-x-trusted-head' : 'head-product-x-head-contract',
      base_contract_available: run.governance?.authority === 'base',
      comparison: 'equivalent',
    },

    // WHICH CONTRACT DECIDED THIS VERDICT (ADR-049 F9).
    //
    // Before this key existed, a base-governed run was still labelled with the
    // head's `contract_version` and `contract_fingerprint`, and the model string
    // above said `head-product-x-head-contract` — which under D1 is simply
    // false. A reader could not tell a governed run from an ungoverned one, and
    // neither could `validate-result.mjs`.
    //
    // `authority` is the whole answer: `base` means a trusted contract governed;
    // `none` and `bootstrap` mean nothing did, and the product claim was
    // withheld for that reason.
    governing_contract: run.governance
      ? {
          authority: run.governance.authority,
          product_claims_permitted: run.governance.product_claims_permitted,
          head_only_features: run.governance.head_only_features ?? [],
          // WHICH base contract, not merely that there was one. The trusted
          // observer materialised it and knows the base SHA independently, so it
          // can compare both and reject a mismatch — without them the field is
          // a self-report and provenance is decorative.
          sha: run.governance.sha ?? null,
          fingerprint: run.governance.fingerprint ?? null,
          note: markerSafe(run.governance.note ?? ''),
        }
      : null,

    // How the product was LAUNCHED, on its own rather than inside the
    // whole-contract digest. Head-authored, untrusted, product-plane only — and
    // conspicuous, because a reviewer must be able to see that this pull request
    // changed the commands Watson ran to start the thing it verified.
    operational_config: run.operationalConfig ?? null,

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

      // What actually executed this run. Recorded because a runtime verdict is
      // only as interpretable as the world it was produced in: "PASS on Node
      // 22.11 / Ubuntu 24.04 / Chromium via Playwright 1.49.1" is a fact
      // somebody can act on months later; "PASS" alone is not.
      //
      // This is PROVENANCE, not reproducibility. Nothing here claims the run
      // could be reproduced bit-for-bit — it could not, and saying so would be
      // the kind of overstatement this envelope exists to avoid. It records what
      // was used, so that a difference between two results can be explained
      // instead of argued about.
      execution: run.execution ?? null,

      // Everything under this key describes WATSON'S OWN synthetic verification
      // environment, never the product's production posture. It was previously a
      // bare `admin_mfa_enforced: false` sitting beside the environment fields,
      // which read out of context as a claim that the product does not enforce
      // admin MFA. It never meant that. Nesting it makes the subject explicit
      // rather than inferable from surrounding keys.
      verification_environment: {
        admin_mfa_enforced: false,
      },

      // Stated in every result, not buried in docs: a verifier silent about its
      // blind spots invites people to assume it has none.
      //
      // Deliberately generic. The engine's semantics do not depend on which
      // identity provider a product uses, so naming one would couple this
      // engine to a particular deployment without making the statement any
      // truer. A product contract can be specific where specificity helps.
      not_proven_by_this_run: [
        'hosted identity-provider login',
        'passwordless / magic-link-or-code delivery',
        'cookie/session lifetime',
        'session sealing and rotation',
        'step-up MFA',
      ],
      auth_seam: 'bearer-local-jwks',
    },

    selection: run.selection,
    // Selected journeys that produced no result at all — a prerequisite failed
    // and the loop stopped. Named, because a run that quietly reports on the
    // subset which happened to execute is under-verifying without saying so.
    not_attempted: run.notAttempted ?? [],
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
  // THE MARKER'S OWN VALUES ARE SANITISED TOO.
  //
  // `JSON.stringify` escapes quotes and backslashes; it does NOT escape `-->`.
  // So a value carrying that sequence closes this comment early, and everything
  // after it becomes document body — including a second, attacker-shaped
  // WATSON_METADATA block. Every field here is engine-derived today, which is why
  // it went unnoticed; the escaping is wrong regardless of who fills the fields,
  // and a field added later will not come back to re-read this comment.
  const clean = (v) => (typeof v === 'string' ? markerSafe(v) : v);
  const payload = {
    schema: MARKER_SCHEMA,
    agent: 'watson',
    status: clean(env.verdict),
    obligation: clean(env.check.obligation),
    verified_head: clean(env.head_sha),
    product_fingerprint: clean(env.product_fingerprint),
    profile: clean(env.profile),
    run_id: clean(env.run_id),
  };
  return `<!-- WATSON_METADATA\n${JSON.stringify(payload, null, 2)}\n-->`;
}

/**
 * Neutralise the three sequences that can open or close a WATSON_METADATA block.
 * Shared by the marker builder and the summary so they cannot drift apart.
 */
export function markerSafe(v) {
  return String(v ?? '')
    .replaceAll('<!--', '<!-\u2011-')
    .replaceAll('-->', '--\u2011>')
    .replaceAll('WATSON_METADATA', 'WATSON\u2011METADATA');
}

const ICON = { PASS: '✓', PASS_WITH_ADVISORIES: '✓', FAIL_PRODUCT: '✗', FAIL_CONTRACT: '⚠', BLOCKED_ENVIRONMENT: '⚠', INDETERMINATE: '?', NOT_APPLICABLE: '–' };

export function summary(env) {
  // Product-controlled text reaches this document: a failing command's stderr
  // travels through the plane's error message into `doctor.probes[].detail` and
  // into step observations. The document ends with a WATSON_METADATA marker that
  // a consumer parses, so anything able to write `<!-- ... -->` into the body can
  // offer a second, forged one. Neutralise the two sequences that matter; the
  // text stays readable and stops being able to close or open a marker block.
  // THE RULE: every value that reaches this document from outside the engine
  // goes through `safe()`. Enforced by a test that walks the whole envelope
  // rather than by remembering, because remembering has now failed twice. Not "every value that looks dangerous" — a review
  // found three that had been missed (`verdict_reason`, which carries a failing
  // command's message straight from the plane, and the contract-evaluation ids,
  // which are FEATURE FILENAMES and so product-authored). Each had been left out
  // because it did not look like product text at the call site. It was.
  const safe = markerSafe;

  const L = [];
  L.push(`## Watson — ${safe(env.verdict)}`);
  L.push('');
  L.push(`**${safe(env.verdict_reason)}**`);
  L.push('');
  L.push(`| | |`);
  L.push(`| --- | --- |`);
  L.push(`| Verified HEAD | \`${safe(env.head_sha)}\` |`);
  L.push(`| Profile | \`${env.profile}\` |`);
  L.push(`| Check obligation | **${safe(env.check.obligation)}**${env.check.shadow ? ' _(shadow — informational)_' : ''} |`);
  L.push(`| Environment | ${safe(env.environment.mode)} · ${safe(env.environment.browser)} |`);
  L.push(`| Fixture | \`${safe(env.environment.fixture_profile)}\` |`);
  L.push('');

  if (env.doctor && !env.doctor.ok) {
    L.push('### Doctor failed — the environment was not worth driving');
    for (const p of env.doctor.probes) L.push(`- ${p.ok ? '✓' : '✗'} **${safe(p.name)}** — ${safe(p.detail)}`);
    L.push('');
  }

  if (env.features.length) {
    L.push('### Features');
    L.push('');
    L.push('| | Feature | Role | Steps | Time |');
    L.push('| --- | --- | --- | --- | --- |');
    for (const f of env.features) {
      L.push(`| ${ICON[f.verdict] ?? '·'} ${f.verdict} | ${safe(f.title)} | ${f.role} | ${f.steps.filter((s) => s.result === 'ok').length}/${f.steps.length} | ${(f.duration_ms / 1000).toFixed(1)}s |`);
    }
    L.push('');
  }

  const blocking = env.runtime_findings.filter((f) => f.severity === 'blocking');
  const advisory = env.runtime_findings.filter((f) => f.severity !== 'blocking');
  if (blocking.length) {
    L.push('### Blocking findings');
    for (const f of blocking) {
      L.push(`- **${safe(f.summary)}** _(${safe(f.rule)}, ${safe(f.feature)})_`);
      if (f.required_action) L.push(`  - Required: ${safe(f.required_action)}`);
    }
    L.push('');
  }
  for (const f of env.features.filter((x) => x.verdict === 'FAIL_PRODUCT')) {
    const bad = f.steps.find((s) => s.result === 'fail');
    if (!bad) continue;
    L.push(`### Failure detail — ${safe(f.title)}`);
    L.push(`Step ${bad.n} (\`${safe(bad.action)}\`): ${safe(bad.observed)}`);
    if (bad.expected) L.push(`Expected: ${safe(bad.expected)}`);
    if (f.evidence?.length) L.push(`Evidence: ${f.evidence.map((e) => `\`${safe(e)}\``).join(', ')}`);
    L.push('');
  }
  if (advisory.length) {
    L.push('### Advisories');
    for (const f of advisory) L.push(`- ${safe(f.summary)} _(${safe(f.rule)}, ${safe(f.feature)})_`);
    L.push('');
  }

  const q = env.quality_signals;
  L.push(`**Signals** — console errors ${q.console_errors} · warnings ${q.console_warnings} · 5xx ${q.http_5xx} · unexpected 4xx ${q.unexpected_4xx} · failed requests ${q.failed_requests} · raw UUIDs ${q.raw_uuid_visible}`);
  L.push('');

  if (env.contract_comparison === 'unavailable') {
    // Said out loud, and NOT as a change. The trusted material for one side was
    // not obtainable, so no comparison happened; reporting that as a contract
    // change would be inventing a finding, and reporting it as silence would be
    // inventing an assurance.
    L.push('### ⚠ The verification contract comparison could not be made');
    L.push(safe(env.contract_evaluation?.why ?? 'trusted comparison material was unavailable'));
    L.push('');
    L.push('_Neither "changed" nor "unchanged" is asserted. Verification escalates rather than narrowing._');
    L.push('');
  } else if (env.contract_change) {
    // DIVERGENCE FROM THE GOVERNING BASE, not authorship.
    //
    // This heading used to read "This PR changes the verification contract",
    // and after D1 that statement can be false: the diff is now governing-base
    // tip vs evaluated head, so a contract change landing on the base branch
    // while this head stays stale diverges without this pull request having
    // authored anything. The reader is told what was measured.
    L.push('### ⚠ The head differs from the governing verification contract');
    const ce = env.contract_evaluation;
    if (ce.expectations_weakened?.length) {
      L.push('Expectations **weakened**:');
      for (const w of ce.expectations_weakened) L.push(`- \`${safe(w.id)}\` — ${safe(w.why)}`);
    }
    if (ce.features_removed?.length) L.push(`Features removed: ${ce.features_removed.map((f) => `\`${safe(f)}\``).join(', ')}`);
    if (ce.features_added?.length) L.push(`Features added: ${ce.features_added.map((f) => `\`${safe(f)}\``).join(', ')}`);
    if (ce.invariants_added?.length) L.push(`Invariants added: ${ce.invariants_added.map((f) => `\`${safe(f)}\``).join(', ')}`);
    if (ce.base_contract_available === false) {
      L.push('The base contract itself could not be loaded, so only the FACT of divergence is reported — review the `.watson/` diff directly.');
    } else if (!ce.expectations_weakened?.length && !ce.features_removed?.length) {
      // Say this explicitly. A bare heading with nothing under it reads as
      // "something was weakened and Watson could not name it".
      L.push('No expectation was removed or weakened: every feature, step and invariant present at the base is still present and still in scope.');
    }
    L.push('');
    L.push('_Divergence is measured between the GOVERNING BASE and the EVALUATED HEAD, so it does not by itself mean this pull request authored the difference — a contract change on the base branch diverges from a stale head too. A PR must not be able to weaken its own verification expectation and thereby manufacture its own PASS; Sherlock is the independent reviewer of whether the difference is legitimate. Watson REPORTS this in Phase 0/1; it does not gate on it._');
    L.push('');
  }

  const wt = env.product_identity ?? env.working_tree;
  if (wt && wt.exact_head === false) {
    L.push('### ⚠ This run is NOT bound to the SHA it reports');
    L.push(
      `The checkout differs from \`${safe((env.head_sha ?? '').slice(0, 7))}\` in ${wt.dirty_count} path(s). ` +
        'The fingerprints above come from git; the contract that ran and the product that was built ' +
        'came from the working tree. Those are different things right now.',
    );
    if (wt.contract_dirty) {
      L.push('');
      L.push('**The contract itself is modified.** This run verified expectations that do not exist at that SHA, so its result cannot be cited for that commit.');
    }
    if (wt.dirty_paths?.length) L.push('', 'Modified: ' + wt.dirty_paths.map((p) => `\`${safe(p)}\``).join(', '));
    L.push('');
  }

  L.push(`_Not proven by this run: ${env.environment.not_proven_by_this_run.map(safe).join(' · ')}._`);
  L.push('');
  L.push(marker(env));
  return L.join('\n');
}

/**
 * Write the run's evidence, and — when the caller named one — the canonical
 * result at an EXACT path the caller chose.
 *
 * `outPath` exists to delete a whole class of CI mistake. A harness that finds
 * the result by listing the run directories newest-first is asking the
 * filesystem which file is newest, and the answer is influenced by every process
 * that ran during the verification — including the product's. The trusted side
 * should not be discovering its own evidence; it should be naming it.
 *
 * Failure to write it is fatal on purpose. A run whose result did not reach the
 * agreed path has produced no observation, and a harness that then finds a
 * STALE file at that path would report the previous run's verdict as this one's.
 */
export function writeResult(runDir, env, outPath = null) {
  const jsonPath = path.join(runDir, 'result.json');
  const mdPath = path.join(runDir, 'summary.md');
  const json = JSON.stringify(env, null, 2);
  fs.writeFileSync(jsonPath, json);
  fs.writeFileSync(mdPath, summary(env));
  if (outPath) {
    fs.mkdirSync(path.dirname(path.resolve(outPath)), { recursive: true });
    fs.writeFileSync(outPath, json);
  }
  return { jsonPath, mdPath, outPath };
}
