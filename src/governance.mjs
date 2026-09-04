// Which contract governs this run's verdict.
//
// THE PROBLEM, reproduced against this engine before it was written:
//
//     CONTROL (no generated_roots):    exact_head=false  dirty=["server/src/backdoor.ts"]
//     ATTACK  (product declares src):  exact_head=true   clean=true  dirty_count=0
//
// The verifier no longer reads the product's `.git`, but it still read, from the
// pull request's own tree, the declarations that decide what PASS means. ADR-049
// D1: a pull request may PROPOSE a contract change; it does not GOVERN its own
// verdict. The head contract is fingerprinted, diffed and reported — and is not
// the authority for the run that judges it.
//
// WHERE THE BASE CONTRACT COMES FROM (ADR-049 F3).
//
// Not from the product's `.git`. `loadContractAt` used `git archive` against a
// repository mounted read-write into the product container: ordering saved it,
// which is not the same as being safe, and D1 makes it verdict-bearing. So the
// governing contract is MATERIALISED BY THE TRUSTED SIDE, outside the product
// tree, and handed to the engine as `--base-contract <dir>`.
//
// This is deliberately the same shape as the trusted manifest, and for the same
// reason: exactly one authority, supplied by the trusted plane, with no fallback
// to asking the product. The fallback WAS the vulnerability, in both cases.
//
//     NO GOVERNING CONTRACT, NO PRODUCT CLAIM.
//
// A run given none does not quietly fall back to head governance — which is what
// the code did before, silently, whenever both sides digested as `absent` (F7).
// It runs, reports everything it observed, and withholds the product verdict.

/**
 * Who owns each top-level key of `config.yaml`.
 *
 * TWO KINDS OF DECLARATION LIVE IN ONE FILE, and conflating them breaks the
 * system in one direction or the other:
 *
 *   SEMANTIC — what PASS means. Base-governed, per D1. A pull request that
 *     narrows a domain, drops a selection rule or adds a generated-root
 *     exemption is proposing a change to the test that judges it.
 *
 *   OPERATIONAL — how to build and start THIS revision. Head-supplied, because
 *     it must match the head's own tree: a pull request that legitimately
 *     renames a build script would otherwise be unrunnable under the base's
 *     command, and every product change would need a contract merge first.
 *
 * Operational keys are not therefore harmless — they are executed. They are
 * covered by being fingerprinted and reported as contract movement (D2), by
 * `validateEnvOwnership` and `validateBrowserOwnership` refusing the keys that
 * reach the verifier's own side, and by running as a separate unprivileged uid
 * in its own plane. That is a different control, not an absent one.
 *
 * AN UNKNOWN KEY FAILS THE RUN. It is not defaulted to either side. A new
 * verdict-bearing key silently defaulting to head authority is precisely the
 * defect this module exists to remove, and a hand-maintained list that is only
 * consulted for the keys someone remembered is not a control.
 */
export const CONFIG_AUTHORITY = Object.freeze({
  contract_version: 'base',
  selection: 'base',
  generated_roots: 'base',
  verdict_bearing_paths: 'base',
  identity: 'base',
  injected_by_engine: 'base',
  launch: 'split',

  install: 'head',
  provision: 'head',
  build: 'head',
  env: 'head',
  browser: 'head',
  engine: 'head',
});

/** `launch:` carries both kinds, so it is split field by field. */
export const LAUNCH_AUTHORITY = Object.freeze({
  fixture_profile: 'base',
  expect_seasons: 'base',

  command: 'head',
  health_path: 'head',
  readiness_path: 'head',
});

/**
 * Merge one governing config out of the two, and report every key that has no
 * declared owner.
 */
export function governingConfig(baseConfig, headConfig) {
  const problems = [];
  const config = {};
  const keys = new Set([...Object.keys(baseConfig ?? {}), ...Object.keys(headConfig ?? {})]);

  for (const key of [...keys].sort()) {
    const who = CONFIG_AUTHORITY[key];
    if (!who) {
      problems.push(
        `contract: \`config.yaml\` declares \`${key}\`, which the engine cannot attribute to the base `
        + 'or the head contract. A key with no declared authority is not defaulted — a verdict-bearing '
        + 'key silently defaulting to the head contract is the defect this rule exists to remove. '
        + 'Classify it in `CONFIG_AUTHORITY`.',
      );
      continue;
    }
    if (who === 'base') config[key] = baseConfig?.[key];
    else if (who === 'head') config[key] = headConfig?.[key];
    else {
      const merged = {};
      const sub = new Set([...Object.keys(baseConfig?.[key] ?? {}), ...Object.keys(headConfig?.[key] ?? {})]);
      for (const f of [...sub].sort()) {
        const owner = LAUNCH_AUTHORITY[f];
        if (!owner) {
          problems.push(
            `contract: \`config.yaml\` declares \`${key}.${f}\`, which has no declared authority. `
            + 'Classify it in `LAUNCH_AUTHORITY`.',
          );
          continue;
        }
        merged[f] = owner === 'base' ? baseConfig?.[key]?.[f] : headConfig?.[key]?.[f];
      }
      config[key] = merged;
    }
  }
  return { config, problems };
}

/**
 * The contract that governs, and an account of how it was decided.
 *
 * `base` is a contract loaded from a TRUSTED materialisation. `head` is the one
 * in the product tree. Everything semantic comes from base; the operational
 * config keys come from head, per `CONFIG_AUTHORITY`.
 *
 * Three F7 rules are settled here rather than left to fall out of the code:
 *
 *   NO BASE SUPPLIED  -> authority `none`. Runs, reports, withholds the product
 *                        verdict. Never head governance.
 *   BASE HAS NO CONTRACT -> authority `bootstrap`. The contract is being
 *                        introduced, so nothing governs yet and the run cannot
 *                        make a product claim. This is the pull request that
 *                        first adds proof-class declarations: they merge
 *                        unexecuted, which is a real cost, and the alternative
 *                        is letting them grade themselves.
 *   JOURNEY IN HEAD, NOT IN BASE -> it does not run for the verdict, and it is
 *                        REPORTED rather than silently dropped. A reviewer
 *                        seeing "the new journey passed" when it never ran is
 *                        worse off than one told it did not run.
 */
export function resolveGovernance({
  base = null, head, baseSupplied = false, baseSha = null, baseFingerprint = null,
  // Why `base` is null, when the caller knows. `null` alone cannot distinguish
  // "the base revision has no contract" (a legitimate bootstrap) from "it has one
  // and the engine could not read it" (a fault). Optional, so a caller that does
  // not know keeps today's behaviour.
  baseError = null,
}) {
  if (!baseSupplied) {
    return {
      authority: 'none', sha: null, fingerprint: null, contract: head, problems: [],
      head_only_features: [], product_claims_permitted: false,
      note: 'no trusted base contract was supplied, so no contract could be established as the '
        + 'governing authority for this verdict. Materialise the base contract on the trusted side '
        + 'and pass it with `--base-contract`.',
    };
  }
  if (!base) {
    // COULD NOT READ IS NOT THE SAME AS DOES NOT EXIST — the same distinction as
    // the base tree's, one layer down and load-bearing for the same field.
    //
    // The caller reduces "loadContract threw" and "there is no `.watson/`" to the
    // same `null`, and this note then told the reader the base revision carries
    // no contract. Reproduced: a base contract that WAS materialised and would
    // not parse produced `authority: bootstrap` with that note, which is false —
    // it carries one the engine could not read. Bootstrap is a legitimate,
    // expected state (the pull request that first introduces the contract); an
    // unparseable base contract is a harness or authoring fault, and reporting
    // the second as the first hides it.
    //
    // Both still withhold the product claim, so the verdict is unchanged. What
    // changes is that the reason is true.
    return {
      authority: 'bootstrap', sha: baseSha, fingerprint: null, contract: head, problems: [],
      head_only_features: [], product_claims_permitted: false,
      base_contract_error: baseError ?? null,
      note: baseError
        ? `the base revision's verification contract could not be READ (${baseError}) — this is not `
          + 'a bootstrap: a contract is present at the base and could not be loaded, so nothing '
          + 'governs this run and no product claim is made.'
        : 'the base revision carries no verification contract, so there is nothing to govern this '
          + 'run. The head contract is being introduced and becomes authoritative when it merges.',
    };
  }

  const baseIds = new Set(base.features.map((f) => f.id));
  const headOnly = head.features.filter((f) => !baseIds.has(f.id)).map((f) => f.id);
  const { config, problems } = governingConfig(base.config, head.config);

  return {
    authority: 'base',
    // WHICH contract governed, not merely THAT one did (ADR-049 F9).
    //
    // A result that says "the base contract governed" is exactly what an
    // ungoverned run would also produce if the claim were the only evidence. The
    // trusted side materialised this directory and knows the base SHA
    // independently, so it can compare both and reject a mismatch. Without them
    // the field is decorative.
    sha: baseSha,
    fingerprint: baseFingerprint,
    contract: {
      ...base,
      config,
      // Named so a reader of the code can see that the product tree supplied the
      // path the operational commands run in, and nothing else.
      __headDir: head.dir,
    },
    problems,
    head_only_features: headOnly,
    product_claims_permitted: true,
    note: headOnly.length
      ? `the base contract governs; ${headOnly.length} journey(s) exist only in the head contract and `
        + 'did not run: ' + headOnly.join(', ')
      : 'the base contract governs this verdict; the head contract is reported as a proposed change.',
  };
}

/**
 * Withhold a product claim from a run no trusted contract governed.
 *
 * Deliberately the same shape as `downgradeForInexactHead`: a verdict about a
 * commit requires that the commit is what was driven, AND that the semantics
 * used to judge it were not supplied by the thing being judged. Either missing
 * makes the verdict INDETERMINATE, not PASS.
 */
export function downgradeForUngovernedContract(verdict, governance, productClaims) {
  if (!productClaims.has(verdict)) return { verdict, reason: null };
  if (governance?.product_claims_permitted) return { verdict, reason: null };
  return {
    verdict: 'INDETERMINATE',
    reason: `${verdict} withheld: ${governance?.note ?? 'no governing contract'} A verdict is only `
      + 'meaningful if the thing being judged did not choose the semantics used to judge it.',
  };
}
