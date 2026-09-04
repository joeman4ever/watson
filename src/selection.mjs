/**
 * Diff-driven impact selection.
 *
 * Decides which mapped journeys a given change actually requires Watson to run,
 * and — the harder half — when it may honestly run none at all.
 *
 * The governing rule is that `NOT_APPLICABLE` must be *positively established*,
 * never reached by falling through. A verifier that skips work whenever it fails
 * to recognise a path would grow quieter exactly as a codebase grew stranger, and
 * its silence would be indistinguishable from a clean bill of health. So every
 * classification that is not an explicit "this cannot affect the running product"
 * escalates instead. Ignorance escalates; only knowledge skips.
 *
 * Three consequences follow, and each is enforced below rather than described:
 *
 *   1. A path under a declared runtime root can NEVER be ignorable, even if the
 *      contract says so. `assertIgnorableRules` refuses such a contract outright.
 *      Otherwise a product PR could widen its own ignorable list and skip itself.
 *   2. A change to `.watson/**` escalates. A PR that edits selection rules is
 *      therefore fully verified by the rules it is trying to change.
 *   3. No base SHA means no diff, and no diff means no knowledge. That falls back
 *      to profile selection — never to a skip.
 */

/** A change to any of these forces escalation regardless of what it maps to. */
export const CLASS = Object.freeze({
  IGNORABLE: 'ignorable',
  GOVERNANCE: 'governance',
  MAPPED: 'mapped',
  GOVERNING: 'governing',
  CROSS_CUTTING: 'cross_cutting',
  UNMAPPED_RUNTIME: 'unmapped_runtime',
  UNCLASSIFIED: 'unclassified',
});

/** Classes that oblige Watson to run something beyond what the diff maps to. */
const ESCALATING = new Set([CLASS.CROSS_CUTTING, CLASS.GOVERNING, CLASS.UNMAPPED_RUNTIME, CLASS.UNCLASSIFIED]);

/**
 * Translate a glob to a RegExp. `**` crosses directory separators, `*` does not,
 * `?` matches one non-separator character. Everything else is literal — a `.` in
 * a path must not become "any character", or `config.ts` would match `configXts`.
 */
export function globToRegExp(glob) {
  let out = '^';
  for (let i = 0; i < glob.length; i += 1) {
    const c = glob[i];
    if (c === '*') {
      if (glob[i + 1] === '*') {
        // `a/**/b` should also match `a/b`, so swallow the following slash.
        if (glob[i + 2] === '/') { out += '(?:.*/)?'; i += 2; } else { out += '.*'; i += 1; }
      } else {
        out += '[^/]*';
      }
    } else if (c === '?') {
      out += '[^/]';
    } else {
      out += c.replace(/[.+^${}()|[\]\\]/g, '\\$&');
    }
  }
  return new RegExp(`${out}$`);
}

export function matchesAny(p, globs = []) {
  return globs.some((g) => globToRegExp(g).test(p));
}

/**
 * Refuse a contract whose ignorable rules reach into runtime code.
 *
 * This is the anti-self-approval guard. `ignorable` is the only input that can
 * cause Watson to skip, so it is the only input worth attacking: add
 * `client/src/**` to it and every future change to the client goes unverified.
 * The engine therefore checks the rules themselves rather than trusting that
 * whoever edited them meant well. Runtime roots are structural — where the
 * product's executable code lives — and nothing there is ever ignorable.
 */
/** The literal prefix of a glob, up to its first wildcard. `client/src/**` → `client/src/`. */
function literalPrefix(glob) {
  const i = glob.search(/[*?]/);
  return i < 0 ? glob : glob.slice(0, i);
}

/**
 * Concrete paths to test a rule against, built from a runtime root.
 *
 * Deciding glob intersection symbolically is fiddly and easy to get subtly
 * wrong, so this decides it by construction instead: build paths the runtime
 * root definitely claims, then ask whether the ignorable rule also claims one.
 *
 * The generic tails alone would be evadable — a rule crafted around whichever
 * extensions we happened to pick would slip through — so the rule's OWN final
 * segment is materialised as a tail too (`*.snap` → `a.snap`). A rule can only
 * reach under the root by using tokens that appear in it, and those tokens are
 * exactly what gets probed.
 */
function witnessPaths(rule, root) {
  const prefix = literalPrefix(root);
  const ruleTail = rule.split('/').pop().replace(/\*\*/g, 'a').replace(/[*?]/g, 'a') || 'a';
  const tails = ['a', 'a.ts', 'a.tsx', 'a/b', 'a/b/c.ts', ruleTail, `a/${ruleTail}`, `a/b/${ruleTail}`];
  const rootRe = globToRegExp(root);
  return tails.map((t) => prefix + t).filter((p) => rootRe.test(p));
}

/**
 * Refuse a contract whose ignorable rules reach into runtime code.
 *
 * This is the anti-self-approval guard. `ignorable` is the only input that can
 * cause Watson to skip, so it is the only input worth attacking: add
 * `client/src/**` to it and every future change to the client goes unverified.
 * The engine therefore checks the rules themselves rather than trusting that
 * whoever edited them meant well. Runtime roots are structural — where the
 * product's executable code lives — and nothing there is ever ignorable.
 *
 * It errs toward refusing: a rule that could match anything under a runtime root
 * is rejected even if the author meant something narrower. The cost of a refusal
 * is one rewritten rule; the cost of a miss is silent non-verification.
 */
export function assertIgnorableRules(ignorable = [], runtimeRoots = [], governingRoots = []) {
  const offending = [];
  const families = [
    ['runtime root', runtimeRoots],
    ['governing-contract root', governingRoots],
  ];
  for (const rule of ignorable) {
    const ruleRe = globToRegExp(rule);
    for (const [kind, roots] of families) {
      for (const root of roots) {
        const witness = witnessPaths(rule, root).find((p) => ruleRe.test(p));
        if (witness) offending.push({ rule, kind, root, witness });
      }
    }
  }
  if (offending.length) {
    const detail = offending
      .map((o) => `\`${o.rule}\` reaches ${o.kind} \`${o.root}\` (e.g. ${o.witness})`)
      .join('; ');
    throw new Error(
      `selection.ignorable may not cover runtime or governing-contract paths — ${detail}. ` +
      'An ignorable rule is the only way a change can go unverified, so it may never reach ' +
      'executable product code, nor the documents that define what Watson is expected to prove. ' +
      'A broad ignore pattern must never override a runtime, ADR, requirement, or Watson-contract ' +
      'signal.',
    );
  }
}

/**
 * Which features claim this path through their declared `source_globs`?
 *
 * Only `mapped` features count. A draft or retired feature's claim is a note of
 * intent, not a verification capability — treating it as one would let a path be
 * classified as covered while nothing runnable covers it, which is a silent skip
 * wearing an applicable label.
 */
function featuresClaiming(p, features) {
  return features
    .filter((f) => f.status === 'mapped' && matchesAny(p, f.source_globs ?? []))
    .map((f) => f.id);
}

/**
 * Which features declare the ADR this path is? An ADR change can move the
 * expectation without moving a line of code, so features that cite it are
 * selected. `docs/adr/ADR-041-....md` → `ADR-041`.
 */
function featuresGovernedBy(p, features, adrDir) {
  if (!p.startsWith(`${adrDir}/`)) return null;
  const m = /(ADR-\d+)/.exec(p.slice(adrDir.length + 1));
  if (!m) return null;
  const id = m[1];
  const citing = features.filter((f) => f.status === 'mapped' && (f.adrs ?? []).includes(id));
  return { adr: id, features: citing.map((f) => f.id) };
}

export function classifyPath(p, {
  features = [], ignorable = [], crossCutting = [], runtimeRoots = [], governingRoots = [],
  adrDir = 'docs/adr',
} = {}) {
  // Cross-cutting is checked FIRST and beats a source_globs match. A migration
  // that some feature happens to claim still changes the schema every other
  // journey reads; narrowing to the claiming feature would be the wrong answer.
  if (matchesAny(p, crossCutting)) {
    return { path: p, class: CLASS.CROSS_CUTTING, reason: 'declared cross-cutting', features: [] };
  }

  // Governing-contract paths: documents that define what Watson is expected to
  // prove, or the contract by which it proves it. They are not executable, which
  // is exactly why a blanket `docs/**` ignore would swallow them — and a changed
  // ADR or requirement can move the expected behaviour without moving a line of
  // code. The question is not "is this file runnable?" but "does this file define
  // what running proves?"
  if (matchesAny(p, governingRoots)) {
    const governed = featuresGovernedBy(p, features, adrDir);
    if (governed?.features.length) {
      // The ADR resolves to features that cite it: verify exactly those.
      return {
        path: p,
        class: CLASS.GOVERNANCE,
        reason: `${governed.adr} governs ${governed.features.length} mapped feature(s)`,
        features: governed.features,
      };
    }
    // A governing document that maps to nothing. This is the dangerous case, not
    // the harmless one: "no feature cites this" is at least as likely to mean the
    // map has not caught up with a new ADR or requirement as it is to mean the
    // change is irrelevant. Escalate — a governing change is never skippable.
    return {
      path: p,
      class: CLASS.GOVERNING,
      reason: governed
        ? `${governed.adr} is cited by no mapped feature — the map may not have caught up`
        : 'governing-contract path with no feature mapping',
      features: [],
    };
  }

  const claimed = featuresClaiming(p, features);
  if (claimed.length) {
    return { path: p, class: CLASS.MAPPED, reason: 'claimed by source_globs', features: claimed };
  }

  // Runtime code that nothing claims. Watson cannot prove this is irrelevant —
  // the feature map's silence about a file is not evidence about that file.
  if (matchesAny(p, runtimeRoots)) {
    return { path: p, class: CLASS.UNMAPPED_RUNTIME, reason: 'runtime code claimed by no feature', features: [] };
  }

  if (matchesAny(p, ignorable)) {
    return { path: p, class: CLASS.IGNORABLE, reason: 'declared non-runtime', features: [] };
  }

  // Nothing recognised it. A new top-level directory, a build input nobody
  // anticipated, a file type the rules predate. Escalate.
  return { path: p, class: CLASS.UNCLASSIFIED, reason: 'matched no selection rule', features: [] };
}

/**
 * Turn a diff into a selection.
 *
 * `changedPaths` of null means "no diff could be computed" — no base SHA, an
 * unreadable base, a first commit. That is an absence of knowledge, and it falls
 * back to the declared profile. It must never become a skip: the one thing worse
 * than running every journey is running none because we could not tell.
 */
export function selectByImpact({
  features = [],
  changedPaths = null,
  profile,
  escalationProfile = 'smoke',
  rules = {},
} = {}) {
  const {
    ignorable = [], cross_cutting: crossCutting = [], runtime_roots: runtimeRoots = [],
    governing_roots: governingRoots = [], adr_dir: adrDir = 'docs/adr',
  } = rules;

  assertIgnorableRules(ignorable, runtimeRoots, governingRoots);

  const mapped = (ids) => features.filter((f) => ids.includes(f.id));
  const inProfile = (name) => features.filter((f) => f.status === 'mapped' && (f.profiles ?? []).includes(name));

  if (changedPaths === null || changedPaths === undefined) {
    return {
      method: 'profile',
      applicable: true,
      // Pre-D1 vocabulary, corrected. `changedPaths` no longer takes SHAs, so
      // null now means "no trusted base/head tree pair to compare", not "no base
      // SHA" — a run can carry a perfectly good base SHA and still land here
      // because the trusted base materialisation was absent or unreadable.
      reason: 'no trustworthy base→head diff — falling back to profile selection',
      features: inProfile(profile),
      classifications: [],
      escalated: false,
      escalation_reasons: [],
    };
  }

  if (changedPaths.length === 0) {
    // An empty diff is a real, positive fact: base and head are the same tree.
    return {
      method: 'impact',
      applicable: false,
      reason: 'no files changed between base and head',
      features: [],
      classifications: [],
      escalated: false,
      escalation_reasons: [],
    };
  }

  const classifications = changedPaths.map((p) =>
    classifyPath(p, { features, ignorable, crossCutting, runtimeRoots, governingRoots, adrDir }));

  const escalating = classifications.filter((c) => ESCALATING.has(c.class));
  if (escalating.length) {
    return {
      method: 'impact',
      applicable: true,
      reason: `escalated to \`${escalationProfile}\` — ${escalating.length} change(s) whose impact could not be bounded`,
      features: inProfile(escalationProfile),
      classifications,
      escalated: true,
      escalation_reasons: escalating.map((c) => `${c.path}: ${c.reason} (${c.class})`),
    };
  }

  const selectedIds = [...new Set(classifications.flatMap((c) => c.features))];
  if (selectedIds.length) {
    const runnable = mapped(selectedIds).filter((f) => f.status === 'mapped');
    // Defence in depth. `featuresClaiming` already refuses non-mapped features, so
    // this should be unreachable; if some future path around it selects ids that
    // resolve to nothing runnable, escalate rather than return an empty run that
    // would report "applicable" while verifying nothing.
    if (!runnable.length) {
      return {
        method: 'impact',
        applicable: true,
        reason: `escalated to \`${escalationProfile}\` — selected features resolved to nothing runnable`,
        features: inProfile(escalationProfile),
        classifications,
        escalated: true,
        escalation_reasons: [`selected ${selectedIds.join(', ')} but none is a runnable mapped feature`],
      };
    }
    return {
      method: 'impact',
      applicable: true,
      reason: `${runnable.length} feature(s) claim the changed paths`,
      features: runnable,
      classifications,
      escalated: false,
      escalation_reasons: [],
    };
  }

  // Every changed path was positively established as unable to affect the
  // running product, and none of them moved an expectation any feature cites.
  // This is the ONLY route to NOT_APPLICABLE.
  return {
    method: 'impact',
    applicable: false,
    reason: `all ${classifications.length} changed path(s) positively established as non-runtime`,
    features: [],
    classifications,
    escalated: false,
    escalation_reasons: [],
  };
}
