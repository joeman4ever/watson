// Exact-HEAD identity.
//
// PHASE 0/1 POLICY: fingerprints are ALWAYS computed and recorded, and are
// NEVER consulted to carry a prior HEAD's PASS forward onto a new HEAD. A new
// HEAD is always re-verified. The cost saving is real but bounded; a single
// mis-classified runtime-relevant path would produce a FALSE PASS, which is the
// one failure this system cannot afford while it is still earning trust.
//
// They are recorded now so that a later phase can evaluate the carry-forward
// entry criteria on evidence rather than on assumption.

import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';

/** Paths whose contents can change RUNTIME behavior of the product. */
const PRODUCT_PATHS = [
  'client',
  'server',
  'package.json',
  'package-lock.json',
  'playwright.config.ts',
];

const CONTRACT_PATHS = ['.watson'];

function treeHash(repoRoot, sha, p) {
  try {
    return execFileSync('git', ['rev-parse', `${sha}:${p}`],
      { cwd: repoRoot, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
  } catch {
    return 'absent';
  }
}

function digest(repoRoot, sha, paths) {
  const h = crypto.createHash('sha256');
  for (const p of paths) h.update(`${p}\0${treeHash(repoRoot, sha, p)}\0`);
  return `sha256:${h.digest('hex')}`;
}

export function productFingerprint(repoRoot, sha) {
  return digest(repoRoot, sha, PRODUCT_PATHS);
}

export function contractFingerprint(repoRoot, sha) {
  return digest(repoRoot, sha, CONTRACT_PATHS);
}

/**
 * Whether the checkout matches the commit it claims to be.
 *
 * This matters more than it looks. Every result carries a 40-char SHA and two
 * fingerprints computed FROM GIT — but the contract that executes, and the product
 * that gets built and launched, both come from the WORKING TREE. When the tree is
 * dirty those are different things, and the run reports a SHA it did not actually
 * verify.
 *
 * That is not hypothetical: during the Phase-1 campaign a feature file written while
 * a campaign was running was picked up mid-campaign, so runs 1-3 verified two
 * journeys and runs 4-10 verified three, all reporting the same SHA.
 *
 * Watson does not refuse a dirty tree — developing against one is the normal way to
 * work — but it must never claim exact-HEAD when it cannot honour it.
 */
export function workingTreeState(repoRoot) {
  let porcelain = '';
  try {
    porcelain = execFileSync('git', ['status', '--porcelain'], {
      cwd: repoRoot, encoding: 'utf8', maxBuffer: 16 * 1024 * 1024,
    });
  } catch {
    return { clean: null, exact_head: false, dirty_paths: [], contract_dirty: false,
      note: 'git status failed; exact-HEAD cannot be established' };
  }
  const paths = porcelain.split('\n').map((l) => l.slice(3).trim()).filter(Boolean);
  const contractDirty = paths.some((p) => p.startsWith('.watson/'));
  return {
    clean: paths.length === 0,
    exact_head: paths.length === 0,
    dirty_paths: paths.slice(0, 20),
    dirty_count: paths.length,
    contract_dirty: contractDirty,
    note: paths.length === 0
      ? 'checkout matches the reported SHA'
      : contractDirty
        ? 'the CONTRACT differs from the reported SHA — this run verified something else'
        : 'the product tree differs from the reported SHA',
  };
}

/** Full 40-char lowercase hex, as the marker protocol requires. */
export function resolveSha(repoRoot, ref = 'HEAD') {
  const sha = execFileSync('git', ['rev-parse', ref], { cwd: repoRoot, encoding: 'utf8' }).trim();
  if (!/^[0-9a-f]{40}$/.test(sha)) throw new Error(`resolved ref is not a full 40-char hex SHA: ${sha}`);
  return sha;
}

/**
 * Base -> head semantic diff of the CONTRACT. Phase 0 REPORTS this; it does not
 * gate on it. The purpose is that a PR must not be able to weaken its own
 * verification expectation and thereby silently manufacture its own PASS.
 *
 * Returns null when the contract did not change.
 */
export function contractChange(repoRoot, baseSha, headSha, loadAt) {
  if (!baseSha) return null;
  if (contractFingerprint(repoRoot, baseSha) === contractFingerprint(repoRoot, headSha)) return null;

  const base = loadAt(baseSha);
  const head = loadAt(headSha);
  if (!base) return { model: 'head-product-x-head-contract', base_contract_available: false };

  const baseById = new Map(base.features.map((f) => [f.id, f]));
  const headById = new Map(head.features.map((f) => [f.id, f]));

  const added = [...headById.keys()].filter((id) => !baseById.has(id));
  const removed = [...baseById.keys()].filter((id) => !headById.has(id));
  const weakened = [];

  for (const [id, h] of headById) {
    const b = baseById.get(id);
    if (!b) continue;
    const bSteps = (b.steps ?? []).length;
    const hSteps = (h.steps ?? []).length;
    if (hSteps < bSteps) weakened.push({ id, why: `steps reduced ${bSteps} -> ${hSteps}` });
    if (b.status === 'mapped' && h.status !== 'mapped') {
      weakened.push({ id, why: `status ${b.status} -> ${h.status} (no longer verified)` });
    }
    const bProfiles = new Set(b.profiles ?? []);
    const dropped = [...bProfiles].filter((p) => !(h.profiles ?? []).includes(p));
    if (dropped.length) weakened.push({ id, why: `dropped from profile(s): ${dropped.join(', ')}` });
  }

  // Invariants are the other half of the contract, and the cheaper thing to weaken:
  // turning a detector off, or downgrading it, removes an expectation without
  // touching a single feature file.
  const bInv = new Map((base.invariants ?? []).map((i) => [i.rule, i]));
  const hInv = new Map((head.invariants ?? []).map((i) => [i.rule, i]));
  for (const [rule, b] of bInv) {
    const h = hInv.get(rule);
    if (!h) {
      weakened.push({ id: `invariant:${rule}`, why: 'invariant removed from the contract' });
      continue;
    }
    if (h.severity === 'off' && b.severity !== 'off') {
      weakened.push({ id: `invariant:${rule}`, why: `severity ${b.severity} -> off (detector disabled)` });
    } else if (b.severity === 'blocking' && h.severity === 'advisory') {
      weakened.push({ id: `invariant:${rule}`, why: 'severity blocking -> advisory' });
    }
    const newExcept = (h.except_features ?? []).filter((f) => !(b.except_features ?? []).includes(f));
    if (newExcept.length) {
      weakened.push({ id: `invariant:${rule}`, why: `newly excepted feature(s): ${newExcept.join(', ')}` });
    }
    // Narrowing an allowlist narrows where the rule runs, which is also a weakening.
    const bOnly = b.applies_to_features;
    const hOnly = h.applies_to_features;
    if (Array.isArray(hOnly) && hOnly.length && !(Array.isArray(bOnly) && bOnly.length)) {
      weakened.push({ id: `invariant:${rule}`, why: `scope narrowed to only: ${hOnly.join(', ')}` });
    } else if (Array.isArray(bOnly) && Array.isArray(hOnly)) {
      const lost = bOnly.filter((f) => !hOnly.includes(f));
      if (lost.length) weakened.push({ id: `invariant:${rule}`, why: `no longer applies to: ${lost.join(', ')}` });
    }
  }
  const invariantsAdded = [...hInv.keys()].filter((r) => !bInv.has(r));

  return {
    model: 'head-product-x-head-contract',
    base_contract_available: true,
    features_added: added,
    features_removed: removed,
    invariants_added: invariantsAdded,
    expectations_weakened: weakened,
    // Populated only once a run has results to compare against; see result.mjs.
    changed_sign: [],
  };
}

/**
 * Files changed between base and head, as repo-relative paths.
 *
 * Uses the merge base rather than a straight `base..head` comparison, so that
 * commits which merely arrived on the base branch after this branch was cut are
 * not attributed to this change. Attributing them would inflate every diff on a
 * long-lived branch and, worse, make selection depend on when someone last
 * merged rather than on what this change actually does.
 *
 * Returns null — never an empty list — when the diff cannot be computed. Callers
 * must treat null as "no knowledge" and refuse to skip on it; an empty array is
 * the positive fact that the two trees are identical.
 */
export function changedPaths(repoRoot, baseSha, headSha) {
  if (!baseSha || !headSha) return null;
  try {
    const mergeBase = execFileSync('git', ['merge-base', baseSha, headSha], {
      cwd: repoRoot, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'],
    }).trim();
    const out = execFileSync('git', ['diff', '--name-only', '-z', `${mergeBase}`, headSha], {
      cwd: repoRoot, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'],
    });
    return out.split('\0').filter(Boolean);
  } catch {
    // An unreachable base, a shallow clone with no common ancestor, a bad ref.
    return null;
  }
}

/**
 * The engine's OWN commit and tree state.
 *
 * A result records which product revision was verified; without this it does not
 * record which VERIFIER produced that judgement. Those are different facts, and
 * the second one decays fastest — an engine changes, and an observation recorded
 * months earlier silently starts meaning something slightly different to whoever
 * reads it.
 *
 * `clean` matters as much as the SHA. An engine running with local modifications
 * is not the commit it names, for exactly the reason a dirty product checkout is
 * not the revision it claims (ADR-039 D7). A SHA reported from a modified tree
 * would be a more convincing lie than no SHA at all, so the two travel together.
 *
 * Returns nulls rather than throwing: not knowing the engine's provenance must
 * never stop a verification, only be recorded honestly.
 */
export function engineProvenance(engineRoot) {
  const git = (args) => execFileSync('git', args, {
    cwd: engineRoot, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'],
  }).trim();
  try {
    const commit = git(['rev-parse', 'HEAD']);
    if (!/^[0-9a-f]{40}$/.test(commit)) return { commit: null, clean: null };
    return { commit, clean: git(['status', '--porcelain']) === '' };
  } catch {
    // No git, or the engine was installed as a plain directory. Honest silence.
    return { commit: null, clean: null };
  }
}
