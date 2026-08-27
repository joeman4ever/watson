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

  return {
    model: 'head-product-x-head-contract',
    base_contract_available: true,
    features_added: added,
    features_removed: removed,
    expectations_weakened: weakened,
    // Populated only once a run has results to compare against; see result.mjs.
    changed_sign: [],
  };
}
