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
import { verifyAgainstManifest } from './manifest.mjs';

// ---------------------------------------------------------------- safe git --
//
// Git is not a pure reader of a repository. Several configuration keys name
// COMMANDS that git executes while doing ordinary work, and they can be set in a
// repository's own `.git/config` — which, for a product checkout, is a file the
// product writes. `core.fsmonitor` is the sharpest: git runs it during
// `git status`, ignores its exit code, and carries on. One line in an install
// script turns the verifier's own exactness check into arbitrary code execution
// as the verifier.
//
// Demonstrated, not theorised:
//
//     git config core.fsmonitor /tmp/payload.sh
//     -> workingTreeState() returns {clean: true} … and the payload ran as uid 0
//
// So every git invocation in this engine goes through here. Command-line `-c`
// has the highest precedence in git's configuration order, so these win over the
// repository config and over anything it `include`s. The environment settings
// remove the system and global files from the picture entirely.
//
// WHY THIS SURVIVED THE MANIFEST. Product identity no longer runs git at all, so
// the wrapper is not what defends it. But git is still used for things the
// manifest does not answer — resolving a ref, the merge-base diff that drives
// selection, the tree hashes behind the fingerprints, and reading the contract
// at the base commit — and several of those still run with the product's
// directory as `cwd`. Those are the calls this protects, and that is the whole
// of its remaining job.
//
// It is defence in depth even there: a deny-list of command-valued keys cannot
// be complete, because content filters are named by the product's own
// `.gitattributes`. What makes that acceptable is that every call which runs on
// the TRUSTED side is an object-store operation — `rev-parse`, `ls-tree`,
// `merge-base`, `diff --name-only`, `archive` — and never reads the working
// tree in a filter-applying way. If a trusted-side call starts reading the
// working tree, this stops being true and that call needs a different answer,
// not another key in the list.
//
// The one exception is deliberate and is not on the trusted side: the plane's
// `/alive` runs `rev-parse HEAD` and `status --porcelain` (`plane.mjs`). That is
// inside the product's own container, reporting on the product's own checkout,
// where product code already runs by design — so hijacking it buys an attacker
// nothing they do not already have, and the verifier treats the answer as
// self-reported either way. It goes through this wrapper because there is no
// reason for it not to, NOT because the wrapper is what makes it safe.

const SAFE_CONFIG = [
  'core.fsmonitor=',            // a command git runs during `git status`
  'core.hooksPath=/dev/null',   // hooks git runs on many operations
  'core.pager=cat',
  'core.editor=true',
  'core.askPass=',
  'core.sshCommand=',
  'diff.external=',             // a command git runs to produce diffs
  'credential.helper=',
  'uploadpack.packObjectsHook=',
  'protocol.ext.allow=never',
  'protocol.file.allow=never',
  // `refs/replace/` lives inside the .git the product owns, and git resolves
  // objects through it by default. Without this, three product-authored lines
  // make `ls-tree` return a tree the author wrote while `rev-parse HEAD` still
  // reports the reviewed commit — arbitrary content at exact_head: true.
  'core.useReplaceRefs=false',
].flatMap((kv) => ['-c', kv]);

const SAFE_ENV = {
  GIT_CONFIG_NOSYSTEM: '1',
  // Belt and braces with `core.useReplaceRefs=false` above.
  GIT_NO_REPLACE_OBJECTS: '1',
  GIT_TERMINAL_PROMPT: '0',
  GIT_ASKPASS: '',
  GIT_OPTIONAL_LOCKS: '0',
};

// DELIBERATELY NOT SET: GIT_CONFIG_GLOBAL=/dev/null.
//
// It looks like more hardening and is the opposite. The global config belongs to
// the VERIFIER, not to the product, so it is not part of the attack surface —
// and it is the only place `safe.directory` can be set, which is exactly what
// makes a checkout owned by another uid readable at all. Discarding it turns
// the intended topology (the product writes the tree, the verifier reads it)
// into `clean: null` on every run, and therefore INDETERMINATE forever.
//
// What actually blocks the attack is the `-c` overrides above: command-line
// config outranks the repository's own, which is where a hostile setting lives.
// `safe.directory` is ignored from `-c` by git on purpose, so there is no way to
// re-add it here — the global file has to stay in the picture.

/** Run git against a repository that may be hostile. */
export function git(args, { cwd, encoding = 'utf8', maxBuffer = 64 * 1024 * 1024, stdio } = {}) {
  return execFileSync('git', [...SAFE_CONFIG, ...args], {
    cwd,
    encoding,
    maxBuffer,
    ...(stdio ? { stdio } : {}),
    env: { ...process.env, ...SAFE_ENV },
  });
}


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
    return git(['rev-parse', `${sha}:${p}`],
      { cwd: repoRoot, stdio: ['ignore', 'pipe', 'ignore'] }).trim();
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
 * Product identity, from the trusted manifest.
 *
 * WHAT REPLACED WHAT, and why the replacement is not another patch.
 *
 * This used to hash the working tree against the commit's object tree, and
 * before that it read `git status`. Three adversarial reviews found four ways
 * past those, and every one had the same shape: the check asked a directory the
 * product writes — whose `.git` the product owns — to describe itself.
 * `--assume-unchanged`, `git replace`, `git add`, a corrupt index, a self-hiding
 * `.gitignore`. Patching each answer never changed who was answering.
 *
 * The expectation now comes from `src/manifest.mjs`, written by the trusted
 * orchestration from the trusted commit before any product code runs. Nothing
 * here consults the product's `.git` at all.
 *
 * NO MANIFEST, NO PRODUCT CLAIM. A run that was not given one cannot establish
 * identity, and says so rather than falling back to asking git — the fallback
 * WAS the vulnerability. It costs a command locally (`watson manifest`) and buys
 * the property that there is exactly one authority for product source identity.
 *
 * The shape of the return value is unchanged so that consumers reading
 * `working_tree.exact_head` keep working; `method` says which authority spoke.
 */
export function productIdentity({ repoRoot, manifest = null, expectedSha = null, generatedRoots = [] }) {
  if (!manifest) {
    return {
      clean: null, exact_head: false, dirty_paths: [], dirty_count: 0, contract_dirty: false,
      head_sha: null, expected_sha: expectedSha, head_matches: null, method: 'no-manifest',
      note: 'no trusted manifest was supplied, so product identity cannot be established. '
        + 'Build one with `watson manifest` from a checkout the product has not run in.',
    };
  }

  const headMatches = expectedSha ? manifest.sha === expectedSha : null;
  if (headMatches === false) {
    return {
      clean: null, exact_head: false, dirty_paths: [], dirty_count: 0, contract_dirty: false,
      head_sha: manifest.sha, expected_sha: expectedSha, head_matches: false, method: 'manifest',
      note: `the manifest describes ${manifest.sha}, but this run is about ${expectedSha}`,
    };
  }

  let result;
  try {
    result = verifyAgainstManifest(repoRoot, manifest, { generatedRoots });
  } catch (err) {
    return {
      clean: null, exact_head: false, dirty_paths: [], dirty_count: 0, contract_dirty: false,
      head_sha: manifest.sha, expected_sha: expectedSha, head_matches: headMatches, method: 'failed',
      note: `the product tree could not be compared against the manifest: ${err.message.slice(0, 200)}`,
    };
  }

  const contractDirty = result.divergent.some((p) => p.startsWith('.watson/'));
  return {
    clean: result.matches,
    exact_head: result.matches && headMatches !== false,
    dirty_paths: result.divergent.slice(0, 20),
    dirty_count: result.divergent.length,
    // WHAT WAS EXEMPTED, and how much. `generated_roots` is read from the
    // PRODUCT's own `.watson/config.yaml`, so a pull request declaring
    // `- server/src` can have its build write new source files that this check
    // then reports as no divergence at all. That is a real hole (watson#7 C1)
    // and it is not closed by recording it — but it WAS previously invisible:
    // the result carried the integer `counts.generated` and not one root name,
    // and the summary printed identity detail only on an inexact head. A reader
    // could not see that anything had been exempted, let alone what. Recorded
    // here so the hole is at least legible while its governance is decided.
    generated_roots: result.generated_roots ?? [],
    generated_count: result.counts?.generated ?? 0,
    contract_dirty: contractDirty,
    head_sha: manifest.sha,
    expected_sha: expectedSha,
    head_matches: headMatches,
    method: 'manifest',
    counts: result.counts,
    note: result.matches
      ? 'the product tree matches the trusted manifest for the reported commit'
      : contractDirty
        ? 'the CONTRACT differs from the trusted manifest — this run verified something else'
        : 'the product tree differs from the trusted manifest for the reported commit',
  };
}

/**
 * Full 40-char lowercase hex, as the marker protocol requires.
 *
 * A value that is ALREADY a full commit id is returned as given, and git is
 * never consulted. The trusted orchestration knows which commit it materialised
 * — that is what the run is about — and the tree it hands over is supposed to
 * need no `.git` at all. Asking git anyway made the documented topology
 * impossible to run:
 *
 *     $ watson verify --repo <materialised tree> --sha <40 hex>
 *     fatal: not a git repository
 *
 * It worked in CI only because that particular tree happens to be a checkout.
 * Found by materialising a commit the way the design describes and running the
 * engine against it, which no unit test does.
 *
 * This is not a new authority: a full SHA comes from the caller, and where a
 * manifest is supplied the manifest is still what proves the tree IS that
 * commit. It only stops the engine consulting a product-owned `.git` for a fact
 * it was already told.
 */
export function resolveSha(repoRoot, ref = 'HEAD') {
  if (/^[0-9a-f]{40}$/.test(ref)) return ref;
  const sha = git(['rev-parse', ref], { cwd: repoRoot }).trim();
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
    const mergeBase = git(['merge-base', baseSha, headSha], {
      cwd: repoRoot, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'],
    }).trim();
    const out = git(['diff', '--name-only', '-z', `${mergeBase}`, headSha], {
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
  const run = (args) => git(args, {
    cwd: engineRoot, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'],
  }).trim();
  try {
    const commit = run(['rev-parse', 'HEAD']);
    if (!/^[0-9a-f]{40}$/.test(commit)) return { commit: null, clean: null };
    return { commit, clean: run(['status', '--porcelain']) === '' };
  } catch {
    // No git, or the engine was installed as a plain directory. Honest silence.
    return { commit: null, clean: null };
  }
}
