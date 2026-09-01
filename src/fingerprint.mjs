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
import fs from 'node:fs';
import path from 'node:path';

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
// This is defence in depth, not the whole defence: a deny-list of
// command-valued keys cannot be complete (content filters, for one, are named
// by the product's own `.gitattributes`). The identity check therefore does not
// rely on it — see `workingTreeState`, which stopped using git's working-tree
// machinery altogether.

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
 *
 * CLEANLINESS IS NOT IDENTITY. `git status` proves only that the tree matches
 * whatever HEAD currently points at — it says nothing about WHICH commit that is.
 * A tree that is modified and then committed is perfectly clean at a commit nobody
 * reviewed, and the gate as originally written would have called that exact-HEAD
 * and let a PASS through for the reported SHA.
 *
 * That is not a theoretical gap. Watson runs the product's own install, build and
 * launch commands from this checkout, so under a threat model where product code
 * may be hostile, `git commit -a` is a one-line forgery of the exact-HEAD property
 * — the single property every product claim rests on. So identity is checked
 * positively, against the SHA the caller says this run is about, and a mismatch is
 * inexact for the same reason dirt is: the run cannot speak for that commit.
 */
export function workingTreeState(repoRoot, expectedSha = null) {
  let head = null;
  try {
    head = git(['rev-parse', 'HEAD'], { cwd: repoRoot }).trim();
  } catch {
    return {
      clean: null, exact_head: false, dirty_paths: [], dirty_count: 0, contract_dirty: false,
      head_sha: null, expected_sha: expectedSha, head_matches: null, method: 'unavailable',
      note: 'git could not be run here; exact-HEAD cannot be established',
    };
  }

  // `null` when the caller named no expectation: unknown, and unknown is not a
  // failure. `false` is a positive contradiction and is fatal to any product claim.
  const headMatches = expectedSha ? head === expectedSha : null;
  const against = expectedSha ?? head;

  let diverged;
  try {
    diverged = divergedPaths(repoRoot, against);
  } catch (err) {
    return {
      clean: null, exact_head: false, dirty_paths: [], dirty_count: 0, contract_dirty: false,
      head_sha: head, expected_sha: expectedSha, head_matches: headMatches, method: 'failed',
      note: `the working tree could not be compared against ${against}: ${err.message.slice(0, 200)}`,
    };
  }

  // Content hashing covers paths that are IN THE COMMIT. Two other kinds of file
  // change how the product behaves without appearing there, and each needs its
  // own source:
  //
  //   untracked — never added. `ls-files --others`.
  //   STAGED    — added but not committed. `ls-files --cached`, compared against
  //               the commit tree.
  //
  // The second was a hole, and a regression against the `git status` check this
  // replaced. "Others" means "not in the index", so `git add server/evil.js`
  // removed the file from the untracked listing while it was never in the commit
  // tree either — invisible to both halves at once, from one word.
  //
  // The union is not defence in depth against an attacker: every source here
  // reads the same product-owned `.git`. It is coverage. What resists tampering
  // is the content hash, which asks git for the commit's tree and nothing else.
  const untracked = untrackedPaths(repoRoot);
  const staged = stagedButUncommitted(repoRoot, against);
  const all = [...new Set([...diverged, ...untracked, ...staged])].sort();

  const contractDirty = all.some((p) => p.startsWith('.watson/'));
  const clean = all.length === 0;
  return {
    clean,
    exact_head: clean && headMatches !== false,
    dirty_paths: all.slice(0, 20),
    dirty_count: all.length,
    tracked_diverged: diverged.length,
    untracked: untracked.length,
    contract_dirty: contractDirty,
    head_sha: head,
    expected_sha: expectedSha,
    head_matches: headMatches,
    method: 'content-hash',
    note: headMatches === false
      ? `the checkout is at ${head}, not the reported ${expectedSha} — this run verified a different commit`
      : clean
        ? 'checkout matches the reported SHA'
        : contractDirty
          ? 'the CONTRACT differs from the reported SHA — this run verified something else'
          : 'the product tree differs from the reported SHA',
  };
}

/**
 * Which tracked paths differ, in CONTENT, between the commit and what is on disk.
 *
 * This deliberately does not use `git status`, `git diff` or the index, and that
 * is the whole point of it.
 *
 * The index belongs to the product. `git update-index --assume-unchanged <path>`
 * tells git to stop comparing that path, permanently, and `--skip-worktree` does
 * the same. Neither moves HEAD, neither leaves the tree dirty, and both are one
 * line in an install script:
 *
 *     git update-index --assume-unchanged server/index.js
 *     echo 'whatever the author wants to run' > server/index.js
 *
 * Against a `git status` check that reads clean, `head_matches` reads true, and
 * a PASS is issued for a commit that was never run. Demonstrated on this engine
 * before it was fixed.
 *
 * So identity is established from the commit's own object tree — read with
 * plumbing that consults no index, and with replace refs disabled — and from the
 * bytes on disk, hashed here. No content filter, fsmonitor, assume-unchanged bit
 * or replacement object takes part in THIS comparison.
 *
 * Stated precisely, because the previous version of this comment overreached:
 * the index does take part elsewhere, in the staged-path listing beside this,
 * and the product's ignore rules decide what counts as untracked. Neither can
 * make a path that IS in the commit look unmodified — that is what this function
 * guarantees, and it is the whole of what it guarantees.
 */
export function divergedPaths(repoRoot, sha) {
  // `-z` because paths may contain anything; `-r` to recurse into subtrees.
  const raw = git(['ls-tree', '-r', '-z', sha], { cwd: repoRoot });
  const diverged = [];

  for (const entry of raw.split('\0')) {
    if (!entry) continue;
    // "<mode> <type> <object>\t<path>"
    const tab = entry.indexOf('\t');
    if (tab < 0) continue;
    const [mode, type, object] = entry.slice(0, tab).split(/\s+/);
    const rel = entry.slice(tab + 1);
    // A gitlink (`160000 commit`) is not a blob, so there is nothing to hash —
    // but the directory it names has working-tree content all the same, and
    // skipping it left an entire subtree unmeasured. A pull request that moves
    // runtime code into a submodule would verify as exact-HEAD whatever is on
    // disk there.
    //
    // Refusing is the honest answer while nothing here uses submodules: Watson
    // says it cannot establish identity rather than quietly establishing it for
    // part of the tree. Measuring them properly means recursing into each
    // submodule's own object store, which is a real change and belongs with a
    // product that actually has one.
    if (type === 'commit') { diverged.push(`${rel} (submodule — content not measurable)`); continue; }
    if (type !== 'blob') continue;

    const abs = path.join(repoRoot, rel);
    let actual;
    try {
      // A symlink's content, to git, is its target — never what it points at.
      // Following it would let a link into /etc read as an unmodified file.
      const st = fs.lstatSync(abs);
      const bytes = st.isSymbolicLink()
        ? Buffer.from(fs.readlinkSync(abs))
        : fs.readFileSync(abs);
      actual = blobHash(bytes);
      // A tracked regular file replaced by a symlink, or vice versa, is a change
      // even when the bytes coincide.
      const isLink = st.isSymbolicLink();
      if (isLink !== (mode === '120000')) { diverged.push(rel); continue; }
    } catch {
      diverged.push(rel);   // missing or unreadable: divergent either way
      continue;
    }
    if (actual !== object) diverged.push(rel);
  }
  return diverged;
}

/**
 * Untracked, non-ignored paths. Best-effort by construction: the ignore rules
 * come from the product's own `.gitignore`, so a file the product chooses to
 * ignore is invisible here. That is a known limit, not an oversight — a change
 * that hides itself in an ignored path is caught, if at all, by the fact that
 * the commit's own tracked content still has to match.
 */
function untrackedPaths(repoRoot) {
  try {
    return git(['ls-files', '--others', '--exclude-standard', '-z'], { cwd: repoRoot })
      .split('\0').filter(Boolean);
  } catch {
    return [];
  }
}

/**
 * Paths the index carries that the commit does not — `git add`ed and not
 * committed.
 *
 * Its own ignore rules do not apply: `git add` is an explicit act, so a path
 * here was deliberately staged and is deliberately not in the reviewed commit.
 */
function stagedButUncommitted(repoRoot, sha) {
  try {
    const cached = git(['ls-files', '--cached', '-z'], { cwd: repoRoot })
      .split('\0').filter(Boolean);
    const inCommit = new Set(
      git(['ls-tree', '-r', '-z', '--name-only', sha], { cwd: repoRoot })
        .split('\0').filter(Boolean),
    );
    return cached.filter((p) => !inCommit.has(p));
  } catch {
    return [];
  }
}

/** git's object id for a blob: sha1("blob <len>\0" + content). */
function blobHash(bytes) {
  return crypto.createHash('sha1')
    .update(`blob ${bytes.length}\0`)
    .update(bytes)
    .digest('hex');
}

/** Full 40-char lowercase hex, as the marker protocol requires. */
export function resolveSha(repoRoot, ref = 'HEAD') {
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
