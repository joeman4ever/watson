// Product identity, established without asking the product.
//
// WHY THIS EXISTS. Three adversarial reviews found four ways past the previous
// gate, and every one had the same shape: the gate asked a directory the product
// writes — whose `.git` the product owns — to describe itself. `--assume-unchanged`,
// `git replace`, `git add`, a corrupt index, a self-hiding `.gitignore`. Patching
// each answer never changed who was answering.
//
// So the authority moves. The TRUSTED orchestration materialises the commit
// before any product code runs, walks what it materialised, and writes down what
// is there. The verifier later compares the product's tree against that record.
// Nothing on the product side takes part: no `.git`, no index, no ignore rules,
// no replace refs, no git config, no `git status`. The product execution plane
// does not need `.git` at all.
//
// WHAT THIS PROVES, exactly — the wording matters and is easy to overstate:
//
//   At the verifier's measurement point, the materialised committed product
//   source matched the trusted manifest for product HEAD X.
//
// It does NOT prove that the bytes loaded into the running process are nothing
// but the committed bytes. Generated build output, runtime mutation and TOCTOU
// between measurements are separate concerns, tracked as C4.
//
// A NOTE ON WHO MAY BUILD IT. The manifest must come from the trusted side,
// from the trusted commit, before untrusted execution. It must not be generated
// by product code, derived from product-owned git config, stored anywhere the
// product can write, or accepted because the product reports the same digest.
// The product is the object being measured; it cannot be the authority for the
// expected measurement.

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

export const MANIFEST_SCHEMA = 'watson-manifest/v1';

/** Never part of product identity: git's own metadata, wherever it appears. */
const GIT_DIR = '.git';

function digestOf(bytes) {
  return `sha256:${crypto.createHash('sha256').update(bytes).digest('hex')}`;
}

/**
 * Walk a directory into `{ path -> entry }`.
 *
 * Deliberately a plain filesystem walk. Every alternative — `git ls-files`,
 * `git ls-tree`, `git status` — reintroduces an authority the product controls.
 *
 * `.git` is skipped everywhere, not just at the root: a nested one is either a
 * submodule or a repository the product planted, and neither is product source.
 * Its presence below the root is reported separately rather than ignored,
 * because a gitlink is exactly the condition the previous gate skipped silently.
 */
export function walkTree(root, { onNestedGit } = {}) {
  const entries = new Map();
  const stack = [''];

  while (stack.length) {
    const rel = stack.pop();
    const abs = rel === '' ? root : path.join(root, rel);
    let dirents;
    try {
      dirents = fs.readdirSync(abs, { withFileTypes: true });
    } catch (err) {
      throw new Error(`could not read ${rel || '.'}: ${err.message}`);
    }

    for (const d of dirents) {
      const childRel = rel === '' ? d.name : `${rel}/${d.name}`;
      if (d.name === GIT_DIR) {
        if (rel !== '') onNestedGit?.(childRel);
        continue;
      }
      // `withFileTypes` reports the entry itself, so a symlink is a symlink even
      // when it points at a directory. Following one would let a link into
      // another tree be walked as if it were product source.
      if (d.isSymbolicLink()) {
        const target = fs.readlinkSync(path.join(root, childRel));
        entries.set(childRel, { type: 'symlink', digest: digestOf(Buffer.from(target)), mode: null });
        continue;
      }
      if (d.isDirectory()) { stack.push(childRel); continue; }
      if (!d.isFile()) {
        // A fifo, socket or device is not product source and cannot be hashed
        // meaningfully. Recorded so it is visible rather than skipped.
        entries.set(childRel, { type: 'special', digest: null, mode: null });
        continue;
      }
      const st = fs.lstatSync(path.join(root, childRel));
      entries.set(childRel, {
        type: 'file',
        digest: digestOf(fs.readFileSync(path.join(root, childRel))),
        // The executable bit is semantic: the same bytes with and without it are
        // different materialisations, and one of them runs.
        mode: st.mode & 0o111 ? 'exec' : 'plain',
      });
    }
  }
  return entries;
}

/**
 * Build the trusted manifest. Run this on the TRUSTED side, against a freshly
 * materialised commit, before any product code executes.
 */
export function buildManifest(treeRoot, { sha, repository = null }) {
  if (!/^[0-9a-f]{40}$/.test(sha ?? '')) {
    throw new Error(`a manifest must name the full 40-character commit it describes, got \`${sha}\``);
  }
  const nested = [];
  const entries = walkTree(treeRoot, { onNestedGit: (p) => nested.push(p) });
  return {
    schema: MANIFEST_SCHEMA,
    repository,
    sha,
    built_at: new Date().toISOString(),
    // A repository nested inside the materialisation is a submodule or a planted
    // one. Recorded here so the verifier refuses rather than measuring around it.
    nested_git: nested.sort(),
    entries: Object.fromEntries([...entries].sort(([a], [b]) => (a < b ? -1 : 1))),
  };
}

/**
 * Compare a product tree against the trusted manifest.
 *
 * `generatedRoots` names paths where build output legitimately appears. They are
 * NOT an ignore list: a file under one is reported as `generated`, counted, and
 * kept out of the identity verdict — visible and distinguished, rather than
 * silently invisible. Anything else that is not in the manifest is `unexpected`
 * and makes the tree inexact, whatever the product's `.gitignore` says about it.
 */
export function verifyAgainstManifest(treeRoot, manifest, { generatedRoots = [] } = {}) {
  if (manifest?.schema !== MANIFEST_SCHEMA) {
    throw new Error(`unrecognised manifest schema \`${manifest?.schema}\``);
  }
  const nested = [];
  const actual = walkTree(treeRoot, { onNestedGit: (p) => nested.push(p) });
  const expected = new Map(Object.entries(manifest.entries ?? {}));

  const isGenerated = (p) => generatedRoots.some((r) => p === r || p.startsWith(`${r.replace(/\/$/, '')}/`));

  const missing = [];
  const modified = [];
  const typeChanged = [];
  const modeChanged = [];
  const unexpected = [];
  const generated = [];

  for (const [p, want] of expected) {
    const got = actual.get(p);
    if (!got) { missing.push(p); continue; }
    if (got.type !== want.type) { typeChanged.push(`${p} (${want.type} -> ${got.type})`); continue; }
    if (got.digest !== want.digest) { modified.push(p); continue; }
    if (want.mode && got.mode !== want.mode) modeChanged.push(`${p} (${want.mode} -> ${got.mode})`);
  }
  for (const p of actual.keys()) {
    if (expected.has(p)) continue;
    (isGenerated(p) ? generated : unexpected).push(p);
  }

  // A repository the manifest did not record is a subtree whose content this
  // check cannot speak for. Refusing is the honest answer; the previous gate
  // skipped gitlinks silently and left a whole subtree unmeasured.
  const nestedUnexpected = nested.filter((p) => !(manifest.nested_git ?? []).includes(p));

  const divergent = [
    ...missing.map((p) => `${p} (missing)`),
    ...modified,
    ...typeChanged,
    ...modeChanged,
    ...unexpected.map((p) => `${p} (unexpected)`),
    ...nestedUnexpected.map((p) => `${p} (nested repository — content not measurable)`),
    ...(manifest.nested_git ?? []).map((p) => `${p} (submodule — content not measurable)`),
  ].sort();

  return {
    matches: divergent.length === 0,
    divergent,
    counts: {
      expected: expected.size,
      missing: missing.length,
      modified: modified.length,
      type_changed: typeChanged.length,
      mode_changed: modeChanged.length,
      unexpected: unexpected.length,
      nested_git: nestedUnexpected.length + (manifest.nested_git ?? []).length,
      // Counted and reported, never folded into the verdict — and never used to
      // decide that an unexpected file is invisible.
      generated: generated.length,
    },
    generated_roots: generatedRoots,
  };
}

export function readManifest(file) {
  const m = JSON.parse(fs.readFileSync(file, 'utf8'));
  if (m?.schema !== MANIFEST_SCHEMA) throw new Error(`\`${file}\` is not a ${MANIFEST_SCHEMA} manifest`);
  return m;
}
