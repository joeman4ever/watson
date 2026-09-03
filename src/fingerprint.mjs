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
// The authority maps live in `governance.mjs`, which is deliberately pure —
// it reads nothing but its arguments, and a structural test enforces that. The
// digest belongs here, where crypto already is.
import { CONFIG_AUTHORITY, LAUNCH_AUTHORITY } from './governance.mjs';

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
// SCOPE. Every git invocation in this engine goes through here, including the
// ones behind the exact-HEAD gate, selection and the fingerprints — all of which
// run with the product's directory as `cwd`.
//
// It is defence in depth, not the whole defence: a deny-list of command-valued
// keys cannot be complete, because content filters are named by the product's own
// `.gitattributes`. That is one of the reasons the identity gate is being
// replaced rather than sanitised further (ADR-049); this slice hardens the calls
// that exist today and does not pretend to have closed the class.
//
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

/**
 * The install surface. Every one of these changes what `npm ci` puts on disk,
 * and therefore what the launched application actually is, without a single
 * line of `.watson/` moving.
 *
 * Listed rather than derived because there is nothing to derive them from: a
 * lockfile is consumed by the package manager, not named by the contract. They
 * are included only when present, so a product using none of them is not
 * fingerprinting phantoms.
 */
const INSTALL_SURFACE = [
  'package.json', 'package-lock.json', 'npm-shrinkwrap.json',
  'yarn.lock', 'pnpm-lock.yaml',
  '.npmrc', '.nvmrc', '.node-version',
];

// A token in a command that is plausibly a path in this repository. Deliberately
// conservative: it must contain a slash and a file extension, so `npm`, `run`,
// `--workspace=server` and `start` do not match, and `server/scripts/x.ts` does.
const PATH_TOKEN = /(?:^|[\s'"=])((?:\.\/)?[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)+\.[A-Za-z0-9]+)/g;

/**
 * The contract's command strings, split by whether resolving them leads to the
 * TEST or to the PRODUCT.
 *
 * The distinction decides whether `contract_change` means anything. Resolving
 * `launch.command` reaches `server/src/index.ts` — the application under test,
 * already measured as `product_fingerprint`. Pulling it in here would make every
 * product pull request report a contract change and destroy the signal this
 * field exists to carry.
 *
 * `world` commands are the ones that decide WHAT THE VERIFICATION DOES: the
 * fixture that builds the world the journeys assert on, and the provisioning that
 * shapes the schema it writes into. Those are resolved through to the files they
 * run. `surface` commands contribute their manifests and lockfiles — what `npm
 * ci` installs is verdict-bearing — but are not followed into product source.
 */
function contractCommands(contract) {
  const world = [];
  const surface = [];
  const push = (into, v) => {
    if (typeof v === 'string') into.push(v);
    else if (Array.isArray(v)) for (const x of v) push(into, x);
  };
  const cfg = contract?.config ?? {};
  push(world, cfg.provision);
  for (const p of Object.values(contract?.fixtures?.profiles ?? {})) push(world, p?.command);
  push(surface, cfg.install); push(surface, cfg.build); push(surface, cfg.launch?.command);
  return { world, surface, all: [...world, ...surface] };
}

/**
 * The directory a workspace PACKAGE NAME lives in.
 *
 * `--workspace=server` names a directory; `--workspace=@nsc-eval/server` names a
 * package, and nsc-eval's contract uses both — one line apart. Without this,
 * `provision: npm run migrate:up --workspace=@nsc-eval/server` resolved to
 * nothing and `server/migrations` silently fell out of the measured scope, which
 * is precisely the kind of near-miss that makes a partial control read as a
 * complete one.
 *
 * Only literal workspace entries are followed. A glob (`packages/*`) is not
 * expanded — that would need a directory listing of the commit, and guessing is
 * what `verdict_bearing_paths` exists to replace.
 */
function workspaceDir(packageName, read) {
  let root;
  try { root = JSON.parse(read('package.json') ?? 'null'); } catch { return null; }
  const globs = Array.isArray(root?.workspaces) ? root.workspaces : root?.workspaces?.packages;
  for (const dir of globs ?? []) {
    if (typeof dir !== 'string' || dir.includes('*')) continue;
    try {
      if (JSON.parse(read(`${dir}/package.json`) ?? 'null')?.name === packageName) return dir;
    } catch { /* not a workspace we can read */ }
  }
  return null;
}

/**
 * Follow `npm run <script> --workspace=<ws>` to the files the script actually
 * runs.
 *
 * Without this the mechanism covers almost nothing for a real product. Run
 * against nsc-eval it returned six paths and NOT the fixture script, because
 * every command in that contract goes through `npm run` and names no file:
 *
 *     command: "npm run watson:fixture --workspace=server -- --profile …"
 *     server/package.json  "watson:fixture": "tsx scripts/watson-fixture.ts"
 *
 * One hop of resolution reaches `server/scripts/watson-fixture.ts` and
 * `server/migrations`. Deeper chains are not followed: two hops of guessing about
 * a shell string is where a mechanical rule stops being mechanical, and
 * `verdict_bearing_paths` is there for whatever this cannot see.
 *
 * Inside a resolved script body a bare token counts as a path when it EXISTS in
 * the workspace — which is what lets `node-pg-migrate up -m migrations` reach
 * `server/migrations`, while `up`, `-m` and `node-pg-migrate` resolve to nothing
 * and drop out.
 */
function resolveNpmScripts(command, read, exists, into) {
  const named = command.match(/--workspace[= ]([A-Za-z0-9_.@/-]+)/)?.[1];
  if (!named) return;
  const ws = named.startsWith('@') ? workspaceDir(named, read) : named;
  if (!ws) return;
  for (const m of command.matchAll(/npm\s+run\s+([A-Za-z0-9_:.-]+)/g)) {
    let manifest;
    try { manifest = JSON.parse(read(`${ws}/package.json`) ?? 'null'); } catch { manifest = null; }
    const body = manifest?.scripts?.[m[1]];
    if (typeof body !== 'string') continue;
    for (const raw of body.split(/\s+/)) {
      const token = raw.replace(/^['"]|['"]$/g, '');
      if (!token || token.startsWith('-')) continue;
      const candidate = `${ws}/${token.replace(/^\.\//, '')}`;
      if (exists(candidate)) into.add(candidate);
    }
  }
}

/**
 * Paths that can change the verdict, from the contract itself (ADR-049 D2).
 *
 * WHY THIS IS NOT JUST `.watson`.
 *
 * `contractFingerprint` digested `.watson/` alone, which left the entire
 * head-authored half of the verdict surface unfingerprinted while the result
 * told a reviewer that contract movement was reported. The contract NAMES a
 * fixture script, build scripts and migrations; it does not CONTAIN them, and
 * every one of them decides what the run observes:
 *
 *     server/scripts/watson-fixture.ts   builds the world the journeys assert on
 *     server/package.json scripts        what `start`, `migrate:up` actually do
 *     package-lock.json                  what code `npm ci` installs
 *     server/migrations/**               the schema the fixture writes into
 *
 * Three sources, in descending order of how mechanical they are:
 *
 *   1. `.watson/` itself.
 *   2. Paths extracted from the contract's own command strings. Mechanical, so a
 *      contract that starts invoking a new script covers it without anyone
 *      remembering to.
 *   3. `verdict_bearing_paths`, declared in the contract for what extraction
 *      cannot see — `npm run migrate:up` names no path. This is BASE-GOVERNED
 *      (`CONFIG_AUTHORITY`).
 *
 * WHAT A PULL REQUEST CAN AND CANNOT DO TO THIS LIST.
 *
 * This comment used to say "a pull request cannot shrink the list that decides
 * whether its own changes are reported". That is FALSE as a statement about the
 * list, and it is worth saying why rather than quietly narrowing it.
 *
 * Source 2 extracts paths from the contract's own command strings, and
 * `install`, `provision`, `build` and `launch.command` are HEAD-AUTHORED by
 * decision (`CONFIG_AUTHORITY`) — they must match the pull request's own tree or
 * nothing runs. So a pull request rewriting its own `provision` from
 * `npm run migrate:up --workspace=@nsc-eval/server` to `npm run migrate:up`
 * drops `server/migrations` out of the extracted scope. Executed against
 * nsc-eval's real contract: 8 paths become 7.
 *
 * The true property is narrower, and is what this function actually guarantees:
 *
 *   CANNOT be shrunk by the head    `.watson` (unconditional)
 *                                   the install surface, where it exists
 *                                   `verdict_bearing_paths` (base-governed)
 *   CAN be shrunk by the head       paths reachable only through head-authored
 *                                   command strings
 *
 * That is a real gap, and three things bound it. It is REPORTING, not a gate:
 * `contract_change` is reported and Sherlock reviews it; nothing in the verdict
 * depends on it. The shrink is itself VISIBLE — rewriting `provision` moves
 * `operational_config.changed_keys`, the trusted validator warns naming the
 * changed key, and `contract_scope` is recorded on every result so the two
 * scopes can be compared directly. And the remedy is in the contract's own
 * hands: any path that must stay in scope regardless of how the head writes its
 * commands belongs in base-governed `verdict_bearing_paths`, which is exactly
 * what source 3 is for.
 *
 * `exists` is injected so this stays a pure function over the contract and one
 * predicate — the caller decides whether "exists" means the working tree or a
 * commit's object store.
 */
export function verdictBearingPaths(contract, exists = () => true, read = () => null) {
  const paths = new Set(CONTRACT_PATHS);
  const { world, all } = contractCommands(contract);

  for (const cmd of world) resolveNpmScripts(String(cmd), read, exists, paths);

  for (const cmd of all) {
    for (const m of String(cmd).matchAll(PATH_TOKEN)) {
      const p = m[1].replace(/^\.\//, '');
      if (exists(p)) paths.add(p);
    }
    // `--workspace=server` means server/package.json decides what the command runs.
    for (const m of String(cmd).matchAll(/--workspace[= ]([A-Za-z0-9_.-]+)/g)) {
      const p = `${m[1]}/package.json`;
      if (exists(p)) paths.add(p);
    }
  }

  for (const p of INSTALL_SURFACE) if (exists(p)) paths.add(p);
  for (const p of contract?.config?.verdict_bearing_paths ?? []) {
    if (typeof p === 'string' && p && !p.startsWith('/') && !p.includes('..')) paths.add(p);
  }

  return [...paths].sort();
}

function treeHash(repoRoot, sha, p) {
  try {
    return git(['rev-parse', `${sha}:${p}`],
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

/**
 * Fingerprint the whole verdict-bearing surface, not only `.watson/`.
 *
 * `paths` defaults to `.watson` alone so a caller with no contract in hand still
 * gets the old, narrower answer rather than an error — but the run passes the
 * full set, and the set is recorded beside the digest so a reader can tell which
 * question was asked. A fingerprint whose scope is invisible is a fingerprint
 * nobody can check.
 */
export function contractFingerprint(repoRoot, sha, paths = CONTRACT_PATHS) {
  return digest(repoRoot, sha, paths);
}

/** `true` if the path exists in that commit's tree. Used to scope the digest. */
export function pathExistsAt(repoRoot, sha) {
  return (p) => treeHash(repoRoot, sha, p) !== 'absent';
}

/**
 * Read a file out of a COMMIT, never the working tree.
 *
 * The scope of the fingerprint has to be a fact about the revision under
 * verification, not about whatever is currently on disk — otherwise a product
 * could widen or narrow what gets measured by writing a file after the run
 * started. `cat-file` is an object-store read; nothing here touches the checkout.
 */
export function pathReaderAt(repoRoot, sha) {
  return (p) => {
    try {
      return git(['cat-file', 'blob', `${sha}:${p}`],
        { cwd: repoRoot, encoding: 'utf8', maxBuffer: 8 * 1024 * 1024, stdio: ['ignore', 'pipe', 'ignore'] });
    } catch {
      return null;
    }
  };
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

/** Full 40-char lowercase hex, as the marker protocol requires. */
export function resolveSha(repoRoot, ref = 'HEAD') {
  // A value that is ALREADY a full commit id is returned as given, and git is
  // never consulted. The trusted orchestration knows which commit it materialised,
  // and the tree it hands over needs no `.git` at all — asking git anyway made
  // the documented topology impossible to run.
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
export function contractChange(repoRoot, baseSha, headSha, loadAt, paths = CONTRACT_PATHS) {
  if (!baseSha) return null;

  // WHICH OF THE VERDICT-BEARING PATHS MOVED, path by path.
  //
  // A single digest answers "did anything change" and nothing else, which is not
  // enough once the scope includes files the contract names but does not
  // contain: a reviewer told "the contract changed" cannot tell a reworded
  // journey from a rewritten fixture script. So each path is compared on its own
  // and the ones that differ are named.
  const pathsChanged = paths.filter(
    (p) => treeHash(repoRoot, baseSha, p) !== treeHash(repoRoot, headSha, p),
  );
  if (!pathsChanged.length) return null;

  const base = loadAt(baseSha);
  const head = loadAt(headSha);
  if (!base) {
    return {
      model: 'head-product-x-head-contract',
      base_contract_available: false,
      paths_changed: pathsChanged,
    };
  }

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

  // DOMAIN NARROWING, named rather than left to the generic diff below.
  //
  // ADR-049's own example: `enum: 14 values -> enum: 1 value` turns a
  // verifier-chosen operand into a constant, so `expect_text: "${seasonName}"`
  // becomes `expect_text: "Sign in"` and the assertion is vacuous. It is a
  // one-line change in a file the pull request owns, and before this it surfaced
  // as nothing at all.
  for (const [profile, bp] of Object.entries(base.fixtures?.profiles ?? {})) {
    const hp = head.fixtures?.profiles?.[profile];
    if (!hp) { weakened.push({ id: `fixture:${profile}`, why: 'fixture profile removed' }); continue; }
    for (const [name, bDomain] of Object.entries(domainsOf(bp))) {
      const hDomain = domainsOf(hp)[name];
      if (hDomain === undefined) {
        weakened.push({ id: `fixture:${profile}.${name}`, why: 'no longer verifier-chosen' });
        continue;
      }
      const bn = domainSize(bDomain);
      const hn = domainSize(hDomain);
      if (bn !== null && hn !== null && hn < bn) {
        weakened.push({
          id: `fixture:${profile}.${name}`,
          why: `domain narrowed ${bn} -> ${hn}`
            + (hn <= 1 ? ' — a one-member domain makes a verifier-chosen operand a constant' : ''),
        });
      }
    }
  }

  return {
    model: 'head-product-x-head-contract',
    base_contract_available: true,
    features_added: added,
    features_removed: removed,
    invariants_added: invariantsAdded,
    expectations_weakened: weakened,
    // The verdict-bearing files that differ between the two revisions, including
    // the ones the contract names but does not contain: the fixture script, the
    // package scripts, the lockfile, the migrations.
    paths_changed: pathsChanged,
    // EVERYTHING ELSE THAT MOVED.
    //
    // The lists above are curated: they say which changes are known weakenings.
    // Curation is exactly what left domain narrowing invisible, so beside them
    // is an uncurated structural diff of the two contracts. It cannot classify
    // what it finds — a changed declaration is reported as changed, and a human
    // decides — but it also cannot fail to notice a construct nobody anticipated.
    changed_declarations: deepDiffPaths(canonicalContract(base), canonicalContract(head)),
    // Populated only once a run has results to compare against; see result.mjs.
    changed_sign: [],
  };
}

/** `verifier_chosen` as a name -> domain map, whatever shape it was declared in. */
function domainsOf(profile) {
  const out = {};
  for (const entry of profile?.verifier_chosen ?? []) {
    if (typeof entry === 'string') out[entry] = null;
    else for (const [k, v] of Object.entries(entry ?? {})) out[k] = v;
  }
  return out;
}

/** How many values a declared domain admits, or null when it is not countable. */
function domainSize(domain) {
  if (Array.isArray(domain?.enum)) return domain.enum.length;
  if (domain && typeof domain === 'object'
      && Number.isFinite(domain.min) && Number.isFinite(domain.max)) {
    return domain.max - domain.min + 1;
  }
  return null;
}

/**
 * A contract reduced to what can decide a verdict, in a stable shape.
 *
 * Features become a map keyed by id, so a reordering is not a change and a
 * renamed file is. `feature_files` is kept separately because feature SET
 * membership is verdict-bearing in its own right: the loader globs `*.md`, so
 * adding or removing a file changes what runs.
 */
/**
 * What the head contract says about HOW TO LAUNCH the product, and whether it
 * differs from the base.
 *
 * Reported on its own rather than folded into the whole-contract digest. These
 * keys are head-authored by decision: they must match the pull request's own
 * tree or nothing runs at all. That makes them untrusted execution inputs — and
 * makes their movement exactly the thing a reviewer needs to see, because it
 * changes how the product under verification was started.
 *
 * `changed` is a fact, not a judgement. Watson cannot tell a legitimate build
 * change from one chosen to alter what gets launched, and pretending to would be
 * worse than saying plainly that it moved.
 */
export function operationalConfigChange(baseConfig, headConfig) {
  const keys = Object.entries(CONFIG_AUTHORITY).filter(([, who]) => who === 'head').map(([k]) => k)
    .concat(Object.entries(LAUNCH_AUTHORITY).filter(([, who]) => who === 'head').map(([k]) => `launch.${k}`))
    .sort();
  const read = (cfg, key) => (key.startsWith('launch.') ? cfg?.launch?.[key.slice(7)] : cfg?.[key]);
  const digest = (cfg) => (cfg
    ? `sha256:${crypto.createHash('sha256').update(JSON.stringify(keys.map((k) => [k, read(cfg, k) ?? null]))).digest('hex')}`
    : null);

  const baseDigest = digest(baseConfig);
  const headDigest = digest(headConfig);
  const changedKeys = baseConfig
    ? keys.filter((k) => JSON.stringify(read(baseConfig, k) ?? null) !== JSON.stringify(read(headConfig, k) ?? null))
    : [];
  return {
    keys,
    base_fingerprint: baseDigest,
    head_fingerprint: headDigest,
    changed: baseDigest === null ? null : baseDigest !== headDigest,
    changed_keys: changedKeys,
  };
}

export function canonicalContract(c) {
  const features = {};
  for (const f of c?.features ?? []) {
    const { __body, __file, ...rest } = f;
    void __body; void __file;
    features[f.id ?? __file] = rest;
  }
  return {
    config: c?.config ?? {},
    fixtures: c?.fixtures ?? {},
    identities: c?.identities ?? [],
    invariants: c?.invariants ?? [],
    features,
    feature_files: (c?.features ?? []).map((f) => f.__file).sort(),
  };
}

const MAX_DIFF_PATHS = 200;

/**
 * Dotted paths at which two plain values differ.
 *
 * Bounded, because this ends up in an evidence envelope: a contract rewritten
 * wholesale would otherwise produce thousands of entries and drown the result
 * that a reader is trying to interpret. The cap is reported as its own entry
 * rather than silently applied.
 */
const CAPPED = `… more than ${MAX_DIFF_PATHS} declarations changed`;

export function deepDiffPaths(a, b, prefix = '', into = []) {
  // The marker is pushed exactly once, and once it is there nothing more is
  // added. Guarding only inside the loop appended a marker per recursion level
  // that unwound past the cap, so a truncated diff reported its own truncation
  // several times over.
  if (into.at(-1) === CAPPED) return into;
  const plain = (v) => v !== null && typeof v === 'object';
  if (!plain(a) || !plain(b) || Array.isArray(a) !== Array.isArray(b)) {
    if (JSON.stringify(a ?? null) !== JSON.stringify(b ?? null)) into.push(prefix || '(root)');
    return into;
  }
  if (Array.isArray(a)) {
    if (JSON.stringify(a) !== JSON.stringify(b)) into.push(prefix || '(root)');
    return into;
  }
  for (const k of [...new Set([...Object.keys(a), ...Object.keys(b)])].sort()) {
    if (into.length >= MAX_DIFF_PATHS) { if (into.at(-1) !== CAPPED) into.push(CAPPED); break; }
    deepDiffPaths(a[k], b[k], prefix ? `${prefix}.${k}` : k, into);
  }
  return into;
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
