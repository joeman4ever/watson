// THE ADVERSARIAL CORPUS, re-run against the architecture that replaced the one
// it defeated.
//
// Every attack below defeated some generation of the git-based exact-HEAD gate.
// They are kept, verbatim in intent, because the claim being made is not "these
// particular bugs are fixed" — it is that the CLASS is gone, because the thing
// the product controls is no longer on the path.
//
// The tell is in the last suite: `.gitignore`, `.git/index`, replace refs and
// git config are now IRRELEVANT to product identity. If a future change makes
// any of them matter again, the class is back and these tests say so.

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

import { buildManifest, verifyAgainstManifest, MANIFEST_SCHEMA, contractDirFingerprint } from '../src/manifest.mjs';
import { productIdentity } from '../src/fingerprint.mjs';

function tmpdir(label) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `watson-${label}-`));
}

/**
 * A trusted materialisation, then a product copy of it — the real topology. The
 * manifest is built from the trusted side BEFORE the product copy is touched,
 * which is the whole point: the product never sees the tree the expectation
 * came from.
 */
function materialised() {
  const dir = tmpdir('trusted');
  const git = (...a) => execFileSync('git', a, { cwd: dir, encoding: 'utf8' }).trim();
  git('init', '-q', '-b', 'main');
  git('config', 'user.email', 'watson@example.invalid');
  git('config', 'user.name', 'watson-test');
  fs.mkdirSync(path.join(dir, 'server'));
  fs.writeFileSync(path.join(dir, 'server/index.js'), 'console.log("real");\n');
  fs.writeFileSync(path.join(dir, 'package.json'), '{"name":"p"}\n');
  git('add', '-A');
  git('commit', '-qm', 'initial');
  const sha = git('rev-parse', 'HEAD');

  const manifest = buildManifest(dir, { sha, repository: 'product' });

  // The product plane's copy. In the shipping topology this is a separate
  // container's mount; here a copy is the same thing for the identity question.
  const product = tmpdir('product');
  fs.cpSync(dir, product, { recursive: true });
  const pgit = (...a) => execFileSync('git', a, { cwd: product, encoding: 'utf8' }).trim();
  return { trusted: dir, product, sha, manifest, git: pgit };
}

const check = (m, tree, opts) => verifyAgainstManifest(tree, m, opts);

describe('a manifest is a claim about a named commit', () => {
  test('it refuses to describe anything but a full commit id', () => {
    const { trusted } = materialised();
    assert.throws(() => buildManifest(trusted, { sha: 'HEAD' }), /full 40-character commit/);
    assert.throws(() => buildManifest(trusted, { sha: 'abc123' }), /full 40-character commit/);
  });

  test('an unmodified product tree matches', () => {
    const { product, manifest } = materialised();
    const r = check(manifest, product);
    assert.equal(r.matches, true, JSON.stringify(r.divergent));
    assert.equal(r.counts.expected, 2);
  });

  test('git metadata is not part of identity', () => {
    // `.git` differs between the two trees the moment either runs a git command,
    // and it is not product source. Recording it would make every run divergent.
    const { manifest } = materialised();
    assert.equal(Object.keys(manifest.entries).some((p) => p.startsWith('.git/')), false);
  });
});

describe('the attacks that defeated the git-based gate', () => {
  test('assume-unchanged + overwrite', () => {
    const { product, manifest, git } = materialised();
    git('update-index', '--assume-unchanged', 'server/index.js');
    fs.writeFileSync(path.join(product, 'server/index.js'), 'PWNED\n');
    assert.equal(git('status', '--porcelain'), '', 'git itself is blind here — that is the point');

    const r = check(manifest, product);
    assert.equal(r.matches, false);
    assert.deepEqual(r.divergent, ['server/index.js (modified)']);
  });

  test('git replace rewrites what git resolves', () => {
    const { product, manifest, git } = materialised();
    fs.writeFileSync(path.join(product, 'server/index.js'), 'PWNED\n');
    git('add', '-A');
    git('replace', '-f', git('rev-parse', 'HEAD'), git('commit-tree', git('write-tree'), '-m', 'forged'));

    const r = check(manifest, product);
    assert.equal(r.matches, false);
    assert.deepEqual(r.divergent, ['server/index.js (modified)']);
  });

  test('git add hides a new file from git, not from the manifest', () => {
    const { product, manifest, git } = materialised();
    fs.writeFileSync(path.join(product, 'server/evil.js'), 'backdoor\n');
    git('add', '-A');

    const r = check(manifest, product);
    assert.equal(r.matches, false);
    assert.deepEqual(r.divergent, ['server/evil.js (unexpected)']);
    assert.equal(r.counts.unexpected, 1);
  });

  test('a corrupt index cannot silence anything, because nothing reads it', () => {
    const { product, manifest, git } = materialised();
    fs.writeFileSync(path.join(product, 'server/evil.js'), 'backdoor\n');
    git('add', '-A');
    fs.writeFileSync(path.join(product, '.git', 'index'), 'GARBAGE-NOT-AN-INDEX');

    const r = check(manifest, product);
    assert.equal(r.matches, false);
    assert.deepEqual(r.divergent, ['server/evil.js (unexpected)']);
  });

  test('a self-hiding .gitignore hides nothing', () => {
    // This one was never closed by any amount of git hardening: the ignore rules
    // are the product's to write, so a file it chose to ignore was invisible.
    const { product, manifest } = materialised();
    fs.writeFileSync(path.join(product, 'server/evil.js'), 'backdoor\n');
    fs.writeFileSync(path.join(product, 'server/.gitignore'), '*\n');

    const r = check(manifest, product);
    assert.equal(r.matches, false);
    assert.deepEqual(r.divergent.sort(), ['server/.gitignore (unexpected)', 'server/evil.js (unexpected)']);
  });

  test('a submodule is refused, not skipped', () => {
    const { product, manifest } = materialised();
    fs.mkdirSync(path.join(product, 'vendor'));
    fs.mkdirSync(path.join(product, 'vendor', '.git'));
    fs.writeFileSync(path.join(product, 'vendor', 'lib.js'), 'EVIL SUBMODULE CODE\n');

    const r = check(manifest, product);
    assert.equal(r.matches, false);
    assert.ok(r.divergent.some((d) => d.includes('nested repository')));
    assert.ok(r.divergent.some((d) => d.includes('vendor/lib.js (unexpected)')));
  });
});

describe('what the manifest catches that git never asked about', () => {
  test('a missing committed file', () => {
    const { product, manifest } = materialised();
    fs.unlinkSync(path.join(product, 'server/index.js'));
    assert.deepEqual(check(manifest, product).divergent, ['server/index.js (missing)']);
  });

  test('a file replaced by a symlink, even to identical bytes', () => {
    const { product, manifest } = materialised();
    fs.writeFileSync(path.join(product, 'decoy'), 'console.log("real");\n');
    fs.unlinkSync(path.join(product, 'server/index.js'));
    fs.symlinkSync('../decoy', path.join(product, 'server/index.js'));

    const r = check(manifest, product);
    assert.equal(r.matches, false);
    assert.ok(r.divergent.some((d) => d.startsWith('server/index.js (file -> symlink)')));
  });

  test('the executable bit, on otherwise identical bytes', () => {
    // Same bytes, different materialisation — and one of them runs.
    const { product, manifest } = materialised();
    fs.chmodSync(path.join(product, 'server/index.js'), 0o755);
    const r = check(manifest, product);
    assert.equal(r.matches, false);
    assert.ok(r.divergent.some((d) => d.includes('plain -> exec')));
  });

  test('a directory where a file belongs', () => {
    const { product, manifest } = materialised();
    fs.unlinkSync(path.join(product, 'server/index.js'));
    fs.mkdirSync(path.join(product, 'server/index.js'));
    fs.writeFileSync(path.join(product, 'server/index.js/payload'), 'x\n');

    const r = check(manifest, product);
    assert.equal(r.matches, false);
    assert.ok(r.divergent.some((d) => d.includes('server/index.js (missing)')));
  });
});

describe('generated output is distinguished, never made invisible', () => {
  test('build output under a declared root is counted, not divergent', () => {
    const { product, manifest } = materialised();
    fs.mkdirSync(path.join(product, 'node_modules', 'left-pad'), { recursive: true });
    fs.writeFileSync(path.join(product, 'node_modules/left-pad/index.js'), 'module.exports=1\n');

    const r = check(manifest, product, { generatedRoots: ['node_modules'] });
    assert.equal(r.matches, true);
    assert.equal(r.counts.generated, 1, 'reported, not ignored');
    assert.equal(r.counts.unexpected, 0);
  });

  test('an undeclared extra file is divergent however the product ignores it', () => {
    const { product, manifest } = materialised();
    fs.writeFileSync(path.join(product, 'server/evil.js'), 'backdoor\n');
    fs.writeFileSync(path.join(product, '.gitignore'), 'server/evil.js\n');

    const r = check(manifest, product, { generatedRoots: ['node_modules'] });
    assert.equal(r.matches, false);
    assert.ok(r.divergent.some((d) => d.startsWith('server/evil.js')));
  });

  test('a generated root does not shelter a modified committed file', () => {
    // The declaration says where NEW files may appear. It must not become a way
    // to excuse a change to something the commit contains.
    const { product, manifest } = materialised();
    fs.writeFileSync(path.join(product, 'server/index.js'), 'PWNED\n');
    const r = check(manifest, product, { generatedRoots: ['server'] });
    assert.equal(r.matches, false);
    assert.deepEqual(r.divergent, ['server/index.js (modified)']);
  });
});

describe('the class is gone, not the instances', () => {
  // The point of the redesign, asserted directly: the four things the product
  // controls that defeated every previous generation of the gate are no longer
  // consulted at all. If any of them starts mattering again, the class is back.
  test('git config, the index, replace refs and ignore rules are all irrelevant', () => {
    const { product, manifest, git } = materialised();
    const marker = path.join(tmpdir('irrelevant'), 'ran');
    const payload = path.join(product, 'payload.sh');
    fs.writeFileSync(payload, `#!/bin/sh\necho ran > ${JSON.stringify(marker).slice(1, -1)}\n`);
    fs.chmodSync(payload, 0o755);

    // Order matters, and the reason is instructive: the git commands have to run
    // BEFORE the hostile config is installed, because otherwise THIS TEST's own
    // raw git calls fire the payload. Which is the point of the redesign, seen
    // from the other side — raw git against a hostile repository is dangerous,
    // so the identity check stopped using it.
    git('update-index', '--assume-unchanged', 'package.json');
    git('config', 'core.fsmonitor', payload);
    git('config', 'core.hooksPath', path.dirname(payload));
    fs.writeFileSync(path.join(product, '.gitignore'), '*\n');
    fs.writeFileSync(path.join(product, '.git', 'index'), 'GARBAGE');
    fs.rmSync(marker, { force: true });

    // Every one of those is set, and identity is established anyway — with the
    // two files the product actually added showing up as divergent.
    const r = check(manifest, product);
    assert.equal(fs.existsSync(marker), false, 'no product-named command ran');
    assert.equal(r.matches, false);
    assert.deepEqual(
      r.divergent.sort(),
      ['.gitignore (unexpected)', 'payload.sh (unexpected)'],
      'the ONLY divergences are the files the product added — none of its git state mattered',
    );
  });

  test('a manifest from the wrong schema is refused', () => {
    const { product } = materialised();
    assert.throws(() => verifyAgainstManifest(product, { schema: 'something-else' }), /unrecognised manifest schema/);
  });

  test('the manifest names the commit it speaks for', () => {
    const { manifest, sha } = materialised();
    assert.equal(manifest.schema, MANIFEST_SCHEMA);
    assert.equal(manifest.sha, sha);
  });
});

// ---------------------------------------------------------------------------
// The same corpus, one level up: at the function the CLI actually calls.
//
// Everything above tests `verifyAgainstManifest`, the primitive. Nothing above
// would notice if `productIdentity` — the only caller, and the thing whose
// `exact_head` decides whether a product claim may be made at all — wired it up
// wrongly, defaulted a missing manifest to `clean`, or dropped `generatedRoots`.
//
// That is not a hypothetical failure mode. It is the shape of rounds 1-3: the
// check was usually right, and what called it was where the hole was.
describe('the gate as the engine calls it', () => {
  test('no manifest means no product claim, and no fallback to asking git', () => {
    const { product, sha } = materialised();
    const id = productIdentity({ repoRoot: product, manifest: null, expectedSha: sha });
    assert.equal(id.exact_head, false);
    assert.equal(id.clean, null, 'unknown, not clean — the difference is the whole gate');
    assert.equal(id.method, 'no-manifest');
    assert.match(id.note, /watson manifest/, 'says how to fix it rather than failing mutely');
  });

  test('a pristine tree with its own manifest is exact', () => {
    const { product, sha, manifest } = materialised();
    const id = productIdentity({ repoRoot: product, manifest, expectedSha: sha });
    assert.equal(id.exact_head, true);
    assert.equal(id.clean, true);
    assert.equal(id.method, 'manifest');
    assert.equal(id.head_sha, sha);
    assert.equal(id.head_matches, true);
  });

  test('a manifest for a DIFFERENT commit authorises nothing, however well the tree matches it', () => {
    // The tree and manifest agree perfectly. They just do not describe the commit
    // this run says it is about — which is a run verifying something else.
    const { product, manifest } = materialised();
    const id = productIdentity({
      repoRoot: product, manifest, expectedSha: 'b'.repeat(40),
    });
    assert.equal(id.exact_head, false);
    assert.equal(id.clean, null);
    assert.equal(id.head_matches, false);
    assert.match(id.note, /but this run is about/);
  });

  test('a tampered tree is inexact, and names what diverged', () => {
    const { product, sha, manifest } = materialised();
    fs.writeFileSync(path.join(product, 'server/index.js'), 'console.log("owned");\n');
    const id = productIdentity({ repoRoot: product, manifest, expectedSha: sha });
    assert.equal(id.exact_head, false);
    assert.equal(id.clean, false);
    assert.deepEqual(id.dirty_paths, ['server/index.js (modified)']);
    assert.equal(id.dirty_count, 1);
  });

  test('a divergent CONTRACT is called out specifically, because it changes what was verified', () => {
    const dir = tmpdir('trusted-contract');
    const git = (...a) => execFileSync('git', a, { cwd: dir, encoding: 'utf8' }).trim();
    git('init', '-q', '-b', 'main');
    git('config', 'user.email', 'watson@example.invalid');
    git('config', 'user.name', 'watson-test');
    fs.mkdirSync(path.join(dir, '.watson'));
    fs.writeFileSync(path.join(dir, '.watson/config.yaml'), 'contract_version: 4\n');
    fs.writeFileSync(path.join(dir, 'app.js'), 'ok\n');
    git('add', '-A');
    git('commit', '-qm', 'initial');
    const sha = git('rev-parse', 'HEAD');
    const manifest = buildManifest(dir, { sha });

    const product = tmpdir('product-contract');
    fs.cpSync(dir, product, { recursive: true });
    fs.writeFileSync(path.join(product, '.watson/config.yaml'), 'contract_version: 4\n# weakened\n');

    const id = productIdentity({ repoRoot: product, manifest, expectedSha: sha });
    assert.equal(id.exact_head, false);
    assert.equal(id.contract_dirty, true);
    assert.match(id.note, /this run verified something else/);
  });

  test('declared generated roots reach the comparison, and shelter nothing committed', () => {
    const { product, sha, manifest } = materialised();
    fs.mkdirSync(path.join(product, 'dist'));
    fs.writeFileSync(path.join(product, 'dist/bundle.js'), 'built\n');

    const withRoot = productIdentity({
      repoRoot: product, manifest, expectedSha: sha, generatedRoots: ['dist'],
    });
    assert.equal(withRoot.exact_head, true, 'build output under a declared root is not tampering');
    assert.equal(withRoot.counts.generated, 1, 'but it is COUNTED, not invisible');

    // Undeclared, the same file is an unexpected file.
    const without = productIdentity({ repoRoot: product, manifest, expectedSha: sha });
    assert.equal(without.exact_head, false, 'the root has to be DECLARED, not inferred');

    // And a declared root does not extend backwards over a committed file.
    fs.writeFileSync(path.join(product, 'server/index.js'), 'console.log("owned");\n');
    const sheltered = productIdentity({
      repoRoot: product, manifest, expectedSha: sha, generatedRoots: ['dist', 'server'],
    });
    assert.equal(sheltered.exact_head, false);
    assert.deepEqual(sheltered.dirty_paths, ['server/index.js (modified)']);
  });

  test('a tree it cannot read fails CLOSED, rather than reporting clean', () => {
    const { sha, manifest } = materialised();
    const id = productIdentity({
      repoRoot: path.join(os.tmpdir(), `watson-absent-${Date.now()}`), manifest, expectedSha: sha,
    });
    assert.equal(id.exact_head, false);
    assert.equal(id.clean, null);
    assert.equal(id.method, 'failed');
  });

  test('the divergence LIST is capped, the divergence COUNT is not', () => {
    // Otherwise the cheapest attack on a reader is volume: bury one real change
    // under fifty harmless ones and let the list truncate before it shows.
    const { product, sha, manifest } = materialised();
    for (let i = 0; i < 50; i += 1) fs.writeFileSync(path.join(product, `extra${i}.js`), 'x\n');
    const id = productIdentity({ repoRoot: product, manifest, expectedSha: sha });
    assert.equal(id.exact_head, false);
    assert.equal(id.dirty_paths.length, 20);
    assert.equal(id.dirty_count, 50, 'the count is the truth; the list is a courtesy');
  });
});

// ----------------------------------------------------------------------------
// THREE INVARIANTS THAT WERE UNPINNED (exact-HEAD confirmation review N10-N12).
//
// Each was found by mutating the source and watching the whole suite stay green.
// None is a live hole: the code is correct today. What was missing is anything
// that would notice if it stopped being.

describe('a symlink in the contract directory is RECORDED, never followed', () => {
  // N10. Deleting the symlink branch from `contractDirFingerprint`'s walk left
  // 418/418 green. Following one would let a link inside `.watson/` pull content
  // from outside the materialised contract into the digest that says WHICH
  // contract governed — the one number the trusted observer compares against.
  //
  // Behavioural, not a source grep: a real symlink on disk, and an assertion
  // about the digest that results.
  const scratch = () => fs.mkdtempSync(path.join(os.tmpdir(), 'watson-symlink-'));

  test('the digest records the link TARGET, not the content behind it', () => {
    const dir = scratch();
    const secret = path.join(dir, 'outside.txt');
    fs.writeFileSync(secret, 'content the contract does not contain\n');

    const a = path.join(dir, 'a', '.watson');
    fs.mkdirSync(a, { recursive: true });
    fs.writeFileSync(path.join(a, 'config.yaml'), 'x: 1\n');
    fs.symlinkSync(secret, path.join(a, 'link'));

    const b = path.join(dir, 'b', '.watson');
    fs.mkdirSync(b, { recursive: true });
    fs.writeFileSync(path.join(b, 'config.yaml'), 'x: 1\n');
    // Same link NAME, different target. If the walk followed links these two
    // would differ only by the content behind them; because it records the
    // target, they differ by the target string — which is the honest thing to
    // digest, and is what a reviewer can see in the diff.
    fs.symlinkSync(path.join(dir, 'elsewhere.txt'), path.join(b, 'link'));

    const da = contractDirFingerprint(path.join(dir, 'a'));
    const db = contractDirFingerprint(path.join(dir, 'b'));
    assert.notEqual(da, db, 'two different link targets digested the same');

    // And the digest does not change when the content BEHIND the link changes,
    // which is the property that matters: the contract is what it contains.
    fs.writeFileSync(secret, 'completely different content\n');
    assert.equal(contractDirFingerprint(path.join(dir, 'a')), da,
      'the digest followed the symlink; content outside the contract reached it');
  });

  test('a dangling symlink does not throw', () => {
    // The `b` case above is already dangling. Stated separately because "records
    // the target" and "does not explode on a broken link" are different claims,
    // and a walk that throws here would turn a hostile contract into a crash
    // rather than a digest.
    const dir = scratch();
    const c = path.join(dir, '.watson');
    fs.mkdirSync(c, { recursive: true });
    fs.symlinkSync(path.join(dir, 'nothing-here'), path.join(c, 'dangling'));
    assert.doesNotThrow(() => contractDirFingerprint(dir));
  });
});

describe('the product fingerprint scope itself', () => {
  // N11. Dropping `server` from PRODUCT_PATHS left the suite green. Recorded and
  // not consulted in Phase 0/1 (a new HEAD is always re-verified), so this is a
  // provenance defect rather than a gate defect — but a fingerprint that silently
  // stops covering the server is worse than one that never claimed to.
  //
  // Independent literal, for the same reason as CONFIG_AUTHORITY and
  // ENGINE_OWNED_ENV: an assertion derived from the list under test shrinks with
  // it.
  const EXPECTED_PRODUCT_PATHS = [
    'client', 'server', 'package.json', 'package-lock.json', 'playwright.config.ts',
  ];

  test('covers exactly these paths', async () => {
    const src = fs.readFileSync(new URL('../src/fingerprint.mjs', import.meta.url), 'utf8');
    const m = src.match(/const PRODUCT_PATHS = \[([\s\S]*?)\];/);
    assert.ok(m, 'PRODUCT_PATHS is no longer a literal array; this test cannot read it');
    const actual = [...m[1].matchAll(/'([^']+)'/g)].map((x) => x[1]);
    assert.deepEqual(actual.sort(), [...EXPECTED_PRODUCT_PATHS].sort());
  });
});

describe('product identity is measured BEFORE any product code runs', () => {
  // N12. The engine runs `git` against the product tree, and that tree is mounted
  // READ-WRITE into the product container. Nothing bad happens today, for one
  // reason only: every one of those reads is on the path before `bringUp`, and
  // the product plane executes nothing until the verifier POSTs `/launch`.
  //
  // Ordering saving a design is not the same as the design being safe — it is
  // exactly what F3 removed `loadContractAt` for. Nothing asserted the ordering,
  // so this does.
  test('every git read of the product tree precedes bringUp in cli.mjs', () => {
    const src = fs.readFileSync(new URL('../src/cli.mjs', import.meta.url), 'utf8');
    const bringUp = src.indexOf('await bringUp(');
    assert.ok(bringUp > 0, 'bringUp is no longer called here; re-derive this ordering');

    // The functions in `fingerprint.mjs` that shell out to git against the
    // product repository. Named explicitly rather than discovered, so adding a
    // new one is a deliberate act that has to come here too.
    // `contractChange` and `changedPaths` are no longer in this list because
    // since D1 they run no git at all: both sides come from trusted
    // materialisations. That is asserted structurally below rather than left to
    // this list quietly shrinking.
    const GIT_READERS = [
      'productFingerprint(', 'contractFingerprint(', 'verdictBearingPaths(', 'resolveSha(',
    ];
    const late = [];
    for (const fn of GIT_READERS) {
      for (const m of src.matchAll(new RegExp(fn.replace('(', '\\('), 'g'))) {
        if (m.index > bringUp) late.push(`${fn} at ${m.index}`);
      }
    }
    assert.deepEqual(late, [],
      'a git read of the product tree happens AFTER the product container can run; '
      + 'the tree is writable by the product, so this ordering is the control');
  });

  test('D1: the base-side comparison functions run no git at all', () => {
    // THE PROPERTY, encoded structurally rather than as "these SHAs happen to
    // exist in one repository".
    //
    //     base-side contract/change computation comes from the trusted base
    //     materialisation and is INDEPENDENT of whether the product checkout
    //     contains the base git object
    //
    // The behavioural half is in contract-scope.test.mjs, which builds the real
    // topology — a product clone holding only the head — and shows the answer is
    // the same with that clone deleted. This half is the reason it can be: the
    // two functions take entry maps and touch git nowhere.
    const src = fs.readFileSync(new URL('../src/fingerprint.mjs', import.meta.url), 'utf8');
    for (const fn of ['contractChange', 'changedPaths']) {
      const start = src.indexOf(`export function ${fn}(`);
      assert.ok(start > 0, `${fn} not found`);
      // To the next top-level export, which is where each of these ends.
      const rest = src.slice(start + 1);
      const end = rest.indexOf('\nexport ');
      const body = end < 0 ? rest : rest.slice(0, end);
      const gitCalls = body.split('\n')
        .filter((l) => !/^\s*(\/\/|\*)/.test(l))
        .filter((l) => /\bgit\(|execFileSync|treeHash\(/.test(l));
      assert.deepEqual(gitCalls, [],
        `${fn} reaches for git or the product tree: ${gitCalls.join(' | ')}`);
    }
  });

  test('D1: neither takes a repository root, so it cannot be handed one', () => {
    // The signature is the boundary. While these accepted `repoRoot` a future
    // edit could reintroduce the read without any structural check noticing.
    const src = fs.readFileSync(new URL('../src/fingerprint.mjs', import.meta.url), 'utf8');
    for (const fn of ['contractChange', 'changedPaths']) {
      const m = src.match(new RegExp(`export function ${fn}\\(([^)]*)\\)`));
      assert.ok(m, `${fn} not found`);
      assert.doesNotMatch(m[1], /repoRoot|baseSha|headSha/,
        `${fn} still takes a product-repository argument: ${m[1].trim()}`);
    }
  });
});
