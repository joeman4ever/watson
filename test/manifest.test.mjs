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

import { buildManifest, verifyAgainstManifest, MANIFEST_SCHEMA } from '../src/manifest.mjs';

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
    assert.deepEqual(r.divergent, ['server/index.js']);
  });

  test('git replace rewrites what git resolves', () => {
    const { product, manifest, git } = materialised();
    fs.writeFileSync(path.join(product, 'server/index.js'), 'PWNED\n');
    git('add', '-A');
    git('replace', '-f', git('rev-parse', 'HEAD'), git('commit-tree', git('write-tree'), '-m', 'forged'));

    const r = check(manifest, product);
    assert.equal(r.matches, false);
    assert.deepEqual(r.divergent, ['server/index.js']);
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
    assert.deepEqual(r.divergent, ['server/index.js']);
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
