import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { buildArtifactDigest, servedBytesMatch } from '../src/manifest.mjs';

function tmpTree(files) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'wtsn-c4-'));
  for (const [rel, body] of Object.entries(files)) {
    const abs = path.join(root, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, body);
  }
  return root;
}

describe('buildArtifactDigest — measuring what the manifest does not', () => {
  test('digests a directory and enumerates its files', () => {
    const root = tmpTree({ 'index.html': '<!doctype html>', 'assets/app.js': 'console.log(1)' });
    const a = buildArtifactDigest(root);
    assert.match(a.digest, /^sha256:[0-9a-f]{64}$/);
    assert.equal(a.file_count, 2);
    assert.ok(a.files['index.html']);
    assert.ok(a.files['assets/app.js'], 'nested paths use forward slashes');
  });

  test('is deterministic across repeated calls', () => {
    const root = tmpTree({ 'a.js': 'x', 'b/c.js': 'y' });
    assert.equal(buildArtifactDigest(root).digest, buildArtifactDigest(root).digest);
  });

  test('two trees with identical content digest identically', () => {
    const one = tmpTree({ 'index.html': 'h', 'assets/app.js': 'j' });
    const two = tmpTree({ 'assets/app.js': 'j', 'index.html': 'h' });
    // Creation order differs; the digest must not.
    assert.equal(buildArtifactDigest(one).digest, buildArtifactDigest(two).digest);
  });

  test('ANY content change moves the digest', () => {
    const root = tmpTree({ 'index.html': 'h' });
    const before = buildArtifactDigest(root).digest;
    fs.writeFileSync(path.join(root, 'index.html'), 'h!');
    assert.notEqual(buildArtifactDigest(root).digest, before);
  });

  test('adding a file moves the digest', () => {
    const root = tmpTree({ 'index.html': 'h' });
    const before = buildArtifactDigest(root).digest;
    fs.writeFileSync(path.join(root, 'extra.js'), '');
    assert.notEqual(buildArtifactDigest(root).digest, before, 'an added empty file must still count');
  });

  test('renaming a file moves the digest, even with identical content', () => {
    // The path is part of the claim: served content is addressed by path.
    const a = tmpTree({ 'app.js': 'same' });
    const b = tmpTree({ 'app2.js': 'same' });
    assert.notEqual(buildArtifactDigest(a).digest, buildArtifactDigest(b).digest);
  });

  test('an absent directory is null, not an empty digest', () => {
    // "Absent" and "present but empty" are different facts, and collapsing
    // them would let a missing build read as a clean one.
    assert.equal(buildArtifactDigest(path.join(os.tmpdir(), 'wtsn-does-not-exist-xyz')), null);
    const empty = tmpTree({});
    assert.notEqual(buildArtifactDigest(empty), null);
    assert.equal(buildArtifactDigest(empty).file_count, 0);
  });

  test('a symlink is recorded, never followed', () => {
    const root = tmpTree({ 'real.js': 'contents' });
    const outside = tmpTree({ 'secret.js': 'elsewhere' });
    fs.symlinkSync(path.join(outside, 'secret.js'), path.join(root, 'link.js'));
    const a = buildArtifactDigest(root);
    // Following it would digest whatever it points at rather than what the
    // directory contains — and would let a build escape its own measurement.
    assert.ok(!('link.js' in a.files), 'a symlink must not appear as a digested file');
    assert.equal(a.file_count, 1);
  });
});

describe('servedBytesMatch — the step that makes the digest evidence', () => {
  const root = tmpTree({ 'index.html': '<!doctype html><title>app</title>' });
  const artifact = buildArtifactDigest(root);
  const served = fs.readFileSync(path.join(root, 'index.html'));

  test('matches when the application served the digested bytes', () => {
    const r = servedBytesMatch(artifact, 'index.html', served);
    assert.equal(r.matched, true);
  });

  /**
   * The whole point. Hashing a build directory proves nothing about what was
   * served — the app could serve a different directory, a cached copy, or
   * content generated at request time.
   */
  test('does NOT match when the application served something else', () => {
    const r = servedBytesMatch(artifact, 'index.html', Buffer.from('<!doctype html><title>other</title>'));
    assert.equal(r.matched, false);
    assert.match(r.reason, /do not match/);
  });

  test('fails closed on a path absent from the artifact', () => {
    const r = servedBytesMatch(artifact, 'nope.html', served);
    assert.equal(r.matched, false);
    assert.match(r.reason, /not in the digested artifact/);
  });

  test('fails closed when nothing was digested', () => {
    const r = servedBytesMatch(null, 'index.html', served);
    assert.equal(r.matched, false);
  });

  test('fails closed when the application served nothing', () => {
    // A fetch failure must never read as a match.
    for (const empty of [null, undefined]) {
      assert.equal(servedBytesMatch(artifact, 'index.html', empty).matched, false);
    }
  });

  test('a one-byte difference is caught', () => {
    const almost = Buffer.concat([served, Buffer.from(' ')]);
    assert.equal(servedBytesMatch(artifact, 'index.html', almost).matched, false);
  });

  /**
   * g1 is recorded as narrowed ONLY where this returns matched. Every other
   * outcome must leave it open, so the engine never reports a control it did
   * not exercise.
   */
  test('every non-match carries a reason a reader can act on', () => {
    const cases = [
      servedBytesMatch(null, 'index.html', served),
      servedBytesMatch(artifact, 'missing', served),
      servedBytesMatch(artifact, 'index.html', null),
      servedBytesMatch(artifact, 'index.html', Buffer.from('x')),
    ];
    for (const c of cases) {
      assert.equal(c.matched, false);
      assert.ok(typeof c.reason === 'string' && c.reason.length > 10, c.reason);
    }
  });
});
