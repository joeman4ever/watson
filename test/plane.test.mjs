// The product plane's contract, and the asymmetry that makes it safe.
//
// The plane runs beside untrusted product code and is therefore untrusted
// itself. What keeps that acceptable is the division of labour: it EXECUTES,
// the verifier DECIDES. These tests hold that line, because the failure mode is
// quiet — a plane that is allowed to decide one small thing (readiness, say) is
// a plane the product can use to make the verifier agree with it.

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { serve, PLANE_PROTOCOL } from '../src/plane.mjs';

function tmpdir(label) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `watson-${label}-`));
}

async function withPlane(fn) {
  const repoRoot = tmpdir('plane-repo');
  const logDir = tmpdir('plane-logs');
  const plane = await serve({ repoRoot, logDir, port: 0, host: '127.0.0.1' });
  const url = `http://127.0.0.1:${plane.port}`;
  const call = async (route, body) => {
    const res = await fetch(`${url}${route}`, {
      method: body === undefined ? 'GET' : 'POST',
      headers: body === undefined ? {} : { 'content-type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    return { status: res.status, json: await res.json() };
  };
  try {
    await fn({ call, repoRoot, logDir, url });
  } finally {
    await plane.close();
  }
}

describe('the product plane executes; it does not decide', () => {
  test('it announces a versioned protocol so the verifier can refuse a stranger', async () => {
    await withPlane(async ({ call }) => {
      const { status, json } = await call('/alive');
      assert.equal(status, 200);
      assert.equal(json.protocol, PLANE_PROTOCOL);
      assert.equal(json.phase, 'idle');
    });
  });

  test('seeding before a launch is refused', async () => {
    // Ordering is the verifier's decision, and the plane enforces the part it
    // can see. A product that could seed before launch could produce `vars` for
    // a world the verifier never confirmed existed.
    await withPlane(async ({ call }) => {
      const { status, json } = await call('/seed', { runId: 'r', seed: 'true', env: {} });
      assert.equal(status, 409);
      assert.equal(json.ok, false);
    });
  });

  test('a failing product command reports the PHASE, and does not throw the plane away', async () => {
    await withPlane(async ({ call }) => {
      const { json } = await call('/launch', {
        runId: 'r',
        install: ['exit 3'],
        provision: [], build: [], launch: 'true',
        env: { DATABASE_URL: 'postgres://x/y' },
      });
      assert.equal(json.ok, false);
      assert.equal(json.phase, 'install');
      assert.match(json.message, /install: exited 3/);
      // Still answering, so the verifier gets a diagnosis rather than a timeout.
      const { json: alive } = await call('/alive');
      assert.equal(alive.ok, true);
      assert.equal(alive.phase, 'failed');
    });
  });

  test('it runs what it is handed, in the product checkout, and reports the seed verbatim', async () => {
    await withPlane(async ({ call, repoRoot }) => {
      const launched = await call('/launch', {
        runId: 'r',
        install: ['echo installed > install.txt'],
        provision: ['echo "$DATABASE_URL" > provision.txt'],
        build: ['echo built > build.txt'],
        // A process that stays up, so the phase reaches `launched`.
        launch: 'sleep 5',
        env: { DATABASE_URL: 'postgres://watson/run-db' },
      });
      assert.equal(launched.json.ok, true, JSON.stringify(launched.json));
      assert.equal(fs.readFileSync(path.join(repoRoot, 'install.txt'), 'utf8').trim(), 'installed');
      assert.equal(fs.readFileSync(path.join(repoRoot, 'provision.txt'), 'utf8').trim(), 'postgres://watson/run-db');
      assert.equal(fs.readFileSync(path.join(repoRoot, 'build.txt'), 'utf8').trim(), 'built');

      const seeded = await call('/seed', {
        runId: 'run-42',
        seed: 'echo \'{"seasonId":"s1","runId":"${RUN_ID}"}\'',
        env: { DATABASE_URL: 'postgres://watson/run-db' },
      });
      assert.equal(seeded.json.ok, true, JSON.stringify(seeded.json));
      assert.deepEqual(seeded.json.vars, { seasonId: 's1', runId: 'run-42' });

      await call('/teardown', {});
    });
  });

  test('a seed that emits unparseable output fails loudly rather than yielding empty vars', async () => {
    // Silently returning `{}` would make every journey's `${var}` interpolate to
    // nothing, and the failures would be reported against the product.
    await withPlane(async ({ call }) => {
      await call('/launch', { runId: 'r', install: [], provision: [], build: [], launch: 'sleep 5', env: {} });
      const { json } = await call('/seed', { runId: 'r', seed: 'echo not-json', env: {} });
      assert.equal(json.ok, false);
      assert.equal(json.phase, 'seed');
      assert.match(json.message, /did not emit parseable JSON/);
      await call('/teardown', {});
    });
  });

  test('it has no endpoint that reports readiness', async () => {
    // THE ASYMMETRY. The verifier polls the PRODUCT's own health endpoint across
    // the network; it never asks the plane whether the product is ready. If this
    // ever grows a `/ready`, the product gains a way to tell the verifier that a
    // world exists which does not.
    await withPlane(async ({ call }) => {
      for (const route of ['/ready', '/health', '/healthz', '/status']) {
        const { status } = await call(route);
        assert.equal(status, 404, `${route} must not exist on the product plane`);
      }
    });
  });

  test('an oversized body is refused rather than read', async () => {
    await withPlane(async ({ url }) => {
      const res = await fetch(`${url}/launch`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: 'x'.repeat(1_100_000),
      });
      const json = await res.json();
      assert.equal(json.ok, false);
      assert.match(json.message, /too large/);
    });
  });
});

describe('the plane costs the untrusted side nothing to start', () => {
  // A regression guard with real consequences. The product container runs the
  // plane from a READ-ONLY engine mount with no install of its own. One
  // third-party import here turns that into "the untrusted side needs a
  // node_modules tree", which means somebody has to provide and maintain a
  // writable dependency surface on the wrong side of the boundary.
  const IMPORT_RE = /^\s*import\s+(?:[^'"]*?\sfrom\s+)?['"]([^'"]+)['"]/gm;

  for (const file of ['../src/plane.mjs', '../src/exec.mjs', '../src/fingerprint.mjs']) {
    test(`${file} imports only node built-ins and engine-local modules`, () => {
      const src = fs.readFileSync(new URL(file, import.meta.url), 'utf8');
      const specifiers = [...src.matchAll(IMPORT_RE)].map((m) => m[1]);
      assert.ok(specifiers.length > 0, 'no imports found — the regex is probably wrong');
      const foreign = specifiers.filter((sp) => !sp.startsWith('node:') && !sp.startsWith('./'));
      assert.deepEqual(foreign, [], `third-party imports reached the untrusted plane: ${foreign.join(', ')}`);
    });
  }

  for (const file of ['../src/exec.mjs', '../src/fingerprint.mjs']) {
    test(`${file}, which the plane pulls in, is itself built-ins only`, () => {
      const src = fs.readFileSync(new URL(file, import.meta.url), 'utf8');
      const specifiers = [...src.matchAll(IMPORT_RE)].map((m) => m[1]);
      assert.deepEqual(specifiers.filter((sp) => !sp.startsWith('node:')), []);
    });
  }

  test('the plane states which checkout it is about to build', async () => {
    await withPlane(async ({ call }) => {
      const { json } = await call('/alive');
      assert.ok('tree' in json, '/alive must report the plane\'s own tree so a mismatch is detectable');
    });
  });
});
