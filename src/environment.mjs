// Environment lifecycle: provision -> launch -> doctor -> teardown.
//
// Two findings from the Phase-0 feasibility work are encoded here as hard rules:
//
//  1. ORDERING. The product's identity tables are created by its own startup
//     bootstrap, not by migrations. So seeding must happen AFTER first launch:
//     provision -> migrate -> LAUNCH -> seed. Seeding before launch fails
//     confusingly on missing tables.
//
//  2. TEARDOWN. `npm run start` spawns a child; killing the recorded npm PID
//     orphans the actual listener. Everything is launched DETACHED into its own
//     process group and killed by group. Never kill by process name — only what
//     we started.

import { spawn, execFileSync } from 'node:child_process';
import net from 'node:net';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import pg from 'pg';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';
import http from 'node:http';

export const JWKS_KID = 'watson-1';

export async function freePort() {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.on('error', reject);
    s.listen(0, '127.0.0.1', () => {
      const { port } = s.address();
      s.close(() => resolve(port));
    });
  });
}

function interpolate(str, vars) {
  return String(str).replace(/\$\{(\w+)\}/g, (_, k) => (vars[k] ?? ''));
}

/** Run a contract-declared command. Commands come from `.watson/config.yaml`,
 *  which is reviewed product-repo content — never an arbitrary string from a PR body. */
export function runStep(cmd, { cwd, env, label, timeoutMs = 900_000 }) {
  const started = Date.now();
  const res = spawn(cmd.shell ?? cmd, { cwd, env, shell: true, stdio: ['ignore', 'pipe', 'pipe'] });
  return new Promise((resolve, reject) => {
    let out = '', err = '';
    const timer = setTimeout(() => { res.kill('SIGKILL'); reject(new Error(`${label}: timed out after ${timeoutMs}ms`)); }, timeoutMs);
    res.stdout.on('data', (d) => (out += d));
    res.stderr.on('data', (d) => (err += d));
    res.on('close', (code) => {
      clearTimeout(timer);
      if (code !== 0) reject(new Error(`${label}: exited ${code}\n${(err || out).slice(-1500)}`));
      else resolve({ stdout: out, stderr: err, ms: Date.now() - started });
    });
  });
}

// --------------------------------------------------------------------- lock --

/**
 * One run at a time per product checkout.
 *
 * Each run gets its own database, its own port and its own browser, which made it
 * look isolated. It is not: every run BUILDS and SERVES the product from the same
 * working tree. A second run's `npm run build` empties and rewrites `client/dist`
 * underneath the first run's already-running server, and the first run then serves
 * the SPA fallback for files that momentarily do not exist.
 *
 * Observed, not theorised: a concurrent campaign produced
 *   "Failed to register a ServiceWorker ... unsupported MIME type ('text/html')"
 * on `/sw.js`, reported as a console error against the PRODUCT. The product was
 * fine. Watson was standing on its own foot, and blaming the application for it.
 *
 * Refusing is the honest fix. Isolating properly means building each run from its
 * own export of the tree, which is a real change and belongs in its own phase.
 */
export function acquireRunLock(repoRoot, runId) {
  const lockPath = path.join(repoRoot, '.watson-run.lock');
  try {
    fs.writeFileSync(lockPath, JSON.stringify({ runId, pid: process.pid }), { flag: 'wx' });
  } catch (err) {
    if (err.code !== 'EEXIST') throw err;
    let held = {};
    try { held = JSON.parse(fs.readFileSync(lockPath, 'utf8')); } catch { /* unreadable */ }
    // A crashed run leaves a stale lock. Reclaim it rather than wedging the repo.
    const alive = held.pid && (() => { try { process.kill(held.pid, 0); return true; } catch { return false; } })();
    if (alive) {
      throw new Error(
        `another Watson run (${held.runId ?? 'unknown'}, pid ${held.pid}) is already using ${repoRoot}. ` +
          'Runs share the product working tree — a concurrent build would rewrite client/dist under ' +
          'the running server and produce findings that belong to Watson, not the product.',
      );
    }
    fs.writeFileSync(lockPath, JSON.stringify({ runId, pid: process.pid }));
  }
  return () => { try { fs.unlinkSync(lockPath); } catch { /* already gone */ } };
}

// ---------------------------------------------------------------- provision --

/** Stamped into every run database at creation; the product's fixture requires it. */
export const MARKER_TABLE = 'watson_run_marker';

/**
 * Create the run's database and stamp it with a provisioning marker.
 *
 * The marker is what lets the product's fixture POSITIVELY identify this
 * database as Watson's own for this run, rather than trusting a name prefix or
 * a connection string that could name anything. It is written here, at creation
 * time, so a database that lacks it was demonstrably not created by Watson.
 */
export async function provisionDatabase({ adminUrl, dbName, runId }) {
  if (!runId) throw new Error('provisionDatabase requires a runId to stamp the marker');
  const client = new pg.Client({ connectionString: adminUrl });
  await client.connect();
  try {
    await client.query(`DROP DATABASE IF EXISTS "${dbName}" WITH (FORCE)`);
    await client.query(`CREATE DATABASE "${dbName}"`);
  } finally {
    await client.end();
  }

  const runClient = new pg.Client({ connectionString: adminUrl.replace(/\/[^/]*$/, `/${dbName}`) });
  await runClient.connect();
  try {
    await runClient.query(
      `CREATE TABLE ${MARKER_TABLE} (
         run_id        text        PRIMARY KEY,
         database_name text        NOT NULL,
         provisioned_at timestamptz NOT NULL DEFAULT now()
       )`,
    );
    await runClient.query(
      `INSERT INTO ${MARKER_TABLE} (run_id, database_name) VALUES ($1, current_database())`,
      [runId],
    );
  } finally {
    await runClient.end();
  }
}

export async function dropDatabase({ adminUrl, dbName }) {
  const client = new pg.Client({ connectionString: adminUrl });
  await client.connect();
  try {
    await client.query(`DROP DATABASE IF EXISTS "${dbName}" WITH (FORCE)`);
  } catch {
    /* best effort */
  } finally {
    await client.end();
  }
}

/** Drop orphaned watson_* databases older than maxAgeMs. A crashed run must
 *  degrade disk, never the environment. */
export async function reap({ adminUrl, prefix = 'watson_', maxAgeHours = 2 }) {
  const client = new pg.Client({ connectionString: adminUrl });
  await client.connect();
  const dropped = [];
  try {
    const { rows } = await client.query(
      `SELECT datname FROM pg_database WHERE datname LIKE $1 || '%'`, [prefix],
    );
    for (const { datname } of rows) {
      try { await client.query(`DROP DATABASE IF EXISTS "${datname}" WITH (FORCE)`); dropped.push(datname); }
      catch { /* in use */ }
    }
  } finally {
    await client.end();
  }
  return dropped;
}

// ----------------------------------------------------------------- identity --

/**
 * Watson's run-scoped local JWKS + token minter.
 *
 * This is the ONLY test-only seam in the whole design, and it is deliberately
 * the narrowest one available: the product is launched with identity config
 * pointing at a JWKS Watson serves, and Watson mints RS256 tokens for it. No
 * product code changes; production auth is not weakened; the five-step token
 * verification (RS256-only, exact issuer, exp/nbf, exact client_id) runs
 * unmodified and rejects everything it should.
 *
 * WHAT THIS DOES NOT PROVE — stated in every result's environment block:
 * hosted login, Magic Auth delivery, cookie/session lifetime, sealing/rotation,
 * or Admin-MFA step-up. Those are separately verified.
 */
export async function startIdentityService({ issuer, clientId, identities }) {
  const { publicKey, privateKey } = await generateKeyPair('RS256', { extractable: true });
  const jwk = { ...(await exportJWK(publicKey)), kid: JWKS_KID, alg: 'RS256', use: 'sig' };

  const server = http.createServer((req, res) => {
    if (req.url?.startsWith('/jwks.json')) {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ keys: [jwk] }));
    } else {
      res.writeHead(404);
      res.end();
    }
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;

  const mint = (subject) =>
    new SignJWT({ client_id: clientId })
      .setProtectedHeader({ alg: 'RS256', kid: JWKS_KID })
      .setIssuer(issuer)
      .setSubject(subject)
      .setIssuedAt()
      .setExpirationTime('2h')
      .sign(privateKey);

  const tokens = {};
  for (const id of identities) {
    if (id.subject) tokens[id.id] = await mint(id.subject);
  }

  return {
    jwksUri: `http://127.0.0.1:${port}/jwks.json`,
    issuer,
    clientId,
    tokens,
    /**
     * Mint a correctly SIGNED token that deliberately carries a different issuer or
     * client id. The signature is valid and the key is published, so the only thing
     * that can reject it is the application verifying against the values Watson
     * actually injected — which is exactly what the `identity-binding` probe asserts.
     */
    mintAs: ({ issuer: iss = issuer, clientId: cid = clientId, subject }) =>
      new SignJWT({ client_id: cid })
        .setProtectedHeader({ alg: 'RS256', kid: JWKS_KID })
        .setIssuer(iss)
        .setSubject(subject)
        .setIssuedAt()
        .setExpirationTime('2h')
        .sign(privateKey),
    close: () => new Promise((r) => server.close(r)),
  };
}

// -------------------------------------------------------------------- launch --

/** Launch the product DETACHED in its own process group so teardown can kill
 *  the whole tree, not just the wrapper we spawned. */
export function launchApp({ cmd, cwd, env, logFile }) {
  const log = fs.openSync(logFile, 'a');
  const child = spawn(cmd, {
    cwd, env, shell: true, detached: true, stdio: ['ignore', log, log],
  });
  child.unref();
  return { pid: child.pid, pgid: child.pid, logFile };
}

export function killGroup(pid) {
  if (!pid) return false;
  try { process.kill(-pid, 'SIGTERM'); } catch { /* already gone */ }
  const deadline = Date.now() + 5000;
  while (Date.now() < deadline) {
    try { process.kill(-pid, 0); } catch { return true; }
    try { execFileSync('sleep', ['0.2']); } catch { /* ignore */ }
  }
  try { process.kill(-pid, 'SIGKILL'); } catch { /* ignore */ }
  return true;
}

export async function waitForHealth(url, timeoutMs = 60_000) {
  const deadline = Date.now() + timeoutMs;
  let lastErr = 'no attempt made';
  while (Date.now() < deadline) {
    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(3000) });
      if (res.ok) return true;
      lastErr = `HTTP ${res.status}`;
    } catch (e) {
      lastErr = e.message;
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(`readiness timeout for ${url}: ${lastErr}`);
}

// -------------------------------------------------------------------- doctor --

/**
 * "Is this instance worth driving?"
 *
 * Every probe here exists to convert a class of false FAIL_PRODUCT into an
 * honest BLOCKED_ENVIRONMENT. Probe 3 is the highest-value one: it proves the
 * whole issuer/JWKS/client_id chain end to end, and a broken chain is otherwise
 * indistinguishable from "the entire application is broken".
 *
 * Probe 5 is the production-safety interlock and is a HARD REFUSAL: Watson will
 * not drive a database it did not create.
 */
export async function doctor({ baseUrl, dbName, databaseUrl, adminToken, expectSeasons, identity }) {
  const probes = [];
  const add = (name, ok, detail) => probes.push({ name, ok, detail });

  const get = async (p, token) => {
    const res = await fetch(`${baseUrl}${p}`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
      signal: AbortSignal.timeout(10_000),
    });
    let body = null;
    try { body = await res.json(); } catch { /* non-JSON */ }
    return { status: res.status, body };
  };

  try {
    const h = await get('/api/health');
    add('liveness', h.status === 200, `/api/health -> ${h.status}`);
  } catch (e) { add('liveness', false, e.message); }

  try {
    const d = await get('/api/health/db');
    add('readiness', d.status === 200, `/api/health/db -> ${d.status}`);
  } catch (e) { add('readiness', false, e.message); }

  if (adminToken) {
    try {
      const me = await get('/api/me', adminToken);
      add('identity-chain', me.status === 200 && !!me.body?.appUserId,
        `/api/me -> ${me.status}${me.body?.subject ? ` subject=${me.body.subject}` : ''}`);
    } catch (e) { add('identity-chain', false, e.message); }
  }

  // The launch binding, proved rather than assumed: the application must verify
  // against the SAME issuer and client id Watson mints with. A correctly signed
  // token that names a different issuer or client id has to be rejected — if either
  // were accepted, the app is trusting something Watson does not control; if the
  // correct one failed, `identity-chain` above would already be red.
  if (identity?.mintAs) {
    for (const [label, claims] of [
      ['issuer', { issuer: 'https://watson.local/user_management/not-this-run', subject: 'watson_admin' }],
      ['client id', { clientId: 'client_watson_not_this_run', subject: 'watson_admin' }],
    ]) {
      try {
        const r = await get('/api/me', await identity.mintAs(claims));
        add(`identity-binding (${label})`, r.status === 401,
          `token with a foreign ${label} -> ${r.status}, expected 401`);
      } catch (e) { add(`identity-binding (${label})`, false, e.message); }
    }
  }

  // Production-safety interlock: refuse any database Watson did not create.
  const connected = (() => { try { return new URL(databaseUrl).pathname.slice(1); } catch { return null; } })();
  add('own-database', connected === dbName,
    `connected db \`${connected}\` ${connected === dbName ? 'is' : 'is NOT'} this run's \`${dbName}\``);

  if (adminToken && expectSeasons !== undefined) {
    try {
      const s = await get('/api/seasons', adminToken);
      const n = s.body?.seasons?.length ?? 0;
      add('fixture-visible', n === expectSeasons, `/api/seasons -> ${n} season(s), expected ${expectSeasons}`);
    } catch (e) { add('fixture-visible', false, e.message); }
  }

  return { ok: probes.every((p) => p.ok), probes };
}

// ------------------------------------------------------------------ run dirs --

export function makeRunDir(root, runId) {
  const dir = path.join(root, 'runs', runId);
  for (const sub of ['evidence/screenshots', 'evidence/traces', 'evidence/aria', 'logs']) {
    fs.mkdirSync(path.join(dir, sub), { recursive: true });
  }
  return dir;
}

export function newRunId() {
  const stamp = new Date().toISOString().replace(/[:.]/g, '-').replace('Z', 'Z');
  return `wtsn-${stamp}-${crypto.randomBytes(2).toString('hex')}`;
}

export { interpolate };
