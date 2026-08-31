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
import os from 'node:os';
import crypto from 'node:crypto';
import url from 'node:url';
import { isAuthorized as isAuthorizedStatus, browserSandbox } from './driver.mjs';
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

// ------------------------------------------------------- product execution --
//
// Everything in this section exists because of one sentence: Watson executes the
// PRODUCT'S OWN commands — install, build, launch, seed — and under the threat
// model that matters (a pull request whose code may be hostile), those commands
// are written by the same author whose work Watson is judging.
//
// That is not a reason to stop running them; running the real product is the
// entire point. It is a reason to be exact about what they can REACH. Two things
// must hold, and neither is achieved by putting files in different directories:
//
//   1. product code must not be able to write the verifier, its evidence, or
//      anything the trusted side later reads as a result;
//   2. product code must not inherit the credentials and command channels of
//      whatever CI system invoked Watson.
//
// (1) is a process-model property, enforced below by dropping to a separate,
// unprivileged uid. (2) is an environment property, enforced below by removing a
// named set of variables before the environment is handed over.

/**
 * Variables removed from the environment of every product-authored command.
 *
 * Two kinds, and the second is the one that is easy to miss:
 *
 *   CREDENTIALS — `ACTIONS_RUNTIME_TOKEN` and friends are live tokens for the
 *   artifact and cache services. They are not "CI plumbing"; they are bearer
 *   credentials that happen to be sitting in the environment.
 *
 *   COMMAND CHANNELS — `GITHUB_ENV`, `GITHUB_PATH`, `GITHUB_OUTPUT` and
 *   `GITHUB_STATE` name FILES that the runner reads back after a step. Anything
 *   that can append to them injects environment variables and PATH entries into
 *   the steps that follow, which is a direct path from the code being verified
 *   into the trusted side that verifies it.
 *
 * An explicit list, not a pattern. A regex over TOKEN/SECRET/KEY would also eat
 * the placeholder credentials the contract deliberately supplies, and a scrub
 * that silently removes something the product needs produces a confusing
 * BLOCKED_ENVIRONMENT instead of a security property.
 */
export const SCRUBBED_ENV_KEYS = Object.freeze([
  'ACTIONS_RUNTIME_TOKEN', 'ACTIONS_RUNTIME_URL', 'ACTIONS_RESULTS_URL', 'ACTIONS_CACHE_URL',
  'ACTIONS_ID_TOKEN_REQUEST_TOKEN', 'ACTIONS_ID_TOKEN_REQUEST_URL',
  'GITHUB_TOKEN', 'GH_TOKEN', 'NPM_TOKEN', 'NODE_AUTH_TOKEN',
  'GITHUB_ENV', 'GITHUB_PATH', 'GITHUB_OUTPUT', 'GITHUB_STATE', 'GITHUB_STEP_SUMMARY',
]);

export function scrubEnv(env = {}) {
  const out = { ...env };
  for (const k of SCRUBBED_ENV_KEYS) delete out[k];
  return out;
}

/**
 * How product-authored commands are executed: as this process, or as a separate
 * unprivileged user.
 *
 * Opt-in and FAIL-CLOSED. Local development runs as the developer, which is
 * correct — there is no boundary to enforce between you and your own code. A
 * caller that ASKS for separation and cannot get it must not silently get the
 * unseparated behaviour instead: that is precisely the failure mode where a
 * security property is believed to hold and does not.
 *
 * `setpriv` rather than `su`/`runuser`: it is a thin wrapper over the syscalls
 * with no PAM session, so it works in a minimal image, and it is invoked with an
 * argv ARRAY — the product's command string is never interpolated into another
 * shell, only passed as a single argument to `/bin/sh -c`.
 */
let POLICY_CACHE = null;
/** Test seam: forget the resolved policy so a test can vary the environment. */
export function resetProductExecution() { POLICY_CACHE = null; }

export function productExecution(environ = process.env) {
  if (environ === process.env && POLICY_CACHE) return POLICY_CACHE;
  const remember = (p) => { if (environ === process.env) POLICY_CACHE = p; return p; };

  const uid = environ.WATSON_PRODUCT_UID;
  if (!uid) return remember({ drop: false });

  const fail = (why) => {
    throw new Error(
      `WATSON_PRODUCT_UID is set, so product commands must run unprivileged, but ${why}. ` +
        'Refusing to run product code with the verifier\'s own privileges.',
    );
  };
  const gid = environ.WATSON_PRODUCT_GID;
  const home = environ.WATSON_PRODUCT_HOME;
  if (!/^\d+$/.test(uid)) fail(`WATSON_PRODUCT_UID=${uid} is not a numeric uid`);
  if (!gid || !/^\d+$/.test(gid)) fail('WATSON_PRODUCT_GID is missing or not a numeric gid');
  if (!home) fail('WATSON_PRODUCT_HOME is not set (product tooling needs a writable HOME)');
  if (typeof process.getuid === 'function' && process.getuid() !== 0) {
    fail('this process is not root and therefore cannot change uid');
  }
  try {
    execFileSync('setpriv', ['--help'], { stdio: 'ignore' });
  } catch {
    fail('`setpriv` is not available on PATH');
  }
  return remember({ drop: true, uid, gid, home });
}

/** Build the argv for one product command under the current execution policy. */
function productArgv(cmdStr, policy) {
  if (!policy.drop) return { file: '/bin/sh', args: ['-c', cmdStr] };
  return {
    file: 'setpriv',
    args: [
      `--reuid=${policy.uid}`, `--regid=${policy.gid}`, '--init-groups',
      // Once dropped, nothing this command runs may regain privilege through a
      // setuid binary. Without it the boundary lasts only until the first
      // setuid helper on the image.
      '--no-new-privs',
      '--', '/bin/sh', '-c', cmdStr,
    ],
  };
}

/** The environment a product command actually receives. */
function productEnv(env, policy) {
  const scrubbed = scrubEnv(env);
  if (!policy.drop) return scrubbed;
  // HOME is not cosmetic here: npm, playwright and most build tooling write
  // caches into it, and root's home is unwritable by the dropped user.
  return { ...scrubbed, HOME: policy.home, USER: `uid-${policy.uid}`, LOGNAME: `uid-${policy.uid}` };
}

/** Run a contract-declared command. Commands come from `.watson/config.yaml`,
 *  which is reviewed product-repo content — never an arbitrary string from a PR body.
 *
 *  Reviewed, but under the PR threat model still authored by the change being
 *  verified, so it runs under `productExecution()` policy like everything else. */
export function runStep(cmd, { cwd, env, label, timeoutMs = 900_000, policy = productExecution() }) {
  const started = Date.now();
  const { file, args } = productArgv(cmd.shell ?? cmd, policy);
  const res = spawn(file, args, { cwd, env: productEnv(env, policy), stdio: ['ignore', 'pipe', 'pipe'] });
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
export function acquireRunLock(repoRoot, runId, lockDir = path.join(os.tmpdir(), 'watson-locks')) {
  // The lock lives OUTSIDE the product checkout, keyed on its absolute path.
  //
  // It used to live at `<repoRoot>/.watson-run.lock`, which was wrong twice over.
  // ADR-039 D6 says Watson never writes to the product repository during a run, and
  // this wrote to it. And because the file was untracked, it made the working tree
  // dirty — so the very lock that stops runs corrupting each other tripped the
  // exact-HEAD gate and withheld every verdict. A verifier that cannot run without
  // dirtying the thing it verifies has no business claiming exactness.
  fs.mkdirSync(lockDir, { recursive: true });
  const key = crypto.createHash('sha256').update(path.resolve(repoRoot)).digest('hex').slice(0, 16);
  const lockPath = path.join(lockDir, `${key}.lock`);
  try {
    fs.writeFileSync(lockPath, JSON.stringify({ runId, pid: process.pid, repoRoot }), { flag: 'wx' });
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
    fs.writeFileSync(lockPath, JSON.stringify({ runId, pid: process.pid, repoRoot }));
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
    // Free: the connection is already open. Which server actually stored the
    // fixtures is part of what a runtime verdict was produced against.
    const v = await runClient.query('SHOW server_version');
    return { serverVersion: v.rows?.[0]?.server_version ?? null };
  } finally {
    await runClient.end();
  }
}

/**
 * What executed this run. Cheap, synchronous, and deliberately modest: it names
 * the components, it does not promise they can be reassembled.
 */
export function executionProvenance(policy = productExecution()) {
  let playwright = null;
  try {
    playwright = JSON.parse(
      fs.readFileSync(path.join(path.dirname(url.fileURLToPath(import.meta.url)), '..', 'package.json'), 'utf8'),
    ).dependencies?.playwright ?? null;
  } catch { /* engine package.json unreadable; not worth failing a run over */ }
  return {
    node: process.version,
    platform: `${process.platform}/${process.arch}`,
    os_release: os.release(),
    playwright,
    // Recorded because it varies with HOW Watson was deployed, and a reader
    // assessing an unexpected verdict deserves to know which protections the run
    // actually had. See `browserSandbox()` for why root implies false.
    browser_sandbox: browserSandbox(),
    database_server_version: null,
    // The security-relevant half: whether product-authored commands actually ran
    // as a different, unprivileged user, or as the verifier itself. A result that
    // does not say which of those happened cannot be assessed for trust.
    product_privilege_separated: policy.drop === true,
    product_uid: policy.drop ? Number(policy.uid) : null,
    // CI provenance, when a CI system supplied it. Read-only labels; nothing here
    // is trusted for a decision.
    ci: process.env.GITHUB_ACTIONS === 'true'
      ? {
          provider: 'github-actions',
          runner_image: process.env.ImageOS ?? null,
          runner_os: process.env.RUNNER_OS ?? null,
          workflow_ref: process.env.GITHUB_WORKFLOW_REF ?? null,
          event_name: process.env.GITHUB_EVENT_NAME ?? null,
          run_id: process.env.GITHUB_RUN_ID ?? null,
          run_attempt: process.env.GITHUB_RUN_ATTEMPT ?? null,
        }
      : null,
  };
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

/**
 * Drop watson_* databases left behind by crashed runs. A crash must degrade disk,
 * never the environment.
 *
 * Three things it refuses to drop, because `reap` is destructive and was previously
 * indiscriminate — it declared a `maxAgeHours` parameter and never read it, so it
 * dropped every watson_* database it could see, including live ones:
 *   - anything with an open connection (a run in progress)
 *   - anything younger than maxAgeHours, read from its own provisioning marker
 *   - anything with no marker at all, which Watson did not create
 *
 * Returns { dropped, kept } — kept carries a reason per database, so a reap that
 * removes nothing explains itself instead of looking broken.
 */
export async function reap({ adminUrl, prefix = 'watson_', maxAgeHours = 2, now = Date.now() }) {
  const client = new pg.Client({ connectionString: adminUrl });
  await client.connect();
  const dropped = [];
  const kept = [];
  try {
    // Skip any database with a live backend. `DROP ... WITH (FORCE)` would happily
    // terminate those connections, which is precisely the accident this guards:
    // reaping while a verification is running would kill that run's database
    // mid-journey and the run would report a product failure.
    const { rows } = await client.query(
      `SELECT d.datname,
              (SELECT count(*) FROM pg_stat_activity a WHERE a.datname = d.datname) AS conns
         FROM pg_database d
        WHERE d.datname LIKE $1 || '%'`,
      [prefix],
    );
    for (const { datname, conns } of rows) {
      if (Number(conns) > 0) { kept.push({ datname, why: `${conns} live connection(s)` }); continue; }

      // Age comes from the run's own provisioning marker. Postgres does not record
      // a database's creation time, so without the marker there is nothing to
      // compare against — and a database with no marker was not created by Watson,
      // which is reason to leave it alone rather than reason to drop it.
      let provisionedAt = null;
      const probe = new pg.Client({ connectionString: adminUrl.replace(/\/[^/]*$/, `/${datname}`) });
      try {
        await probe.connect();
        const m = await probe.query(
          `SELECT provisioned_at FROM ${MARKER_TABLE} ORDER BY provisioned_at LIMIT 1`,
        );
        provisionedAt = m.rows[0]?.provisioned_at ?? null;
      } catch {
        provisionedAt = null;
      } finally {
        await probe.end().catch(() => {});
      }

      if (!provisionedAt) { kept.push({ datname, why: 'no Watson provisioning marker' }); continue; }
      const ageHours = (now - new Date(provisionedAt).getTime()) / 3_600_000;
      if (ageHours < maxAgeHours) {
        kept.push({ datname, why: `only ${ageHours.toFixed(1)}h old (threshold ${maxAgeHours}h)` });
        continue;
      }

      try {
        await client.query(`DROP DATABASE IF EXISTS "${datname}" WITH (FORCE)`);
        dropped.push(datname);
      } catch (err) {
        kept.push({ datname, why: err.message });
      }
    }
  } finally {
    await client.end();
  }
  return { dropped, kept };
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
 * hosted identity-provider login, passwordless delivery, cookie/session
 * lifetime, session sealing and rotation, or step-up MFA. Those are separately
 * verified. Named generically for the same reason as the result envelope: the
 * engine's semantics do not depend on which identity provider a product uses.
 */
export async function startIdentityService({
  issuer, clientId, identities,
  // Loopback by default: in a single-process run nothing else should be able to
  // reach the JWKS. When the product runs in a separate container it must, so
  // the caller widens the bind and says which name to advertise. The SIGNING KEY
  // never leaves this process either way — only the public JWK is served.
  bindHost = '127.0.0.1', advertiseHost = '127.0.0.1',
} = {}) {
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
  await new Promise((r) => server.listen(0, bindHost, r));
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
    jwksUri: `http://${advertiseHost}:${port}/jwks.json`,
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
export function launchApp({ cmd, cwd, env, logFile, policy = productExecution() }) {
  const log = fs.openSync(logFile, 'a');
  const { file, args } = productArgv(cmd, policy);
  const child = spawn(file, args, {
    cwd, env: productEnv(env, policy), detached: true, stdio: ['ignore', log, log],
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
export async function doctor({ baseUrl, dbName, databaseUrl, adminToken, expectSeasons, identity, preconditions, tokens, vars }) {
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

  // FIXTURE PRECONDITION PROOF (Phase-1 defect W5).
  //
  // Seeding rows successfully is not proof that the fixture represents a valid,
  // REACHABLE product state. The scoring fixture wrote a session, groups, members,
  // a form version and a scoring rule — every insert succeeded — and the feature
  // still did not work, because EF-05 also needs a route. The journey asserting
  // that endpoint was reachable stayed green over a world where it resolved to
  // nothing.
  //
  // So each named profile declares what its rows must RESOLVE TO through the
  // application's own read paths, and those are checked here, before any journey
  // runs. A failure is BLOCKED_ENVIRONMENT: the world the contract asked for could
  // not be established. That is deliberately not FAIL_PRODUCT — the fixture is
  // Watson's — and deliberately not silence.
  for (const [i, pre] of (preconditions ?? []).entries()) {
    const label = `precondition ${i + 1}: ${pre.note ?? pre.get}`;
    try {
      const token = pre.as ? tokens?.[pre.as] : adminToken;
      if (pre.as && !token) { add(label, false, `no token for identity ${pre.as}`); continue; }
      const r = await get(interpolate(pre.get, vars ?? {}), token);
      if (pre.expect?.authorized !== undefined) {
        const ok = isAuthorizedStatus(r.status) === pre.expect.authorized;
        add(label, ok, `${r.status} (expected ${pre.expect.authorized ? 'authorized' : 'denied'})`);
        continue;
      }
      if (pre.expect?.json) {
        const bad = Object.entries(pre.expect.json)
          .filter(([k, v]) => String(r.body?.[k]) !== String(interpolate(String(v), vars ?? {})));
        add(label, bad.length === 0,
          bad.length ? bad.map(([k, v]) => `${k}: wanted ${v}, got ${JSON.stringify(r.body?.[k])}`).join('; ')
                     : Object.keys(pre.expect.json).map((k) => `${k}=${r.body?.[k]}`).join(', '));
        continue;
      }
      if (pre.expect?.count_at) {
        const n = Array.isArray(r.body?.[pre.expect.count_at]) ? r.body[pre.expect.count_at].length : -1;
        add(label, n === pre.expect.equals, `${pre.expect.count_at} -> ${n}, expected ${pre.expect.equals}`);
        continue;
      }
      add(label, false, 'precondition declares no expectation');
    } catch (e) { add(label, false, e.message); }
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
