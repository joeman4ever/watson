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

import net from 'node:net';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import url from 'node:url';
// `interp` rather than `interpolate`: preconditions are ASSERTIONS about the
// product's read paths, and the two differ on an unresolved name — `interpolate`
// substitutes the empty string, which makes a precondition URL collapse to a
// prefix that may well answer 200 and pass vacuously.
import { isAuthorized as isAuthorizedStatus, browserSandbox, BROWSER_CHANNEL, interp } from './driver.mjs';
// Re-exported rather than redefined: product-command execution lives in a
// dependency-free module so the product plane can run it from a read-only
// engine mount without installing anything.
import { interpolate, runStep, launchApp, killGroup, productExecution, resetProductExecution, scrubEnv, SCRUBBED_ENV_KEYS } from './exec.mjs';
import { runTrustedProofs, proveProbeCanFail } from './proofs.mjs';
export { interpolate, runStep, launchApp, killGroup, productExecution, resetProductExecution, scrubEnv, SCRUBBED_ENV_KEYS };
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
    browser_channel: BROWSER_CHANNEL,
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
export async function doctor({
  baseUrl, dbName, databaseUrl, adminToken, expectSeasons, identity, fixtureProfile, tokens, vars,
}) {
  const preconditions = fixtureProfile?.preconditions;
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
      const r = await get(interp(pre.get, vars ?? {}), token);
      if (pre.expect?.authorized !== undefined) {
        const ok = isAuthorizedStatus(r.status) === pre.expect.authorized;
        add(label, ok, `${r.status} (expected ${pre.expect.authorized ? 'authorized' : 'denied'})`);
        continue;
      }
      if (pre.expect?.json) {
        const bad = Object.entries(pre.expect.json)
          .filter(([k, v]) => String(r.body?.[k]) !== String(interp(String(v), vars ?? {})));
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
      // `contains` — the entity is IN the authorized collection this identity can
      // read. This is what makes a product's own read path usable as existence
      // evidence for a name that appears nowhere in a URL: an unassigned group
      // has no admin route of its own, but it is a member of the session's group
      // list, and an administrator may read that list.
      if (pre.expect?.contains) {
        const { at, field, value } = pre.expect.contains;
        const rows = Array.isArray(r.body?.[at]) ? r.body[at] : null;
        const want = interp(String(value ?? ''), vars ?? {});
        const found = !!rows?.some((row) => String(row?.[field]) === want);
        add(label, found, rows === null
          ? `${at} is not a list in the response`
          : `${at}[].${field} ${found ? 'contains' : 'does NOT contain'} the expected value (${rows.length} row(s))`);
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

  // TRUSTED PRECONDITION EVIDENCE (F1).
  //
  // The fixture reporting back a value proves it RECEIVED the value. It does not
  // prove the entity behind it was built, and a denial asserted against an entity
  // that does not exist is satisfied by a product that denies correctly, by one
  // that denies everything, and by one asked about nothing at all.
  //
  // So the engine reads its own database directly, for the values IT chose, using
  // a probe shape the base contract declares. An unestablished proof is a doctor
  // failure, which is BLOCKED_ENVIRONMENT — the world the journeys assert on was
  // not shown to exist, so there is no product verdict to give.
  //
  // WHO CONTROLS WHAT:
  //   value        the trusted verifier (`verifier_chosen`)
  //   probe shape  the BASE contract, not the pull request under test
  //   connection   this function, from the run's own `databaseUrl`, and only
  //                after `own-database` has established it is the run's own
  //                database. Watson does not read a database it did not create,
  //                and that interlock is not weakened to run a proof.
  const trustedProofs = (fixtureProfile?.proofs ?? []).filter((p) => p?.source === 'trusted_setup');
  if (trustedProofs.length) {
    if (connected !== dbName) {
      add('trusted-proof', false, 'refusing to read a database this run did not create');
    } else {
      // Bounded, because an unestablished proof must FAIL the run and a hung one
      // never does. Found by the negative control for the interlock above: with
      // that check removed the connection attempt blocked indefinitely instead
      // of erroring, and the same would happen to a legitimate run whose own
      // database stopped answering.
      const client = new pg.Client({
        connectionString: databaseUrl,
        connectionTimeoutMillis: 10_000,
        statement_timeout: 10_000,
      });
      try {
        await client.connect();
        const query = (sql, params) => client.query(sql, params);

        // The probe must be shown capable of answering NO before any YES from it
        // is worth anything. A probe that always says yes makes every proof below
        // pass and the whole mechanism decoration.
        for (const p of trustedProofs) {
          const control = await proveProbeCanFail(query, p.probe, vars?.[p.subject]);
          add(`proof-control ${p.subject}`, control.ok, control.detail);
        }

        for (const ev of await runTrustedProofs(query, { proofs: trustedProofs }, vars ?? {})) {
          add(`proof ${ev.type} ${ev.subject}`, ev.established, ev.detail);
        }
      } catch (e) {
        add('trusted-proof', false, `could not read the run's own database: ${e.message}`);
      } finally {
        await client.end().catch(() => {});
      }
    }
  }

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

