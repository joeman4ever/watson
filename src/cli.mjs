#!/usr/bin/env node
// Watson CLI — Phase 0.
//
//   watson verify --repo <path> [--sha <ref>] [--profile poc] [--base <ref>] [--out <file>]
//   watson doctor --repo <path>            (bring up, probe, tear down)
//   watson reap                            (drop orphaned watson_* databases)
//
// Watson NEVER modifies product code. During a verification run it does not
// edit anything in the product checkout — not source, not the feature map.

import fs from 'node:fs';
import path from 'node:path';
import url from 'node:url';

import {
  loadContract, selectByProfile, withDependencies,
  validateFeatureVars, validateEnvOwnership, validateBrowserOwnership, validateContractVersion, validateStepOrder,
  validateAssertionOperands, validateDenialProofs, validateReachedConditions,
  fixtureValues, fixtureValueEnv, reconcileFixtureValues,
  normaliseChosen,
} from './contract.mjs';
import { validateProofDeclarations } from './proofs.mjs';
import { resolveGovernance, downgradeForUngovernedContract } from './governance.mjs';
import { productFingerprint, contractFingerprint, resolveSha, contractChange, productIdentity, changedPaths, engineProvenance, verdictBearingPaths, pathExistsAt, pathReaderAt, operationalConfigChange } from './fingerprint.mjs';
import { readManifest, contractDirFingerprint, walkTree } from './manifest.mjs';
import { runManifest } from './manifest-cli.mjs';
import { selectByImpact } from './selection.mjs';
import * as env from './environment.mjs';
import * as drive from './driver.mjs';
import * as plane from './plane.mjs';
import { evaluate, featureVerdict } from './checks.mjs';
import { buildEnvelope, runVerdict, writeResult, summary, downgradeForInexactHead,
  WITHHELD_WITHOUT_GOVERNANCE } from './result.mjs';

const HERE = path.dirname(url.fileURLToPath(import.meta.url));
const ROOT = path.join(HERE, '..');
const VERSION = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8')).version;

function parseArgs(argv) {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const k = a.slice(2);
      const v = argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[++i] : true;
      out[k] = v;
    } else out._.push(a);
  }
  return out;
}

const log = (...a) => console.log(...a);
const step = (m) => console.log(`  · ${m}`);

/**
 * The environment the product is launched with.
 *
 * `inherit` decides whether the verifier's own environment is passed through.
 * In a single-process run it is, because the product legitimately needs the
 * developer's PATH and toolchain. Across a plane boundary it is NOT: sending the
 * verifier's environment over the network to the untrusted side would hand the
 * product every variable the verifier happens to hold, which is the opposite of
 * what the boundary is for. The product plane merges what it receives into its
 * OWN environment, where the product's toolchain already lives.
 */
function buildAppEnv({ cfg, runId, databaseUrl, appPort, baseUrl, identity, inherit }) {
  const appEnv = {
    ...(inherit ? process.env : {}),
    DATABASE_URL: databaseUrl,
    PORT: String(appPort),
    WORKOS_ISSUER: identity.issuer,
    WORKOS_CLIENT_ID: identity.clientId,
    WORKOS_JWKS_URI: identity.jwksUri,
    WORKOS_REDIRECT_URI: `${baseUrl}/auth/callback`,
    SESSION_SEALING_KEY_CURRENT: 'w'.repeat(48),
    WORKOS_API_KEY: 'sk_watson_local_placeholder_not_a_real_key',
  };

  // The contract's `env` may reference run-scoped values the engine owns, as
  // ${WATSON_*} placeholders. Substitute them and FAIL CLOSED on any that is
  // left unresolved: launching a half-configured application would let the
  // identity seam fall back to an ambient key source or stay unmounted, and the
  // run would then "verify" an app whose guarded routes never mounted.
  const injected = {
    WATSON_JWKS_URI: identity.jwksUri,
    WATSON_BASE_URL: baseUrl,
    WATSON_DATABASE_URL: databaseUrl,
    WATSON_PORT: String(appPort),
    WATSON_RUN_ID: runId,
  };
  for (const [key, raw] of Object.entries(cfg.env ?? {})) {
    // Deliberately NOT the general interpolate(): that substitutes an unknown
    // name with an empty string, which here would hand the application an empty
    // WORKOS_JWKS_URI. The identity seam would then read as "not configured",
    // the guarded routes would never mount, and the run would fail much later
    // with an unrelated-looking error. Resolve explicitly and throw on a miss.
    appEnv[key] = String(raw).replace(/\$\{(WATSON_\w+)\}/g, (_, name) => {
      if (!(name in injected)) {
        throw new Error(
          `.watson/config.yaml env.${key} references \${${name}}, which the engine does not supply. ` +
            `Known injected values: ${Object.keys(injected).join(', ')}.`,
        );
      }
      return injected[name];
    });
  }
  return appEnv;
}

/**
 * Reconcile what the fixture emitted with what the verifier supplied.
 *
 * The verifier's values WIN, always — that is the point of supplying them. The
 * emitted value is compared only to notice a fixture that ignored what it was
 * given, which is a broken world rather than a product defect: the entity
 * Watson's journeys are about to assert on does not carry the name Watson
 * chose, so the assertions would fail for a reason that has nothing to do with
 * the product's behaviour.
 */
/** Bring the product up exactly as Watson will drive it. Returns a handle whose
 *  `teardown()` kills only what we started, by process group. */
async function bringUp({ repoRoot, contract, runDir, runId, adminUrl, policy }) {
  const cfg = contract.config;
  const dbName = `watson_${runId.replace(/[^a-z0-9]/gi, '').slice(-16).toLowerCase()}`;
  const appPort = await env.freePort();
  const started = {};
  const timings = {};
  let dbServerVersion = null;

  const teardown = async () => {
    if (started.app) env.killGroup(started.app.pid);
    if (started.identity) await started.identity.close().catch(() => {});
    if (started.dbCreated) await env.dropDatabase({ adminUrl, dbName }).catch(() => {});
    // Released LAST: the lock must outlive the server it protects, or the next
    // run's build can start while this one is still shutting down.
    if (started.releaseLock) started.releaseLock();
  };

  try {
    // 0. LOCK ------------------------------------------------------------------
    // Before anything: runs share the product working tree, so two at once
    // corrupt each other's build. Refuse rather than produce findings that
    // belong to Watson rather than to the product.
    started.releaseLock = env.acquireRunLock(repoRoot, runId);

    // 0. INSTALL ---------------------------------------------------------------
    // A PR-targeted run starts from a fresh detached worktree at the product's
    // exact HEAD: no `node_modules`, nothing built. Phase-1 Observation 1 hit
    // exactly this — `provision: exited 127`, because the runner for the migrate
    // command was not installed. Borrowing another checkout's `node_modules`
    // would defeat the point of verifying an exact HEAD, so the product declares
    // its own dependency step and Watson runs it.
    //
    // Deliberately BEFORE the database is created: a failed install then cannot
    // orphan a `watson_<runId>` database that `reap` has to clean up later.
    let t = Date.now();
    for (const cmd of cfg.install ?? []) {
      await env.runStep(cmd, { cwd: repoRoot, env: { ...process.env }, label: 'install', policy });
    }
    if ((cfg.install ?? []).length) step(`install commands: ${cfg.install.length}`);
    timings.install_ms = Date.now() - t;

    // 1. PROVISION -------------------------------------------------------------
    t = Date.now();
    const provisioned = await env.provisionDatabase({ adminUrl, dbName, runId });
    started.dbCreated = true;
    dbServerVersion = provisioned?.serverVersion ?? null;
    const databaseUrl = adminUrl.replace(/\/[^/]*$/, `/${dbName}`);
    step(`database ${dbName}`);

    for (const cmd of cfg.provision ?? []) {
      await env.runStep(env.interpolate(cmd, { DATABASE_URL: databaseUrl }), {
        cwd: repoRoot, env: { ...process.env, DATABASE_URL: databaseUrl }, label: 'provision', policy,
      });
    }
    step(`provision commands: ${(cfg.provision ?? []).length}`);
    timings.provision_ms = Date.now() - t;

    // 2. IDENTITY --------------------------------------------------------------
    t = Date.now();
    const issuer = cfg.identity.issuer;
    const clientId = env.interpolate(cfg.identity.client_id, { RUN_ID: runId });
    started.identity = await env.startIdentityService({ issuer, clientId, identities: contract.identities });
    step(`local JWKS on ${started.identity.jwksUri}`);

    // 3. LAUNCH ----------------------------------------------------------------
    const appEnv = buildAppEnv({
      cfg, runId, databaseUrl, appPort,
      baseUrl: `http://127.0.0.1:${appPort}`,
      identity: { issuer, clientId, jwksUri: started.identity.jwksUri },
      inherit: true,
    });
    for (const cmd of cfg.build ?? []) {
      await env.runStep(cmd, { cwd: repoRoot, env: appEnv, label: 'build', policy });
    }
    started.app = env.launchApp({
      cmd: cfg.launch.command, cwd: repoRoot, env: appEnv,
      logFile: path.join(runDir, 'logs', 'app.log'), policy,
    });
    const baseUrl = `http://127.0.0.1:${appPort}`;
    await env.waitForHealth(`${baseUrl}${cfg.launch.health_path}`, 90_000);
    step(`app listening on ${baseUrl} (pgid ${started.app.pid})`);
    timings.launch_ms = Date.now() - t;

    // 4. SEED — AFTER launch. The product's identity tables are created by its
    //    own startup bootstrap, not by migrations, so seeding earlier fails on
    //    missing tables.
    t = Date.now();
    const fixture = contract.fixtures.profiles?.[cfg.launch.fixture_profile];
    if (!fixture) throw new Error(`fixture profile \`${cfg.launch.fixture_profile}\` not declared`);
    // THE VERIFIER PICKS THE VALUES ITS ASSERTIONS REST ON, and hands them to the
    // fixture as input. The fixture may SEE them — a running application observes
    // its own data, and Phase 1 does not claim otherwise — but it may not CHOOSE
    // them (ADR-049 D4).
    const chosen = fixtureValues(runId, fixture.verifier_chosen ?? []);
    const seed = await env.runStep(
      env.interpolate(fixture.command, { RUN_ID: runId, DATABASE_URL: databaseUrl }),
      {
        cwd: repoRoot,
        env: { ...appEnv, DATABASE_URL: databaseUrl, ...fixtureValueEnv(chosen) },
        label: 'seed',
        policy,
      },
    );
    let vars = {};
    try {
      vars = JSON.parse(seed.stdout.slice(seed.stdout.indexOf('{'), seed.stdout.lastIndexOf('}') + 1));
    } catch (e) {
      throw new Error(`seed did not emit parseable JSON vars: ${e.message}\n${seed.stdout.slice(-400)}`);
    }
    // The fixture is held to what it was given. Contradicting a chosen value, or
    // never reporting one back at all, means the world the journeys are about to
    // assert on is not the world the verifier asked for — a broken environment,
    // not a product defect.
    //
    // This is NOT by itself proof that the required world EXISTS: an untrusted
    // fixture echoing an id back proves it received the id. That gap is F1, and
    // trusted precondition evidence is what closes it.
    const reconciled = reconcileFixtureValues(vars, chosen);
    if (reconciled.ignored.length) {
      throw new Error(
        `the fixture did not build its world from the values the verifier supplied:\n  - ${reconciled.ignored.join('\n  - ')}`,
      );
    }
    vars = reconciled.vars;
    step(`seeded: ${Object.keys(vars).join(', ')}`);
    timings.seed_ms = Date.now() - t;

    return { dbName, databaseUrl, baseUrl, appPort, vars, timings, dbServerVersion,
      tokens: started.identity.tokens, identity: started.identity, teardown };
  } catch (err) {
    await teardown();
    throw err;
  }
}

/**
 * Bring the product up ACROSS A BOUNDARY: the product runs somewhere this
 * process cannot write, and this process runs somewhere the product cannot
 * reach.
 *
 * The division of labour IS the security property, so it is worth stating
 * exactly:
 *
 *   THE VERIFIER (here) decides. It reads the contract, provisions and stamps
 *   the database, mints the identity and serves the JWKS, chooses the port,
 *   resolves every command and every environment variable, and — critically —
 *   confirms readiness itself by polling the product's own health endpoint.
 *
 *   THE PRODUCT PLANE (there) executes. It runs the commands it is handed, in
 *   the product's checkout, and answers with what came back.
 *
 * Nothing the plane says is trusted. Readiness is never taken on its word, and
 * the seed's variables are product-supplied data — exactly as they always were —
 * used only as substitution values in journeys.
 */
async function bringUpRemote({ contract, runId, adminUrl, planeUrl, productBaseUrl, productPort, headSha }) {
  const cfg = contract.config;
  const dbName = `watson_${runId.replace(/[^a-z0-9]/gi, '').slice(-16).toLowerCase()}`;
  const started = {};
  let timings = {};
  let planeTree = null;

  // The plane is untrusted and is on the other end of this read, so the response
  // is treated as hostile input: status checked, size bounded, parsed by hand.
  // `res.json()` on an unbounded body is an invitation.
  const MAX_PLANE_RESPONSE = 8 * 1024 * 1024;
  const plane = async (route, body) => {
    const res = await fetch(`${planeUrl}${route}`, {
      method: body === undefined ? 'GET' : 'POST',
      headers: body === undefined ? {} : { 'content-type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(1_200_000),
    });
    const reader = res.body?.getReader();
    if (!reader) throw new Error(`product plane ${route}: no response body`);
    const chunks = [];
    let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.length;
      if (total > MAX_PLANE_RESPONSE) {
        await reader.cancel();
        throw new Error(`product plane ${route}: response exceeded ${MAX_PLANE_RESPONSE} bytes`);
      }
      chunks.push(value);
    }
    const text = Buffer.concat(chunks).toString('utf8');
    if (!res.ok && !text) throw new Error(`product plane ${route}: HTTP ${res.status}`);
    try {
      return JSON.parse(text);
    } catch {
      throw new Error(`product plane ${route}: HTTP ${res.status}, response was not JSON: ${text.slice(0, 300)}`);
    }
  };

  const teardown = async () => {
    try { await plane('/teardown', {}); } catch { /* the container is going away anyway */ }
    if (started.identity) await started.identity.close().catch(() => {});
    if (started.dbCreated) await env.dropDatabase({ adminUrl, dbName }).catch(() => {});
  };

  try {
    // 0. REACHABILITY — fail here, with a clear message, rather than minutes
    //    later inside a bring-up that was never going to be delivered.
    const alive = await plane('/alive');
    if (!alive?.ok) throw new Error(`product plane at ${planeUrl} did not answer /alive`);
    step(`product plane ${alive.protocol} at ${planeUrl}`);

    // The verifier measures exactness against ITS OWN copy of the product tree.
    // If the plane is about to build a different one, every claim in this run is
    // about a commit that was never driven. The plane is untrusted, so a matching
    // answer proves little — but a MISMATCHING one is conclusive, and this is the
    // only thing that would notice an orchestration wired to two checkouts.
    if (!alive.tree?.head_sha) {
      throw new Error(
        `the product plane did not say which checkout it is about to build. Silence and agreement `
          + 'are not the same answer, and this check exists to tell them apart.',
      );
    }
    if (headSha && alive.tree.head_sha !== headSha) {
      throw new Error(
        `the product plane is at ${alive.tree.head_sha}, but this run is about ${headSha}. `
          + 'The verifier and the plane are looking at different checkouts.',
      );
    }
    // A peer reporting its OWN tree dirty is the one statement an untrusted
    // party can usefully make against itself. Recording it and carrying on
    // would waste the only self-incrimination available.
    if (alive.tree.clean === false) {
      throw new Error(
        `the product plane reports its own checkout is not clean (${alive.tree.dirty_count} path(s)). `
          + 'It is about to build something other than the commit this run is about.',
      );
    }
    planeTree = alive.tree;

    // 1. PROVISION — from the verifier side. The database is reachable from both
    //    planes over the isolated network, but only the verifier may CREATE one,
    //    and only the verifier stamps the marker the product's fixture requires.
    //
    //    This runs before install, which reverses the single-process ordering:
    //    the environment carrying DATABASE_URL must exist before any command can
    //    be sent. A failed install therefore leaves a database behind — harmless
    //    here, because `teardown` drops it unconditionally and the server itself
    //    is ephemeral.
    let t = Date.now();
    const provisioned = await env.provisionDatabase({ adminUrl, dbName, runId });
    started.dbCreated = true;
    const databaseUrl = adminUrl.replace(/\/[^/]*$/, `/${dbName}`);
    timings.provision_ms = Date.now() - t;
    step(`database ${dbName}`);

    // 2. IDENTITY — served BY THE VERIFIER, bound so the other plane can reach
    //    it. The signing key never leaves this process.
    t = Date.now();
    const issuer = cfg.identity.issuer;
    const clientId = env.interpolate(cfg.identity.client_id, { RUN_ID: runId });
    started.identity = await env.startIdentityService({
      issuer, clientId, identities: contract.identities,
      bindHost: '0.0.0.0',
      advertiseHost: process.env.WATSON_ADVERTISE_HOST ?? 'watson-verifier',
    });
    step(`local JWKS on ${started.identity.jwksUri}`);

    const appEnv = buildAppEnv({
      cfg, runId, databaseUrl, appPort: productPort, baseUrl: productBaseUrl,
      identity: { issuer, clientId, jwksUri: started.identity.jwksUri },
      inherit: false,
    });

    // 3. LAUNCH — install, provision commands, build, start. Everything the pull
    //    request wrote runs THERE, as an unprivileged user, in a container that
    //    holds no credential and cannot see this process's filesystem.
    const launched = await plane('/launch', {
      runId,
      install: cfg.install ?? [],
      provision: cfg.provision ?? [],
      build: cfg.build ?? [],
      launch: cfg.launch.command,
      env: appEnv,
    });
    if (!launched?.ok) {
      throw new Error(
        `product plane failed during ${launched?.phase ?? 'launch'}: ${launched?.message ?? 'no message'}\n` +
        `${(launched?.log ?? '').slice(-1500)}`,
      );
    }
    // A PURE spread, reassigning. The previous attempt spread into
    // `Object.assign`, which still writes each key with [[Set]] and so still
    // invokes the prototype setter — the fix was on the wrong side of the call
    // and did nothing.
    timings = { ...timings, ...(launched.timings ?? {}) };
    timings.launch_ms = Date.now() - t;

    // 4. READINESS — proven by the verifier, across the network, against the
    //    product's own endpoint. The plane's success response is not readiness.
    await env.waitForHealth(`${productBaseUrl}${cfg.launch.health_path}`, 180_000);
    step(`app answering on ${productBaseUrl}`);

    // 5. SEED — after a LIVE application, because a product may create its
    //    identity tables in its own startup bootstrap rather than in migrations.
    t = Date.now();
    const fixture = contract.fixtures.profiles?.[cfg.launch.fixture_profile];
    if (!fixture) throw new Error(`fixture profile \`${cfg.launch.fixture_profile}\` not declared`);
    const chosen = fixtureValues(runId, fixture.verifier_chosen ?? []);
    const seeded = await plane('/seed', {
      runId,
      seed: fixture.command,
      env: { ...appEnv, DATABASE_URL: databaseUrl, ...fixtureValueEnv(chosen) },
    });
    if (!seeded?.ok) {
      throw new Error(
        `product plane failed during seed: ${seeded?.message ?? 'no message'}\n${(seeded?.log ?? '').slice(-1500)}`,
      );
    }
    // The fixture is held to what it was given. Contradicting a chosen value, or
    // never reporting one back at all, means the world the journeys are about to
    // assert on is not the world the verifier asked for — a broken environment,
    // not a product defect.
    //
    // This is NOT by itself proof that the required world EXISTS: an untrusted
    // fixture echoing an id back proves it received the id. That gap is F1, and
    // trusted precondition evidence is what closes it.
    const reconciledPlane = reconcileFixtureValues(seeded.vars, chosen);
    if (reconciledPlane.ignored.length) {
      throw new Error(
        `the fixture did not build its world from the values the verifier supplied:\n  - ${reconciledPlane.ignored.join('\n  - ')}`,
      );
    }
    timings.seed_ms = Date.now() - t;
    step(`seeded: ${Object.keys(seeded.vars).join(', ')}`);

    return {
      dbName, databaseUrl, baseUrl: productBaseUrl, appPort: productPort,
      vars: reconciledPlane.vars, timings, dbServerVersion: provisioned?.serverVersion ?? null, planeTree,
      tokens: started.identity.tokens, identity: started.identity, teardown,
    };
  } catch (err) {
    await teardown();
    throw err;
  }
}

async function cmdVerify(args) {
  const repoRoot = path.resolve(args.repo ?? '.');
  const adminUrl = args['db-url'] ?? process.env.WATSON_ADMIN_DB_URL ?? 'postgres://watson:watson@127.0.0.1:5432/postgres';
  const profile = args.profile ?? 'poc';
  // Resolved ONCE, before anything runs, and before a database exists. A caller
  // that asked for privilege separation and cannot have it must find out here —
  // not after the product's install script has already run as the verifier.
  // Cleared FIRST, before any refusal below can end the run. A stale file at the
  // agreed path is read by a harness as this run's verdict, so removing it has to
  // happen earlier than every exit — including the ones a few lines down, which
  // is where it used to sit and therefore did not run.
  // The trusted orchestration's account of what it materialised, written before
  // any product code ran. Without it there is no authority for product identity
  // NO MANIFEST, NO PRODUCT CLAIM. A run that was not given one cannot establish
  // identity, and says so rather than falling back to asking git — the fallback
  // WAS the vulnerability (ADR-049 D3).
  const manifest = typeof args.manifest === 'string' ? readManifest(path.resolve(args.manifest)) : null;
  const outPath = typeof args.out === 'string' ? path.resolve(args.out) : null;
  if (outPath) {
    try { fs.rmSync(outPath, { force: true, recursive: true }); } catch { /* nothing there */ }
  }

  const policy = env.productExecution();
  // uid separation requires root; a sandboxed browser requires NOT root. A
  // `verify` asked for both would run the entire bring-up and then throw at the
  // browser, reporting BLOCKED_ENVIRONMENT after several minutes of work. Refuse
  // here, and say what to use instead.
  if (policy.drop) {
    throw new Error(
      'WATSON_PRODUCT_UID requires this process to be root, and a sandboxed browser requires that it '
        + 'is not — `verify` cannot have both. Use --plane to run the product in its own container, '
        + 'which is the stronger boundary anyway. uid separation remains available for `watson doctor`.',
    );
  }
  // When a plane URL is given, the product runs on the far side of a boundary
  // and this process never executes a line of it. Both values come from trusted
  // orchestration, never from the product.
  const planeUrl = typeof args.plane === 'string' ? args.plane.replace(/\/$/, '') : null;
  const productBaseUrl = typeof args['product-base-url'] === 'string'
    ? args['product-base-url'].replace(/\/$/, '') : null;
  if (planeUrl && !productBaseUrl) {
    throw new Error('--plane requires --product-base-url: the verifier must know where to reach the running product');
  }
  const runId = env.newRunId();
  const runDir = env.makeRunDir(ROOT, runId);
  const startedAt = new Date().toISOString();
  const t0 = Date.now();

  log(`\nWatson ${VERSION} — run ${runId}`);
  const headSha = resolveSha(repoRoot, args.sha ?? 'HEAD');
  const baseSha = args.base ? resolveSha(repoRoot, args.base) : null;
  const headContract = loadContract(repoRoot);

  // WHICH CONTRACT GOVERNS (ADR-049 D1/F3/F7).
  //
  // `--base-contract` names a TRUSTED materialisation of the base revision's
  // `.watson/`, produced on the trusted side before either container starts. It
  // is not read out of the product's own `.git`, which is mounted read-write into
  // the product container — ordering used to save that, which is not the same as
  // being safe.
  //
  // Absent, the run does not silently fall back to head governance. It runs and
  // reports, and withholds the product claim. Same shape as the manifest: one
  // authority, supplied by the trusted plane, no fallback to asking the product.
  const baseContractDir = typeof args['base-contract'] === 'string' ? args['base-contract'] : null;
  const baseContract = baseContractDir
    ? (() => { try { return loadContract(baseContractDir); } catch { return null; } })()
    : null;
  // THE TRUSTED BASE TREE — the base side of every comparison.
  //
  // `--base-contract` carries the base revision's `.watson/` and is the semantic
  // authority. This is the other half: the base revision's TREE, materialised by
  // the same trusted step, so base-side CONTENT for the wider verdict-bearing
  // scope — migrations, lockfile, fixture script — comes from trusted material
  // too. It used to come from `git rev-parse <baseSha>:<path>` inside the product
  // clone, which is `refs/pull/N/head` and holds the base commit only by
  // coincidence. See `contractChange` for what that produced.
  //
  // Kept as a SEPARATE directory from `--base-contract` on purpose. Folding the
  // whole tree into that one would silently redefine `governing_contract`'s
  // fingerprint — a field the trusted validator recomputes and compares — from
  // "the base contract" to "the base tree". Both sides would still agree, and
  // the field would quietly mean something else.
  const baseTreeDir = typeof args['base-tree'] === 'string' ? args['base-tree'] : null;
  let baseEntries = null;
  let baseTreeError = null;
  if (baseTreeDir) {
    try {
      baseEntries = walkTree(baseTreeDir);
    } catch (err) {
      // Recorded, never swallowed into "unchanged". `contractChange` reports the
      // comparison as unavailable and selection escalates.
      baseTreeError = err.message;
      log(`  ⚠ the trusted base tree at ${baseTreeDir} could not be read (${baseTreeError});`
        + ' the base-side comparison is UNAVAILABLE and selection escalates');
    }
  }
  const governance = resolveGovernance({
    base: baseContract, head: headContract, baseSupplied: !!baseContractDir,
    baseSha,
    // Computed from the materialised directory, by the same function the trusted
    // observer uses to check it. Two notions of "the same contract" is how this
    // field would become decorative.
    baseFingerprint: baseContractDir ? contractDirFingerprint(baseContractDir) : null,
  });
  const contract = governance.contract;
  // Scoped from the governing contract, and from what exists at the HEAD commit —
  // a path the head deleted still has to be compared, and `treeHash` reports it
  // as `absent` on that side rather than dropping out of the digest.
  const contractScope = verdictBearingPaths(
    contract, pathExistsAt(repoRoot, headSha), pathReaderAt(repoRoot, headSha),
  );

  log(`  repo   ${repoRoot}`);
  log(`  head   ${headSha}`);
  log(`  govern ${governance.authority} — ${governance.note}`);
  log(`  map    ${contract.features.length} feature(s), profile \`${profile}\`\n`);

  // Diff-driven impact selection when the contract declares rules AND a base
  // resolves; declared profile otherwise. The fallback direction matters: an
  // absent base or absent rules means MORE journeys run, never fewer.
  const rules = contract.config.selection ?? null;
  // Same trusted inputs as `contractChange`, and for the same reason: this used
  // to run `git merge-base` / `git diff` inside the product clone, so a base SHA
  // that clone did not contain dropped the run out of diff-driven selection and
  // into the broad profile without saying so.
  const changed = rules ? changedPaths({ baseEntries, headEntries: manifest?.entries ?? null }) : null;

  const impact = rules
    ? selectByImpact({
        features: contract.features,
        changedPaths: changed,
        profile,
        escalationProfile: rules.escalation_profile ?? 'smoke',
        rules,
      })
    : { method: 'profile', applicable: true, reason: 'contract declares no selection rules',
        features: selectByProfile(contract.features, profile),
        classifications: [], escalated: false, escalation_reasons: [] };

  const plan = withDependencies(impact.features, contract.features);

  const selection = {
    method: impact.method,
    profile,
    applicable: impact.applicable,
    reason: impact.reason,
    escalated: impact.escalated,
    escalation_reasons: impact.escalation_reasons,
    changed_paths: changed,
    classifications: impact.classifications,
    selected: plan.filter((p) => p.role === 'verified').map((p) => p.feature.id),
    setup: plan.filter((p) => p.role === 'setup').map((p) => p.feature.id),
    deferred: contract.features.filter((f) => !plan.some((p) => p.feature.id === f.id)).map((f) => f.id),
  };

  log(`  select ${impact.method} — ${impact.reason}`);

  const base = {
    runId, watsonVersion: VERSION,
    // Resolved from the engine's own checkout, not passed in by a caller: a
    // verifier that accepted its own identity as an argument could be told to
    // report any identity at all.
    engine: engineProvenance(ROOT),
    repository: args.repository ?? path.basename(repoRoot),
    pullRequest: args.pr ? Number(args.pr) : null,
    headSha, baseSha,
    contractVersion: contract.config?.contract_version ?? null,
    productFingerprint: productFingerprint(repoRoot, headSha),
    // D2: the fingerprint covers everything verdict-bearing, which is more than
    // `.watson/`. The scope is derived from the GOVERNING contract and recorded
    // beside the digest, because a fingerprint whose scope is invisible is one
    // nobody can check — and here that visibility is load-bearing rather than
    // decorative. `.watson`, the install surface and base-governed
    // `verdict_bearing_paths` cannot be shrunk by the head; paths reachable only
    // through head-authored command strings CAN be, because those commands must
    // match the pull request's own tree. See `verdictBearingPaths` for what that
    // does and does not buy. Watson reports contract movement; it does not gate
    // on it.
    contractFingerprint: contractFingerprint(repoRoot, headSha, contractScope),
    contractScope,
    // Resolves the contract from BOTH SIDES so the diff can name what changed,
    // not merely that something did.
    //
    // Every input is trusted material. The base side is the trusted
    // materialisation — never `git archive` out of the product's own `.git` (F3)
    // and, since D1, never `git rev-parse` against it either. The head side is
    // the trusted MANIFEST, built by the trusted plane before a line of product
    // code ran, rather than the product repository's view of its own commit. The
    // head CONTRACT is the head contract as authored, not the governing merge,
    // which would diff the base against itself and report no change however much
    // the head moved.
    contractChange: contractChange({
      baseEntries,
      headEntries: manifest?.entries ?? null,
      loadAt: (side) => (side === 'head' ? headContract : baseContract),
      paths: contractScope,
    }),
    // HOW THE PRODUCT WAS LAUNCHED, reported separately from everything else.
    //
    // These keys are head-authored by decision — `install`, `provision`,
    // `build`, `launch.command`, `env` must match the pull request's own tree or
    // nothing runs. That makes them untrusted execution inputs, not verdict
    // authority, and it makes their movement worth seeing on its own: a reviewer
    // must be able to tell that this pull request changed how Watson launched
    // the product, without that fact being buried inside a whole-contract digest.
    operationalConfig: operationalConfigChange(baseContract?.config, headContract.config),
    governance,
    // Recorded on EVERY result, pass or fail. A run that reports a SHA it did not
    // actually verify is worse than one that reports nothing.
    workingTree: productIdentity({
      repoRoot, manifest, expectedSha: headSha,
      generatedRoots: contract.config.generated_roots ?? [],
    }),
    manifest: manifest ? { schema: manifest.schema, sha: manifest.sha, built_at: manifest.built_at,
      entries: Object.keys(manifest.entries ?? {}).length } : null,
    repoRoot,
    manifestObject: manifest, generatedRoots: contract.config.generated_roots ?? [],
    profile, selection, startedAt, shadow: true, outPath,
    execution: {
      ...env.executionProvenance(policy),
      // Which boundary this run actually had between the verifier and the code
      // it was verifying. A reader assessing a verdict needs to know whether the
      // product ran in its own plane, was merely uid-separated in this process
      // tree, or shared everything with the verifier — those are three different
      // levels of confidence in the same JSON.
      product_plane: planeUrl ? { url: planeUrl, product_base_url: productBaseUrl } : null,
      product_isolation: planeUrl ? 'separate-plane' : (policy.drop ? 'uid-separated' : 'same-process'),
    },
    fixtureProfile: contract.config.launch.fixture_profile,
    viewports: ['1280x800'],
    browser: 'chromium/playwright-1.49.1',
  };

  // Fail fast on an undeclared variable: an unresolved `${name}` would otherwise
  // interpolate as a literal and surface later as a misleading product failure.
  // Alongside it, refuse a contract that tries to redefine an engine-owned key.
  // Both are pure contract checks, so they run BEFORE a database is created or a
  // single provisioning command is executed.
  // ONE profile object, read once and passed everywhere.
  //
  // This is not tidiness. `validateDenialProofs` credits a declared trusted proof
  // as evidence that an entity exists, and that credit is only honest because
  // `doctor` EXECUTES the proof and fails the run when it is not established. If
  // the pre-flight and doctor could be handed different profiles, the credit
  // would be extended against an obligation nobody discharges.
  const fixtureProfile = contract.fixtures.profiles?.[contract.config.launch.fixture_profile];
  const varProblems = [
    // An unattributed contract key is a contract error, not a default.
    ...governance.problems,
    ...validateContractVersion(contract.config),
    ...validateStepOrder(plan.map((p) => p.feature)),
    ...validateEnvOwnership(contract.config),
    ...validateProofDeclarations(
      fixtureProfile,
      normaliseChosen(fixtureProfile?.verifier_chosen ?? []).map(([n]) => n),
    ),
    ...validateAssertionOperands(plan.map((p) => p.feature), fixtureProfile),
    ...validateDenialProofs(plan.map((p) => p.feature), fixtureProfile),
    ...validateReachedConditions(plan.map((p) => p.feature)),
    ...validateBrowserOwnership(contract.config),
    ...validateFeatureVars(plan.map((p) => p.feature), fixtureProfile),
  ];
  if (varProblems.length) {
    log('');
    for (const p of varProblems) log(`  ✗ ${p}`);
    return finish(runDir, {
      ...base, dbName: 'n/a', baseUrl: 'n/a',
      verdict: 'FAIL_CONTRACT',
      verdictReason: `${varProblems.length} contract problem(s) found before bring-up`,
      doctor: { ok: false, probes: varProblems.map((p, i) => ({ name: `contract-preflight-${i + 1}`, ok: false, detail: p })) },
      features: [], findings: [], qualitySignals: zeroSignals(),
      evidence: { bundle: path.relative(ROOT, runDir), retention_days: 7 },
      timings: { total_ms: Date.now() - t0 },
      finishedAt: new Date().toISOString(),
    });
  }
  // --- nothing to verify -------------------------------------------------------
  // Terminal NOT_APPLICABLE, decided BEFORE bring-up. A skipped run must be
  // cheap, or the cost of skipping teaches the wrong lesson; and it must never
  // create a database or a process it then has to reap.
  //
  // Reaching here required `selectByImpact` to positively establish that every
  // changed path is unable to affect the running product. Every other route —
  // an absent base, an unrecognised path, unmapped runtime code — escalates
  // instead, so this branch cannot be reached by falling through.
  if (!selection.applicable) {
    log(`\n  – NOT_APPLICABLE — ${selection.reason}`);
    return finish(runDir, {
      ...base, dbName: 'n/a', baseUrl: 'n/a',
      verdict: 'NOT_APPLICABLE',
      verdictReason: selection.reason,
      doctor: { ok: true, probes: [] },
      features: [], findings: [], qualitySignals: zeroSignals(),
      evidence: { bundle: path.relative(ROOT, runDir), retention_days: 7 },
      timings: { total_ms: Date.now() - t0 },
      finishedAt: new Date().toISOString(),
    });
  }

  // --- bring the environment up ------------------------------------------------
  let up;
  try {
    up = planeUrl
      ? await bringUpRemote({
          contract, runId, adminUrl, planeUrl, productBaseUrl, headSha,
          productPort: Number(new URL(productBaseUrl).port || 80),
        })
      : await bringUp({ repoRoot, contract, runDir, runId, adminUrl, policy });
  } catch (err) {
    return finish(runDir, {
      ...base, dbName: 'n/a', baseUrl: 'n/a',
      verdict: 'BLOCKED_ENVIRONMENT',
      verdictReason: `environment could not be brought up: ${err.message.split('\n')[0]}`,
      doctor: { ok: false, probes: [{ name: 'bring-up', ok: false, detail: err.message.slice(0, 500) }] },
      features: [], findings: [], qualitySignals: zeroSignals(),
      evidence: { bundle: path.relative(ROOT, runDir), retention_days: 7 },
      timings: { total_ms: Date.now() - t0 },
      finishedAt: new Date().toISOString(),
    });
  }

  // Filled in after provisioning rather than guessed before it: the version is a
  // fact about the server that actually held the fixtures. `base.execution` is
  // shared by reference with every envelope built below, which is exactly what is
  // wanted — one record of one run's environment.
  base.execution.database_server_version = up.dbServerVersion;
  // What the plane said about its own checkout, recorded verbatim as the
  // untrusted claim it is. A reader can see that the two sides agreed, and that
  // agreement between the verifier and an untrusted peer is not the same as proof.
  if (up.planeTree) base.execution.product_plane_tree_claimed = up.planeTree;

  try {
    // --- doctor ---------------------------------------------------------------
    const adminIdentity = contract.identities.find((i) => i.role === 'admin' && i.doctor) ?? contract.identities[0];
    const dr = await env.doctor({
      baseUrl: up.baseUrl, dbName: up.dbName, databaseUrl: up.databaseUrl,
      adminToken: up.tokens[adminIdentity?.id], expectSeasons: contract.config.launch.expect_seasons,
      identity: up.identity,
      // W5: what the seeded rows must RESOLVE TO through the product's own read
      // paths — and F1: the trusted proofs that the entities behind the
      // verifier's own values were actually built. Both are declared by the
      // profile that seeded them, and the same object the pre-flight read.
      fixtureProfile,
      tokens: up.tokens,
      vars: up.vars,
    });
    for (const p of dr.probes) step(`doctor ${p.ok ? '✓' : '✗'} ${p.name} — ${p.detail}`);
    if (!dr.ok) {
      return finish(runDir, {
        ...base, dbName: up.dbName, baseUrl: up.baseUrl,
        verdict: 'BLOCKED_ENVIRONMENT',
        verdictReason: `doctor failed: ${dr.probes.filter((p) => !p.ok).map((p) => p.name).join(', ')}`,
        doctor: dr, features: [], findings: [], qualitySignals: zeroSignals(),
        evidence: { bundle: path.relative(ROOT, runDir), retention_days: 7 },
        timings: { ...up.timings, total_ms: Date.now() - t0 },
        finishedAt: new Date().toISOString(),
      });
    }

    // --- drive ----------------------------------------------------------------
    const cdpPort = await env.freePort();
    // THE VERIFIER CHOOSES ITS OWN BROWSER BINARY.
    //
    // This used to fall back to `contract.config.browser.executable_path` — a
    // path out of the PRODUCT's `.watson/config.yaml`, handed to
    // `chromium.launch()`, which runs it in the VERIFIER plane, as the verifier's
    // uid, with the verifier's unscrubbed environment. Reproduced by a review: a
    // shell script named there executed as the verifier and read the CI bearer
    // tokens out of its own environment.
    //
    // It also defeated everything this slice claims about the browser. The root
    // refusal, the channel pin and the sandbox probe all sit downstream of the
    // binary, so choosing the binary skips all three. And it survived `--plane`,
    // whose whole argument is that the verifier never executes a line of product
    // code — this was the line.
    //
    // The path now comes only from the trusted side. A contract that declares one
    // is refused (see `validateBrowserOwnership`), not silently ignored, because a
    // contract whose key is quietly dropped reads as a contract that works.
    const browser = await drive.launchBrowser({
      executablePath: process.env.WATSON_CHROMIUM,
      cdpPort,
    });
    step(`browser up, CDP on http://127.0.0.1:${cdpPort} (MCP layers attach here)`);

    // Ask Chromium what its sandbox is doing rather than inferring it from the
    // absence of a flag. The pages this browser loads are served by the product
    // under verification, so "is the sandbox actually on" is a fact about the
    // integrity of this run, and belongs in the evidence beside the verdict.
    base.execution.browser_sandbox_probe = await drive.probeSandbox(browser);
    // Recorded AND acted on. Recording that the browser said it was not
    // sandboxed, and then producing a verdict anyway, is the shape of a control
    // that exists only on paper.
    //
    // POSITIVE, not merely `!== false`. The earlier form let a build that will
    // not render `chrome://sandbox` — `available: false`, `effective`
    // undefined — through to a product verdict with no layer-1 evidence at all.
    // "An unprovable sandbox is not one this design gets to claim" was written
    // in the README and not implemented here. A run that reaches this point has
    // already opened a browser (a NOT_APPLICABLE run returns terminally before
    // bring-up), so there is no legitimate case that needs the softer test.
    if (base.execution.browser_sandbox_probe.effective !== true) {
      await browser.close();
      return finish(runDir, {
        ...base, dbName: up.dbName, baseUrl: up.baseUrl,
        verdict: 'BLOCKED_ENVIRONMENT',
        verdictReason: base.execution.browser_sandbox_probe.available
          ? 'Chromium reports it is not adequately sandboxed; the browser is part of the verifier and the pages it loads come from the product'
          : 'this browser build will not report its sandbox state, so the layer-1 sandbox cannot be established; the browser is part of the verifier and the pages it loads come from the product',
        doctor: dr, features: [], findings: [], qualitySignals: zeroSignals(),
        evidence: { bundle: path.relative(ROOT, runDir), retention_days: 7 },
        timings: { ...up.timings, total_ms: Date.now() - t0 },
        finishedAt: new Date().toISOString(),
      });
    }
    step(`browser sandbox: ${base.execution.browser_sandbox_probe.available
      ? (base.execution.browser_sandbox_probe.effective ? 'reported effective' : 'reported NOT effective')
      : 'not reportable by this build'} (running as uid ${typeof process.getuid === 'function' ? process.getuid() : 'n/a'})`);

    const tDrive = Date.now();
    const features = [];
    const findings = [];
    const signals = zeroSignals();

    for (const { feature, role } of plan) {
      const token = up.tokens[feature.personas[0]];
      const { ctx, page, evidence } = await drive.openIdentity(browser, {
        baseUrl: up.baseUrl, token, viewport: feature.viewport,
      });
      const vars = { ...up.vars, runId };
      const fStart = Date.now();
      const steps = [];
      let stepFailure = null;
      let pageText = '';

      for (let i = 0; i < feature.steps.length; i++) {
        const s = feature.steps[i];
        const action = Object.keys(s).find((k) => drive.STEPS.includes(k)) ?? 'unknown';
        try {
          const observed = await drive.runStep(s, { page, evidence, vars });
          steps.push({ n: i + 1, action, result: 'ok', observed, url: page.url() });
        } catch (err) {
          stepFailure = { n: i + 1, action, message: err.message };
          steps.push({
            n: i + 1, action, result: 'fail',
            expected: s.note ?? null, observed: err.message.split('\n')[0], url: page.url(),
          });
          break;
        }
      }

      try { pageText = await page.evaluate(() => document.body.innerText); } catch { /* page gone */ }

      const fFindings = evaluate({ featureId: feature.id, evidence, invariants: contract.invariants, pageText });
      const { verdict, reason: verdictReason } = featureVerdict({ stepFailure, findings: fFindings });
      const evFiles = (verdict === 'FAIL_PRODUCT' || verdict === 'FAIL_CONTRACT') && stepFailure
        ? await drive.captureFailure(page, runDir, feature.id, stepFailure.n)
        : [];

      findings.push(...fFindings);
      accumulate(signals, evidence, pageText);
      features.push({
        id: feature.id, title: feature.title, persona: feature.personas[0], role,
        verdict, verdict_reason: verdictReason, contract_ref: 'head',
        requirements: feature.requirements ?? [], adrs: feature.adrs ?? [],
        attempts: 1, duration_ms: Date.now() - fStart,
        steps, evidence: evFiles,
        api_calls: evidence.requests.length,
      });
      log(`  ${verdict === 'PASS' ? '✓' : verdict === 'PASS_WITH_ADVISORIES' ? '✓' : '✗'} ${feature.id} — ${verdict} (${steps.filter((x) => x.result === 'ok').length}/${feature.steps.length} steps, ${((Date.now() - fStart) / 1000).toFixed(1)}s)`);
      if (stepFailure) log(`      step ${stepFailure.n} ${stepFailure.action}: ${stepFailure.message.split('\n')[0]}`);
      if (stepFailure && verdictReason) log(`      -> ${verdictReason}`);

      await ctx.close();
      // A setup prerequisite that fails blocks its dependants rather than
      // letting them report a misleading verdict.
      if (role === 'setup' && verdict === 'FAIL_PRODUCT') {
        log('      prerequisite failed — dependent features not attempted');
        break;
      }
    }

    await browser.close();

    // The run-level verdict, decided in one place that has its own tests.
    // `plan` is what was SELECTED; `features` is what actually executed.
    const roll = runVerdict({ executed: features, plan, applicable: selection.applicable });
    const { notAttempted } = roll;

    if (notAttempted.length) {
      log(`\n  ⚠ ${notAttempted.length} selected journey(s) never ran: ${notAttempted.join(', ')}`);
    }
    return finish(runDir, {
      ...base, dbName: up.dbName, baseUrl: up.baseUrl,
      verdict: roll.verdict,
      verdictReason: roll.reason,
      notAttempted,
      doctor: dr, features, findings, qualitySignals: signals,
      evidence: {
        bundle: path.relative(ROOT, runDir),
        retention_days: 7,
        redaction_applied: false,
        note: 'synthetic fixtures only — Watson refuses any database it did not create',
      },
      timings: { ...up.timings, drive_ms: Date.now() - tDrive, total_ms: Date.now() - t0 },
      finishedAt: new Date().toISOString(),
    });
  } finally {
    await up.teardown();
    step('teardown complete (process group killed, database dropped, evidence kept)');
  }
}

function zeroSignals() {
  return {
    console_errors: 0, console_warnings: 0, expected_denial_console: 0, http_5xx: 0,
    unexpected_4xx: 0, failed_requests: 0, raw_uuid_visible: 0,
  };
}

function accumulate(sig, evidence, pageText) {
  // Expected-denial artifacts are counted in their OWN signal, not in
  // console_errors. A signal that mixes "the product logged an error" with
  // "Watson provoked a denial on purpose" measures neither.
  const expectedDenial = evidence.expectedDenialConsole ?? [];
  const expectedTexts = new Set(expectedDenial.map((e) => `${e.resourcePath}\u0000${e.text}`));
  sig.expected_denial_console += expectedDenial.length;
  sig.console_errors += evidence.pageErrors.length
    + evidence.console.filter((c) => c.type === 'error'
        && !expectedTexts.has(`${c.resourcePath}\u0000${c.text}`)).length;
  sig.console_warnings += evidence.console.filter((c) => c.type === 'warning').length;
  sig.http_5xx += evidence.requests.filter((r) => r.status >= 500).length;
  sig.unexpected_4xx += evidence.requests.filter((r) => r.status >= 400 && r.status < 500 && ![401, 403, 404].includes(r.status)).length;
  sig.failed_requests += evidence.failed.filter((f) => !String(f.url).startsWith('data:')).length;
  if (pageText && /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i.test(pageText)) sig.raw_uuid_visible += 1;
}

function finish(runDir, run) {
  // GOVERNING-CONTRACT GATE (ADR-049 D1).
  //
  // Runs BEFORE the exact-head gate, and both apply: a verdict about a commit
  // requires that the commit is what was driven AND that the semantics used to
  // judge it were not supplied by the thing being judged. Either one missing
  // makes the verdict INDETERMINATE.
  //
  // FAIL_PRODUCT is withheld here as well as PASS, and that is deliberate. An
  // accusation reached on semantics nobody trusted is not a better outcome than
  // an unearned pass; it is the same defect pointed the other way.
  if (run.verdict && run.governance) {
    const gov = downgradeForUngovernedContract(run.verdict, run.governance, WITHHELD_WITHOUT_GOVERNANCE);
    if (gov.verdict !== run.verdict) {
      log('');
      log(`  ⚠ ${gov.reason}`);
      run.verdictReason = gov.reason;
      run.verdict = gov.verdict;
    }
  }

  // EXACT-HEAD GATE (W2). The last thing that happens before a verdict is written:
  // re-read the working tree and refuse to make a claim ABOUT THE COMMIT unless the
  // checkout still is that commit.
  //
  // Re-read rather than reuse the value captured at start-up, because the tree can
  // change WHILE a run is in flight — that is how runs 4-10 of a campaign silently
  // began verifying a journey that runs 1-3 had never seen. A run that started clean
  // and ended dirty drove some mixture of the two, and cannot honestly speak for
  // either.
  if (run.repoRoot && run.verdict) {
    const at_end = productIdentity({
      repoRoot: run.repoRoot, manifest: run.manifestObject ?? null,
      expectedSha: run.headSha ?? null, generatedRoots: run.generatedRoots ?? [],
    });
    const at_start = run.workingTree ?? at_end;
    const changed_mid_run =
      at_start.exact_head !== at_end.exact_head
      || at_start.dirty_count !== at_end.dirty_count
      // A run that started at the reported commit and ended somewhere else moved
      // under the verifier. `dirty_count` cannot see that: committing the change
      // is what makes the count go back to zero.
      || at_start.head_sha !== at_end.head_sha;

    run.workingTree = { ...at_end, at_start_exact_head: at_start.exact_head, changed_mid_run };

    const gate = downgradeForInexactHead(
      run.verdict,
      changed_mid_run ? { ...at_end, exact_head: false } : at_end,
    );
    if (gate.verdict !== run.verdict) {
      log('');
      log(`  ⚠ ${gate.reason}`);
      run.verdictReason = gate.reason;
      run.verdict = gate.verdict;
    }
  }

  const envlp = buildEnvelope(run);
  const { jsonPath, mdPath } = writeResult(runDir, envlp, run.outPath ?? null);
  log('');
  log(summary(envlp).split('\n').slice(0, 3).join('\n'));
  log('');
  log(`  result   ${path.relative(process.cwd(), jsonPath)}`);
  if (run.outPath) log(`  canonical ${run.outPath}`);
  log(`  summary  ${path.relative(process.cwd(), mdPath)}`);
  log('');
  return envlp;
}

async function cmdDoctor(args) {
  const repoRoot = path.resolve(args.repo ?? '.');
  const adminUrl = args['db-url'] ?? process.env.WATSON_ADMIN_DB_URL ?? 'postgres://watson:watson@127.0.0.1:5432/postgres';
  const runId = env.newRunId();
  const runDir = env.makeRunDir(ROOT, runId);
  const contract = loadContract(repoRoot);
  const up = await bringUp({ repoRoot, contract, runDir, runId, adminUrl, policy: env.productExecution() });
  try {
    const adminIdentity = contract.identities.find((i) => i.role === 'admin' && i.doctor) ?? contract.identities[0];
    const dr = await env.doctor({
      baseUrl: up.baseUrl, dbName: up.dbName, databaseUrl: up.databaseUrl,
      adminToken: up.tokens[adminIdentity?.id], expectSeasons: contract.config.launch.expect_seasons,
      identity: up.identity,
      // W5 read-path preconditions and F1 trusted proofs, from the profile that
      // seeded the world.
      fixtureProfile: contract.fixtures.profiles?.[contract.config.launch.fixture_profile],
      tokens: up.tokens,
      vars: up.vars,
    });
    for (const p of dr.probes) log(`  ${p.ok ? '✓' : '✗'} ${p.name} — ${p.detail}`);
    log(`\n  doctor: ${dr.ok ? 'OK' : 'FAILED'}\n`);
    return dr.ok ? 0 : 1;
  } finally {
    await up.teardown();
  }
}

// ONLY WHEN INVOKED AS THE COMMAND, never on import.
//
// Without this guard, `import('./cli.mjs')` runs the CLI: it prints usage and
// calls `process.exit`, which kills whatever imported it. That made the entry
// point untestable, and the cost was concrete — this slice was extracted with a
// fully green suite and a `cli.mjs` that threw on its first import, because
// nothing in the suite could reach it.
const invokedDirectly = process.argv[1]
  && path.resolve(process.argv[1]) === path.resolve(url.fileURLToPath(import.meta.url));

if (invokedDirectly) {
const args = parseArgs(process.argv.slice(2));
const cmd = args._[0];
try {
  if (cmd === 'verify') {
    const envlp = await cmdVerify(args);
    // The exit code follows the OBLIGATION, not the verdict. Those are the two
    // axes: the verdict says what Watson learned, the obligation says whether
    // the verification duty was discharged. NOT_APPLICABLE discharges it —
    // Watson established there was nothing here to verify — so it must exit 0.
    // Keying on the verdict made it exit 1 and read as a failure to any CI
    // system, which was latent until selection made NOT_APPLICABLE reachable.
    process.exit(envlp.check?.obligation === 'satisfied' ? 0 : 1);
  } else if (cmd === 'doctor') {
    process.exit(await cmdDoctor(args));
  } else if (cmd === 'manifest') {
    // RUN THIS ON THE TRUSTED SIDE, against a checkout the product has not run
    // in, before handing that tree to anything untrusted. A manifest built after
    // the product has touched the tree describes the product's work, not the
    // commit's.
    //
    // The implementation lives in `manifest-cli.mjs`, which imports node
    // built-ins only, and CI invokes that file directly — the trusted runner has
    // no `node_modules`, so it cannot load this file at all. Delegating keeps
    // one implementation rather than two that drift.
    runManifest(process.argv.slice(3));
    process.exit(0);
  } else if (cmd === 'plane') {
    // The product plane. Runs in the UNTRUSTED container, as an unprivileged
    // user, and executes only what the verifier hands it. It never sees the
    // evidence, the run bundle, or the browser.
    const repoRoot = path.resolve(args.repo ?? '.');
    const port = Number(args.port ?? 8079);
    const logDir = path.resolve(args['log-dir'] ?? path.join(repoRoot, '..', 'plane-logs'));
    const { port: bound } = await plane.serve({ repoRoot, logDir, port });
    log(`\nwatson product plane ${plane.PLANE_PROTOCOL}`);
    log(`  repo   ${repoRoot}`);
    log(`  listen 0.0.0.0:${bound}`);
    log(`  uid    ${typeof process.getuid === 'function' ? process.getuid() : 'n/a'}\n`);
    // Deliberately never resolves: the container's lifetime is the plane's.
    await new Promise(() => {});
  } else if (cmd === 'reap') {
    const { dropped, kept } = await env.reap({
      adminUrl: args['db-url'] ?? process.env.WATSON_ADMIN_DB_URL ?? 'postgres://watson:watson@127.0.0.1:5432/postgres',
      maxAgeHours: args['max-age-hours'] ? Number(args['max-age-hours']) : 2,
    });
    log(`reaped ${dropped.length} orphaned database(s): ${dropped.join(', ') || 'none'}`);
    // A reap that removes nothing should say why, or it reads as broken.
    for (const k of kept) log(`  kept ${k.datname} — ${k.why}`);
    process.exit(0);
  } else {
    log(`watson ${VERSION}\n\n  watson verify --repo <path> [--sha <ref>] [--base <ref>] [--profile poc] [--pr N] [--out <file>]\n               [--plane <url> --product-base-url <url>]\n               [--manifest <file>] [--base-contract <dir>] [--base-tree <dir>]\n  watson manifest --repo <path> [--sha <ref>] [--out <file>]   (TRUSTED side, before product code runs)\n  watson doctor --repo <path>\n  watson plane --repo <path> [--port 8079]\n  watson reap\n`);
    process.exit(cmd ? 1 : 0);
  }
} catch (err) {
  console.error(`\nwatson: ${err.message}\n`);
  process.exit(2);
}
}
