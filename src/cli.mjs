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
  loadContract, loadContractAt, selectByProfile, withDependencies,
  validateFeatureVars, validateEnvOwnership, validateContractVersion, validateStepOrder,
  validateSeedValues,
} from './contract.mjs';
import { productFingerprint, contractFingerprint, resolveSha, contractChange, workingTreeState, changedPaths, engineProvenance } from './fingerprint.mjs';
import { selectByImpact } from './selection.mjs';
import * as env from './environment.mjs';
import * as drive from './driver.mjs';
import * as plane from './plane.mjs';
import { evaluate, featureVerdict } from './checks.mjs';
import { buildEnvelope, rollUp, writeResult, summary, downgradeForInexactHead } from './result.mjs';

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
    const seed = await env.runStep(
      env.interpolate(fixture.command, { RUN_ID: runId, DATABASE_URL: databaseUrl }),
      { cwd: repoRoot, env: { ...appEnv, DATABASE_URL: databaseUrl }, label: 'seed', policy },
    );
    let vars = {};
    try {
      vars = JSON.parse(seed.stdout.slice(seed.stdout.indexOf('{'), seed.stdout.lastIndexOf('}') + 1));
    } catch (e) {
      throw new Error(`seed did not emit parseable JSON vars: ${e.message}\n${seed.stdout.slice(-400)}`);
    }
    const seedProblems = validateSeedValues(vars, fixture);
    if (seedProblems.length) {
      throw new Error(`the fixture emitted unusable variables:\n  - ${seedProblems.join('\n  - ')}`);
    }
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
async function bringUpRemote({ contract, runId, adminUrl, planeUrl, productBaseUrl, productPort }) {
  const cfg = contract.config;
  const dbName = `watson_${runId.replace(/[^a-z0-9]/gi, '').slice(-16).toLowerCase()}`;
  const started = {};
  const timings = {};

  const plane = async (route, body) => {
    const res = await fetch(`${planeUrl}${route}`, {
      method: body === undefined ? 'GET' : 'POST',
      headers: body === undefined ? {} : { 'content-type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(1_200_000),
    });
    return res.json();
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
    // Spread, not Object.assign: the plane is untrusted, and `Object.assign`
    // routes a `__proto__` key through the prototype setter.
    Object.assign(timings, { ...(launched.timings ?? {}) });
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
    const seeded = await plane('/seed', {
      runId, seed: fixture.command, env: { ...appEnv, DATABASE_URL: databaseUrl },
    });
    if (!seeded?.ok) {
      throw new Error(
        `product plane failed during seed: ${seeded?.message ?? 'no message'}\n${(seeded?.log ?? '').slice(-1500)}`,
      );
    }
    const seedProblems = validateSeedValues(seeded.vars, fixture);
    if (seedProblems.length) {
      throw new Error(`the fixture emitted unusable variables:\n  - ${seedProblems.join('\n  - ')}`);
    }
    timings.seed_ms = Date.now() - t;
    step(`seeded: ${Object.keys(seeded.vars ?? {}).join(', ')}`);

    return {
      dbName, databaseUrl, baseUrl: productBaseUrl, appPort: productPort,
      vars: seeded.vars ?? {}, timings, dbServerVersion: provisioned?.serverVersion ?? null,
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
  const outPath = typeof args.out === 'string' ? path.resolve(args.out) : null;
  // Removed BEFORE anything runs. A crash later would otherwise leave the
  // PREVIOUS run's result sitting at the agreed path, where a harness would read
  // it as this run's verdict — the exact hazard `--out` exists to remove.
  if (outPath) { try { fs.rmSync(outPath, { force: true }); } catch { /* nothing there */ } }
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
  const contract = loadContract(repoRoot);
  log(`  repo   ${repoRoot}`);
  log(`  head   ${headSha}`);
  log(`  map    ${contract.features.length} feature(s), profile \`${profile}\`\n`);

  // Diff-driven impact selection when the contract declares rules AND a base
  // resolves; declared profile otherwise. The fallback direction matters: an
  // absent base or absent rules means MORE journeys run, never fewer.
  const rules = contract.config.selection ?? null;
  const changed = rules ? changedPaths(repoRoot, baseSha, headSha) : null;

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
    contractFingerprint: contractFingerprint(repoRoot, headSha),
    // Resolves the contract at BOTH SHAs so the diff can name what changed, not
    // merely that something did. `loadContractAt` returns null for an unreadable
    // or invalid base, which the diff reports as `base_contract_available: false`.
    contractChange: contractChange(repoRoot, baseSha, headSha, (sha) =>
      sha === headSha ? contract : loadContractAt(repoRoot, sha)),
    // Recorded on EVERY result, pass or fail. A run that reports a SHA it did not
    // actually verify is worse than one that reports nothing.
    workingTree: workingTreeState(repoRoot, headSha),
    repoRoot,
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
  const varProblems = [
    ...validateContractVersion(contract.config),
    ...validateStepOrder(plan.map((p) => p.feature)),
    ...validateEnvOwnership(contract.config),
    ...validateFeatureVars(
      plan.map((p) => p.feature),
      contract.fixtures.profiles?.[contract.config.launch.fixture_profile],
    ),
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
          contract, runId, adminUrl, planeUrl, productBaseUrl,
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

  try {
    // --- doctor ---------------------------------------------------------------
    const adminIdentity = contract.identities.find((i) => i.role === 'admin' && i.doctor) ?? contract.identities[0];
    const dr = await env.doctor({
      baseUrl: up.baseUrl, dbName: up.dbName, databaseUrl: up.databaseUrl,
      adminToken: up.tokens[adminIdentity?.id], expectSeasons: contract.config.launch.expect_seasons,
      identity: up.identity,
      // W5: what the seeded rows must RESOLVE TO through the product's own read
      // paths, declared by the profile that seeded them.
      preconditions: contract.fixtures.profiles?.[contract.config.launch.fixture_profile]?.preconditions,
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
    const browser = await drive.launchBrowser({
      executablePath: contract.config.browser?.executable_path ?? process.env.WATSON_CHROMIUM,
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
    if (base.execution.browser_sandbox_probe.effective === false) {
      await browser.close();
      return finish(runDir, {
        ...base, dbName: up.dbName, baseUrl: up.baseUrl,
        verdict: 'BLOCKED_ENVIRONMENT',
        verdictReason: 'Chromium reports it is not adequately sandboxed; the browser is part of the verifier and the pages it loads come from the product',
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

    const verified = features.filter((f) => f.role === 'verified');
    const verdict = rollUp(verified.length ? verified : features);
    const failed = features.filter((f) => f.verdict === 'FAIL_PRODUCT');
    return finish(runDir, {
      ...base, dbName: up.dbName, baseUrl: up.baseUrl,
      verdict,
      verdictReason: (() => {
        const drift = features.filter((f) => f.verdict === 'FAIL_CONTRACT');
        if (failed.length) return `${failed.length} of ${features.length} feature(s) failed their proof`;
        if (drift.length) return `${drift.length} feature(s) could not be verified — the map names something that no longer exists`;
        return `${features.length} feature(s) met their proof`;
      })(),
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
    const at_end = workingTreeState(run.repoRoot, run.headSha ?? null);
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
      // W5: what the seeded rows must RESOLVE TO through the product's own read
      // paths, declared by the profile that seeded them.
      preconditions: contract.fixtures.profiles?.[contract.config.launch.fixture_profile]?.preconditions,
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
    log(`watson ${VERSION}\n\n  watson verify --repo <path> [--sha <ref>] [--base <ref>] [--profile poc] [--pr N] [--out <file>]\n               [--plane <url> --product-base-url <url>]\n  watson doctor --repo <path>\n  watson plane --repo <path> [--port 8079]\n  watson reap\n`);
    process.exit(cmd ? 1 : 0);
  }
} catch (err) {
  console.error(`\nwatson: ${err.message}\n`);
  process.exit(2);
}
