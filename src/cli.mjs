#!/usr/bin/env node
// Watson CLI — Phase 0.
//
//   watson verify --repo <path> [--sha <ref>] [--profile poc] [--base <ref>]
//   watson doctor --repo <path>            (bring up, probe, tear down)
//   watson reap                            (drop orphaned watson_* databases)
//
// Watson NEVER modifies product code. During a verification run it does not
// edit anything in the product checkout — not source, not the feature map.

import fs from 'node:fs';
import path from 'node:path';
import url from 'node:url';
import { execFileSync } from 'node:child_process';

import {
  loadContract, loadContractAt, selectByProfile, withDependencies,
  validateFeatureVars, validateEnvOwnership,
} from './contract.mjs';
import { productFingerprint, contractFingerprint, resolveSha, contractChange } from './fingerprint.mjs';
import * as env from './environment.mjs';
import * as drive from './driver.mjs';
import { evaluate, featureVerdict } from './checks.mjs';
import { buildEnvelope, rollUp, writeResult, summary } from './result.mjs';

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

/** Bring the product up exactly as Watson will drive it. Returns a handle whose
 *  `teardown()` kills only what we started, by process group. */
async function bringUp({ repoRoot, contract, runDir, runId, adminUrl }) {
  const cfg = contract.config;
  const dbName = `watson_${runId.replace(/[^a-z0-9]/gi, '').slice(-16).toLowerCase()}`;
  const appPort = await env.freePort();
  const started = {};
  const timings = {};

  const teardown = async () => {
    if (started.app) env.killGroup(started.app.pid);
    if (started.identity) await started.identity.close().catch(() => {});
    if (started.dbCreated) await env.dropDatabase({ adminUrl, dbName }).catch(() => {});
  };

  try {
    // 1. PROVISION -------------------------------------------------------------
    let t = Date.now();
    await env.provisionDatabase({ adminUrl, dbName, runId });
    started.dbCreated = true;
    const databaseUrl = adminUrl.replace(/\/[^/]*$/, `/${dbName}`);
    step(`database ${dbName}`);

    for (const cmd of cfg.provision ?? []) {
      await env.runStep(env.interpolate(cmd, { DATABASE_URL: databaseUrl }), {
        cwd: repoRoot, env: { ...process.env, DATABASE_URL: databaseUrl }, label: 'provision',
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
    const appEnv = {
      ...process.env,
      DATABASE_URL: databaseUrl,
      PORT: String(appPort),
      WORKOS_ISSUER: issuer,
      WORKOS_CLIENT_ID: clientId,
      WORKOS_JWKS_URI: started.identity.jwksUri,
      WORKOS_REDIRECT_URI: `http://127.0.0.1:${appPort}/auth/callback`,
      SESSION_SEALING_KEY_CURRENT: 'w'.repeat(48),
      WORKOS_API_KEY: 'sk_watson_local_placeholder_not_a_real_key',
    };

    // The contract's `env` may reference run-scoped values the engine owns, as
    // ${WATSON_*} placeholders. Substitute them and FAIL CLOSED on any that is
    // left unresolved: launching a half-configured application would let the
    // identity seam fall back to an ambient key source or stay unmounted, and
    // the run would then "verify" an app whose guarded routes never mounted.
    const injected = {
      WATSON_JWKS_URI: started.identity.jwksUri,
      WATSON_BASE_URL: `http://127.0.0.1:${appPort}`,
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
    for (const cmd of cfg.build ?? []) {
      await env.runStep(cmd, { cwd: repoRoot, env: appEnv, label: 'build' });
    }
    started.app = env.launchApp({
      cmd: cfg.launch.command, cwd: repoRoot, env: appEnv,
      logFile: path.join(runDir, 'logs', 'app.log'),
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
      { cwd: repoRoot, env: { ...appEnv, DATABASE_URL: databaseUrl }, label: 'seed' },
    );
    let vars = {};
    try {
      vars = JSON.parse(seed.stdout.slice(seed.stdout.indexOf('{'), seed.stdout.lastIndexOf('}') + 1));
    } catch (e) {
      throw new Error(`seed did not emit parseable JSON vars: ${e.message}\n${seed.stdout.slice(-400)}`);
    }
    step(`seeded: ${Object.keys(vars).join(', ')}`);
    timings.seed_ms = Date.now() - t;

    return { dbName, databaseUrl, baseUrl, appPort, vars, timings, tokens: started.identity.tokens, identity: started.identity, teardown };
  } catch (err) {
    await teardown();
    throw err;
  }
}

async function cmdVerify(args) {
  const repoRoot = path.resolve(args.repo ?? '.');
  const adminUrl = args['db-url'] ?? process.env.WATSON_ADMIN_DB_URL ?? 'postgres://watson:watson@127.0.0.1:5432/postgres';
  const profile = args.profile ?? 'poc';
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

  const selected = selectByProfile(contract.features, profile);
  const plan = withDependencies(selected, contract.features);

  const selection = {
    method: 'profile',
    profile,
    selected: plan.filter((p) => p.role === 'verified').map((p) => p.feature.id),
    setup: plan.filter((p) => p.role === 'setup').map((p) => p.feature.id),
    deferred: contract.features.filter((f) => !plan.some((p) => p.feature.id === f.id)).map((f) => f.id),
    note: 'Phase 0 selects by declared profile. Diff-driven impact selection is Phase 1.',
  };

  const base = {
    runId, watsonVersion: VERSION, repository: args.repository ?? path.basename(repoRoot),
    pullRequest: args.pr ? Number(args.pr) : null,
    headSha, baseSha,
    productFingerprint: productFingerprint(repoRoot, headSha),
    contractFingerprint: contractFingerprint(repoRoot, headSha),
    // Resolves the contract at BOTH SHAs so the diff can name what changed, not
    // merely that something did. `loadContractAt` returns null for an unreadable
    // or invalid base, which the diff reports as `base_contract_available: false`.
    contractChange: contractChange(repoRoot, baseSha, headSha, (sha) =>
      sha === headSha ? contract : loadContractAt(repoRoot, sha)),
    profile, selection, startedAt, shadow: true,
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
  // --- bring the environment up ------------------------------------------------
  let up;
  try {
    up = await bringUp({ repoRoot, contract, runDir, runId, adminUrl });
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

  try {
    // --- doctor ---------------------------------------------------------------
    const adminIdentity = contract.identities.find((i) => i.role === 'admin' && i.doctor) ?? contract.identities[0];
    const dr = await env.doctor({
      baseUrl: up.baseUrl, dbName: up.dbName, databaseUrl: up.databaseUrl,
      adminToken: up.tokens[adminIdentity?.id], expectSeasons: contract.config.launch.expect_seasons,
      identity: up.identity,
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
    console_errors: 0, console_warnings: 0, http_5xx: 0,
    unexpected_4xx: 0, failed_requests: 0, raw_uuid_visible: 0,
  };
}

function accumulate(sig, evidence, pageText) {
  sig.console_errors += evidence.pageErrors.length + evidence.console.filter((c) => c.type === 'error').length;
  sig.console_warnings += evidence.console.filter((c) => c.type === 'warning').length;
  sig.http_5xx += evidence.requests.filter((r) => r.status >= 500).length;
  sig.unexpected_4xx += evidence.requests.filter((r) => r.status >= 400 && r.status < 500 && ![401, 403, 404].includes(r.status)).length;
  sig.failed_requests += evidence.failed.filter((f) => !String(f.url).startsWith('data:')).length;
  if (pageText && /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i.test(pageText)) sig.raw_uuid_visible += 1;
}

function finish(runDir, run) {
  const envlp = buildEnvelope(run);
  const { jsonPath, mdPath } = writeResult(runDir, envlp);
  log('');
  log(summary(envlp).split('\n').slice(0, 3).join('\n'));
  log('');
  log(`  result   ${path.relative(process.cwd(), jsonPath)}`);
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
  const up = await bringUp({ repoRoot, contract, runDir, runId, adminUrl });
  try {
    const adminIdentity = contract.identities.find((i) => i.role === 'admin' && i.doctor) ?? contract.identities[0];
    const dr = await env.doctor({
      baseUrl: up.baseUrl, dbName: up.dbName, databaseUrl: up.databaseUrl,
      adminToken: up.tokens[adminIdentity?.id], expectSeasons: contract.config.launch.expect_seasons,
      identity: up.identity,
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
    process.exit(envlp.verdict === 'PASS' || envlp.verdict === 'PASS_WITH_ADVISORIES' ? 0 : 1);
  } else if (cmd === 'doctor') {
    process.exit(await cmdDoctor(args));
  } else if (cmd === 'reap') {
    const dropped = await env.reap({ adminUrl: args['db-url'] ?? process.env.WATSON_ADMIN_DB_URL ?? 'postgres://watson:watson@127.0.0.1:5432/postgres' });
    log(`reaped ${dropped.length} orphaned database(s): ${dropped.join(', ') || 'none'}`);
    process.exit(0);
  } else {
    log(`watson ${VERSION}\n\n  watson verify --repo <path> [--sha <ref>] [--base <ref>] [--profile poc] [--pr N]\n  watson doctor --repo <path>\n  watson reap\n`);
    process.exit(cmd ? 1 : 0);
  }
} catch (err) {
  console.error(`\nwatson: ${err.message}\n`);
  process.exit(2);
}
