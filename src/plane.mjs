// The product plane: a deliberately dumb executor.
//
// WHERE THIS RUNS. Inside the untrusted container, as an unprivileged user,
// beside the product it brings up. It shares a filesystem with the product's
// checkout and nothing else. It cannot see the evidence directory, the engine's
// run bundle, the trusted orchestration, the host workspace, a GitHub token, or
// the browser.
//
// WHY IT IS DUMB. The verifier decides WHAT to run and with WHICH environment —
// it holds the contract, it provisions the database, it mints the identity, it
// waits on health itself. This process only executes the commands it is handed
// and reports what came back. Every decision that could change a verdict stays
// on the verifier side of the network.
//
// WHAT IT IS TRUSTED FOR: nothing. Its answers are product-supplied data, the
// same as the product's HTTP responses. A product that subverts this process
// entirely can lie about its own bring-up — which surfaces as a health timeout,
// or as an application that behaves however it behaves, which is exactly what
// Watson is there to observe. It cannot reach the evidence, because the evidence
// is not in this container.
//
// The verifier NEVER takes readiness from this process's word: it polls the
// product's own health endpoint across the network. That asymmetry is the point.

import http from 'node:http';
import path from 'node:path';
import fs from 'node:fs';

import { runStep, launchApp, interpolate, killGroup } from './environment.mjs';

export const PLANE_PROTOCOL = 'watson-product-plane/v1';

/** Bounded, so a hostile or merely noisy product cannot make the verifier read an
 *  unbounded body. Everything here is diagnostics, never evidence. */
const MAX_REQUEST_BYTES = 1_000_000;
const MAX_LOG_BYTES = 256 * 1024;

async function readJson(req) {
  const chunks = [];
  let total = 0;
  for await (const c of req) {
    total += c.length;
    if (total > MAX_REQUEST_BYTES) throw new Error('request body too large');
    chunks.push(c);
  }
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

/**
 * Bring the product up from an explicit plan.
 *
 * The plan is entirely the verifier's: commands resolved from the contract,
 * environment already interpolated, port already chosen. Nothing is read from
 * the product's own contract here, because contract interpretation is a
 * verification decision and belongs on the other side of the boundary.
 */
export async function bringUpFromPlan(plan, { repoRoot, logDir }) {
  const started = {};
  const timings = {};
  fs.mkdirSync(logDir, { recursive: true });
  const appLog = path.join(logDir, 'app.log');
  const env = { ...process.env, ...plan.env };

  const phase = async (label, fn) => {
    const t = Date.now();
    try {
      const out = await fn();
      timings[`${label}_ms`] = Date.now() - t;
      return out;
    } catch (err) {
      err.phase = label;
      throw err;
    }
  };

  await phase('install', async () => {
    for (const cmd of plan.install ?? []) {
      await runStep(cmd, { cwd: repoRoot, env, label: 'install' });
    }
  });

  await phase('provision', async () => {
    for (const cmd of plan.provision ?? []) {
      await runStep(interpolate(cmd, { DATABASE_URL: plan.env.DATABASE_URL }), {
        cwd: repoRoot, env, label: 'provision',
      });
    }
  });

  await phase('build', async () => {
    for (const cmd of plan.build ?? []) {
      await runStep(cmd, { cwd: repoRoot, env, label: 'build' });
    }
  });

  await phase('launch', async () => {
    started.app = launchApp({ cmd: plan.launch, cwd: repoRoot, env, logFile: appLog });
  });

  return { timings, pid: started.app?.pid ?? null, appLog };
}

/**
 * Seed the running product, and return the variables its fixture emitted.
 *
 * A SEPARATE call, because the ordering is load-bearing and was learned by
 * running the real thing: a product may create tables in its own startup
 * bootstrap rather than in migrations, so seeding must follow a live
 * application. Splitting it means "after launch" can mean what it should mean —
 * after the VERIFIER confirmed, across the network, that the product answers its
 * own health endpoint — rather than merely "after this process started something".
 */
export async function seedFromPlan(plan, { repoRoot }) {
  const env = { ...process.env, ...plan.env };
  const started = Date.now();
  const seed = await runStep(
    interpolate(plan.seed, { RUN_ID: plan.runId, DATABASE_URL: plan.env.DATABASE_URL }),
    { cwd: repoRoot, env, label: 'seed' },
  );
  let vars;
  try {
    vars = JSON.parse(seed.stdout.slice(seed.stdout.indexOf('{'), seed.stdout.lastIndexOf('}') + 1));
  } catch (e) {
    const err = new Error(`seed did not emit parseable JSON vars: ${e.message}\n${seed.stdout.slice(-400)}`);
    err.phase = 'seed';
    throw err;
  }
  return { vars, timings: { seed_ms: Date.now() - started } };
}

function tailFile(file, bytes = MAX_LOG_BYTES) {
  try {
    const { size } = fs.statSync(file);
    const start = Math.max(0, size - bytes);
    const fd = fs.openSync(file, 'r');
    try {
      const buf = Buffer.alloc(size - start);
      fs.readSync(fd, buf, 0, buf.length, start);
      return buf.toString('utf8');
    } finally {
      fs.closeSync(fd);
    }
  } catch {
    return '';
  }
}

/**
 * Serve the plane.
 *
 * Bound to every interface on purpose: the only thing that can reach it is the
 * isolated container network the trusted orchestration created, and the only
 * peer on that network that speaks to it is the verifier.
 */
export function serve({ repoRoot, logDir, port, host = '0.0.0.0' }) {
  const state = { app: null, appLog: null, phase: 'idle' };

  const server = http.createServer(async (req, res) => {
    const send = (code, body) => {
      res.writeHead(code, { 'content-type': 'application/json' });
      res.end(JSON.stringify(body));
    };
    try {
      if (req.method === 'GET' && req.url === '/alive') {
        return send(200, { ok: true, protocol: PLANE_PROTOCOL, phase: state.phase });
      }
      if (req.method === 'GET' && req.url?.startsWith('/app-log')) {
        return send(200, { ok: true, log: state.appLog ? tailFile(state.appLog) : '' });
      }
      // Everything up to and including starting the process. The verifier then
      // confirms health ITSELF before asking for /seed, so readiness is never
      // taken on this process's word.
      if (req.method === 'POST' && req.url === '/launch') {
        if (state.phase !== 'idle') return send(409, { ok: false, message: `plane is ${state.phase}` });
        state.phase = 'launching';
        const plan = await readJson(req);
        try {
          const out = await bringUpFromPlan(plan, { repoRoot, logDir });
          state.app = out.pid;
          state.appLog = out.appLog;
          state.phase = 'launched';
          return send(200, { ok: true, timings: out.timings });
        } catch (err) {
          state.phase = 'failed';
          state.appLog = state.appLog ?? path.join(logDir, 'app.log');
          return send(200, {
            ok: false,
            phase: err.phase ?? 'unknown',
            message: String(err.message ?? err).slice(0, 4000),
            log: tailFile(state.appLog, 32 * 1024),
          });
        }
      }
      if (req.method === 'POST' && req.url === '/seed') {
        if (state.phase !== 'launched') return send(409, { ok: false, message: `plane is ${state.phase}` });
        const plan = await readJson(req);
        try {
          const out = await seedFromPlan(plan, { repoRoot });
          state.phase = 'up';
          return send(200, { ok: true, vars: out.vars, timings: out.timings });
        } catch (err) {
          state.phase = 'failed';
          return send(200, {
            ok: false, phase: 'seed',
            message: String(err.message ?? err).slice(0, 4000),
            log: state.appLog ? tailFile(state.appLog, 32 * 1024) : '',
          });
        }
      }
      if (req.method === 'POST' && req.url === '/teardown') {
        if (state.app) killGroup(state.app);
        state.phase = 'idle';
        state.app = null;
        return send(200, { ok: true });
      }
      return send(404, { ok: false, message: 'no such endpoint' });
    } catch (err) {
      send(400, { ok: false, message: String(err.message ?? err).slice(0, 500) });
      // A refused body is still arriving. Left alone, the socket stays open with
      // the sender pushing megabytes at a request nobody is reading — which is
      // how "we refuse oversized bodies" becomes "we hold the connection open
      // forever instead". Hang up.
      req.destroy();
      return undefined;
    }
  });

  return new Promise((resolve) => {
    server.listen(port, host, () => resolve({
      port: server.address().port,
      close: () => new Promise((r) => {
        server.closeAllConnections?.();
        server.close(r);
      }),
    }));
  });
}
