// Process execution for product-authored commands.
//
// Deliberately DEPENDENCY-FREE — node built-ins only. The product plane runs
// this code inside the untrusted container, from a read-only mount of the
// engine, with no `npm install` of its own. Every third-party import added here
// becomes something the untrusted side must be given, and something that must be
// installed before it can start.

import { spawn, execFileSync } from 'node:child_process';
import fs from 'node:fs';

/** Substitute ${NAME} from a map, with an unknown name becoming an empty string. */
export function interpolate(str, vars) {
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

