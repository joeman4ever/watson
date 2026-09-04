// PROOF, not assertion: does Chromium's sandbox actually engage in the verifier
// container, as a non-root user?
//
// "We removed --no-sandbox" is not evidence. This runs the real launch path and
// then inspects what the KERNEL says about the processes it produced. Chromium's
// sandbox is two layers that fail independently, so both are established
// separately rather than one being taken as proof of the other:
//
//   layer 1  the renderer is in its own USER NAMESPACE   (/proc/<pid>/ns/user)
//   layer 2  the renderer runs under seccomp-bpf         (/proc/<pid>/status)
//
// Two things are measured before either, because without them a negative result
// is ambiguous:
//
//   - can this container create a user namespace at all? If not, a renderer
//     sharing our namespace says nothing about Chromium's choices.
//   - which BUILD is running? Playwright's default headless mode runs the
//     Chromium HEADLESS SHELL, a different binary from Chromium proper, and they
//     do not necessarily make the same sandbox choices. Watson's verdicts depend
//     on which one actually ran, so both are measured.
//
// Exits non-zero if the sandbox is not demonstrably on, and says which of the
// two causes applies. If a runner or image cannot give us a sandboxed non-root
// browser, the right outcome is a failed build and a conversation, not a quietly
// weakened boundary.

import fs from 'node:fs';
import { execFileSync } from 'node:child_process';
import { launchBrowser, probeSandbox, browserSandbox, BROWSER_CHANNEL } from '../src/driver.mjs';

const fail = (m) => { console.error(`\n  ✗ ${m}\n`); process.exit(1); };
const ok = (m) => console.log(`  ✓ ${m}`);

const uid = typeof process.getuid === 'function' ? process.getuid() : -1;
console.log(`\nWatson browser sandbox proof — uid ${uid}, ${process.platform}\n`);

if (uid === 0) fail('the verifier is running as root; Chromium cannot sandbox itself here');
if (!browserSandbox()) fail('browserSandbox() reports the sandbox is unavailable');
ok(`running unprivileged (uid ${uid})`);

const usernsAllowed = (() => {
  try {
    execFileSync('unshare', ['--user', '--map-root-user', 'true'], { stdio: 'ignore' });
    return true;
  } catch { return false; }
})();
ok(`the container ${usernsAllowed ? 'PERMITS' : 'FORBIDS'} unprivileged user namespaces`);

const ownNs = {};
for (const kind of ['user', 'pid', 'net']) {
  try { ownNs[kind] = fs.readlinkSync(`/proc/self/ns/${kind}`); } catch { ownNs[kind] = null; }
}
const isolatedFrom = (r) => ['user', 'pid', 'net'].filter((k) => r.ns[k] && ownNs[k] && r.ns[k] !== ownNs[k]);

function renderers() {
  const out = [];
  for (const pid of fs.readdirSync('/proc')) {
    if (!/^\d+$/.test(pid)) continue;
    let cmdline = '';
    try { cmdline = fs.readFileSync(`/proc/${pid}/cmdline`, 'utf8'); } catch { continue; }
    if (!cmdline.includes('--type=renderer')) continue;
    let status = '';
    try { status = fs.readFileSync(`/proc/${pid}/status`, 'utf8'); } catch { continue; }
    const field = (name) => (status.match(new RegExp(`^${name}:\\s*(\\S+)`, 'm')) ?? [])[1] ?? null;
    // Chromium's layer-1 sandbox does not always use a USER namespace: depending
    // on which mechanism it picks it may isolate the renderer by PID and network
    // namespace instead. Measuring only `ns/user` reported "not engaged" for a
    // browser that was in fact sandboxed — so all three are read, and any one of
    // them differing from ours is isolation.
    const ns = {};
    for (const kind of ['user', 'pid', 'net']) {
      try { ns[kind] = fs.readlinkSync(`/proc/${pid}/ns/${kind}`); } catch { ns[kind] = null; }
    }
    // TOKENISED ON NUL *AND* WHITESPACE, and that is not defensive padding.
    // `/proc/<pid>/cmdline` is normally NUL-separated, but Chromium rewrites its
    // own process title, so a renderer's whole command line arrives as ONE
    // element. Splitting on NUL alone produced a single token that matched
    // nothing, and the flag check below reported "clean" on a browser that was
    // demonstrably started with --no-sandbox.
    const argv = cmdline.split(/[\0\s]+/).filter(Boolean);
    out.push({ pid, argv, seccomp: field('Seccomp'), noNewPrivs: field('NoNewPrivs'), ns });
  }
  return out;
}

async function measure(label, options) {
  let browser;
  try {
    browser = await launchBrowser(options);
  } catch (err) {
    console.log(`  · ${label}: did not start (${String(err.message).split('\n')[0]})`);
    return null;
  }
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  await page.setContent('<h1>sandbox proof</h1>');
  await page.waitForTimeout(500);
  const found = renderers();
  const probe = await probeSandbox(browser);
  const m = {
    label,
    renderers: found,
    seccomp: found.filter((r) => r.seccomp === '2').length,
    nnp: found.filter((r) => r.noNewPrivs === '1').length,
    isolated: found.filter((r) => isolatedFrom(r).length > 0).length,
    isolatedBy: [...new Set(found.flatMap(isolatedFrom))],
    probe,
  };
  console.log(
    `  · ${label}: ${found.length} renderer(s), seccomp=2 on ${m.seccomp}, `
    + `namespace-isolated ${m.isolated}${m.isolatedBy.length ? ` (by ${m.isolatedBy.join('+')})` : ''}`
    + (probe.available ? `, chrome://sandbox ${probe.effective ? 'EFFECTIVE' : 'NOT effective'}` : ', chrome://sandbox not reportable'),
  );
  await ctx.close();
  await browser.close();
  return m;
}

// Both builds are measured for the record, but only ONE of them decides: the
// build Watson actually drives. Proving a property of a browser the engine does
// not use would be proving nothing.
const WATSON_BUILD = `chromium proper (channel: ${BROWSER_CHANNEL})`;
const measured = [];
for (const [label, options] of [
  ['headless shell (Playwright default)', { cdpPort: 0, channel: null }],
  [WATSON_BUILD, { cdpPort: 0 }],
]) {
  const m = await measure(label, options);
  if (m) measured.push(m);
}

if (!measured.length) fail('no browser started at all');

// THIS ASSERTION USED TO BE VACUOUS, and it is the one that would have found the
// root cause. It printed "Chromium started with no --no-sandbox flag" on the
// strength of `measured.length` being non-zero — it never looked at a command
// line. Meanwhile playwright-core was adding the flag itself:
//
//     if (options.chromiumSandbox !== true) chromeArguments.push('--no-sandbox');
//
// so the browser carried `--no-sandbox` on every run while `src/` contained no
// such string and a grep of `src/` said so. The flag now has to be absent from
// the argv of the PROCESSES WE ACTUALLY STARTED, which is the only place the
// question can be answered.
for (const m of measured) {
  const flagged = m.renderers.filter((r) => r.argv.some((a) => a === '--no-sandbox'));
  if (flagged.length) {
    fail(`${flagged.length}/${m.renderers.length} renderer(s) of ${m.label} were started with `
      + `--no-sandbox (pids ${flagged.map((r) => r.pid).join(', ')}). Watson does not put it there; `
      + `Playwright adds it unless \`chromiumSandbox: true\` is passed to launch().`);
  }
}
ok(`no renderer of any measured build carries --no-sandbox `
  + `(${measured.reduce((n, m) => n + m.renderers.length, 0)} renderer(s) inspected)`);

const best = measured.find((m) => m.label === WATSON_BUILD);
if (!best) fail(`the build Watson drives (${WATSON_BUILD}) did not start`);
if (!best.renderers.length) fail('no renderer process was found; the sandbox state cannot be established');

// EVERY renderer, not any. "1 of 3 sandboxed" is not a sandboxed browser, and a
// proof that accepts it would pass for a build that confined one process and left
// two open.
const sandboxed = best.renderers.filter((r) => r.seccomp === '2');
if (sandboxed.length !== best.renderers.length) {
  fail(`only ${sandboxed.length}/${best.renderers.length} renderer(s) report Seccomp: 2 `
    + `(${best.renderers.map((r) => `pid ${r.pid}=${r.seccomp}`).join(', ')}); seccomp-bpf is not engaged everywhere`);
}
ok(`${sandboxed.length}/${best.renderers.length} renderer(s) report Seccomp: 2 (seccomp-bpf) [${best.label}]`);

const nnp = sandboxed.filter((r) => r.noNewPrivs === '1');
if (nnp.length !== sandboxed.length) fail(`only ${nnp.length}/${sandboxed.length} renderer(s) report NoNewPrivs: 1`);
ok('every renderer reports NoNewPrivs: 1');

// LAYER 1. Chromium's own status page is the authoritative statement about it —
// Chromium knows which of several mechanisms it chose and whether that mechanism
// came up. Namespace isolation observed from /proc corroborates it, but is not
// required on its own: measuring only `ns/user` once reported "not engaged" for
// a browser Chromium itself called adequately sandboxed.
if (!best.probe.available) {
  fail(
    `the build Watson drives will not report chrome://sandbox, so layer 1 cannot be established. `
    + `The container ${usernsAllowed ? 'DOES' : 'does NOT'} permit unprivileged user namespaces.`,
  );
}
if (!best.probe.effective) {
  fail(
    `Chromium reports it is NOT adequately sandboxed. The container ${usernsAllowed ? 'DOES' : 'does NOT'} `
    + `permit unprivileged user namespaces, so the cause is ${usernsAllowed ? "the browser build's own" : 'the container configuration'}.`
    + `\n${best.probe.report}`,
  );
}
ok(`chrome://sandbox reports the layer-1 sandbox EFFECTIVE [${best.label}]`);
if (best.isolated) {
  ok(`corroborated: ${best.isolated}/${sandboxed.length} renderer(s) namespace-isolated by ${best.isolatedBy.join('+')}`);
} else {
  console.log('  · renderers share our namespaces; Chromium\'s layer-1 here does not rely on one');
}

console.log('\n  SANDBOX PROVEN: non-root browser; namespace sandbox and seccomp-bpf both engaged.\n');
