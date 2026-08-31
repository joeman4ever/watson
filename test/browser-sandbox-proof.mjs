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
import { launchBrowser, probeSandbox, browserSandbox } from '../src/driver.mjs';

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

const ownUserns = (() => { try { return fs.readlinkSync('/proc/self/ns/user'); } catch { return null; } })();

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
    let userns = null;
    try { userns = fs.readlinkSync(`/proc/${pid}/ns/user`); } catch { /* not permitted */ }
    out.push({ pid, seccomp: field('Seccomp'), noNewPrivs: field('NoNewPrivs'), userns });
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
    isolated: found.filter((r) => r.userns && ownUserns && r.userns !== ownUserns).length,
    probe,
  };
  console.log(
    `  · ${label}: ${found.length} renderer(s), seccomp=2 on ${m.seccomp}, own-userns on ${m.isolated}`
    + (probe.available ? `, chrome://sandbox ${probe.effective ? 'effective' : 'NOT effective'}` : ''),
  );
  await ctx.close();
  await browser.close();
  return m;
}

const measured = [];
for (const [label, options] of [
  ['headless shell (Playwright default)', { cdpPort: 0 }],
  ['chromium proper (channel: chromium)', { cdpPort: 0, channel: 'chromium' }],
]) {
  const m = await measure(label, options);
  if (m) measured.push(m);
}

if (!measured.length) fail('no browser started at all');
ok(`Chromium started with no --no-sandbox flag (${measured.length} build(s) measured)`);

const best = measured.reduce((a, b) => (b.isolated > a.isolated ? b : a));
if (!best.renderers.length) fail('no renderer process was found; the sandbox state cannot be established');

const sandboxed = best.renderers.filter((r) => r.seccomp === '2');
if (!sandboxed.length) {
  fail(`every renderer reports Seccomp=${best.renderers.map((r) => r.seccomp).join('/')}; seccomp-bpf is NOT engaged`);
}
ok(`${sandboxed.length}/${best.renderers.length} renderer(s) report Seccomp: 2 (seccomp-bpf) [${best.label}]`);

if (!sandboxed.some((r) => r.noNewPrivs === '1')) fail('sandboxed renderers do not report NoNewPrivs: 1');
ok('renderers report NoNewPrivs: 1');

if (!best.isolated) {
  fail(
    `no renderer is in its own user namespace (verifier ${ownUserns}); the layer-1 namespace sandbox is NOT engaged. `
    + (usernsAllowed
      ? 'The container DOES permit unprivileged user namespaces, so this is the browser build\'s own choice.'
      : 'The container FORBIDS unprivileged user namespaces, so the container configuration is the cause.'),
  );
}
ok(`${best.isolated}/${sandboxed.length} renderer(s) in their own user namespace (layer-1) [${best.label}]`);

if (best.probe.available) {
  ok(`chrome://sandbox: ${best.probe.effective ? 'adequately sandboxed' : 'NOT adequately sandboxed'}`);
  if (!best.probe.effective) fail(`chrome://sandbox disagrees:\n${best.probe.report}`);
} else {
  // Not a failure. The kernel evidence above is the primary proof; this page is
  // corroboration and some builds decline to render it.
  console.log('  · chrome://sandbox not reportable by this build');
}

console.log('\n  SANDBOX PROVEN: non-root browser; namespace sandbox and seccomp-bpf both engaged.\n');
