// PROOF, not assertion: does Chromium's sandbox actually engage in the verifier
// container, as a non-root user?
//
// "We removed --no-sandbox" is not evidence. This runs the real launch path and
// then inspects what the kernel says about the processes it produced:
//
//   1. the verifier is not root                     (a precondition, not proof)
//   2. Chromium started at all                      (it refuses to, unsandboxed
//                                                    as root, and its zygote
//                                                    fails hard when the
//                                                    namespace sandbox cannot be
//                                                    created)
//   3. a RENDERER process exists and reports
//      `Seccomp: 2` in /proc/<pid>/status           (seccomp-bpf filter mode —
//                                                    the layer-2 sandbox)
//   4. that renderer reports `NoNewPrivs: 1`
//   5. chrome://sandbox agrees, where the build
//      will render it                               (corroboration, not the
//                                                    primary evidence)
//
// (3) and (4) are the load-bearing ones: they are read from the kernel about a
// process Chromium actually forked, so no flag, comment or configuration can
// make them true by accident.
//
// Exits non-zero if the sandbox is not demonstrably on. That is the point: if a
// runner or image cannot give us a sandboxed non-root browser, the right outcome
// is a failed build and a conversation, not a quietly weakened boundary.

import fs from 'node:fs';
import { launchBrowser, probeSandbox, browserSandbox } from '../src/driver.mjs';

const fail = (m) => { console.error(`\n  ✗ ${m}\n`); process.exit(1); };
const ok = (m) => console.log(`  ✓ ${m}`);

const uid = typeof process.getuid === 'function' ? process.getuid() : -1;
console.log(`\nWatson browser sandbox proof — uid ${uid}, ${process.platform}\n`);

if (uid === 0) fail('the verifier is running as root; Chromium cannot sandbox itself here');
if (!browserSandbox()) fail('browserSandbox() reports the sandbox is unavailable');
ok(`running unprivileged (uid ${uid})`);

let browser;
try {
  browser = await launchBrowser({ cdpPort: 0 });
} catch (err) {
  fail(`Chromium did not start: ${err.message}`);
}
ok('Chromium started with no --no-sandbox flag');

// A renderer only exists once something is rendered.
const ctx = await browser.newContext();
const page = await ctx.newPage();
await page.setContent('<h1>sandbox proof</h1>');
await page.waitForTimeout(500);

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
    try { userns = fs.readlinkSync(`/proc/${pid}/ns/user`); } catch { /* not permitted to read */ }
    out.push({ pid, seccomp: field('Seccomp'), noNewPrivs: field('NoNewPrivs'), uid: field('Uid'), userns });
  }
  return out;
}

const found = renderers();
if (!found.length) fail('no Chromium renderer process was found; the sandbox state cannot be established');
console.log(`  renderers: ${found.map((r) => `pid ${r.pid} seccomp=${r.seccomp} nnp=${r.noNewPrivs}`).join(', ')}`);

const sandboxed = found.filter((r) => r.seccomp === '2');
if (!sandboxed.length) {
  fail(`every renderer reports Seccomp=${found.map((r) => r.seccomp).join('/')}; seccomp-bpf is NOT engaged`);
}
ok(`${sandboxed.length}/${found.length} renderer(s) report Seccomp: 2 (seccomp-bpf filter mode)`);

const nnp = sandboxed.filter((r) => r.noNewPrivs === '1');
if (!nnp.length) fail('sandboxed renderers do not report NoNewPrivs: 1');
ok('renderers report NoNewPrivs: 1');

// LAYER 1. Seccomp-bpf is the second layer; the first is the namespace sandbox,
// which puts the renderer in its own user namespace so a compromised renderer is
// not merely syscall-filtered but unable to see the rest of the container. They
// fail independently, so proving one is not proving the other.
const ownUserns = (() => { try { return fs.readlinkSync('/proc/self/ns/user'); } catch { return null; } })();
const isolated = sandboxed.filter((r) => r.userns && ownUserns && r.userns !== ownUserns);
if (!isolated.length) {
  fail(
    `no renderer is in its own user namespace (verifier ${ownUserns}, renderers ` +
    `${sandboxed.map((r) => r.userns ?? 'unreadable').join('/')}); the layer-1 namespace sandbox is NOT engaged`,
  );
}
ok(`${isolated.length}/${sandboxed.length} renderer(s) are in their own user namespace (layer-1 sandbox)`);

const probe = await probeSandbox(browser);
if (probe.available) {
  ok(`chrome://sandbox: ${probe.effective ? 'adequately sandboxed' : 'NOT adequately sandboxed'}`);
  if (!probe.effective) fail(`chrome://sandbox disagrees:\n${probe.report}`);
} else {
  // Not a failure. The kernel evidence above is the primary proof; this page is
  // corroboration and some builds decline to render it.
  console.log(`  · chrome://sandbox not reportable by this build (${probe.report})`);
}

await ctx.close();
await browser.close();
console.log('\n  SANDBOX PROVEN: non-root browser; namespace sandbox and seccomp-bpf both engaged.\n');
