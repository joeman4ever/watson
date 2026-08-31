// Derive the verifier container's seccomp profile from Docker's default.
//
// Chromium's layer-1 sandbox puts each renderer in its own user namespace. On
// GitHub's runners that fails under Docker's default profile — measured, not
// assumed; see seccomp/README.md for the probe results. The two configurations
// that make it work are dropping seccomp entirely or granting CAP_SYS_ADMIN, and
// both are enormously larger than what Chromium actually needs.
//
// So this makes the smallest change that works, from Docker's own default, and
// prints it. The point of deriving rather than vendoring a finished profile is
// that the thing a reviewer has to read is this file — two edits — instead of
// 13KB of JSON.
//
//   node tools/seccomp-profile.mjs > /tmp/chromium-seccomp.json
//   docker run --security-opt seccomp=/tmp/chromium-seccomp.json ...

import fs from 'node:fs';
import path from 'node:path';
import url from 'node:url';

const HERE = path.dirname(url.fileURLToPath(import.meta.url));
export const DEFAULT_PROFILE = path.join(HERE, '..', 'seccomp', 'moby-default.json');

// The namespace bits Docker's default `clone` rule forbids, as one mask.
export const CLONE_NEWNS = 0x00020000;
export const CLONE_NEWCGROUP = 0x02000000;
export const CLONE_NEWUTS = 0x04000000;
export const CLONE_NEWIPC = 0x08000000;
export const CLONE_NEWUSER = 0x10000000;
export const CLONE_NEWPID = 0x20000000;
export const CLONE_NEWNET = 0x40000000;

/** Docker's mask: clone is allowed only when none of these are requested. */
export const DOCKER_CLONE_MASK =
  CLONE_NEWNS | CLONE_NEWCGROUP | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNET;

/**
 * What Chromium's namespace sandbox creates. Deliberately not "all of them":
 * new cgroup, UTS and IPC namespaces stay forbidden, because Chromium does not
 * ask for them and a profile should not permit what nothing needs.
 */
export const CHROMIUM_NEEDS = CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNET | CLONE_NEWNS;

export const RELAXED_CLONE_MASK = DOCKER_CLONE_MASK & ~CHROMIUM_NEEDS;

export function derive(profile) {
  const out = structuredClone(profile);
  let unshareRelaxed = 0;
  let cloneRelaxed = 0;

  for (const group of out.syscalls) {
    // (1) `unshare` sits in a group gated on CAP_SYS_ADMIN. Split it out so the
    //     container can create a namespace without being handed the capability
    //     that lets it do a hundred other things.
    if (group.action === 'SCMP_ACT_ALLOW' && group.includes?.caps?.includes('CAP_SYS_ADMIN')
        && group.names.includes('unshare')) {
      group.names = group.names.filter((n) => n !== 'unshare');
      unshareRelaxed += 1;
    }
    // (2) Widen the `clone` argument mask so the four flags Chromium needs are
    //     no longer inspected. The rule, its action and its architecture
    //     conditions are untouched.
    if (group.names.length === 1 && group.names[0] === 'clone' && Array.isArray(group.args)) {
      for (const arg of group.args) {
        if (arg.op === 'SCMP_CMP_MASKED_EQ' && arg.value === DOCKER_CLONE_MASK) {
          arg.value = RELAXED_CLONE_MASK;
          cloneRelaxed += 1;
        }
      }
    }
  }

  if (!unshareRelaxed) throw new Error('expected to find `unshare` gated on CAP_SYS_ADMIN; the vendored default changed');
  if (!cloneRelaxed) throw new Error('expected to find a masked `clone` rule; the vendored default changed');

  out.syscalls.push({
    names: ['unshare'],
    action: 'SCMP_ACT_ALLOW',
    comment: 'Chromium layer-1 sandbox: create a user namespace for each renderer',
  });
  return out;
}

export function load(file = DEFAULT_PROFILE) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

if (import.meta.url === url.pathToFileURL(process.argv[1] ?? '').href) {
  process.stdout.write(`${JSON.stringify(derive(load()), null, 1)}\n`);
}
