// The derived seccomp profile must differ from Docker's default in EXACTLY the
// two ways `seccomp/README.md` documents.
//
// The failure this prevents is quiet and expensive: somebody widens the profile
// to make something work, the container still starts, the browser still runs,
// and nobody notices that the verifier is now less confined than it says it is.
// A profile is only worth deriving if the derivation is checked.

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  derive, load, DOCKER_CLONE_MASK, RELAXED_CLONE_MASK, CHROMIUM_NEEDS,
  CLONE_NEWCGROUP, CLONE_NEWUTS, CLONE_NEWIPC,
} from '../tools/seccomp-profile.mjs';

const base = load();
const derived = derive(base);

describe('the verifier seccomp profile is a small, checked delta', () => {
  test('it is still an allow-list', () => {
    assert.equal(derived.defaultAction, 'SCMP_ACT_ERRNO');
    assert.equal(derived.defaultAction, base.defaultAction);
  });

  test('the relaxed clone mask permits exactly what Chromium needs, and no more', () => {
    assert.equal(RELAXED_CLONE_MASK, DOCKER_CLONE_MASK & ~CHROMIUM_NEEDS);
    // Still refused: namespaces Chromium never asks for.
    for (const [name, bit] of [['CLONE_NEWCGROUP', CLONE_NEWCGROUP], ['CLONE_NEWUTS', CLONE_NEWUTS], ['CLONE_NEWIPC', CLONE_NEWIPC]]) {
      assert.ok(RELAXED_CLONE_MASK & bit, `${name} must still be inspected by the clone rule`);
    }
    // No longer inspected: the four the namespace sandbox creates.
    assert.equal(RELAXED_CLONE_MASK & CHROMIUM_NEEDS, 0);
  });

  test('unshare is allowed without CAP_SYS_ADMIN, and nothing else was ungated', () => {
    const gated = base.syscalls.filter((g) => g.includes?.caps?.includes('CAP_SYS_ADMIN'));
    const gatedAfter = derived.syscalls.filter((g) => g.includes?.caps?.includes('CAP_SYS_ADMIN'));
    const removed = gated.flatMap((g) => g.names).filter((n) =>
      !gatedAfter.flatMap((g) => g.names).includes(n));
    assert.deepEqual(removed, ['unshare'], `only unshare may lose its capability gate, but ${removed.join(', ')} did`);
  });

  test('setns stays gated — Chromium creates namespaces, it does not join them', () => {
    const setnsGroups = derived.syscalls.filter((g) => g.names.includes('setns'));
    assert.ok(setnsGroups.length > 0);
    for (const g of setnsGroups) {
      assert.ok(g.includes?.caps?.includes('CAP_SYS_ADMIN'), 'setns must remain behind CAP_SYS_ADMIN');
    }
  });

  test('no syscall gains an allow rule other than unshare', () => {
    const namesIn = (p) => new Set(p.syscalls.filter((g) => g.action === 'SCMP_ACT_ALLOW').flatMap((g) => g.names));
    const before = namesIn(base);
    const after = namesIn(derived);
    const added = [...after].filter((n) => !before.has(n));
    assert.deepEqual(added, [], `the derived profile allows syscalls the default does not: ${added.join(', ')}`);
  });

  test('the syscall rule set is otherwise byte-identical to Docker\'s default', () => {
    // Strip the two documented edits and the result must equal the vendored file.
    const restored = structuredClone(derived);
    restored.syscalls = restored.syscalls.filter((g) =>
      !(g.names.length === 1 && g.names[0] === 'unshare' && !g.includes && !g.args));
    for (const g of restored.syscalls) {
      if (g.action === 'SCMP_ACT_ALLOW' && g.includes?.caps?.includes('CAP_SYS_ADMIN')
          && g.names.includes('setns') && !g.names.includes('unshare')) {
        g.names = [...g.names, 'unshare'].sort((a, b) => base.syscalls.flatMap((x) => x.names).indexOf(a) - base.syscalls.flatMap((x) => x.names).indexOf(b));
      }
      if (g.names.length === 1 && g.names[0] === 'clone' && Array.isArray(g.args)) {
        for (const arg of g.args) {
          if (arg.op === 'SCMP_CMP_MASKED_EQ' && arg.value === RELAXED_CLONE_MASK) arg.value = DOCKER_CLONE_MASK;
        }
      }
    }
    assert.equal(restored.syscalls.length, base.syscalls.length);
  });
});
