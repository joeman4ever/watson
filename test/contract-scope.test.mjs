// ADR-049 D2 — contract-change detection must cover everything verdict-bearing.
//
// The defect this closes is not that a check was wrong. It is that a check was
// NARROW while the result told a reviewer it was complete: `contractFingerprint`
// digested `.watson/` alone, and `contractChange` diffed features and invariants
// alone, so the entire head-authored half of the verdict surface — the fixture
// script that builds the world, the package scripts, the lockfile, the migrations
// — moved without appearing anywhere.
//
// Everything here runs against a real git repository, because these functions are
// about what a commit contains and a stub would only re-state my assumptions.

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

import {
  verdictBearingPaths, contractFingerprint, contractChange, changedPaths, pathExistsAt, subtreeDigest,
  canonicalContract, deepDiffPaths, operationalConfigChange,
} from '../src/fingerprint.mjs';
import { walkTree } from '../src/manifest.mjs';
import { buildEnvelope, summary } from '../src/result.mjs';
import { loadContract } from '../src/contract.mjs';
import { CONFIG_AUTHORITY } from '../src/governance.mjs';

const contract = (over = {}) => ({
  config: {
    install: ['npm ci'],
    provision: ['npm run migrate:up --workspace=server'],
    build: [],
    launch: { command: 'npm run start --workspace=server' },
    ...over.config,
  },
  fixtures: { profiles: { p: { command: 'npx tsx server/scripts/watson-fixture.ts' } }, ...over.fixtures },
  features: [], invariants: [], identities: [],
});

describe('the scope is derived from the contract, not remembered', () => {
  test('a script the contract invokes is in scope', () => {
    const p = verdictBearingPaths(contract(), (x) => x === 'server/scripts/watson-fixture.ts');
    assert.ok(p.includes('server/scripts/watson-fixture.ts'));
  });

  test('so is the workspace package.json a `--workspace` command runs through', () => {
    const p = verdictBearingPaths(contract(), (x) => x === 'server/package.json');
    assert.ok(p.includes('server/package.json'));
  });

  test('and the install surface, when it is present', () => {
    const p = verdictBearingPaths(contract(), (x) => ['package-lock.json', '.npmrc'].includes(x));
    assert.ok(p.includes('package-lock.json'));
    assert.ok(p.includes('.npmrc'));
    assert.ok(!p.includes('yarn.lock'), 'fingerprinting a file that is not there');
  });

  test('`.watson` is always in scope, with or without a contract', () => {
    assert.ok(verdictBearingPaths(null, () => false).includes('.watson'));
  });

  test('command words that merely look pathy are not', () => {
    // `npm`, `run`, `start` and `--workspace=server` must not become paths, or
    // the digest becomes a list of `absent` entries that hides real movement.
    const p = verdictBearingPaths(contract(), () => true);
    for (const junk of ['npm', 'run', 'start', 'ci', 'server']) assert.ok(!p.includes(junk), junk);
  });

  test('what extraction cannot see is DECLARED — and declared in the BASE contract', () => {
    // `npm run migrate:up` names no path, so migrations need a declaration. The
    // declaration being base-governed is the whole reason it is not another
    // `generated_roots`.
    const c = contract();
    c.config.verdict_bearing_paths = ['server/migrations'];
    assert.ok(verdictBearingPaths(c, () => true).includes('server/migrations'));
    assert.equal(CONFIG_AUTHORITY.verdict_bearing_paths, 'base');
  });

  // WHAT THE HEAD CAN SHRINK, STATED EXACTLY.
  //
  // The comment above this test used to end "a pull request cannot shrink the
  // list that decides whether its own changes get reported". The independent
  // review of #9 (NB4) was right that this is false as written, and the honest
  // response is a test that draws the line rather than a softer sentence.
  //
  // `install`, `provision`, `build` and `launch.command` are HEAD-AUTHORED by
  // decision — they must match the pull request's own tree or nothing runs — so
  // every path reachable only through them is reachable only through something
  // the pull request writes.
  describe('the head can shrink the extracted half, and only the extracted half', () => {
    const present = new Set([
      'server/migrations', 'server/package.json', 'package.json',
      'package-lock.json', 'server/scripts/watson-fixture.ts',
    ]);
    const exists = (x) => present.has(x);
    const manifests = {
      'package.json': JSON.stringify({ workspaces: ['client', 'server'] }),
      'server/package.json': JSON.stringify({
        name: '@nsc-eval/server',
        scripts: { 'migrate:up': 'node-pg-migrate up -m migrations' },
      }),
    };
    const read = (p) => manifests[p] ?? null;

    const withProvision = (cmd) => {
      const c = contract();
      c.config.provision = [cmd];
      return c;
    };

    test('dropping `--workspace` from its own provision command drops a path', () => {
      // This is the defect, reproduced. It is not hypothetical: run against
      // nsc-eval's real contract the same edit takes the scope from 8 to 7.
      const full = verdictBearingPaths(
        withProvision('npm run migrate:up --workspace=@nsc-eval/server'), exists, read,
      );
      const shrunk = verdictBearingPaths(withProvision('npm run migrate:up'), exists, read);

      assert.ok(full.includes('server/migrations'),
        'the workspace hop is what puts migrations in scope');
      assert.ok(!shrunk.includes('server/migrations'),
        'HEAD-AUTHORED provision decides whether migrations are fingerprinted');
      assert.deepEqual(full.filter((p) => !shrunk.includes(p)), ['server/migrations']);
    });

    test('the base-governed declaration puts it back, and the head cannot take it out', () => {
      // The remedy is not engine code. It is source 3, used: a path that must
      // stay in scope however the head writes its commands is declared in the
      // BASE contract, where the head has no authority over it.
      const c = withProvision('npm run migrate:up');
      c.config.verdict_bearing_paths = ['server/migrations'];
      assert.ok(verdictBearingPaths(c, exists, read).includes('server/migrations'));
      assert.equal(CONFIG_AUTHORITY.verdict_bearing_paths, 'base');
    });

    test('and the unconditional half is not reachable from any command at all', () => {
      // `.watson` and the install surface do not come from a command string, so
      // no rewrite of one can remove them. Emptying EVERY head-authored command
      // is the strongest version of the attack, and it still leaves these.
      const c = contract();
      c.config.install = []; c.config.provision = []; c.config.build = [];
      c.config.launch = { command: '' };
      c.fixtures = { profiles: {} };
      const p = verdictBearingPaths(c, exists, read);
      assert.ok(p.includes('.watson'));
      assert.ok(p.includes('package.json'));
      assert.ok(p.includes('package-lock.json'));
    });

    test('the shrink is reported: rewriting provision moves operational_config', () => {
      // The gap is bounded by being VISIBLE. A reviewer sees the changed key and
      // can compare `contract_scope` between the two results directly.
      const base = withProvision('npm run migrate:up --workspace=@nsc-eval/server');
      const head = withProvision('npm run migrate:up');
      const change = operationalConfigChange(base.config, head.config);
      assert.equal(change.changed, true);
      assert.ok(change.changed_keys.includes('provision'));
      assert.notEqual(change.base_fingerprint, change.head_fingerprint);
    });
  });

  test('a declared path cannot escape the repository', () => {
    const c = contract();
    c.config.verdict_bearing_paths = ['../../etc/passwd', '/etc/passwd', 'ok/here.txt'];
    const p = verdictBearingPaths(c, () => true);
    assert.deepEqual(p.filter((x) => x.includes('..') || x.startsWith('/')), []);
    assert.ok(p.includes('ok/here.txt'));
  });
});

describe('following `npm run` to the file it actually runs', () => {
  // Run against nsc-eval WITHOUT this, the mechanism returned six paths and not
  // the fixture script — every command in that contract goes through `npm run`
  // and names no file. A control that covers almost nothing while the result
  // says the contract surface is fingerprinted is worse than one that is
  // obviously absent.
  const manifests = {
    'package.json': JSON.stringify({ workspaces: ['client', 'server'] }),
    'server/package.json': JSON.stringify({
      name: '@nsc-eval/server',
      scripts: {
        'watson:fixture': 'tsx scripts/watson-fixture.ts',
        'migrate:up': 'node-pg-migrate up -m migrations',
        start: 'tsx src/index.ts',
      },
    }),
  };
  const read = (p) => manifests[p] ?? null;
  const present = new Set([
    'server/package.json', 'package.json',
    'server/scripts/watson-fixture.ts', 'server/migrations', 'server/src/index.ts',
  ]);

  test('the fixture command reaches the fixture script', () => {
    const c = contract({ fixtures: { profiles: { p: { command: 'npm run watson:fixture --workspace=server -- --force' } } } });
    const p = verdictBearingPaths(c, (x) => present.has(x), read);
    assert.ok(p.includes('server/scripts/watson-fixture.ts'), p.join(','));
  });

  test('a workspace PACKAGE NAME resolves to its directory', () => {
    // nsc-eval's contract uses `--workspace=server` and
    // `--workspace=@nsc-eval/server` one line apart. Handling only the first
    // dropped `server/migrations` out of the measured scope in silence.
    const c = contract({ config: { provision: ['npm run migrate:up --workspace=@nsc-eval/server'], launch: {} } });
    const p = verdictBearingPaths(c, (x) => present.has(x), read);
    assert.ok(p.includes('server/migrations'), p.join(','));
  });

  test('non-path words in a resolved script body drop out', () => {
    const c = contract({ config: { provision: ['npm run migrate:up --workspace=server'], launch: {} } });
    const p = verdictBearingPaths(c, (x) => present.has(x), read);
    for (const junk of ['server/up', 'server/node-pg-migrate']) assert.ok(!p.includes(junk), junk);
  });

  test('THE LINE THAT MATTERS: launch is NOT followed into product source', () => {
    // Resolving `launch.command` reaches `server/src/index.ts` — the application
    // under test, already measured as `product_fingerprint`. Including it would
    // make every product pull request report a contract change, which destroys
    // the only signal this field carries.
    const c = contract({ config: { launch: { command: 'npm run start --workspace=server' }, install: [], provision: [], build: [] } });
    const p = verdictBearingPaths(c, (x) => present.has(x), read);
    assert.ok(!p.includes('server/src/index.ts'), p.join(','));
    assert.ok(p.includes('server/package.json'), 'the workspace manifest is still in scope');
  });

  test('an unreadable or absent manifest resolves to nothing, not to an error', () => {
    const c = contract({ fixtures: { profiles: { p: { command: 'npm run x --workspace=server' } } } });
    assert.doesNotThrow(() => verdictBearingPaths(c, () => true, () => 'not json at all'));
    assert.doesNotThrow(() => verdictBearingPaths(c, () => true, () => null));
  });
});

describe('against a real repository', () => {
  const repo = () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'watson-d2-'));
    const g = (...a) => execFileSync('git', a, { cwd: dir, stdio: ['ignore', 'pipe', 'pipe'] });
    g('init', '-q', '-b', 'main');
    g('config', 'user.email', 'w@example.invalid');
    g('config', 'user.name', 'w');
    return { dir, g, commit: (m) => { g('add', '-A'); g('commit', '-q', '-m', m); return g('rev-parse', 'HEAD').toString().trim(); } };
  };

  // MATERIALISE THE TWO TRUSTED SIDES, the way the observer does.
  //
  // The engine no longer reads either side out of the product clone, so these
  // tests must not hand it one. `base/` is a directory the trusted plane
  // produced from the base revision; the head side is the trusted MANIFEST's
  // entries, which the trusted plane builds before a line of product code runs.
  //
  // `git archive` here is the TEST constructing the topology, not the engine
  // reading it. That distinction is the whole point of the change: what the
  // engine is given is two trees, and where the test got them is the test's
  // business.
  const materialise = (r, sha) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'watson-trusted-'));
    const tar = execFileSync('git', ['archive', '--format=tar', sha], { cwd: r.dir, maxBuffer: 64 * 1024 * 1024 });
    const t = path.join(dir, 'x.tar');
    fs.writeFileSync(t, tar);
    execFileSync('tar', ['-xf', t, '-C', dir]);
    fs.unlinkSync(t);
    return dir;
  };
  const sides = (r, base, head) => ({
    baseEntries: walkTree(materialise(r, base)),
    headEntries: walkTree(materialise(r, head)),
  });

  const writeContract = (dir, { enumValues = ['A', 'B', 'C'] } = {}) => {
    const d = path.join(dir, '.watson');
    fs.mkdirSync(path.join(d, 'features'), { recursive: true });
    fs.mkdirSync(path.join(d, 'fixtures'), { recursive: true });
    fs.writeFileSync(path.join(d, 'config.yaml'), [
      'contract_version: 4',
      'launch: { command: "npm run start --workspace=server", fixture_profile: p }',
      'install: ["npm ci"]',
    ].join('\n'));
    fs.writeFileSync(path.join(d, 'identities.yaml'), 'identities: []\n');
    fs.writeFileSync(path.join(d, 'invariants.yaml'), 'invariants: []\n');
    fs.writeFileSync(path.join(d, 'fixtures', 'profiles.yaml'),
      `profiles:\n  p:\n    command: "npx tsx server/scripts/watson-fixture.ts"\n    verifier_chosen:\n      - grade: { enum: ${JSON.stringify(enumValues)} }\n`);
    fs.writeFileSync(path.join(d, 'features', 'j1.md'),
      ['---', 'id: j1', 'title: j1', 'status: mapped', 'personas: [A]', 'profiles: [poc]',
        'steps:', '  - goto: /', '---', '', 'b'].join('\n'));
  };

  test('THE MISS: the fixture script moves and `.watson` does not', () => {
    // Before D2 this was invisible: the digest covered `.watson/` only, so the
    // code that builds the world the journeys assert on could be rewritten with
    // `contract_change: false` on the result.
    const r = repo();
    fs.mkdirSync(path.join(r.dir, 'server/scripts'), { recursive: true });
    fs.writeFileSync(path.join(r.dir, 'server/scripts/watson-fixture.ts'), 'original\n');
    writeContract(r.dir);
    const base = r.commit('base');

    fs.writeFileSync(path.join(r.dir, 'server/scripts/watson-fixture.ts'), 'rewritten\n');
    const head = r.commit('head');

    const c = loadContract(r.dir);
    const scope = verdictBearingPaths(c, pathExistsAt(r.dir, head));
    assert.ok(scope.includes('server/scripts/watson-fixture.ts'), scope.join(','));

    assert.equal(contractFingerprint(r.dir, base, ['.watson']),
      contractFingerprint(r.dir, head, ['.watson']),
      '`.watson` is unchanged — which is exactly why the narrow digest missed it');
    assert.notEqual(contractFingerprint(r.dir, base, scope),
      contractFingerprint(r.dir, head, scope));

    const change = contractChange({ ...sides(r, base, head), loadAt: () => c, paths: scope });
    assert.ok(change, 'no contract change reported');
    assert.deepEqual(change.paths_changed, ['server/scripts/watson-fixture.ts']);
  });

  test('a lockfile change is reported — it decides what `npm ci` installs', () => {
    const r = repo();
    writeContract(r.dir);
    fs.writeFileSync(path.join(r.dir, 'package-lock.json'), '{"v":1}\n');
    const base = r.commit('base');
    fs.writeFileSync(path.join(r.dir, 'package-lock.json'), '{"v":2}\n');
    const head = r.commit('head');
    const c = loadContract(r.dir);
    const scope = verdictBearingPaths(c, pathExistsAt(r.dir, head));
    const change = contractChange({ ...sides(r, base, head), loadAt: () => c, paths: scope });
    assert.deepEqual(change.paths_changed, ['package-lock.json']);
  });

  test('nothing changed is still null, so the report does not cry wolf', () => {
    const r = repo();
    writeContract(r.dir);
    const base = r.commit('base');
    fs.writeFileSync(path.join(r.dir, 'unrelated.txt'), 'x\n');
    const head = r.commit('head');
    const c = loadContract(r.dir);
    const scope = verdictBearingPaths(c, pathExistsAt(r.dir, head));
    assert.equal(contractChange({ ...sides(r, base, head), loadAt: () => c, paths: scope }), null);
  });

  // ===========================================================================
  // D1 / N9 — THE BASE SIDE COMES FROM THE TRUSTED MATERIALISATION.
  //
  // `contractChange` and `changedPaths` used to run git inside the PRODUCT clone
  // for base-side facts. That clone is `refs/pull/N/head`; the base SHA is the
  // base branch tip and is in it only by coincidence. When it was not,
  // `treeHash` returned the string `absent` for every scoped path, EVERY path
  // read as changed, and the result asserted a contract change nothing had
  // established — while `base_contract_available` said `true`.
  //
  // Two defects, and the second is the worse: base-side facts asked of the
  // untrusted repository, and "could not read" reported as "absent".
  //
  // The property these cases pin is NOT "the base object happens to be there".
  // It is:
  //
  //     base-side computation comes from the trusted base materialisation and is
  //     INDEPENDENT of whether the product checkout contains the base git object
  //
  // so the tests are written against that, not against a lucky repository.
  describe('D1: base-side comparison is independent of the product clone', () => {
    // The real topology, built rather than described: a product clone holding
    // ONLY the head commit — no base object, exactly as `refs/pull/N/head` gives
    // it — beside a trusted materialisation of each side.
    const topology = ({ headDiffers = false } = {}) => {
      const r = repo();
      writeContract(r.dir);
      fs.mkdirSync(path.join(r.dir, 'server/scripts'), { recursive: true });
      fs.writeFileSync(path.join(r.dir, 'server/scripts/watson-fixture.ts'), 'original\n');
      const base = r.commit('base');
      if (headDiffers) fs.writeFileSync(path.join(r.dir, 'server/scripts/watson-fixture.ts'), 'rewritten\n');
      else fs.writeFileSync(path.join(r.dir, 'unrelated.txt'), 'x\n');
      const head = r.commit('head');

      // The product clone as the observer actually produces it.
      const product = fs.mkdtempSync(path.join(os.tmpdir(), 'watson-product-'));
      const pg = (...a) => execFileSync('git', a, { cwd: product, stdio: ['ignore', 'pipe', 'pipe'] });
      pg('init', '-q', '-b', 'main');
      pg('remote', 'add', 'origin', r.dir);
      pg('fetch', '-q', '--depth', '1', 'origin', head);
      pg('checkout', '-q', '--detach', 'FETCH_HEAD');

      const c = loadContract(r.dir);
      return { r, base, head, product, c, scope: verdictBearingPaths(c, pathExistsAt(r.dir, head)) };
    };

    test('the product clone really does lack the base object — the premise, executed', () => {
      // Without this the rest proves nothing: a test that never built the
      // failing condition cannot show the condition no longer matters.
      const t = topology();
      const has = (sha) => {
        try {
          execFileSync('git', ['cat-file', '-e', sha], { cwd: t.product, stdio: 'ignore' });
          return true;
        } catch { return false; }
      };
      assert.equal(has(t.head), true, 'the product clone should hold the head');
      assert.equal(has(t.base), false, 'the product clone should NOT hold the base — the premise of N9');
    });

    test('CASE 1 — identical contract content reports NO change, base object absent', () => {
      // THE KEY NEGATIVE CONTROL. Before this change the same topology reported
      // every scoped path as changed. The product clone's missing base object is
      // now irrelevant, because the product clone is not consulted.
      const t = topology();
      const change = contractChange({ ...sides(t.r, t.base, t.head), loadAt: () => t.c, paths: t.scope });
      assert.equal(change, null, `spurious contract change: ${JSON.stringify(change)}`);
    });

    test('CASE 1b — changedPaths is computed, not abandoned', () => {
      const t = topology();
      const changed = changedPaths(sides(t.r, t.base, t.head));
      assert.ok(Array.isArray(changed), 'changedPaths gave up and returned null');
      assert.deepEqual(changed, ['unrelated.txt']);
    });

    test('CASE 2 — a real contract modification is still reported, with no loss of sensitivity', () => {
      const t = topology({ headDiffers: true });
      const change = contractChange({ ...sides(t.r, t.base, t.head), loadAt: () => t.c, paths: t.scope });
      assert.ok(change, 'a real change went unreported');
      assert.deepEqual(change.paths_changed, ['server/scripts/watson-fixture.ts']);
      assert.equal(change.base_contract_available, true);
    });

    test('CASE 3 — a genuinely unavailable base is UNAVAILABLE, not changed and not clean', () => {
      const t = topology({ headDiffers: true });
      const { headEntries } = sides(t.r, t.base, t.head);
      const change = contractChange({ baseEntries: null, headEntries, loadAt: () => t.c, paths: t.scope });

      assert.ok(change, 'an unavailable comparison must be reported, not silently null');
      assert.equal(change.comparison, 'unavailable');
      // NOT asserted false here any more, and the change is deliberate. This key
      // means "was the base CONTRACT loadable", and in this case it was — what
      // was unobtainable is the base TREE. Asserting false conflated two
      // subjects under one name; the tree's absence is carried by `comparison`
      // and `why`.
      assert.equal(change.base_contract_available, true);
      // NEITHER fabrication. This is the whole point of the case.
      assert.deepEqual(change.paths_changed, [], 'fabricated a change from missing information');
      assert.notEqual(change, null, 'fabricated "unchanged" from missing information');
      assert.match(change.why, /base/);

      // And selection stays fail-conservative rather than diff-driven.
      assert.equal(changedPaths({ baseEntries: null, headEntries }), null);
    });

    test('CASE 3b — an unreadable head manifest is equally unavailable', () => {
      const t = topology();
      const { baseEntries } = sides(t.r, t.base, t.head);
      const change = contractChange({ baseEntries, headEntries: null, loadAt: () => t.c, paths: t.scope });
      assert.equal(change.comparison, 'unavailable');
      assert.deepEqual(change.paths_changed, []);
      assert.equal(changedPaths({ baseEntries, headEntries: null }), null);
    });

    test('CASE 4 — a path the base PROVABLY lacks is a real addition, not an unreadable one', () => {
      // The distinction the old code could not express: it spelled "absent" and
      // "unreadable" with the same string. Here the trusted base materialisation
      // proves the path is not there.
      const r = repo();
      writeContract(r.dir);
      const base = r.commit('base');
      fs.mkdirSync(path.join(r.dir, 'server/scripts'), { recursive: true });
      fs.writeFileSync(path.join(r.dir, 'server/scripts/watson-fixture.ts'), 'new file\n');
      const head = r.commit('head');
      const c = loadContract(r.dir);
      const scope = verdictBearingPaths(c, pathExistsAt(r.dir, head));

      const change = contractChange({ ...sides(r, base, head), loadAt: () => c, paths: scope });
      assert.ok(change, 'a head-added contract path was not reported');
      assert.ok(change.paths_changed.includes('server/scripts/watson-fixture.ts'));
      assert.equal(change.base_contract_available, true);
    });

    test('a scoped path absent from BOTH sides is not a change', () => {
      // Scope can name a path that exists at neither revision — a base-declared
      // `verdict_bearing_paths` entry for a directory not created yet — and that
      // must be silence, not a change.
      //
      // HONEST NOTE ON WHAT THIS TEST IS. It is a characterisation test, not a
      // control. I could not construct a mutation of `subtreeDigest`'s absent
      // return that breaks it, because the function is a pure function of
      // `(entries, p)` and both sides are called with the same `p` — so any
      // constant, and any value derived from `p`, compares equal on both sides.
      // Two attempted controls stayed green and are recorded rather than counted.
      //
      // What CAN regress is the absent return becoming ENTRIES-dependent, and
      // the assertion below pins that directly. Reported as a characterisation
      // test so nobody reads a green here as evidence of a control.
      const r = repo();
      writeContract(r.dir);
      const base = r.commit('base');
      fs.writeFileSync(path.join(r.dir, 'unrelated.txt'), 'x\n');
      const head = r.commit('head');
      const c = loadContract(r.dir);
      const change = contractChange({
        ...sides(r, base, head), loadAt: () => c,
        paths: ['.watson', 'does/not/exist/at/either/revision'],
      });
      assert.equal(change, null, 'a path absent from both sides was reported as changed');
    });

    // -------------------------------------------------------------------------
    // FOUR INVARIANTS INSIDE THE D1 COMPARISON CODE THAT NOTHING PINNED.
    //
    // Found by the exact-HEAD confirmation: each of these mutations left the
    // whole 438-test suite green. The shipped code is correct in all four cases;
    // what was missing is anything that would notice it stopping being. These
    // are the load-bearing details of a function written three commits ago, so
    // they get pinned in the same slice that introduced them.
    test('the prefix match requires a path separator', () => {
      // The classic: `server/mig` must not match `server/migrations`. Without
      // the trailing `/` a scoped path silently absorbs every sibling whose name
      // it prefixes, and two different trees start comparing equal.
      const tree = new Map([
        ['server/migrations/001.sql', { type: 'file', digest: 'sha256:aa', mode: '644' }],
        ['server/migrations-old/x.sql', { type: 'file', digest: 'sha256:bb', mode: '644' }],
      ]);
      const d = subtreeDigest(tree, 'server/migrations');
      const only = new Map([['server/migrations/001.sql', tree.get('server/migrations/001.sql')]]);
      assert.equal(d, subtreeDigest(only, 'server/migrations'),
        'the digest absorbed a sibling directory that merely shares a prefix');
    });

    test('`type` is part of the digest, because a symlink and a file collide without it', () => {
      // NOT decorative. `walkTree` digests a symlink as sha256(target) and a
      // file as sha256(content), so a symlink whose TARGET STRING equals a
      // file's CONTENT has the identical `digest`. Only `type` separates them,
      // and a contract path swapped from file to symlink is exactly the
      // substitution that would matter.
      // MODE HELD EQUAL, so `type` is the only difference. The first version of
      // this test left the file at mode 644 and the symlink at null, so removing
      // `type` from the digest left it green — it was passing on `mode`. Caught
      // by running the control.
      const asFile = new Map([['.watson/x', { type: 'file', digest: 'sha256:same', mode: null }]]);
      const asLink = new Map([['.watson/x', { type: 'symlink', digest: 'sha256:same', mode: null }]]);
      assert.notEqual(subtreeDigest(asFile, '.watson'), subtreeDigest(asLink, '.watson'),
        'a symlink and a file with equal digests were indistinguishable');
    });

    test('`mode` is part of the digest — the executable bit is semantic', () => {
      // The same bytes with and without the executable bit are different
      // materialisations, and one of them runs.
      const a = new Map([['.watson/run.sh', { type: 'file', digest: 'sha256:same', mode: '644' }]]);
      const b = new Map([['.watson/run.sh', { type: 'file', digest: 'sha256:same', mode: '755' }]]);
      assert.notEqual(subtreeDigest(a, '.watson'), subtreeDigest(b, '.watson'));
    });

    test('changedPaths notices a mode-only change', () => {
      const base = new Map([['s.sh', { type: 'file', digest: 'sha256:same', mode: '644' }]]);
      const head = new Map([['s.sh', { type: 'file', digest: 'sha256:same', mode: '755' }]]);
      assert.deepEqual(changedPaths({ baseEntries: base, headEntries: head }), ['s.sh'],
        'a file that became executable was reported as unchanged');
    });

    test('a base tree that was SUPPLIED but could not be READ says so', () => {
      // The could-not-read/was-not-supplied distinction, one layer up from where
      // D1 fixed it. The reason used to survive only in the run log — which the
      // observer uploads ONLY when the step fails, so on a green run it was not
      // preserved at all — while the envelope said "no trusted base
      // materialisation was supplied". A materialisation WAS supplied.
      const supplied = contractChange({
        baseEntries: null, headEntries: new Map(), loadAt: () => null, paths: ['.watson'],
      });
      assert.match(supplied.why, /was not supplied|no trusted base materialisation was supplied/);

      const unreadable = contractChange({
        baseEntries: null, headEntries: new Map(), loadAt: () => null, paths: ['.watson'],
        baseTreeError: 'could not read .: ENOENT',
      });
      assert.match(unreadable.why, /could not be read/);
      assert.match(unreadable.why, /ENOENT/);
      // Both are still UNAVAILABLE — the distinction is in the reason, not the state.
      assert.equal(unreadable.comparison, 'unavailable');
      assert.deepEqual(unreadable.paths_changed, []);
    });

    test('EVERY branch reports its comparison state — a three-state field expressing two is the bug', () => {
      // The `comparison` key was added on the unavailable branch only, so a
      // DIVERGED result left it undefined and a consumer writing
      // `ce.comparison ?? 'equivalent'` — the exact pattern removed from the
      // top-level field one commit earlier — was told a diverged contract was
      // equivalent. A three-state carrier that can only express two states is
      // the collapse this work exists to remove, reintroduced by the field
      // added to prevent it.
      const base = new Map([['.watson/c.yaml', { type: 'file', digest: 'sha256:aa', mode: '644' }]]);
      const head = new Map([['.watson/c.yaml', { type: 'file', digest: 'sha256:bb', mode: '644' }]]);
      const c = { config: {}, features: [], invariants: [], identities: [], fixtures: { profiles: {} } };

      const diverged = contractChange({ baseEntries: base, headEntries: head, loadAt: () => c, paths: ['.watson'] });
      assert.equal(diverged.comparison, 'diverged',
        'a diverged comparison did not say so; `?? "equivalent"` would read it as equivalent');

      const noBaseContract = contractChange({ baseEntries: base, headEntries: head, loadAt: () => null, paths: ['.watson'] });
      assert.equal(noBaseContract.comparison, 'diverged');

      const unavailable = contractChange({ baseEntries: null, headEntries: head, loadAt: () => c, paths: ['.watson'] });
      assert.equal(unavailable.comparison, 'unavailable');

      // And the model string tells the truth about which arrangement produced it.
      assert.equal(diverged.model, 'trusted-base-x-trusted-head');
    });

    test('base_contract_available means the base CONTRACT on every branch', () => {
      // One name, one subject. The unavailable branch hardcoded `false` and
      // meant "the base TREE was unobtainable", while every other branch used
      // the same key for "the base CONTRACT was loadable". A run can have a
      // perfectly good governing contract and an unreadable base tree.
      const base = new Map([['.watson/c.yaml', { type: 'file', digest: 'sha256:aa', mode: '644' }]]);
      const head = new Map([['.watson/c.yaml', { type: 'file', digest: 'sha256:bb', mode: '644' }]]);
      const c = { config: {}, features: [], invariants: [], identities: [], fixtures: { profiles: {} } };
      const withContract = (b) => contractChange({ baseEntries: b, headEntries: head, loadAt: () => c, paths: ['.watson'] });
      const without = (b) => contractChange({ baseEntries: b, headEntries: head, loadAt: () => null, paths: ['.watson'] });

      assert.equal(withContract(base).base_contract_available, true);
      assert.equal(without(base).base_contract_available, false);
      assert.equal(withContract(null).base_contract_available, true,
        'an unreadable base TREE was reported as an unavailable base CONTRACT');
      assert.equal(without(null).base_contract_available, false);
    });

    test('base_contract_available is factual in BOTH directions', () => {
      // `contractChange` returns null only when BOTH trusted sides were read and
      // AGREED — so the envelope's default asserted the base was unavailable in
      // exactly the case where it demonstrably was available, on every
      // base-governed run with an unchanged contract. A false negative is as
      // much a lie as a false positive, and it was the one shipping.
      const governed = buildEnvelope({
        runId: 'r', watsonVersion: '0', repository: 'x', headSha: 'a'.repeat(40),
        governance: { authority: 'base' }, contractChange: null,
        features: [], findings: [], selection: {}, qualitySignals: {},
        doctor: { ok: true, probes: [] }, verdict: 'PASS',
      });
      assert.equal(governed.contract_comparison, 'equivalent');
      assert.equal(governed.contract_evaluation.base_contract_available, true,
        'a base-governed run with an equivalent contract claimed the base was unavailable');
      assert.equal(governed.contract_evaluation.model, 'trusted-base-x-trusted-head');

      const ungoverned = buildEnvelope({
        runId: 'r', watsonVersion: '0', repository: 'x', headSha: 'a'.repeat(40),
        governance: { authority: 'bootstrap' }, contractChange: null,
        features: [], findings: [], selection: {}, qualitySignals: {},
        doctor: { ok: true, probes: [] }, verdict: 'INDETERMINATE',
      });
      assert.equal(ungoverned.contract_evaluation.base_contract_available, false);
      assert.equal(ungoverned.contract_evaluation.model, 'head-product-x-head-contract');
    });

    test('an absent path digests the same whatever tree it is absent from', () => {
      // THE CONTROL the case above cannot be. If the absent return ever becomes
      // derived from the entry map — a count, a digest of the map, anything —
      // then two different trees that both lack a path stop agreeing, and every
      // such path reports as changed. That is the original N9 failure mode
      // arriving by a new route.
      const a = new Map([['x', { type: 'file', digest: 'sha256:aa', mode: '644' }]]);
      const b = new Map([
        ['y', { type: 'file', digest: 'sha256:bb', mode: '644' }],
        ['z', { type: 'file', digest: 'sha256:cc', mode: '755' }],
      ]);
      assert.equal(subtreeDigest(a, 'nowhere'), subtreeDigest(b, 'nowhere'));
      assert.equal(subtreeDigest(a, 'nowhere'), null);
      // And a path present on one side only is still a difference.
      assert.notEqual(subtreeDigest(a, 'x'), subtreeDigest(b, 'x'));
    });

    test('CASE 5 — an unchanged real topology produces no warning at all', () => {
      // The signal-to-noise property this change exists to restore.
      const r = repo();
      writeContract(r.dir);
      const base = r.commit('base');
      const head = base;
      const c = loadContract(r.dir);
      const scope = verdictBearingPaths(c, pathExistsAt(r.dir, head));
      assert.equal(contractChange({ ...sides(r, base, head), loadAt: () => c, paths: scope }), null);
      assert.deepEqual(changedPaths(sides(r, base, head)), []);
    });

    test('THE ENVELOPE CARRIES ALL THREE STATES, not a boolean that cannot express them', () => {
      // A defect I introduced fixing D1, and caught by reading the envelope
      // rather than the function: `contract_change` was `!!run.contractChange`,
      // and `contractChange` now returns a TRUTHY object for an unavailable
      // comparison — so an unobtainable base reported `contract_change: true`.
      // That is "unavailable -> changed", the exact collapse the disposition
      // forbids, reintroduced one layer above the function fixed to prevent it.
      const t = topology();
      const { baseEntries, headEntries } = sides(t.r, t.base, t.head);

      const cases = [
        ['unavailable', contractChange({ baseEntries: null, headEntries, loadAt: () => t.c, paths: t.scope })],
        ['equivalent', contractChange({ baseEntries, headEntries, loadAt: () => t.c, paths: t.scope })],
      ];
      const envelopeOf = (cc) => buildEnvelope({
        runId: 'r', watsonVersion: '0', repository: 'x', headSha: 'a'.repeat(40),
        contractChange: cc, features: [], findings: [], selection: {},
        qualitySignals: {}, doctor: { ok: true, probes: [] }, verdict: 'INDETERMINATE',
      });

      const [, unavailable] = cases[0];
      const e1 = envelopeOf(unavailable);
      assert.equal(e1.contract_comparison, 'unavailable');
      assert.equal(e1.contract_change, false, 'an unavailable comparison was reported as a change');

      const [, equivalent] = cases[1];
      const e2 = envelopeOf(equivalent);
      assert.equal(e2.contract_comparison, 'equivalent');
      assert.equal(e2.contract_change, false);

      const e3 = envelopeOf({ paths_changed: ['.watson'], base_contract_available: true });
      assert.equal(e3.contract_comparison, 'diverged');
      assert.equal(e3.contract_change, true, 'a real divergence stopped being reported');
    });

    test('the summary says DIVERGENCE, never that the pull request authored it', () => {
      // Required wording. After D1 the diff is governing-base tip vs evaluated
      // head, so "this PR changes the verification contract" can be false: a
      // contract change landing on the base branch diverges from a stale head
      // without this pull request having authored anything.
      const doc = summary(buildEnvelope({
        runId: 'r', watsonVersion: '0', repository: 'x', headSha: 'a'.repeat(40),
        contractChange: { paths_changed: ['.watson'], base_contract_available: true,
          expectations_weakened: [], features_removed: [], features_added: [] },
        features: [], findings: [], selection: { method: 'profile', selected: [], setup: [], deferred: [] },
        qualitySignals: { console_errors: 0, console_warnings: 0, http_5xx: 0, unexpected_4xx: 0, failed_requests: 0, raw_uuid_visible: 0 },
        doctor: { ok: true, probes: [] }, verdict: 'INDETERMINATE',
        environment: { mode: 'test' },
      }));
      assert.doesNotMatch(doc, /This PR changes the verification contract/,
        'the summary still claims the pull request authored the difference');
      assert.match(doc, /differs from the governing verification contract/);
      assert.match(doc, /does not by itself mean this pull request authored/);
    });

    test('an unavailable comparison is not printed as a contract change', () => {
      const doc = summary(buildEnvelope({
        runId: 'r', watsonVersion: '0', repository: 'x', headSha: 'a'.repeat(40),
        contractChange: { model: 'comparison-unavailable', comparison: 'unavailable',
          base_contract_available: false, why: 'no trusted base materialisation was supplied', paths_changed: [] },
        features: [], findings: [], selection: { method: 'profile', selected: [], setup: [], deferred: [] },
        qualitySignals: { console_errors: 0, console_warnings: 0, http_5xx: 0, unexpected_4xx: 0, failed_requests: 0, raw_uuid_visible: 0 },
        doctor: { ok: true, probes: [] }, verdict: 'INDETERMINATE',
        environment: { mode: 'test' },
      }));
      assert.match(doc, /comparison could not be made/);
      assert.match(doc, /Neither "changed" nor "unchanged" is asserted/);
      assert.doesNotMatch(doc, /differs from the governing verification contract/);
    });

    test('THE PROPERTY — destroying the product clone changes nothing', () => {
      // Encoded as the property rather than as "these SHAs happen to exist in
      // one git repo". If the base-side computation were still reaching into the
      // product clone, removing it would change the answer. It does not, because
      // it is not an input.
      const t = topology({ headDiffers: true });
      const before = contractChange({ ...sides(t.r, t.base, t.head), loadAt: () => t.c, paths: t.scope });
      const beforePaths = changedPaths(sides(t.r, t.base, t.head));

      fs.rmSync(t.product, { recursive: true, force: true });

      const after = contractChange({ ...sides(t.r, t.base, t.head), loadAt: () => t.c, paths: t.scope });
      const afterPaths = changedPaths(sides(t.r, t.base, t.head));
      assert.deepEqual(after, before);
      assert.deepEqual(afterPaths, beforePaths);
    });
  });

  test('a `.watson` symlink is refused, not followed', () => {
    // The contract is fingerprinted as the PATH `.watson`. A link digests as a
    // link — whose target never changes — while the loader reads wherever it
    // points, so the bytes measured and the bytes obeyed come apart.
    const r = repo();
    const real = path.join(r.dir, 'elsewhere');
    fs.mkdirSync(real, { recursive: true });
    writeContract(r.dir);
    fs.cpSync(path.join(r.dir, '.watson'), real, { recursive: true });
    fs.rmSync(path.join(r.dir, '.watson'), { recursive: true });
    fs.symlinkSync(real, path.join(r.dir, '.watson'));
    assert.throws(() => loadContract(r.dir), /symbolic link/);
  });
});

describe('domain narrowing is named, and the uncurated diff catches the rest', () => {
  const withEnum = (values) => ({
    config: { launch: { fixture_profile: 'p' } },
    fixtures: { profiles: { p: { verifier_chosen: [{ grade: { enum: values } }] } } },
    features: [], invariants: [], identities: [],
  });

  test("ADR-049's own example: 14 values -> 1 value", () => {
    const base = withEnum(Array.from({ length: 14 }, (_, i) => `g${i}`));
    const head = withEnum(['g0']);
    const paths = deepDiffPaths(canonicalContract(base), canonicalContract(head));
    assert.ok(paths.some((p) => /verifier_chosen/.test(p)), paths.join(','));
  });

  test('the structural diff finds a construct nobody anticipated', () => {
    // The point of the uncurated half: curation is what left domain narrowing
    // invisible in the first place.
    const base = withEnum(['a']);
    const head = withEnum(['a']);
    head.config.something_invented_next_year = { off: true };
    assert.deepEqual(
      deepDiffPaths(canonicalContract(base), canonicalContract(head)),
      ['config.something_invented_next_year'],
    );
  });

  test('feature SET membership is a change, not just feature content', () => {
    const base = { config: {}, fixtures: {}, features: [{ id: 'a', __file: 'a.md' }], invariants: [], identities: [] };
    const head = { config: {}, fixtures: {}, features: [{ id: 'a', __file: 'a.md' }, { id: 'b', __file: 'b.md' }], invariants: [], identities: [] };
    const paths = deepDiffPaths(canonicalContract(base), canonicalContract(head));
    assert.ok(paths.includes('feature_files'), paths.join(','));
  });

  test('reordering features is not a change', () => {
    const a = { config: {}, fixtures: {}, features: [{ id: 'a', __file: 'a.md' }, { id: 'b', __file: 'b.md' }], invariants: [], identities: [] };
    const b = { config: {}, fixtures: {}, features: [{ id: 'b', __file: 'b.md' }, { id: 'a', __file: 'a.md' }], invariants: [], identities: [] };
    assert.deepEqual(deepDiffPaths(canonicalContract(a), canonicalContract(b)), []);
  });

  test('the diff is bounded, and says so rather than truncating silently', () => {
    const big = (n) => ({ config: Object.fromEntries(Array.from({ length: n }, (_, i) => [`k${i}`, i])), fixtures: {}, features: [], invariants: [], identities: [] });
    const paths = deepDiffPaths(canonicalContract(big(0)), canonicalContract(big(500)));
    assert.ok(paths.length <= 201, paths.length);
    assert.match(paths.at(-1), /more than 200 declarations changed/);
  });
});
