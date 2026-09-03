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
  verdictBearingPaths, contractFingerprint, contractChange, pathExistsAt,
  canonicalContract, deepDiffPaths,
} from '../src/fingerprint.mjs';
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
    // `generated_roots`: a pull request cannot shrink the list that decides
    // whether its own changes get reported.
    const c = contract();
    c.config.verdict_bearing_paths = ['server/migrations'];
    assert.ok(verdictBearingPaths(c, () => true).includes('server/migrations'));
    assert.equal(CONFIG_AUTHORITY.verdict_bearing_paths, 'base');
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

    const change = contractChange(r.dir, base, head, () => c, scope);
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
    const change = contractChange(r.dir, base, head, () => c, scope);
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
    assert.equal(contractChange(r.dir, base, head, () => c, scope), null);
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
