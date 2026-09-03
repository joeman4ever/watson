// The base contract governs.
//
// The property under test: a pull request may propose a contract change, and
// cannot use it to decide its own verdict. Everything here is about WHO the
// value came from, never about whether the value looks reasonable — no predicate
// over a declaration distinguishes a legitimate one from one chosen to weaken
// the test.

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  resolveGovernance, governingConfig, downgradeForUngovernedContract,
  CONFIG_AUTHORITY, LAUNCH_AUTHORITY,
} from '../src/governance.mjs';

const PRODUCT_CLAIMS = new Set(['PASS', 'PASS_WITH_ADVISORIES', 'FAIL_PRODUCT']);

const contract = (over = {}) => ({
  dir: '/x/.watson',
  config: {
    contract_version: 3,
    selection: { escalation_profile: 'smoke' },
    generated_roots: [],
    identity: { issuer: 'https://watson.local/base' },
    injected_by_engine: [],
    launch: { fixture_profile: 'watson-poc', expect_seasons: 2, command: 'npm start', health_path: '/h', readiness_path: '/r' },
    install: 'npm ci', provision: 'npm run migrate', build: 'npm run build',
    env: {}, browser: {}, engine: {},
  },
  features: [{ id: 'a' }],
  invariants: [], identities: [], fixtures: { profiles: {} },
  ...over,
});

describe('the reproduced attack', () => {
  test('a generated_roots exemption added by the head does not reach the run', () => {
    // This is the exact escalation from ADR-049's Context: the head declares
    // `server/src` generated, and the identity check stops noticing source the
    // build wrote. Under base governance the head's list is never consulted.
    const head = contract();
    head.config.generated_roots = ['server/src'];
    const g = resolveGovernance({ base: contract(), head, baseSupplied: true });
    assert.deepEqual(g.contract.config.generated_roots, []);
    assert.equal(g.authority, 'base');
  });

  test('a head that narrows a fixture domain to one member does not reach the run', () => {
    const base = contract({ fixtures: { profiles: { p: { verifier_chosen: [{ grade: { enum: ['A', 'B', 'C'] } }] } } } });
    const head = contract({ fixtures: { profiles: { p: { verifier_chosen: [{ grade: { enum: ['A'] } }] } } } });
    const g = resolveGovernance({ base, head, baseSupplied: true });
    assert.deepEqual(g.contract.fixtures.profiles.p.verifier_chosen[0].grade.enum, ['A', 'B', 'C']);
  });

  test('a head that drops a journey does not reduce what runs', () => {
    const base = contract({ features: [{ id: 'a' }, { id: 'b' }] });
    const head = contract({ features: [{ id: 'a' }] });
    const g = resolveGovernance({ base, head, baseSupplied: true });
    assert.deepEqual(g.contract.features.map((f) => f.id), ['a', 'b']);
  });
});

describe('the head still supplies what only the head can', () => {
  test('build and launch commands come from the head — they must match its own tree', () => {
    const head = contract();
    head.config.build = 'npm run build:new';
    head.config.launch.command = 'npm run start:new';
    const g = resolveGovernance({ base: contract(), head, baseSupplied: true });
    assert.equal(g.contract.config.build, 'npm run build:new');
    assert.equal(g.contract.config.launch.command, 'npm run start:new');
  });

  test('but the semantic half of `launch` still comes from the base', () => {
    const head = contract();
    head.config.launch.fixture_profile = 'weaker';
    head.config.launch.expect_seasons = 0;
    const g = resolveGovernance({ base: contract(), head, baseSupplied: true });
    assert.equal(g.contract.config.launch.fixture_profile, 'watson-poc');
    assert.equal(g.contract.config.launch.expect_seasons, 2);
  });
});

describe('an unattributed key fails the run rather than defaulting', () => {
  test('a new top-level key is a contract problem, named', () => {
    const head = contract();
    head.config.exempt_everything = true;
    const { problems } = governingConfig(contract().config, head.config);
    assert.equal(problems.length, 1);
    assert.match(problems[0], /`exempt_everything`/);
    assert.match(problems[0], /not defaulted/);
  });

  test('a new `launch` field is too', () => {
    const head = contract();
    head.config.launch.skip_doctor = true;
    const { problems } = governingConfig(contract().config, head.config);
    assert.equal(problems.length, 1);
    assert.match(problems[0], /`launch\.skip_doctor`/);
  });

  test('an unattributed key is not silently carried through either', () => {
    const head = contract();
    head.config.exempt_everything = true;
    const { config } = governingConfig(contract().config, head.config);
    assert.ok(!('exempt_everything' in config));
  });

  test('every classified key resolves to exactly one side', () => {
    // Property, not instance: the map itself is the thing under test, so a value
    // typo cannot leave a key silently unowned.
    for (const [k, v] of Object.entries(CONFIG_AUTHORITY)) {
      assert.ok(['base', 'head', 'split'].includes(v), `${k} -> ${v}`);
    }
    for (const [k, v] of Object.entries(LAUNCH_AUTHORITY)) {
      assert.ok(['base', 'head'].includes(v), `${k} -> ${v}`);
    }
  });
});

describe('F7: the three cases that used to fail open', () => {
  test('no base supplied withholds the product claim — it never falls back to head', () => {
    const g = resolveGovernance({ head: contract(), baseSupplied: false });
    assert.equal(g.authority, 'none');
    assert.equal(g.product_claims_permitted, false);
  });

  test('a base revision with no contract is bootstrap, not head governance', () => {
    const g = resolveGovernance({ base: null, head: contract(), baseSupplied: true });
    assert.equal(g.authority, 'bootstrap');
    assert.equal(g.product_claims_permitted, false);
    assert.match(g.note, /becomes authoritative when it merges/);
  });

  test('a head-only journey does not run, and is reported rather than dropped', () => {
    const head = contract({ features: [{ id: 'a' }, { id: 'brand-new' }] });
    const g = resolveGovernance({ base: contract(), head, baseSupplied: true });
    assert.deepEqual(g.head_only_features, ['brand-new']);
    assert.deepEqual(g.contract.features.map((f) => f.id), ['a']);
    assert.match(g.note, /did not run: brand-new/);
  });
});

describe('the downgrade', () => {
  for (const v of ['PASS', 'PASS_WITH_ADVISORIES', 'FAIL_PRODUCT']) {
    test(`${v} is withheld when nothing governed the run`, () => {
      const r = downgradeForUngovernedContract(v, { product_claims_permitted: false, note: 'x' }, PRODUCT_CLAIMS);
      assert.equal(r.verdict, 'INDETERMINATE');
      assert.match(r.reason, new RegExp(`^${v} withheld`));
    });
  }

  test('FAIL_PRODUCT is withheld too — a governed accusation is the point, not just a governed pass', () => {
    // Deliberate. An ungoverned run that reports FAIL_PRODUCT is making a claim
    // about the product on semantics nobody trusted either.
    const r = downgradeForUngovernedContract('FAIL_PRODUCT', { product_claims_permitted: false, note: 'x' }, PRODUCT_CLAIMS);
    assert.equal(r.verdict, 'INDETERMINATE');
  });

  test('non-product verdicts pass through untouched', () => {
    for (const v of ['BLOCKED_ENVIRONMENT', 'FAIL_CONTRACT', 'NOT_APPLICABLE', 'INDETERMINATE']) {
      assert.equal(downgradeForUngovernedContract(v, { product_claims_permitted: false }, PRODUCT_CLAIMS).verdict, v);
    }
  });

  test('a governed run keeps its verdict', () => {
    assert.equal(downgradeForUngovernedContract('PASS', { product_claims_permitted: true }, PRODUCT_CLAIMS).verdict, 'PASS');
  });
});

// ---------------------------------------------------------------------------
// The wiring, exercised through the real entry point.
//
// Everything above tests `resolveGovernance` in isolation, which is exactly the
// kind of test that has passed over a defect twice in this project: the module
// was right and nothing called it. So these drive `watson verify` as a process,
// against a synthetic product, and read the governing contract back out of the
// canonical result the run wrote. No database is involved — the pre-flight
// contract check terminates the run before bring-up, which is enough to prove
// which contract the engine loaded and what it recorded.

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const CLI = fileURLToPath(new URL('../src/cli.mjs', import.meta.url));

function writeContract(root, { generatedRoots = [], featureIds = ['j1'], expectSeasons = 2 } = {}) {
  const dir = path.join(root, '.watson');
  fs.mkdirSync(path.join(dir, 'features'), { recursive: true });
  fs.mkdirSync(path.join(dir, 'fixtures'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'config.yaml'), [
    'contract_version: 4',
    `generated_roots: ${JSON.stringify(generatedRoots)}`,
    'identity: { issuer: "https://watson.local/x", client_id: "c" }',
    'injected_by_engine: []',
    // The run is stopped here, deliberately and before any database is created.
    // What these tests are about is which contract the engine loaded and what it
    // recorded about that — which is decided, and written to the envelope, well
    // before bring-up.
    'install: ["/bin/false"]', 'provision: []', 'build: []',
    'env: {}', 'browser: {}', 'engine: {}',
    'launch:',
    '  command: "true"',
    '  health_path: /api/health',
    '  readiness_path: /api/health/db',
    '  fixture_profile: p',
    `  expect_seasons: ${expectSeasons}`,
  ].join('\n'));
  fs.writeFileSync(path.join(dir, 'identities.yaml'), 'identities: [{ id: A, role: admin, doctor: true }]\n');
  fs.writeFileSync(path.join(dir, 'invariants.yaml'), 'invariants: []\n');
  fs.writeFileSync(path.join(dir, 'fixtures', 'profiles.yaml'), 'profiles:\n  p:\n    command: "true"\n    emits: []\n');
  for (const id of featureIds) {
    fs.writeFileSync(path.join(dir, 'features', `${id}.md`), [
      '---', `id: ${id}`, `title: ${id}`, 'status: mapped',
      'personas: [A]', 'profiles: [poc]',
      'steps:', '  - goto: /', '---', '', 'body',
    ].join('\n'));
  }
  return dir;
}

function verify(repo, extra = []) {
  const out = path.join(repo, 'result.json');
  try {
    // An explicit 40-hex SHA: `resolveSha` returns one as given without
    // consulting git, so the synthetic product needs no repository.
    execFileSync(process.execPath, [CLI, 'verify', '--repo', repo, '--out', out,
      '--sha', '1'.repeat(40), ...extra],
      { stdio: ['ignore', 'pipe', 'pipe'], timeout: 60_000 });
  } catch { /* a non-product verdict exits non-zero; the envelope is what matters */ }
  return fs.existsSync(out) ? JSON.parse(fs.readFileSync(out, 'utf8')) : null;
}

describe('driving the real CLI', () => {
  const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'watson-gov-'));

  test('THE REPRODUCED ATTACK: the head\'s generated_roots never reaches the run', () => {
    // The head declares `server/src` generated. The base does not. Under D1 the
    // run must be conducted with the base's empty list.
    const repo = tmp();
    writeContract(repo, { generatedRoots: ['server/src'] });
    const baseDir = tmp();
    writeContract(baseDir, { generatedRoots: [] });

    const env = verify(repo, ['--base-contract', baseDir]);
    assert.ok(env, 'the run wrote no result');
    assert.equal(env.governing_contract.authority, 'base');
    assert.equal(env.governing_contract.product_claims_permitted, true);
  });

  test('with no base contract the run records that nothing governed it', () => {
    const repo = tmp();
    writeContract(repo);
    const env = verify(repo);
    assert.ok(env, 'the run wrote no result');
    assert.equal(env.governing_contract.authority, 'none');
    assert.equal(env.governing_contract.product_claims_permitted, false);
    assert.ok(!['PASS', 'PASS_WITH_ADVISORIES', 'FAIL_PRODUCT'].includes(env.verdict), env.verdict);
  });

  test('a base revision without a contract is bootstrap, and makes no product claim', () => {
    const repo = tmp();
    writeContract(repo);
    const env = verify(repo, ['--base-contract', tmp()]);
    assert.equal(env.governing_contract.authority, 'bootstrap');
    assert.ok(!['PASS', 'PASS_WITH_ADVISORIES', 'FAIL_PRODUCT'].includes(env.verdict), env.verdict);
  });

  test('a head-only journey is named in the result rather than silently absent', () => {
    const repo = tmp();
    writeContract(repo, { featureIds: ['j1', 'j2'] });
    const baseDir = tmp();
    writeContract(baseDir, { featureIds: ['j1'] });
    const env = verify(repo, ['--base-contract', baseDir]);
    assert.deepEqual(env.governing_contract.head_only_features, ['j2']);
  });

  test('an unattributed contract key stops the run before anything is provisioned', () => {
    const repo = tmp();
    const dir = writeContract(repo);
    fs.appendFileSync(path.join(dir, 'config.yaml'), '\nexempt_everything: true\n');
    const baseDir = tmp();
    writeContract(baseDir);
    const env = verify(repo, ['--base-contract', baseDir]);
    assert.equal(env.verdict, 'FAIL_CONTRACT');
    assert.ok(env.doctor.probes.some((p) => /exempt_everything/.test(p.detail)), JSON.stringify(env.doctor.probes));
  });
});

describe('the gate is applied where the verdict is written', () => {
  // Honest about what this is: a STRUCTURAL check, not an executed one. Driving
  // a run all the way to PASS needs a database and a real application, which
  // this suite does not have. The unit tests above establish that the gate
  // withholds the right verdicts; this establishes that `finish` reaches it, and
  // that it reaches it before the envelope is built. Between them the join is
  // covered — a module that is correct and never called is the failure mode this
  // project has already produced twice.
  test('finish() runs the governing-contract gate before building the envelope', () => {
    const src = fs.readFileSync(new URL('../src/cli.mjs', import.meta.url), 'utf8');
    const body = src.slice(src.indexOf('function finish(runDir, run) {'));
    const gate = body.indexOf('downgradeForUngovernedContract(');
    const build = body.indexOf('buildEnvelope(run)');
    assert.ok(gate > 0, 'finish() does not apply the governing-contract gate');
    assert.ok(build > 0 && gate < build, 'the gate runs after the envelope is built');
  });

  test('the exact-head gate is still there — both hold, neither replaces the other', () => {
    const src = fs.readFileSync(new URL('../src/cli.mjs', import.meta.url), 'utf8');
    const body = src.slice(src.indexOf('function finish(runDir, run) {'));
    assert.ok(body.includes('downgradeForInexactHead('), 'the exact-head gate was lost');
  });
});
