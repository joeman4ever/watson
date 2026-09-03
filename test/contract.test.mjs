// Contract pre-flight checks.
//
// Each of these exists because a specific failure got through once. They run
// before a database is created, so a bad contract costs nothing and — more
// importantly — never reaches a state where it could be reported as a product
// defect.

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  validateContractVersion,
  validateEnvOwnership,
  validateStepOrder,
  validateFeatureVars,
  ENGINE_OWNED_ENV,
  SUPPORTED_CONTRACT_VERSIONS,
} from '../src/contract.mjs';

describe('validateContractVersion', () => {
  test('accepts every supported version', () => {
    for (const v of SUPPORTED_CONTRACT_VERSIONS) {
      assert.deepEqual(validateContractVersion({ contract_version: v }), [], String(v));
    }
  });

  test('version 2 — the constructs nsc-eval’s contract now uses — is understood', () => {
    // The bump that made this necessary: profile `preconditions` (ADR-039 D8).
    // An engine without it reads no preconditions, proves nothing, and reports a
    // PASS over a world that was never established. Sherlock caught that the
    // contract had grown the construct without ever declaring a version that an
    // older engine would refuse.
    assert.ok(SUPPORTED_CONTRACT_VERSIONS.includes(2));
    assert.deepEqual(validateContractVersion({ contract_version: 2 }), []);
  });

  test('refuses a contract NEWER than the engine, and says which way to fix it', () => {
    // The whole point of the version gate: an engine that cannot run a contract
    // must say so before provisioning, not discover it mid-run or — worse — not
    // discover it at all.
    // Deliberately one past the newest supported version, so this keeps testing the
    // BOUNDARY rather than a number that a later bump quietly makes valid.
    const newest = Math.max(...SUPPORTED_CONTRACT_VERSIONS);
    const [p] = validateContractVersion({ contract_version: newest + 1 });
    assert.match(p, /NEWER than the engine/);
    assert.match(p, /Update Watson/);
  });

  test('version 3 — the `install` phase — is understood', () => {
    // A fresh PR worktree has no node_modules. An engine that does not know
    // `install` would not establish the product's dependencies, and bring-up
    // would fail at whatever first needed them. The contract must be able to
    // refuse such an engine outright.
    assert.ok(SUPPORTED_CONTRACT_VERSIONS.includes(3));
    assert.deepEqual(validateContractVersion({ contract_version: 3 }), []);
  });

  test('a v3 contract is refused by an engine that only knows 1 and 2', () => {
    const [p] = validateContractVersion({ contract_version: 3 }, Object.freeze([1, 2]));
    assert.match(p, /NEWER than the engine/);
  });

  test('an engine that predates a construct refuses the contract that uses it', () => {
    // Simulates the real skew: this contract (v2, with preconditions) handed to an
    // engine that only knows v1. It must refuse rather than silently under-verify.
    const [p] = validateContractVersion({ contract_version: 2 }, Object.freeze([1]));
    assert.match(p, /NEWER than the engine/);
  });

  test('refuses a contract OLDER than anything supported', () => {
    const [p] = validateContractVersion({ contract_version: 0 });
    assert.match(p, /OLDER than any version/);
    assert.match(p, /Migrate the contract/);
  });

  test('refuses a MISSING version rather than defaulting', () => {
    // Defaulting is the guess this check exists to prevent: an engine too old to
    // understand a step does not error on it, it skips it, and reports a PASS that
    // proves less than the contract asked for.
    const [p] = validateContractVersion({});
    assert.match(p, /does not declare/);
  });

  test('refuses a non-integer version', () => {
    assert.equal(validateContractVersion({ contract_version: '1' }).length, 1);
  });
});

describe('validateEnvOwnership', () => {
  test('accepts a contract that sets only its own product settings', () => {
    assert.deepEqual(validateEnvOwnership({ env: { NODE_ENV: 'production' } }), []);
  });

  test('refuses a contract that redefines the identity binding', () => {
    // The whole point: a contract that set WORKOS_ISSUER could point the launched
    // app at an issuer Watson does not control, and the run would "verify" an app
    // trusting a stranger.
    //
    // THIS LOOP IS NOT THE CONTROL. It iterates the list under test, so shrinking
    // `ENGINE_OWNED_ENV` shrinks the assertion with it — remove three keys and
    // this still passes, having checked the three that are left. See the literal
    // below, which is the actual control.
    for (const key of ENGINE_OWNED_ENV) {
      const [p] = validateEnvOwnership({ env: { [key]: 'x' } });
      assert.match(p, new RegExp(key), `${key} must be refused`);
      assert.match(p, /cannot redefine/);
    }
  });

  // ---------------------------------------------------------------------------
  // THE LIST IS THE DECISION. PIN IT INDEPENDENTLY.
  //
  // Found by the exact-HEAD confirmation review (its N3) and reproduced before
  // fixing: cutting `ENGINE_OWNED_ENV` from six keys to three left the whole
  // suite at 401/401 green, and `validateEnvOwnership` then accepted a contract
  // setting WORKOS_ISSUER, DATABASE_URL and PORT.
  //
  // `config.env` is HEAD-AUTHORED. This list is the only thing between a pull
  // request's `env:` block and the identity binding the run is judged against —
  // and, for DATABASE_URL, the isolation of the run's own database. An assertion
  // that iterates it cannot defend it.
  //
  // Written out here so that changing the module changes only one side of the
  // comparison, and so that editing the trust boundary is a visible act.
  describe('the engine-owned environment list itself', () => {
    const EXPECTED = [
      'WORKOS_ISSUER', 'WORKOS_CLIENT_ID', 'WORKOS_JWKS_URI', 'DATABASE_URL', 'PORT', 'PATH',
    ];

    test('is exactly these keys', () => {
      assert.deepEqual([...ENGINE_OWNED_ENV].sort(), [...EXPECTED].sort());
    });

    // Driven from the independent literal, so a key deleted from the module is
    // still tested — and fails, which is the point.
    for (const key of EXPECTED) {
      test(`a contract setting \`${key}\` is refused`, () => {
        const [p] = validateEnvOwnership({ env: { [key]: 'x' } });
        assert.ok(p, `${key} was accepted; a pull request can set it`);
        assert.match(p, new RegExp(key));
        assert.match(p, /cannot redefine/);
      });
    }
  });
});

describe('validateStepOrder', () => {
  const f = (steps) => [{ id: 'x', __file: 'x.md', steps }];

  test('accepts a journey that navigates before it asserts', () => {
    assert.deepEqual(
      validateStepOrder(f([{ goto: '/' }, { expect_api: { path: '/api/me' } }])),
      [],
    );
  });

  test('refuses the exact bug that produced this engine’s only false FAIL_PRODUCT', () => {
    // expect_api reads the traffic the BROWSER made. Before any goto it observes an
    // empty list, fails as a behavioral assertion, and accuses the product of a
    // defect that is a typo in the map.
    const [p] = validateStepOrder(f([{ expect_api: { path: '/api/me' } }, { goto: '/' }]));
    assert.match(p, /has not navigated yet/);
    assert.match(p, /product defect/);
  });

  test('expect_denied is exempt — it issues its own request', () => {
    assert.deepEqual(
      validateStepOrder(f([{ expect_denied: { path: '/api/x' } }, { goto: '/' }])),
      [],
    );
  });

  test('reload and back count as navigation', () => {
    assert.deepEqual(validateStepOrder(f([{ reload: null }, { expect_text: 'x' }])), []);
  });
});

describe('validateFeatureVars', () => {
  test('accepts variables the fixture declares', () => {
    const features = [{ id: 'a', steps: [{ goto: '/x?s=${seasonId}' }] }];
    assert.deepEqual(validateFeatureVars(features, { emits: ['seasonId'] }), []);
  });

  test('refuses an undeclared variable, naming the file and the variable', () => {
    // Undeclared names interpolate to the literal `${name}` and fail later with a
    // message that points at the product.
    const features = [{ id: 'a', __file: 'a.md', steps: [{ goto: '/x?s=${typo}' }] }];
    const [p] = validateFeatureVars(features, { emits: ['seasonId'] });
    assert.match(p, /a\.md/);
    assert.match(p, /typo/);
  });

  test('runId is always available without being declared', () => {
    const features = [{ id: 'a', steps: [{ goto: '/x?r=${runId}' }] }];
    assert.deepEqual(validateFeatureVars(features, { emits: [] }), []);
  });
});
