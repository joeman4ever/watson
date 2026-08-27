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
} from '../src/contract.mjs';

describe('validateContractVersion', () => {
  test('accepts a supported version', () => {
    assert.deepEqual(validateContractVersion({ contract_version: 1 }), []);
  });

  test('refuses a contract NEWER than the engine, and says which way to fix it', () => {
    const [p] = validateContractVersion({ contract_version: 2 });
    assert.match(p, /NEWER than the engine/);
    assert.match(p, /Update Watson/);
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
    for (const key of ENGINE_OWNED_ENV) {
      const [p] = validateEnvOwnership({ env: { [key]: 'x' } });
      assert.match(p, new RegExp(key), `${key} must be refused`);
      assert.match(p, /cannot redefine/);
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
