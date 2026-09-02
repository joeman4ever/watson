// Loads a product's verification contract from its `.watson/` directory.
//
// The engine is generic: it knows the SHAPE of a contract, never the product.
// Everything NSC-Eval-specific lives in nsc-eval/.watson/ and versions with the
// code it describes.

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { ASSERTION_STEPS } from './driver.mjs';
import { execFileSync } from 'node:child_process';
// The hardened wrapper, so the claim that EVERY git invocation goes through it
// is true rather than nearly true. This one reads a base-branch tree, which the
// pull request's author does not write — but 'not exploitable today' is a worse
// property than 'covered'.
import { git } from './fingerprint.mjs';
import YAML from 'yaml';

/** Parse `---\nyaml\n---\nmarkdown` into { data, body }. */
export function parseFrontmatter(text, sourceLabel) {
  if (!text.startsWith('---')) {
    throw new Error(`${sourceLabel}: feature file must open with YAML frontmatter`);
  }
  const end = text.indexOf('\n---', 3);
  if (end < 0) throw new Error(`${sourceLabel}: unterminated frontmatter`);
  const raw = text.slice(3, end);
  const body = text.slice(text.indexOf('\n', end + 1) + 1);
  let data;
  try {
    data = YAML.parse(raw) ?? {};
  } catch (err) {
    throw new Error(`${sourceLabel}: invalid frontmatter YAML — ${err.message}`);
  }
  return { data, body };
}

/**
 * Contract schema versions this engine understands.
 *
 * The two repositories move independently: nsc-eval's `.watson/` is reviewed and
 * merged on its own cadence, and this engine on another. Without a version check
 * the failure mode of that skew is silent and misleading — an engine too old to
 * understand a step simply does not run it, and the run reports a PASS that
 * proves less than the contract asked for. A verifier that quietly under-verifies
 * is worse than one that refuses.
 *
 * So: an unknown version stops the run rather than guessing. Widen this list in
 * the same change that teaches the engine the new shape.
 *
 * ## Versions
 *
 * - **1** — the Phase-0 shape: the original step vocabulary, no profile
 *   `preconditions`.
 * - **2** — adds the `expect_allowed`, `expect_json` and `expect_count_at_least`
 *   steps, and profile-level `preconditions` (ADR-039 D8).
 * - **3** — adds the `install` phase: the product's own dependency-establishment
 *   commands, run before anything else. A PR-targeted run starts from a fresh
 *   worktree at an exact HEAD with no `node_modules`, and an engine that does
 *   not know the key simply will not install — so the contract must be able to
 *   say "this engine is too old for me" rather than have its dependencies
 *   silently not established.
 *
 * The bump exists because of `preconditions` specifically. An unknown *step*
 * fails loudly — `runStep` throws rather than skipping — which is wrong in its
 * own way (the failure lands on the product) but is at least visible.
 * `preconditions` is a key an older engine simply does not read: `doctor()`
 * iterates `preconditions ?? []`, finds nothing, proves nothing, and the run
 * goes on to report a PASS over a world that was never established. That is the
 * silent under-verification this list exists to make impossible, and nothing but
 * a version refusal catches it.
 */
export const SUPPORTED_CONTRACT_VERSIONS = Object.freeze([1, 2, 3]);

/** Problems with a contract's declared version. Checked before anything is provisioned. */
export function validateContractVersion(config, supported = SUPPORTED_CONTRACT_VERSIONS) {
  const declared = config?.contract_version;
  if (declared === undefined || declared === null) {
    return [
      '.watson/config.yaml does not declare `contract_version`. The engine cannot tell ' +
        'whether it understands this contract, so it will not guess. ' +
        `Add \`contract_version: ${supported[supported.length - 1]}\`.`,
    ];
  }
  if (!Number.isInteger(declared)) {
    return [`.watson/config.yaml \`contract_version: ${JSON.stringify(declared)}\` is not an integer.`];
  }
  if (!supported.includes(declared)) {
    const newest = Math.max(...supported);
    const direction = declared > newest
      ? 'This contract is NEWER than the engine. Update Watson, or pin the run to an engine that understands it.'
      : 'This contract is OLDER than any version the engine still supports. Migrate the contract.';
    return [
      `.watson/config.yaml declares \`contract_version: ${declared}\`, which this engine ` +
        `(supports: ${supported.join(', ')}) does not understand. ${direction}`,
    ];
  }
  return [];
}

const REQUIRED_FEATURE_FIELDS = ['id', 'title', 'status', 'personas', 'profiles'];

/** Validate one feature entry. Returns an array of human-readable problems. */
export function validateFeature(f, label) {
  const problems = [];
  for (const k of REQUIRED_FEATURE_FIELDS) {
    if (f[k] === undefined || f[k] === null) problems.push(`${label}: missing required field \`${k}\``);
  }
  if (f.status && !['mapped', 'draft', 'unreachable', 'retired'].includes(f.status)) {
    problems.push(`${label}: status \`${f.status}\` is not one of mapped|draft|unreachable|retired`);
  }
  if (!Array.isArray(f.steps) || f.steps.length === 0) {
    problems.push(`${label}: needs a non-empty \`steps\` block for the deterministic layer`);
  }
  return problems;
}

function readYaml(file, label) {
  if (!fs.existsSync(file)) throw new Error(`contract: missing ${label} (${file})`);
  return YAML.parse(fs.readFileSync(file, 'utf8')) ?? {};
}

/**
 * Load the whole contract. `repoRoot` is a checkout of the product at the SHA
 * under verification — the contract is read from that same tree, so it always
 * describes the code being verified.
 */
export function loadContract(repoRoot) {
  const dir = path.join(repoRoot, '.watson');
  if (!fs.existsSync(dir)) {
    throw new Error(`contract: ${repoRoot} has no .watson/ directory — this product is not onboarded`);
  }

  const config = readYaml(path.join(dir, 'config.yaml'), 'config.yaml');
  const identities = readYaml(path.join(dir, 'identities.yaml'), 'identities.yaml');
  const invariants = readYaml(path.join(dir, 'invariants.yaml'), 'invariants.yaml');
  const fixtures = readYaml(path.join(dir, 'fixtures', 'profiles.yaml'), 'fixtures/profiles.yaml');

  const featuresDir = path.join(dir, 'features');
  const features = [];
  const problems = [];
  const files = fs.existsSync(featuresDir)
    ? fs.readdirSync(featuresDir).filter((f) => f.endsWith('.md') && f !== 'README.md').sort()
    : [];
  for (const file of files) {
    const label = `.watson/features/${file}`;
    const { data, body } = parseFrontmatter(fs.readFileSync(path.join(featuresDir, file), 'utf8'), label);
    problems.push(...validateFeature(data, label));
    if (data.id && `${data.id}.md` !== file) {
      problems.push(`${label}: id \`${data.id}\` does not match filename`);
    }
    features.push({ ...data, __file: label, __body: body });
  }
  if (problems.length) {
    throw new Error(`contract is invalid:\n  - ${problems.join('\n  - ')}`);
  }

  return { dir, config, identities: identities.identities ?? [], invariants: invariants.invariants ?? [], fixtures, features };
}

/** Features that belong to a named profile, in declared order. */
export function selectByProfile(features, profile) {
  return features.filter((f) => f.status === 'mapped' && (f.profiles ?? []).includes(profile));
}

/** Every `${name}` a value references, at any depth. */
export function referencedVars(value, into = new Set()) {
  if (typeof value === 'string') {
    for (const m of value.matchAll(/\$\{(\w+)\}/g)) into.add(m[1]);
  } else if (Array.isArray(value)) {
    for (const v of value) referencedVars(v, into);
  } else if (value && typeof value === 'object') {
    for (const v of Object.values(value)) referencedVars(v, into);
  }
  return into;
}

/**
 * Check every variable a feature interpolates against the fixture profile's declared
 * `emits`, BEFORE anything is driven.
 *
 * Without this an undeclared name interpolates to the literal `${name}` and the run fails
 * somewhere later with a misleading message — a typo in the map reads as a broken product.
 * Failing here instead makes it unambiguously a contract problem.
 *
 * `alwaysAvailable` are names the engine itself supplies (not the fixture).
 */
export function validateFeatureVars(features, fixtureProfile, alwaysAvailable = ['runId']) {
  const declared = new Set([...(fixtureProfile?.emits ?? []), ...alwaysAvailable]);
  const problems = [];
  for (const f of features) {
    const used = referencedVars(f.steps ?? []);
    const missing = [...used].filter((v) => !declared.has(v)).sort();
    if (missing.length) {
      problems.push(
        `${f.__file ?? f.id}: interpolates ${missing.map((m) => `\`\${${m}}\``).join(', ')}, ` +
          'which the fixture profile does not declare in `emits`',
      );
    }
  }
  return problems;
}

/**
 * Check the VALUES the fixture actually emitted, not only that their names were
 * declared.
 *
 * `validateFeatureVars` above proves a journey only interpolates names the
 * profile promises. It says nothing about what comes back, and what comes back
 * is authored by the product — the seed command runs in the product's own
 * checkout, on the untrusted side of the boundary.
 *
 * That matters because these values land in ASSERTION OPERANDS, not merely in
 * inputs: `expect_text: "${seasonName}"`, `expect_url_contains: "${sessionId}"`,
 * the expected values of `expect_json`, and doctor's read-path preconditions. An
 * empty string interpolates to an empty expectation, and an empty expectation is
 * satisfied by anything:
 *
 *     expect_text ""            -> true against a blank page
 *     expect_url_contains ""    -> true against any URL
 *
 * So a product could neutralise the journeys that judge it by emitting `""`, and
 * the run would report PASS having proved nothing. Refusing here makes that a
 * BLOCKED_ENVIRONMENT — a statement about the world Watson was given, which is
 * exactly what it is — rather than a green tick.
 */
/**
 * Sanity-check the values a fixture emitted. See `degenerateOperand`: this is
 * usability, not a boundary. The boundary is `validateAssertionOperands`.
 */
export function validateSeedValues(vars, fixtureProfile) {
  const declared = fixtureProfile?.emits ?? [];
  const problems = [];
  for (const name of declared) {
    if (!(name in (vars ?? {}))) {
      problems.push(`the fixture declares \`${name}\` in \`emits\` but did not emit it`);
      continue;
    }
    const bad = degenerateOperand(vars[name]);
    if (bad) problems.push(`\`${name}\` ${bad}`);
  }
  return problems;
}

/**
 * A USABILITY CHECK. Not a trust control, and no longer described as one.
 *
 * It began as a defence: reject values too unspecific to prove anything, and a
 * hostile fixture would find it harder to neutralise its own journeys. That was
 * never going to work, and two reviews said so — `http`, `Sign` and `Home` are
 * all plausible and all make a substring assertion true against a generic error
 * page. No predicate over a string separates a real season name from a string
 * chosen because it appears on the failure page.
 *
 * `validateAssertionOperands` closes that properly, by taking the choice away.
 * What survives here is worth keeping for a different and much smaller reason:
 * a fixture that emits an empty or malformed value for a name a journey uses as
 * INPUT produces a confusing failure three steps later, and saying so at the
 * source is kinder than debugging it.
 */
export function degenerateOperand(value) {
  if (value === null || value === undefined) return 'is null; an unresolved operand is not an expectation';
  if (typeof value === 'object') return 'is not a scalar; an assertion operand must be a string or number';
  const v = String(value).trim();
  if (v === '') return 'came back empty; an empty expectation is satisfied by anything';
  if (v.length < MIN_OPERAND_LENGTH) {
    return `is ${v.length} character(s) long. Assertions on it are substring tests, so a short `
      + `value is satisfied by almost any page — it proves nothing about the product.`;
  }
  if (new Set(v).size < 2) return 'repeats a single character; as a substring test that proves nothing';
  if (!/[a-z0-9]/i.test(v)) return 'contains no alphanumeric character; as a substring test that proves nothing';
  return null;
}

/**
 * Chosen against what a fixture legitimately emits: database ids, slugs, season
 * names, session names. Four characters admits `2026`, which is a real season
 * name, and excludes `a` and `/`, which are not identifiers at all.
 */
export const MIN_OPERAND_LENGTH = 4;

/**
 * The variables a feature uses AS PROOF, as opposed to as input.
 *
 * Only assertion steps count. A value that merely gets typed into a form can be
 * anything; a value that makes an assertion true cannot be chosen by the thing
 * the assertion is about.
 */
export function assertionVars(feature) {
  const into = new Set();
  for (const step of feature.steps ?? []) {
    for (const [key, value] of Object.entries(step)) {
      if (ASSERTION_STEPS.has(key)) referencedVars(value, into);
    }
  }
  return into;
}

/**
 * Refuse a contract in which the PRODUCT chooses the values that make Watson's
 * assertions true.
 *
 * This is the rule three rounds of review converged on, and it is the one
 * property that closes the class rather than raising its cost:
 *
 *   The thing being tested cannot choose the value that makes the verifier's
 *   assertion true.
 *
 * The heuristic this replaces — refusing values that look vacuous — could never
 * establish it. `http`, `Sign` and `Home` are all syntactically plausible and all
 * make a substring assertion true against a generic error page. There is no
 * predicate over a string that distinguishes "a real season name" from "a string
 * chosen because it appears on the failure page", because the difference is not
 * in the string. It is in who picked it.
 *
 * So the contract must declare, per fixture profile, which names the VERIFIER
 * supplies. Anything a journey asserts on must be one of those. A journey that
 * wants to assert on a database-assigned id has to stop, and assert on something
 * the verifier named instead — which is the right pressure, because a product
 * that assigns the id also decides what the assertion sees.
 */
export function validateAssertionOperands(features, fixtureProfile, engineSupplied = ['runId']) {
  const chosen = new Set([
    ...normaliseChosen(fixtureProfile?.verifier_chosen ?? []).map(([n]) => n),
    ...engineSupplied,
  ]);
  const problems = [];
  for (const f of features) {
    const used = [...assertionVars(f)].filter((v) => !chosen.has(v)).sort();
    if (used.length) {
      problems.push(
        `${f.__file ?? f.id}: asserts on ${used.map((m) => `\`\${${m}}\``).join(', ')}, which the ` +
          'fixture profile does not declare in `verifier_chosen`. The product would be choosing the ' +
          'value that makes its own test pass.',
      );
    }
  }
  return problems;
}

/**
 * The values the verifier supplies to the fixture.
 *
 * Deterministic per run, derived from the run identity the verifier owns, so a
 * re-run of the same run is reproducible and two concurrent runs never collide.
 * Not random, because flakiness bought nothing here — what matters is that the
 * product cannot predict or choose them, and a value keyed to a run id it never
 * sees satisfies that.
 *
 * Long enough that a substring assertion on one is meaningful: 16 hex characters
 * do not appear on an error page by accident.
 */
export function fixtureValues(runId, declared = []) {
  const out = {};
  for (const [name, shape] of normaliseChosen(declared)) {
    const h = crypto.createHash('sha256').update(`watson-fixture\0${runId}\0${name}`).digest('hex');
    out[name] = SHAPES[shape](h, name);
  }
  return out;
}

/**
 * A verifier-chosen value still has to be something the product can store.
 *
 * A season NAME can be any string; a season ID is a uuid column; a cohort SIZE
 * is an integer the fixture has to actually create that many rows for. Handing
 * the fixture `watson-primarySeasonId-3f2a…` where a uuid belongs would fail at
 * the insert and read as a broken world, so the contract declares the shape and
 * the verifier generates something that fits it.
 *
 * Every shape is derived from the same run-scoped hash, so all of them are
 * deterministic per run, unpredictable to a product that cannot see the run id,
 * and distinct from each other.
 */
export const SHAPES = {
  text: (h, name) => `watson-${name}-${h.slice(0, 16)}`,
  // RFC 4122 layout, deterministic content. Version 4 nibble and variant bits are
  // set so a strict uuid column or validator accepts it.
  uuid: (h) => [
    h.slice(0, 8), h.slice(8, 12),
    `4${h.slice(13, 16)}`,
    `${((parseInt(h.slice(16, 17), 16) & 0x3) | 0x8).toString(16)}${h.slice(17, 20)}`,
    h.slice(20, 32),
  ].join('-'),
  // Small and positive: the fixture has to create this many rows, and a cohort
  // of 4 billion is not a test, it is an outage.
  integer: (h) => 3 + (parseInt(h.slice(0, 6), 16) % 7),
};

/** `[name, shape]` pairs from either a bare list or a name -> shape mapping. */
export function normaliseChosen(declared) {
  const pairs = Array.isArray(declared)
    ? declared.map((n) => (typeof n === 'string' ? [n, 'text'] : Object.entries(n)[0]))
    : Object.entries(declared ?? {});
  for (const [name, shape] of pairs) {
    if (!SHAPES[shape]) {
      throw new Error(
        `\`${name}\` declares verifier-chosen shape \`${shape}\`, which the engine does not generate. ` +
          `Known shapes: ${Object.keys(SHAPES).join(', ')}.`,
      );
    }
  }
  return pairs;
}

/**
 * The environment the fixture receives them in. A product that ignores these and
 * invents its own values fails the cross-check at the call site rather than here.
 */
export function fixtureValueEnv(values) {
  return Object.fromEntries(
    Object.entries(values).map(([k, v]) => [`WATSON_FIXTURE_${k.replace(/[^A-Za-z0-9]/g, '_').toUpperCase()}`, v]),
  );
}

/**
 * Expand `depends_on` into an ordered setup list. A prerequisite runs as SETUP,
 * not as its own verdict — a failing prerequisite blocks its dependants rather
 * than silently passing them.
 */
export function withDependencies(selected, all) {
  const byId = new Map(all.map((f) => [f.id, f]));
  const seen = new Set();
  const ordered = [];
  const visit = (f, isSetup) => {
    if (seen.has(f.id)) return;
    seen.add(f.id);
    for (const dep of f.depends_on ?? []) {
      const d = byId.get(dep);
      if (d) visit(d, true);
    }
    ordered.push({ feature: f, role: isSetup ? 'setup' : 'verified' });
  };
  for (const f of selected) visit(f, false);
  return ordered;
}

/**
 * Load the contract as it stood at an arbitrary SHA, by exporting just `.watson/`
 * from that commit into a scratch directory.
 *
 * Used only for the base→head contract diff. It returns null rather than throwing
 * when the base contract cannot be read or does not validate: a run must not die
 * because a PREVIOUS commit's contract was malformed, and "unavailable" is already
 * a reported outcome.
 */
export function loadContractAt(repoRoot, sha) {
  let tmp;
  try {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'watson-contract-'));
    // `git archive` writes only what the commit contains — nothing from the
    // working tree, so a dirty checkout cannot contaminate the base side.
    const tar = git(['archive', '--format=tar', sha, '.watson'], {
      cwd: repoRoot, maxBuffer: 64 * 1024 * 1024, stdio: ['ignore', 'pipe', 'ignore'],
    });
    execFileSync('tar', ['-x', '-C', tmp], { input: tar, stdio: ['pipe', 'ignore', 'ignore'] });
    return loadContract(tmp);
  } catch {
    return null;
  } finally {
    if (tmp) fs.rmSync(tmp, { recursive: true, force: true });
  }
}

/**
 * Environment keys the ENGINE owns. A contract that set one of these could point the
 * launched application at an issuer or client id other than the ones Watson mints
 * with — the app would then verify against something Watson does not control — or,
 * by dropping one, leave the identity seam unconfigured so no guarded route mounts
 * and the run "verifies" an application that never enforced anything.
 *
 * DATABASE_URL and PORT are here for the same reason in a different register: the
 * run's isolation is not the contract's to redefine.
 */
export const ENGINE_OWNED_ENV = Object.freeze([
  'WORKOS_ISSUER', 'WORKOS_CLIENT_ID', 'WORKOS_JWKS_URI', 'DATABASE_URL', 'PORT',
]);

/** Problems with a contract's `env` block. Checked BEFORE anything is provisioned. */
export function validateEnvOwnership(config) {
  const reserved = Object.keys(config?.env ?? {}).filter((k) => ENGINE_OWNED_ENV.includes(k));
  if (!reserved.length) return [];
  return [
    `.watson/config.yaml env sets engine-owned key(s): ${reserved.join(', ')}. ` +
      'These are injected by the engine and bind the identity seam to the tokens it mints; ' +
      'a contract cannot redefine them.',
  ];
}

/** Steps that can only be true of a page the browser has actually loaded. */
const REQUIRES_A_LOADED_PAGE = new Set([
  'expect_api', 'expect_text', 'expect_no_text', 'expect_no_uuid',
  'expect_count_at_most', 'expect_count_at_least', 'expect_url_contains',
  'wait_for_text', 'click', 'fill', 'select', 'expect_no_overflow',
]);
const NAVIGATES = new Set(['goto', 'reload', 'back']);

/**
 * Refuse a journey that asserts about the page before it has loaded one.
 *
 * `expect_api` reads the traffic the BROWSER made. Placed before any navigation it
 * observes an empty list and fails — and it fails as a behavioral assertion, so the
 * triage reads FAIL_PRODUCT and the run accuses the application of a defect that is
 * really a typo in the map. That is the most expensive kind of false positive this
 * system can produce, so it is refused up front rather than triaged after.
 *
 * `expect_denied` is deliberately absent: it issues its own request and does not
 * depend on the page.
 */
export function validateStepOrder(features) {
  const problems = [];
  for (const f of features) {
    let navigated = false;
    for (const [i, step] of (f.steps ?? []).entries()) {
      const kind = Object.keys(step).find((k) => NAVIGATES.has(k) || REQUIRES_A_LOADED_PAGE.has(k));
      if (!kind) continue;
      if (NAVIGATES.has(kind)) { navigated = true; continue; }
      if (!navigated) {
        problems.push(
          `${f.__file ?? f.id}: step ${i + 1} \`${kind}\` asserts about a page, but the journey ` +
            'has not navigated yet. Add a `goto` first — otherwise this fails as a product defect ' +
            'when it is a map defect.',
        );
        break;
      }
    }
  }
  return problems;
}
