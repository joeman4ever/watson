// Loads a product's verification contract from its `.watson/` directory.
//
// The engine is generic: it knows the SHAPE of a contract, never the product.
// Everything NSC-Eval-specific lives in nsc-eval/.watson/ and versions with the
// code it describes.

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
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
 */
export const SUPPORTED_CONTRACT_VERSIONS = Object.freeze([1]);

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
    const tar = execFileSync('git', ['archive', '--format=tar', sha, '.watson'], {
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
