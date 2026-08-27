// Loads a product's verification contract from its `.watson/` directory.
//
// The engine is generic: it knows the SHAPE of a contract, never the product.
// Everything NSC-Eval-specific lives in nsc-eval/.watson/ and versions with the
// code it describes.

import fs from 'node:fs';
import path from 'node:path';
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
