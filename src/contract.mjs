// Loads a product's verification contract from its `.watson/` directory.
//
// The engine is generic: it knows the SHAPE of a contract, never the product.
// Everything NSC-Eval-specific lives in nsc-eval/.watson/ and versions with the
// code it describes.

// THIS MODULE NO LONGER RUNS GIT, AND SHOULD NOT AGAIN.
//
// It used to, for one thing: `loadContractAt` exported `.watson/` at the base SHA
// with `git archive` out of the product's own `.git` — a directory mounted
// read-write into the product container. That was tolerable while the base
// contract was only used to DESCRIBE a diff. ADR-049 D1 makes it decide the
// verdict, and asking the product's repository for the contract that governs the
// product is the same shape as asking the product's `.git` whether the product's
// tree is clean, which three reviews got past.
//
// The governing contract now arrives as a trusted materialisation the trusted
// side produced (`--base-contract`), and this module only reads directories it
// is handed. `test/isolation.test.mjs` enforces the absence structurally.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { ASSERTION_STEPS } from './driver.mjs';
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
// v4 adds `verifier_chosen` (with shapes and closed domains), `generated_roots`,
// and the `expect_text_in` step. The bump is load-bearing for the first of those:
// an engine that predates `verifier_chosen` does not error on the key, it simply
// does not read it — so it would run the journeys with product-chosen assertion
// operands and report a confident PASS over exactly the hole v4 exists to close.
// Silent under-verification is what contract versions are for.
export const SUPPORTED_CONTRACT_VERSIONS = Object.freeze([1, 2, 3, 4, 5]);

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
  // A SYMLINK IS REFUSED RATHER THAN FOLLOWED (ADR-049 D2).
  //
  // The contract is fingerprinted as the path `.watson`. If that path is a link,
  // the bytes that are digested and the bytes that are LOADED can be different
  // things — the digest sees a link whose target never changes, and the loader
  // reads wherever it points. Following it also lets the contract escape the
  // scope the fingerprint was computed over entirely.
  if (fs.lstatSync(dir).isSymbolicLink()) {
    throw new Error(
      `contract: ${dir} is a symbolic link. The contract is fingerprinted as this path, so following `
      + 'a link would digest one thing and load another. Refused rather than followed.',
    );
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
  if (value === null || value === undefined) return 'is null, so nothing can be interpolated from it';
  if (typeof value === 'object') return 'is not a scalar; a fixture variable must be a string or number';
  if (String(value).trim() === '') return 'came back empty, which interpolates to nothing';
  return null;
}

// A length floor lived here briefly and has been removed, which is worth
// recording because removing a check usually deserves more suspicion than adding
// one.
//
// It was introduced as a defence — reject operands too short to prove anything —
// and it never worked, because `http` and `Sign` are long enough and still
// vacuous. `validateAssertionOperands` closes that properly. What the floor DID
// do, once it was no longer defending anything, was reject values a product
// legitimately emits: nsc-eval's grades are `'5'` and `'7'`, and a threshold it
// displays is `10`. A usability check that fails valid contracts is not a
// usability check.

/**
 * The variables a feature uses AS PROOF, as opposed to as input.
 *
 * Only assertion steps count. A value that merely gets typed into a form can be
 * anything; a value that makes an assertion true cannot be chosen by the thing
 * the assertion is about.
 */
/**
 * Within an assertion step, WHICH FIELD carries the proof.
 *
 * The first version of this rule counted every `${...}` inside an assertion step,
 * and that is too coarse: in `expect_denied` the assertion is an AUTHORIZATION
 * OUTCOME and the path names WHICH thing. But "address" never meant "harmless",
 * and the first cut of this table got two things wrong.
 *
 * WRONG ONE — a selector is not an address. `locator()` resolves `text=...`
 * through `page.getByText`, so
 *
 *     expect_count_at_least: { selector: "text=${sessionName}", min: 1 }
 *
 * IS `expect_text: "${sessionName}"` wearing a different hat, and the table said
 * it carried no proof at all. Anything that can name content — a `text=`
 * selector, `:has-text(...)` — is proof, so selectors are counted. A selector
 * that addresses structurally (`testid=`, `css=`) simply has no variables in it
 * and costs nothing.
 *
 * WRONG TWO — see `validateDenialAddresses` below. The justification for
 * exempting `expect_denied.path` rested on a claim about the product ("a
 * nonexistent id gets a 404, which is FAIL_CONTRACT, not a pass") that is FALSE
 * against nsc-eval, whose authorization layer deliberately has no existence
 * oracle and answers 403 for anything outside the caller's scope. The exemption
 * survives, because the alternative — forcing every id to be verifier-supplied —
 * would push a product architecture change for a property a journey can carry
 * itself. What replaces the false justification is an enforced obligation:
 * something has to prove the address resolves.
 *
 * Contrast `expect_text: "${seasonName}"`, where the operand IS the proof: a
 * product that picks the string picks whether the assertion holds.
 */
const PROOF_FIELDS = {
  // Both fields: the text is the proof, and a `text=` selector is also proof.
  expect_text_in: ['text', 'selector'],
  expect_json: ['contains', 'body', 'expect'],
  // `path` addresses; the assertion is the status class it comes back with. The
  // obligation that makes this safe is enforced by `validateDenialAddresses`.
  expect_api: [],
  expect_denied: [],
  expect_allowed: [],
  // The BOUND is a number from the contract, but the selector can name content.
  expect_count_at_most: ['selector'],
  expect_count_at_least: ['selector'],
};

export function assertionVars(feature) {
  const into = new Set();
  for (const step of feature.steps ?? []) {
    for (const [key, value] of Object.entries(step)) {
      if (!ASSERTION_STEPS.has(key)) continue;
      if (!(key in PROOF_FIELDS)) { referencedVars(value, into); continue; }
      for (const field of PROOF_FIELDS[key]) referencedVars(value?.[field], into);
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
/**
 * The four denial-proof classes, and what each one obliges a journey to show.
 *
 * A denial is the easiest assertion in the world to satisfy by accident. `403`
 * comes back from a product that denies correctly, from a product that denies
 * everything, and from a product asked about something that does not exist — and
 * the three are indistinguishable at the status line.
 *
 * `expect_denied` therefore has NO universal operand rule. What it must prove
 * depends on what kind of negative claim it is making, and the kind is DECLARED in
 * the trusted contract. Never inferred from a variable's name: `unassignedGroupId`
 * and `ungrantedGrade` need opposite obligations, and nothing in the spelling says
 * so.
 *
 * An undeclared or unrecognised class fails closed. That is the whole point: a
 * denial whose meaning the engine cannot establish is not a weak proof, it is no
 * proof, and shipping it as a green step is how a product that denies everything
 * passes a security journey.
 */
export const DENIAL_PROOF_CLASSES = Object.freeze([
  // The denied ENTITY must be real, and must stand in the relationship the denial
  // is about. `unassignedGroupId` is the case: a group that does not exist denies
  // exactly like a group this evaluator was not assigned to.
  'entity_existence',
  // The denied VALUE is a legal member of the domain for which no grant exists.
  // Demanding a positive read of it would invert the condition under test, so
  // what is required instead is a known-positive SIBLING that works.
  'domain_negative',
  // The denial follows a lifecycle: allowed, then a transition, then denied. A
  // never-granted value denies identically and proves nothing about the
  // transition, which is the entire property.
  'state_transition',
  // The route and target are real and the operation works for an authorized
  // caller; the denied caller differs in exactly the authorization predicate
  // under test. This is the common shape — role, scope, assignment, tier — and it
  // is most of any real map.
  'capability',
]);

/**
 * Check every `expect_denied` step against the obligation its declared class
 * carries. Returns human-readable problems; empty means the map's denials are
 * capable of meaning something.
 */
/**
 * Subjects a profile's proofs establish, split by what they actually establish.
 *
 * ONLY `trusted_setup` proofs count. That restriction is the whole reason this is
 * honest evidence rather than another declaration: a `trusted_setup` proof is
 * EXECUTED by `doctor` against the run's own database before any journey runs, and
 * an unestablished one blocks the run. An `application_read` proof describes a
 * read the product exposes — which is a precondition, and is credited through
 * `resolvedByPrecondition` when one is actually declared and run.
 *
 * `exists` and `transitioned` are separate on purpose. An existence proof says a
 * row is there; it says nothing about a state change, and a value that was never
 * granted in the first place satisfies it.
 */
export function provenSubjects(fixtureProfile) {
  const exists = new Set();
  const transitioned = new Set();
  for (const p of fixtureProfile?.proofs ?? []) {
    if (p?.source !== 'trusted_setup' || typeof p.subject !== 'string') continue;
    if (p.type === 'entity_exists') exists.add(p.subject);
    if (p.type === 'state_transition' && Object.keys(p.probe?.requires ?? {}).length) {
      transitioned.add(p.subject);
      exists.add(p.subject);
    }
  }
  return { exists, transitioned };
}

/**
 * A route template, comparable across journeys: query string dropped, `${var}`
 * placeholders kept.
 *
 * The query string is dropped on purpose. `?grade=${grantedGrade}` and
 * `?grade=${ungrantedGrade}` are the SAME capability answering differently about
 * two values — which is what a `domain_negative` denial is about, and it has its
 * own obligations. What `capability` asks is whether the route exists and is
 * reachable by somebody.
 */
export function routeOf(path) {
  // `${var}` becomes a positional placeholder, because a parameter's VALUE is not
  // part of a route. `/api/seasons/${foreignSeasonId}/players` and
  // `/api/seasons/${primarySeasonId}/players` are one route asked about two
  // seasons — and "which season" is an `entity_existence` or scope question with
  // its own obligations, not a question about whether the route exists.
  //
  // Without this, a denial on a season the admin does not administer would demand
  // a positive control on that same season, which is the property under test
  // inverted: the control could only be built by granting the access the journey
  // exists to prove is absent.
  return String(path ?? '').split('?')[0].replace(/\$\{[^}]*\}/g, ':param');
}

export function validateDenialProofs(features, fixtureProfile) {
  const problems = [];

  // Names a precondition RESOLVES. A precondition that expects a denial proves
  // nothing about existence — two denials are not an existence proof.
  const resolvedByPrecondition = new Set();
  for (const pre of fixtureProfile?.preconditions ?? []) {
    if (pre.expect?.authorized === false) continue;
    referencedVars(pre.get, resolvedByPrecondition);
    // A NAME THE PRECONDITION PROVES WITHOUT NAMING IT IN THE URL.
    //
    // Not every entity has a route of its own. An unassigned group has no admin
    // endpoint — it is reachable only as a MEMBER of the session's group list,
    // which an administrator may read. `proves:` lets that read count as the
    // existence evidence D5 Class 1 asks for.
    //
    // It is credited only when the precondition actually asserts on the value:
    // the declaration alone would be the fixture vouching for itself, which is
    // the thing this whole mechanism exists to stop. `doctor` runs the assertion
    // and fails the run when the entity is not in the collection.
    for (const name of pre.proves ?? []) {
      const asserted = new Set();
      referencedVars(pre.expect?.contains?.value, asserted);
      referencedVars(pre.expect?.json, asserted);
      if (asserted.has(name)) resolvedByPrecondition.add(name);
    }
  }
  const chosen = new Set(normaliseChosen(fixtureProfile?.verifier_chosen ?? []).map(([n]) => n));
  const proven = provenSubjects(fixtureProfile);

  // POSITIVE CONTROLS ARE COUNTED ACROSS THE WHOLE RUN, NOT PER FEATURE.
  //
  // The obligation a positive control discharges is "this route is not simply
  // denied to everyone" — and the identity that legitimately holds a capability
  // is usually in a DIFFERENT journey from the one proving it is denied. The
  // administrator reads the audit log; the no-role persona is denied it. Requiring
  // both in one feature meant either an unsatisfiable rule or a journey rewritten
  // to suit the checker.
  //
  // `features` is the RUN PLAN, not the whole map, and that is the property that
  // keeps this from being a loophole: a control in a journey impact selection
  // deselected is a control that does not execute, and it does not count here
  // either. Widening this to the full map would credit a control that never ran.
  const runPositiveVars = new Set();
  const runPositiveRoutes = new Set();
  let runPositiveSteps = 0;
  for (const f of features) {
    for (const step of f.steps ?? []) {
      for (const [key, value] of Object.entries(step)) {
        if (key === 'expect_allowed' || key === 'expect_api' || key === 'expect_json') {
          referencedVars(value?.path, runPositiveVars);
          if (typeof value?.path === 'string') runPositiveRoutes.add(routeOf(value.path));
          runPositiveSteps += 1;
        }
        // `expect_reached` counts for the ROUTE and NOT for the entities in it.
        //
        // It establishes that this identity got past authorization on this
        // route — which is exactly the `capability` obligation. It does NOT
        // establish that the entities named in the path exist: a 400 for a
        // missing query parameter says nothing about the season in the URL. So
        // `entity_existence` and the `domain_negative` sibling check, which are
        // about entities, do not see it.
        if (key === 'expect_reached') {
          if (typeof value?.path === 'string') runPositiveRoutes.add(routeOf(value.path));
          runPositiveSteps += 1;
        }
      }
    }
  }

  for (const feature of features) {
    const label = feature.__file ?? feature.id;
    const positive = runPositiveVars;
    const positiveSteps = runPositiveSteps;

    for (const [index, step] of (feature.steps ?? []).entries()) {
      if (!('expect_denied' in step)) continue;
      const at = `${label} step ${index + 1}`;
      const declared = step.proof ?? null;
      const cls = typeof declared === 'string' ? declared : declared?.class ?? null;

      if (!cls) {
        problems.push(
          `${at}: \`expect_denied\` does not declare which kind of denial it proves. `
          + `Add \`proof:\` naming one of ${DENIAL_PROOF_CLASSES.join(', ')}. A denial whose meaning `
          + 'the engine cannot establish is not a weak proof, it is no proof.',
        );
        continue;
      }
      if (!DENIAL_PROOF_CLASSES.includes(cls)) {
        problems.push(`${at}: unknown denial-proof class \`${cls}\` (expected one of ${DENIAL_PROOF_CLASSES.join(', ')}).`);
        continue;
      }

      const vars = new Set();
      referencedVars(step.expect_denied?.path, vars);

      if (cls === 'entity_existence') {
        const unproven = [...vars].filter(
          (v) => !positive.has(v) && !resolvedByPrecondition.has(v) && !proven.exists.has(v),
        );
        if (unproven.length) {
          problems.push(
            `${at}: declares \`entity_existence\` but nothing proves ${unproven.map((v) => `\`\${${v}}\``).join(', ')} `
            + 'exists. Reach it with a positive assertion in this run, resolve it in a precondition '
            + 'as an identity permitted to see it, or declare a `trusted_setup` proof for it. An entity '
            + 'that does not exist denies exactly like one that does.',
          );
        }
      } else if (cls === 'domain_negative') {
        const sibling = declared?.sibling ?? null;
        const denied = [...vars];
        if (!sibling) {
          problems.push(`${at}: \`domain_negative\` must name the known-positive \`sibling\` that the same capability accepts.`);
        } else if (!positive.has(sibling) && !resolvedByPrecondition.has(sibling)) {
          problems.push(
            `${at}: the sibling \`\${${sibling}}\` is never positively exercised, so the capability itself is `
            + 'unproven and the denial is satisfied by a product that denies everything.',
          );
        }
        const unchosen = denied.filter((v) => !chosen.has(v));
        if (unchosen.length) {
          problems.push(
            `${at}: \`domain_negative\` requires the denied value to be verifier-chosen from the trusted `
            + `domain; ${unchosen.map((v) => `\`\${${v}}\``).join(', ')} is not declared in \`verifier_chosen\`.`,
          );
        }
        if (sibling && denied.includes(sibling)) {
          problems.push(`${at}: the denied value and its sibling are the same name (\`${sibling}\`).`);
        }
      } else if (cls === 'state_transition') {
        // A precondition run as a permitted identity establishes the prior state
        // through the product's own read path. Where the product deliberately
        // exposes no such path, a `state_transition` proof does it directly, and
        // that proof is required to test the transition column itself — an
        // `entity_exists` proof is NOT accepted here, because a never-granted
        // value satisfies it.
        const established = [...vars].filter(
          (v) => !resolvedByPrecondition.has(v) && !proven.transitioned.has(v),
        );
        if (established.length) {
          problems.push(
            `${at}: \`state_transition\` needs trusted evidence that ${established.map((v) => `\`\${${v}}\``).join(', ')} `
            + 'was ALLOWED before the transition. A never-granted value denies identically, so without the '
            + 'prior state this step proves nothing about the transition it names.',
          );
        }
      } else if (cls === 'capability') {
        // THE ROUTE ITSELF, not merely some route in the run.
        //
        // Measured against nsc-eval's map this is the difference between a rule
        // that means something and one that does not: 48 of 58 denials were
        // against routes NOTHING positively exercised. A product answering 403
        // for every one of those sixteen routes, to every identity, passed all
        // of them. `positiveSteps > 0` alone would have called that satisfied.
        const route = routeOf(step.expect_denied?.path ?? '');
        if (positiveSteps === 0) {
          problems.push(
            `${at}: \`capability\` requires the route or capability to be positively demonstrated `
            + 'by an authorized control that SUCCEEDS. This run has no positive assertion at all, so '
            + 'every denial in it is satisfied by a product that denies everything.',
          );
        } else if (route && !runPositiveRoutes.has(route)) {
          problems.push(
            `${at}: \`capability\` names \`${route}\`, which no journey in this run reaches `
            + 'successfully. A denial on a route nobody can reach is satisfied by a product that '
            + 'has removed the route, denies it to everyone, or never had it. Exercise it as an '
            + 'identity that legitimately holds the capability.',
          );
        }
        const context = [...vars].filter((v) => !positive.has(v) && !resolvedByPrecondition.has(v));
        if (context.length) {
          problems.push(
            `${at}: the context ${context.map((v) => `\`\${${v}}\``).join(', ')} is never shown to exist, so the `
            + 'denied request may be denied for the wrong reason.',
          );
        }
      }
    }
  }
  return problems;
}

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
 * Not random, because flakiness bought nothing here.
 *
 * THE PROPERTY IS "CANNOT CHOOSE", NOT "CANNOT PREDICT", and the difference is
 * worth stating because the docs used to claim the second. The product CAN
 * predict these: the run id is passed to the fixture on its own command line
 * (nsc-eval's `command:` interpolates `${RUN_ID}`), a contract's `env:` block can
 * put it in front of the running application, and this derivation is public. A
 * hostile application can recompute every value at startup and render them.
 *
 * That is survivable, and choosing would not be. An application that renders
 * `${primarySeasonName}` on every page makes `expect_text` pass — and fails the
 * negative journeys, which assert that the same string does NOT appear where it
 * must not, and the denials, which are status-class assertions it cannot paint
 * its way out of. What the old design allowed was different in kind: the fixture
 * picked a string that was ALREADY on the failure page, so the product did not
 * have to do anything at all.
 *
 * Long enough that a substring assertion on one is meaningful: 16 hex characters
 * do not appear on an error page by accident.
 */
export function fixtureValues(runId, declared = []) {
  const chosen = normaliseChosen(declared);
  const out = {};

  // POOLS FIRST. Names drawn from the same closed domain usually have to differ
  // from each other — nsc-eval takes five grades from one fourteen-member set,
  // and a journey whose "granted" and "ungranted" grades collide does not test
  // an authorization boundary, it tests nothing, non-deterministically.
  //
  // Hashing each name independently makes that collision a matter of luck. A
  // pool takes the choice out of luck as well as out of the product's hands.
  const pools = new Map();
  for (const [name, shape, domain, pool] of chosen) {
    if (shape !== 'enum' || !pool) continue;
    if (!pools.has(pool)) pools.set(pool, { domain, names: [] });
    const p = pools.get(pool);
    if (JSON.stringify(p.domain) !== JSON.stringify(domain)) {
      throw new Error(`pool \`${pool}\` is declared with two different domains; a pool is one set`);
    }
    p.names.push(name);
  }
  for (const [pool, { domain, names }] of pools) {
    if (names.length > domain.length) {
      throw new Error(
        `pool \`${pool}\` needs ${names.length} distinct values but its domain has ${domain.length}`,
      );
    }
    // A deterministic permutation of the domain, keyed on the run and the pool,
    // dealt out in declaration order. Every member is as likely as any other and
    // no two names collide.
    const order = [...domain]
      .map((v) => [v, crypto.createHash('sha256').update(`watson-pool\0${runId}\0${pool}\0${v}`).digest('hex')])
      .sort((a, b) => (a[1] < b[1] ? -1 : 1))
      .map(([v]) => v);
    names.forEach((name, i) => { out[name] = order[i]; });
  }

  for (const [name, shape, domain] of chosen) {
    if (name in out) continue;
    const h = crypto.createHash('sha256').update(`watson-fixture\0${runId}\0${name}`).digest('hex');
    if (shape === 'enum') out[name] = pickFromDomain(h, name, domain);
    else if (shape === 'integer' && domain) out[name] = pickInteger(h, domain);
    else out[name] = SHAPES[shape](h, name);
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
 * deterministic per run, not chosen by the product,
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
  // of 4 billion is not a test, it is an outage. A range narrows it further when
  // the product's own semantics require one — see `pickInteger`.
  integer: (h) => pickInteger(h, { min: 3, max: 9 }),
};

/**
 * An integer the verifier chooses, optionally within a range the contract
 * declares.
 *
 * The range exists because some numbers are not free. nsc-eval seeds a cohort
 * that must be ABOVE its disclosure threshold, so that the journey observes a
 * reportable aggregate; a verifier that picked 4 would produce a suppressed
 * cohort, the journey would see a suppression notice where it expected a count,
 * and Watson would report FAIL_PRODUCT against a product that did exactly the
 * right thing. A false accusation is the most expensive kind of wrong a verifier
 * can be.
 *
 * A declared range is a RESTATEMENT of something the product decides, and that
 * coupling is real: if the product's threshold moves past the range, the journey
 * breaks. It breaks LOUDLY rather than silently — the contract is then stale and
 * says so in review — but it is a coupling, and a contract that declares one
 * should say why beside it.
 */
function pickInteger(h, { min, max }) {
  if (!Number.isInteger(min) || !Number.isInteger(max) || max < min) {
    throw new Error(`integer range { min: ${min}, max: ${max} } is not a usable range`);
  }
  return min + (parseInt(h.slice(0, 8), 16) % (max - min + 1));
}

/**
 * A CLOSED DOMAIN the verifier picks from.
 *
 * Some values cannot be invented. A school grade is one: nsc-eval constrains it
 * to `PK, K, 1..12` with a database CHECK mirroring its own domain module, so a
 * verifier-generated `watson-grantedGrade-a1b2…` fails at the insert. Refusing
 * to let the verifier choose at all would hand the fixture back the decision
 * this whole mechanism exists to take away — it could pick whichever member of
 * the domain makes an assertion most vacuous.
 *
 * So the CONTRACT declares the domain and the VERIFIER picks the member. The set
 * is product-authored, which is fine and visible: it is reviewed in the pull
 * request, it is covered by the contract fingerprint, and a change to it shows up
 * as a contract change. What the product no longer does is choose which one the
 * assertion rests on.
 *
 * WHAT THIS DOES NOT FIX, because it cannot: an assertion on a one-character
 * value from a fourteen-member domain is weak whoever picks it — `expect_text:
 * "5"` matches almost any page. That is a JOURNEY design problem, not a value
 * ownership problem, and it needs a different answer: assert on something
 * specific and scope the grade with a selector, rather than asserting the grade
 * as text.
 */
function pickFromDomain(h, name, domain) {
  if (!Array.isArray(domain) || domain.length === 0) {
    throw new Error(`\`${name}\` declares an enum shape with no values to choose from`);
  }
  return domain[parseInt(h.slice(0, 8), 16) % domain.length];
}

/**
 * `[name, shape, domain, pool]` from a bare list, a name -> shape mapping, or a
 * name -> `{ enum: [...], pool?: string }` mapping. Names sharing a pool are
 * guaranteed distinct values from the same domain.
 */
export function normaliseChosen(declared) {
  const entries = Array.isArray(declared)
    ? declared.map((n) => (typeof n === 'string' ? [n, 'text'] : Object.entries(n)[0]))
    : Object.entries(declared ?? {});

  return entries.map(([name, spec]) => {
    if (spec && typeof spec === 'object' && Array.isArray(spec.enum)) {
      return [name, 'enum', spec.enum, spec.pool ?? null];
    }
    if (spec && typeof spec === 'object' && spec.integer) {
      return [name, 'integer', spec.integer, null];
    }
    if (!SHAPES[spec]) {
      throw new Error(
        `\`${name}\` declares verifier-chosen shape \`${JSON.stringify(spec)}\`, which the engine does not ` +
          `generate. Known shapes: ${Object.keys(SHAPES).join(', ')}, or \`{ enum: [...] }\` for a closed domain.`,
      );
    }
    return [name, spec, null, null];
  });
}

/**
 * The environment the fixture receives them in. A product that ignores these and
 * invents its own values fails the cross-check at the call site rather than here.
 */
/**
 * Reconcile what the fixture reports it built against what the verifier chose.
 *
 * Lives here rather than in `cli.mjs` because it is fixture-value logic, and
 * because `cli.mjs` runs the CLI on import — so anything in it is untestable
 * without launching the tool. That is not a hypothetical cost: this function was
 * untested, and shipped a comparison that flagged every integer-shaped value as
 * ignored on every run.
 */
export function reconcileFixtureValues(emitted, chosen) {
  const out = emitted ?? {};
  const ignored = [];
  for (const [k, v] of Object.entries(chosen)) {
    if (!(k in out)) {
      // OMISSION, not contradiction. This used to be invisible: the filter
      // required the key to be present, so a fixture that simply never reported
      // back on a value passed — and then the engine back-filled it from
      // `chosen`, so `validateSeedValues` could not see it either.
      //
      // It matters most for the negative journeys, which is where it is hardest
      // to notice. A fixture that never grants-then-revokes the verifier's
      // `revokedGrade` still passes "the revoked grant is denied", because a
      // grade that was never granted denies identically to one that was
      // revoked. The assertion holds and the property it names was never built.
      ignored.push(
        `\`${k}\`: the verifier supplied \`${v}\`, and the fixture did not report building anything with it. `
        + 'A world that does not contain the value the assertions are about is not the world that was asked for.',
      );
      continue;
    }
    // BOTH sides stringified. `pickInteger` returns a NUMBER, so comparing
    // `String(emitted) !== chosen` was `"13" !== 13` — always true. Every run
    // with an integer-shaped verifier-chosen value failed as a broken world,
    // reporting `fixture used 13, verifier supplied 13`. Unit tests missed it
    // because they all used strings; the first local end-to-end run found it
    // immediately, which is the whole argument for running them.
    if (String(out[k]) !== String(v)) {
      ignored.push(`\`${k}\`: fixture used \`${out[k]}\`, verifier supplied \`${v}\``);
    }
  }
  return { vars: { ...out, ...chosen }, ignored };
}

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
  // A FEATURE THAT WAS SELECTED IS VERIFIED, whatever order it is reached in.
  //
  // Without this set, a journey that is BOTH selected in its own right AND a
  // dependency of another selected journey is demoted to `setup` — because the
  // dependency edge is walked first and `seen` stops the second visit. Setup
  // verdicts are excluded from the run roll-up, so the demotion silently removed
  // a journey from the verdict.
  //
  // Observed, not theorised: adding `depends_on: [prospective-report-boundary]`
  // to another journey turned a real FAIL_PRODUCT into a run that reported
  // PASS_WITH_ADVISORIES. Selection, not visit order, decides the role.
  const selectedIds = new Set(selected.map((f) => f.id));
  const seen = new Set();
  const ordered = [];
  const visit = (f, isSetup) => {
    if (seen.has(f.id)) return;
    seen.add(f.id);
    for (const dep of f.depends_on ?? []) {
      const d = byId.get(dep);
      if (d) visit(d, true);
    }
    ordered.push({ feature: f, role: isSetup && !selectedIds.has(f.id) ? 'setup' : 'verified' });
  };
  for (const f of selected) visit(f, false);
  return ordered;
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
  // PATH decides which binary any bare program name resolves to — including the
  // ones the ENGINE spawns around the product's command. Defence in depth: the
  // privilege-separation wrapper is now resolved absolutely on the trusted side,
  // so PATH cannot redirect it, but a contract has no business setting PATH for
  // the process tree the verifier builds either.
  'PATH',
]);

/**
 * Refuse a contract that tries to choose what the VERIFIER executes.
 *
 * `browser.executable_path` used to be honoured, and it was arbitrary code
 * execution as the verifier: the path went to `chromium.launch()`, which runs it
 * on the verifier's side of the boundary, as the verifier's uid, with the
 * verifier's unscrubbed environment — and it sat upstream of the root refusal,
 * the channel pin and the sandbox probe, so naming a binary skipped all three.
 *
 * Refused rather than ignored. A key that is silently dropped reads to whoever
 * wrote it as a key that works, and the next reader of the contract has no way to
 * tell. The verifier's browser comes from the trusted side (`WATSON_CHROMIUM`) or
 * from the pinned channel, and from nowhere else.
 */
export function validateBrowserOwnership(config) {
  const declared = config?.browser ?? null;
  if (!declared || typeof declared !== 'object') return [];
  const keys = Object.keys(declared);
  if (!keys.length) return [];
  return [
    `.watson/config.yaml declares \`browser\` (${keys.join(', ')}). The verifier chooses what it `
    + 'executes; a contract cannot name the browser binary, because that binary runs on the '
    + "verifier's side of the boundary with the verifier's privileges. Set WATSON_CHROMIUM on the "
    + 'trusted side instead.',
  ];
}

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
