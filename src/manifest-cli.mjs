// The trusted side's entry point for building a product manifest.
//
// WHY THIS IS A SEPARATE FILE FROM `cli.mjs`.
//
// This step runs on the CI runner itself — the trusted plane — against a
// checkout no product code has run in, before either container starts. The
// runner has the engine's source and nothing else: `npm ci` happens inside the
// verifier container, not out here. So the trusted step cannot import anything
// that is not a node built-in.
//
// `cli.mjs` cannot satisfy that and should not try. It imports the contract
// loader (`yaml`), the driver (playwright) and the environment module, because
// `verify` genuinely needs them. Routing the manifest build through it made the
// trusted step depend on a `node_modules` tree that is not there:
//
//     $ node engine/src/cli.mjs manifest --repo product …
//     Error [ERR_MODULE_NOT_FOUND]: Cannot find package 'yaml'
//
// That was not a near miss. The workflow's manifest step had never executed once
// — it also sat above the step that fetches the engine, so it was invoking a
// file that did not exist yet. Both are fixed; this file is the half that keeps
// it fixed, because the dependency-free property is now enforced by a test
// instead of by whoever edits `cli.mjs` next remembering it.
//
// `manifest.mjs` and `fingerprint.mjs` are already dependency-free and already
// covered by that test.

import fs from 'node:fs';
import path from 'node:path';
import url from 'node:url';

import { buildManifest, MANIFEST_SCHEMA } from './manifest.mjs';
import { resolveSha } from './fingerprint.mjs';

/** `--flag value` pairs. Deliberately tiny: this runs before anything else exists. */
export function parseManifestArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (!a.startsWith('--')) continue;
    const key = a.slice(2);
    const next = argv[i + 1];
    args[key] = next && !next.startsWith('--') ? (i += 1, next) : true;
  }
  return args;
}

/**
 * Build the manifest and write it where the caller named.
 *
 * Returns the manifest so a caller can report on it; throws on anything it
 * cannot establish, because a trusted step that half-succeeds is worse than one
 * that stops.
 */
export function runManifest(argv, { log = console.log } = {}) {
  const args = parseManifestArgs(argv);
  const repoRoot = path.resolve(args.repo ?? '.');
  const sha = resolveSha(repoRoot, args.sha ?? 'HEAD');
  const manifest = buildManifest(repoRoot, {
    sha,
    repository: args.repository ?? path.basename(repoRoot),
  });
  const json = `${JSON.stringify(manifest, null, 1)}\n`;

  if (args.out && args.out !== true) {
    const out = path.resolve(args.out);
    fs.mkdirSync(path.dirname(out), { recursive: true });
    fs.writeFileSync(out, json);
    log(`\n${MANIFEST_SCHEMA}  ${sha}`);
    log(`  ${Object.keys(manifest.entries).length} entries -> ${out}\n`);
  } else {
    process.stdout.write(json);
  }
  return manifest;
}

const invokedDirectly = process.argv[1]
  && path.resolve(process.argv[1]) === path.resolve(url.fileURLToPath(import.meta.url));

if (invokedDirectly) {
  try {
    runManifest(process.argv.slice(2));
  } catch (err) {
    console.error(`watson manifest: ${err.message}`);
    process.exit(1);
  }
}
