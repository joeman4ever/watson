# Watson

**W**orkflow-**A**ware **T**esting, **S**imulation, **O**bservation & **N**avigation.

An independent runtime verifier. It launches a real product at an exact commit,
drives it through mapped user journeys in a real browser, and returns evidence
bound to that commit.

```text
Claude Code   builds it
CI            proves the deterministic tests pass
Watson        proves the running application actually behaves correctly
Sherlock      proves the code, design and security are correct
```

Watson answers one question — *does the running application actually behave
correctly on this exact SHA?* — and deliberately does not answer any other. It
never reviews code, and it never modifies the product it verifies.

> **Status: Phase 0.** Enough to prove the architecture, and no more. See
> [Deliberately not built yet](#deliberately-not-built-yet).

## Design in one paragraph

The **engine is generic** and lives here; the **verification contract is
product-local** and lives in the product repo under `.watson/`. That split is
the whole design: a product's description of its own behavior must version with
the code it describes and be reviewed in the PR that changes it, while the
verifier stays reusable and independent. Watson reads that contract; it never
writes it during a run.

## Usage

```bash
watson verify --repo /path/to/product [--sha <ref>] [--base <ref>] [--profile poc] [--pr 123] [--out result.json]
watson doctor --repo /path/to/product     # bring up, probe, tear down
watson reap                               # drop orphaned watson_* databases
```

Exit code is `0` for `PASS` / `PASS_WITH_ADVISORIES`, `1` otherwise. Every run
writes `runs/<runId>/result.json` (machine) and `runs/<runId>/summary.md`
(human, with a `WATSON_METADATA` marker).

`--out` additionally writes the canonical result to a path **the caller names**.
A harness should never have to find Watson's evidence by asking the filesystem
which file is newest: that answer is influenced by every process that ran during
the verification, the product's included.

## Lifecycle

```text
provision -> migrate -> LAUNCH -> seed -> doctor -> drive -> evidence -> teardown
```

Two orderings are load-bearing and were learned by running the real thing:

- **Seed after launch.** A product may create tables in its own startup
  bootstrap rather than in migrations; seeding earlier fails on missing tables
  in a way that looks like a broken migration.
- **Tear down by process group.** `npm run start` spawns a child; killing the
  PID you recorded orphans the actual listener. Everything launches detached
  into its own group and is killed by group — never by process name, only what
  we started.

## Two axes: verdict and obligation

A single axis cannot be both trustworthy and a merge gate.

| Verdict | Meaning | Obligation |
| --- | --- | --- |
| `PASS` / `PASS_WITH_ADVISORIES` | Selected features met their proof | satisfied |
| `NOT_APPLICABLE` | Diff touched no runtime path | satisfied |
| `FAIL_PRODUCT` | Observable behavior is wrong | **failed** |
| `FAIL_CONTRACT` | The map names something that no longer exists — Watson's own defect | not satisfied |
| `BLOCKED_ENVIRONMENT` | Doctor failed, build failed, database unreachable | not satisfied |
| `INDETERMINATE` | Failed once, passed on a clean retry, uncorroborated | not satisfied |
| `STALE_CONTRACT` | The contract moved under a verified product HEAD | not satisfied |
| `CONTRACT_CHANGE_REVIEW_REQUIRED` | A contract change materially alters this PR's own gate | not satisfied |

Only `FAIL_PRODUCT` asserts the product is broken. The "not satisfied" states
say something weaker and more honest: *Watson did not establish that this HEAD
behaves correctly.* They are never laundered into `FAIL_PRODUCT` to force a red,
nor into `PASS` to clear a gate.

**The invariant this protects:** a runtime-relevant HEAD must not merge merely
because Watson was unable to verify it.

## Drift is not regression

A step that cannot find the handle it names is most likely **contract drift**,
not a broken product, so it resolves to `FAIL_CONTRACT` — unless corroborated by
a runtime signal (a `5xx`, a console error, a failed request), in which case it
is a real failure. Assertions about observable behavior are the opposite: when
they fail, the app did something the contract says it should not.

Watson cannot always tell these apart. The rule is therefore explicit and
conservative rather than confident, and every failure records which rule fired
and why.

## Exact-HEAD identity

Evidence is bound to a full 40-char SHA plus two fingerprints
(`product_fingerprint`, `contract_fingerprint`) derived from git tree hashes.

**Phase 0/1 policy: a new HEAD is always re-verified.** The fingerprints are
always recorded and never consulted to carry a prior PASS forward. The cost
saving is real but bounded; one mis-classified runtime-relevant path would
produce a false PASS, which is the one failure this system cannot afford while
it is still earning trust. Carry-forward is earned later, on measured evidence,
and should then reason about *provably inert* diffs rather than about a
runtime-relevant path list that must be complete to be correct.

## The browser stack

One Chromium, one CDP endpoint, three layers:

| Layer | Owns |
| --- | --- |
| **Playwright library** | Lifecycle, authentication, scripted steps, console/network evidence, traces |
| **Playwright MCP** (`--cdp-endpoint`) | Agentic exploration over the accessibility tree |
| **Chrome DevTools MCP** (`--browser-url`) | Failure forensics; expedition-only deeper inspection |

Verified rather than assumed: an `extraHTTPHeaders` context created by the
library layer keeps its identity when MCP drives it, so an MCP-triggered
navigation still authenticates as the same synthetic user. DevTools observes
only from the moment it attaches, which is exactly why always-on console and
network capture belongs in the library layer.

## Safety

- **Synthetic environments only.** Doctor refuses, hard, to drive a database
  Watson did not create. Fixtures refuse any database not named `watson_*`.
- **Watson never modifies product code**, in any mode.
- **The runner executes untrusted product code by design** — that is the job.
  Treat it as compromised-by-assumption: no product secrets on it, and no
  repository write credential in the same process as the browser.
- Contract commands come from reviewed product-repo content, never from a PR
  body or any untrusted input.

## The verifier / product boundary

Watson runs the product's own install, build, launch and seed commands. When the
revision under verification is a pull request, those commands were written by the
author whose work Watson is judging. It is inconsistent to call that code
untrusted where credentials are concerned and trusted where the verdict is
concerned, so the engine assumes it may be hostile and holds one invariant:

> **The thing being verified must not be able to alter the verifier, the
> orchestration that invokes it, or the evidence accepted as its result.**

Three mechanisms, none of which is "put the files in different directories":

**Privilege separation (opt-in, fail-closed).** Set `WATSON_PRODUCT_UID`,
`WATSON_PRODUCT_GID` and `WATSON_PRODUCT_HOME` and every product-authored
command runs as that unprivileged user via `setpriv` — invoked with an argv
array, so the product's command string is never interpolated into another shell.
Point the engine's evidence directory somewhere that uid cannot write and the
product cannot forge a result, overwrite one, or plant a newer file for a
mtime-ordered harness to pick up. If separation is requested and cannot be
established — not root, no `setpriv`, incomplete configuration — the run
**refuses**. It never falls back to running product code with the verifier's own
privileges, because a security property believed to hold and silently absent is
worse than one that was never claimed.

**Environment scrubbing.** A named set of variables is removed before the
product's environment is handed over: CI bearer tokens
(`ACTIONS_RUNTIME_TOKEN`, `GITHUB_TOKEN`, …) and, just as important, the runner's
*command channels* — `GITHUB_ENV`, `GITHUB_PATH`, `GITHUB_OUTPUT`,
`GITHUB_STATE`. Those name files the runner reads back after a step, so anything
able to append to them can inject environment variables and PATH entries into the
trusted side that follows.

**Positive HEAD identity.** The exact-HEAD gate asserts that `HEAD` *is* the SHA
the run reports, not merely that the tree is clean. Cleanliness alone is forgeable
in one command: modify the product, commit the modification, and `git status` is
clean again at a commit nobody reviewed.

`test/isolation.test.mjs` is the negative control for all three. Where a control
needs real privilege separation and cannot have it (no root), it asserts the
fail-closed contract instead and says so in its own name — it never silently
skips, because a green tick on a security test that did nothing is read as proof.

Local development sets none of this, and should not: there is no boundary to
enforce between you and your own code.

## Deliberately not built yet

GitHub App · required checks · nightly scheduling · always-on runner ·
map-maintenance automation · web UI · native/mobile automation · fingerprint
carry-forward · diff-driven impact selection · dual-contract evaluation.

Each is earned by Phase-0/1 evidence rather than assumed up front.

## Layout

```text
src/
  cli.mjs          verify | doctor | reap
  contract.mjs     .watson loader + validation + profile selection
  fingerprint.mjs  exact-HEAD identity, contract semantic diff
  environment.mjs  provision, identity service, launch, doctor, teardown
  driver.mjs       browser, step vocabulary, evidence capture
  checks.mjs       scoped runtime invariants, drift-vs-regression triage
  result.mjs       envelope, verdict/obligation mapping, marker, summary
schemas/           result + feature JSON Schemas
skills/            agent-facing instructions
```
