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
# TRUSTED side, against a checkout the product has not run in:
watson manifest --repo /path/to/product --sha <ref> --out manifest.json

watson verify --repo /path/to/product --manifest manifest.json \
              [--sha <ref>] [--base <ref>] [--profile poc] [--pr 123] [--out result.json] \
              [--plane <url> --product-base-url <url>]
watson doctor --repo /path/to/product     # bring up, probe, tear down
watson plane  --repo /path/to/product     # the untrusted side's executor
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

### Two planes

```text
VERIFIER PLANE                          PRODUCT PLANE
  engine, contract, selection             the exact PR checkout
  database provisioning + marker          npm install / build / start
  identity: signing key, JWKS             the fixture seed
  Playwright + SANDBOXED Chromium
  the evidence directory                  runs unprivileged
  runs unprivileged                       holds no credential
                    │                              │
                    └──── isolated network ────────┘
                          HTTP only, verifier → product
```

`watson verify --plane <url> --product-base-url <url>` splits them; without those
flags everything runs in one process, which is right for local development —
there is no boundary to enforce between you and your own code.

The division of labour is the security property. **The verifier decides:** it
reads the contract, provisions and stamps the database, mints the identity,
chooses the port, resolves every command and environment variable, and confirms
readiness itself by polling the product's own health endpoint. **The product
plane executes:** it runs what it is handed and answers with what came back.

The plane has no endpoint that reports readiness — deliberately, and there is a
test for it. A plane allowed to decide one small thing is a plane the product can
use to make the verifier agree with it.

Nothing the plane says decides a verdict, and the reason is architectural rather
than a promise.

The fixture's emitted variables used to be the exception. They become **assertion
operands** — `expect_text: "${seasonName}"` asserted against a string the product
chose, which let the product decide whether it passed its own test. Refusing
values that *look* vacuous could never fix that: `http`, `Sign` and `Home` are all
plausible and all match a generic error page. The difference is not in the string,
it is in who picked it.

So the verifier picks it. It generates the values a journey asserts on from a run
identity the product never sees, and passes them **into** the fixture:

```text
verifier            → WATSON_FIXTURE_SEASONNAME=watson-seasonName-240b876c04012e82
fixture             → creates the season with that name
Watson's assertion  → expects the value the VERIFIER chose
```

The contract declares which names those are, and the engine **refuses a contract
that asserts on anything else** — a journey may still navigate to a
product-assigned id, it just may not treat that id as evidence. A fixture that
ignores what it was given fails the run as a broken world, not a product defect.

### The browser is part of the verifier

The pages Chromium loads are served by the product under verification, so an
unsandboxed browser is a hole in the same boundary that protects the evidence.
Chromium refuses to start as root with its sandbox on; the response is to refuse
to be root, never to pass `--no-sandbox`. `launchBrowser` throws as root, the
flag appears nowhere in `src/`, and a test greps for it.

`test/browser-sandbox-proof.mjs` proves the sandbox rather than asserting it. It
launches the real browser as an unprivileged user in the pinned container image
and establishes both of Chromium's layers, which fail independently:

| layer | how it is established |
| --- | --- |
| seccomp-bpf | `Seccomp: 2` and `NoNewPrivs: 1` in the renderer's `/proc/<pid>/status` |
| namespace sandbox | `chrome://sandbox` reporting *adequately sandboxed*, corroborated by the renderer's `/proc/<pid>/ns/{user,pid,net}` |

Chromium's own status page is authoritative for layer 1 because Chromium knows
which mechanism it chose. An earlier version of this proof demanded a separate
*user* namespace and reported the sandbox missing on a browser Chromium itself
called adequately sandboxed — the check was wrong, not the browser.

Two things this proof had to learn the hard way, both now permanent:

- **Docker's default seccomp profile forbids the namespace sandbox.** Measured on
  the runners: not AppArmor, not `no-new-privileges`. `seccomp/` and
  `tools/seccomp-profile.mjs` derive the smallest profile that permits it, and a
  test asserts the delta from Docker's default is exactly two documented edits.
- **Watson drives Chromium proper, not Playwright's default headless shell.** The
  headless shell does not answer `chrome://sandbox` at all, and a sandbox this
  design cannot prove is not one it gets to claim.

CI runs the proof on every change. If an image or runner cannot give us a
sandboxed non-root browser, the right outcome is a red build and a conversation,
not a quietly weakened threat model.

### Within one process, when that is what you have

Where a container boundary is not available, the same protection is approximated
by uid separation: `WATSON_PRODUCT_UID` / `_GID` / `_HOME` run every
product-authored command as an unprivileged user via `setpriv` — invoked with an
argv array, so the product's command string is never interpolated into another
shell. Requested-but-unavailable **refuses**; it never falls back to running
product code with the verifier's own privileges, because a security property
believed to hold and silently absent is worse than one never claimed.

This is weaker than two planes and is not what CI uses: it shares a process tree
with the browser.

### Environment scrubbing

A named set of variables is removed before the product's environment is handed
over: CI bearer tokens (`ACTIONS_RUNTIME_TOKEN`, `GITHUB_TOKEN`, …) and, just as
important, the runner's *command channels* — `GITHUB_ENV`, `GITHUB_PATH`,
`GITHUB_OUTPUT`, `GITHUB_STATE`. Those name files the runner reads back after a
step, so anything able to append to them can inject environment variables and
PATH entries into the trusted side that follows. Across a plane boundary the
verifier's environment is not sent at all.

### Product identity comes from a trusted manifest, not from git

Three adversarial reviews found four ways past a git-based identity gate, and
every one had the same shape: the gate asked a directory the product writes,
whose `.git` the product owns, to describe itself.

| attack | what it defeated |
| --- | --- |
| `git update-index --assume-unchanged` | `git status` |
| `git replace` | the commit tree `ls-tree` resolves |
| `git add` on a new file | the untracked listing |
| corrupt `.git/index` | both listings at once |
| self-hiding `.gitignore` | every generation |

Patching each answer never changed who was answering. So the authority moved:

```text
trusted orchestration          materialises the commit
        ↓                      BEFORE any product code runs
watson manifest                walks it, records path + type + digest + exec bit
        ↓                      the product never sees this tree
product plane                  builds and runs — needs no .git at all
        ↓
verifier                       compares the product tree against the manifest
```

**No manifest, no product claim.** A run that was not given one withholds every
product claim rather than falling back to asking git — the fallback *was* the
vulnerability.

It also catches what git was never asked about: a missing file, a symlink to
identical bytes, the executable bit, a directory where a file belongs. Generated
output under a declared root is **counted and reported**, never used to make an
unexpected file invisible, and never able to shelter a change to a committed file.

### What that proves, and what it does not

> At the verifier's measurement point, the materialised committed product source
> matched the trusted manifest for product HEAD X.

Not: *the bytes loaded into the running process are nothing but the committed
bytes.* Build output is outside the manifest by construction, the source is
measured at two instants rather than continuously, and nothing yet binds the
artefact actually launched to the commit. Closing that means a trusted build
producing an artefact or image digest and launching exactly that. It is tracked,
not claimed.

### Known limitations, and where they must be closed

Recorded here rather than in a comment nobody reads, because the difference
between shadow mode and a required check is exactly this list.

| | Limitation | Phase 1 (advisory) | Before Watson is a required check |
| --- | --- | --- | --- |
| **C3** | The product's `DATABASE_URL` carries the same Postgres role as the admin URL, so it is not least-privilege. Bounded today by the deployment — a per-run Postgres destroyed with the run — which is a property of the orchestration, not of this code | documented | explicit final disposition |
| **C4** | Identity binds committed *source* at two instants, not the running artefact | documented | closed, or an owner-accepted equivalent runtime binding |

Neither is called fixed. Phase-1 maturity counters do not retire them; they are
separate requirements.

### The controls

`test/manifest.test.mjs` runs the full adversarial corpus — every attack that
defeated a previous generation of the gate — against the architecture that
replaced it. `test/operands.test.mjs` covers who may choose an assertion's
operand. `test/isolation.test.mjs` and `test/plane.test.mjs` cover the rest.

Where a control needs real privilege separation and cannot have it (no root), it
asserts the fail-closed contract instead and says so **in its own name** — it
never silently skips, because a green tick on a security test that did nothing is
read as proof.

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
