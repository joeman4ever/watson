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
watson verify --repo /path/to/product [--sha <ref>] [--base <ref>] [--profile poc] [--pr 123] [--out <file>]
             [--plane <url> --product-base-url <url>]   # run the product in its own plane
             [--manifest <file>]                        # trusted product identity
             [--base-contract <dir>]                    # the contract that GOVERNS the verdict
watson manifest --repo /path/to/product [--out <file>]  # TRUSTED side, before product code runs
watson doctor --repo /path/to/product     # bring up, probe, tear down
watson plane  --repo /path/to/product     # the UNTRUSTED side, inside the product container
watson reap                               # drop orphaned watson_* databases
```

### Two things the trusted side must supply

Both have the same shape, and it is the shape that matters: **exactly one
authority, handed in by the trusted plane, with no fallback to asking the
product.** In both cases the fallback *was* the vulnerability.

| flag | supplies | without it |
| --- | --- | --- |
| `--manifest` | what the product source IS | product identity cannot be established |
| `--base-contract` | what PASS MEANS | no contract governed the run |

Either missing withholds the product claim: the run executes, reports everything
it observed, and returns `INDETERMINATE` rather than `PASS` or `FAIL_PRODUCT`.
A verdict about a commit needs both that the commit is what was driven and that
the thing being judged did not choose the semantics used to judge it.

`--base-contract` names a directory the trusted side materialised from the base
revision — not a path inside the product tree, and never `git archive` out of the
product's own `.git` (ADR-049 F3). The head's contract is still loaded,
fingerprinted, diffed and reported; it is a proposal, not the authority for its
own verdict.

Exit code is `0` for `PASS` / `PASS_WITH_ADVISORIES`, `1` otherwise. Every run
writes `runs/<runId>/result.json` (machine) and `runs/<runId>/summary.md`
(human, with a `WATSON_METADATA` marker).

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
run identity, and passes them **into** the fixture:

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
flag appears nowhere in `src/`, and a test greps for it. Those parts hold.

> **THE SANDBOX WAS NOT ENGAGED FOR THE WHOLE LIFE OF THIS PROJECT, AND THIS
> SECTION USED TO SAY IT WAS.** The cause is found and fixed; the real-topology
> proof is what settles it, and until that job is green this repository does not
> claim a sandboxed browser.

#### What was claimed, what was true, and why

`probeSandbox` decided the layer-1 question with
`/adequately sandboxed/i.test(text)`. Chromium's negative verdict — *"You are
**NOT** adequately sandboxed."* — contains the positive one as a substring, so
the field was `true` for both answers and **could never be false**. Three gates
read it (the `BLOCKED_ENVIRONMENT` gate, the trusted validator, and this repo's
own per-commit proof); none could fire.

With the predicate corrected, the proof job ran for the first time as a real
assertion, and reported:

```text
chromium proper (channel: chromium): 2 renderer(s), seccomp=2 on 2,
namespace-isolated 0, chrome://sandbox NOT effective

Sandbox Status
Layer 1 Sandbox                      None
Seccomp-BPF sandbox                  No
You are NOT adequately sandboxed.
```

**The cause was not the container.** It was one option Watson never passed.
playwright-core, at the version this repository pins, contains:

```js
if (options.chromiumSandbox !== true) chromeArguments.push('--no-sandbox');
```

Playwright's default is `chromiumSandbox: false`, so **the library added the flag
Watson was careful never to write**. Measured as an unprivileged user, one
variable changed and nothing else — no container option, no seccomp edit, no
privilege added:

| `chromium.launch(…)` | Layer 1 | renderer argv |
| --- | --- | --- |
| `{}` — what the engine did | `None`, *NOT adequately sandboxed* | every renderer carries `--no-sandbox` |
| `{ chromiumSandbox: true }` | `Namespace`, PID + net namespaces, seccomp-bpf, *adequately sandboxed* | none does |

Two checks stood between this and being noticed, and both were vacuous. The
first is the substring bug above. The second is worse, because it was the one
aimed straight at the cause: the proof printed *"Chromium started with no
`--no-sandbox` flag"* on the strength of a browser having started at all — it
never read a command line. Beside it, a unit test grepped `src/` for the string
and passed, truthfully, while every renderer carried the flag. **The absence of a
string in our source is not a property of the process we start**, and both checks
now read the argv of the processes actually launched.

Two measurements that were being conflated:

| measured | says |
| --- | --- |
| `/proc/<renderer>/status` → `Seccomp: 2` | a seccomp filter is attached |
| `chrome://sandbox` → `Seccomp-BPF sandbox: No` | **Chromium's own** sandbox is not engaged |

Both are true. The attached filter is the one **Docker applies to the whole
container**, not Chromium's per-renderer sandbox. Counting the first as evidence
of the second is what made this section wrong.

| | state |
| --- | --- |
| browser runs as a non-root uid | **true, measured** |
| `--no-sandbox` absent | **true, measured** |
| container-level seccomp filter attached | **true, measured** |
| Chromium layer-1 / namespace sandbox | **NOT engaged** |
| Chromium seccomp-BPF sandbox | **NOT engaged** |

#### Where this stands

The browser sandbox is part of the frozen Phase-1 trust claim, not a deferred
promotion gate: the browser consumes product-controlled content inside the
verifier plane, so an unsandboxed browser bears directly on *the untrusted pull
request cannot alter the verifier or fabricate its evidence*.

So the corrected probe stays and the gate stays — and it is now **stronger** than
it was. It used to fire only on `effective === false`, which let a browser build
that will not render `chrome://sandbox` through to a product verdict with no
layer-1 evidence at all. "An unprovable sandbox is not one this design gets to
claim" was written here and not implemented; the gate now demands
`effective === true`, and the trusted validator does the same.

`seccomp/` and `tools/seccomp-profile.mjs` still derive a profile from Docker's
default with an asserted two-edit delta, and that machinery is deliberately
**unchanged**. It was not the cause, and one variable was changed at a time. What
is now unsupported is the *reason* it was adopted: the earlier claim that Docker's
default profile was the thing forbidding Chromium's namespace sandbox rested on
the same vacuous measurement. Whether it is necessary is a separate question, to
be answered by measurement rather than by removing it and seeing.

**What is established, and where.** The fix was measured as an unprivileged user
against Chromium 131, going from *NOT adequately sandboxed* to *adequately
sandboxed* with `chromiumSandbox` as the only variable — but that was not the
verifier's container, and a sandbox proven somewhere else is not a sandbox. The
CI job in `.github/workflows/ci.yml` runs the same proof in the pinned image
under the observer's own container options, and it is the only thing that settles
this. Until it is green, this repository does not claim a sandboxed browser.

#### What the proof does establish

`test/browser-sandbox-proof.mjs` launches the real browser as an unprivileged
user in the pinned container image and measures, independently:

| layer | how it is established |
| --- | --- |
| non-root | the verifier's uid |
| no `--no-sandbox` | the **argv of every renderer it started**, read from `/proc/<pid>/cmdline` — not a grep of our source, which is what made this check vacuous |
| seccomp filter attached | `Seccomp: 2` and `NoNewPrivs: 1` in the renderer's `/proc/<pid>/status` — **supporting telemetry, not proof of Chromium's own sandbox** |
| Chromium's own sandbox | `chrome://sandbox` reporting *adequately sandboxed* — **authoritative** |

Chromium's self-report is authoritative because Chromium knows which mechanism
it chose and whether it came up. An earlier version of this proof demanded a
separate *user* namespace and reported the sandbox missing on a browser Chromium
called adequately sandboxed; the lesson taken from that was to trust the
self-report, which was right — the error was reading a field derived from it
with a predicate that could not express "no".

**Watson drives Chromium proper, not Playwright's default headless shell.** On
the build measured when this was decided, the headless shell did not answer
`chrome://sandbox` at all, and a sandbox this design cannot prove is not one it
gets to claim. (A later build was observed to answer it. The channel stays
explicit regardless: the point is that the engine drives a build whose sandbox it
can read, not that one particular build is mute.)

The proof reads `/proc/<pid>/cmdline` **tokenised on NUL *and* whitespace**.
Chromium rewrites its own process title, so a renderer's whole command line
arrives as a single element; splitting on NUL alone produced one token that
matched nothing, and the flag check reported "clean" on a browser demonstrably
started with `--no-sandbox`. That was caught by running the negative control, not
by reading the code.

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

### The controls

`test/isolation.test.mjs` covers the execution boundary: privilege separation,
credential scrubbing, evidence protection, and that a hostile repository cannot
execute code through the verifier's own git. `test/plane.test.mjs` covers the
plane protocol and the dependency-free rule. `test/boundary.test.mjs` covers the
result marker and that the CLI itself starts. `test/seccomp.test.mjs` and
`test/browser-sandbox-proof.mjs` cover the browser sandbox.

Where a control needs real privilege separation and cannot have it (no root), it
asserts the fail-closed contract instead and says so **in its own name** — it
never silently skips, because a green tick on a security test that did nothing is
read as proof.

### What is still open

Product identity and contract authority were open when the execution-isolation
slice merged; the verification-policy slice replaced both, under `nsc-eval`
ADR-049 — a trusted content manifest, base-branch contract authority, and
verifier-chosen assertion operands.

What that does **not** close, stated because a verifier silent about its blind
spots invites people to assume it has none:

- **The base contract governs the semantics, not the code that builds the world.**
  `server/scripts/watson-fixture.ts` is head-authored and is told every value the
  verifier chose. A product that denies exactly those values and allows every
  other one satisfies every base-governed assertion. That is ADR-049 F1: the
  trusted proofs narrow it — the entity a denial is asserted against must be shown
  to exist in the engine's own database — and they do not close it.
- **Operational config keys are head-supplied.** `install`, `provision`, `build`,
  `launch.command` and `env` must match the head's own tree or nothing runs at
  all. They are fingerprinted and reported rather than base-governed, and the
  keys that would reach the verifier's own side are refused outright.
- **D1 buys "not in the same commit", not "cannot happen".** The sanctioned
  two-step workflow — merge the contract change, then verify the product change
  under it — is the same attack spread across two pull requests, resting on human
  review of a `.watson/` diff. That is a real increase in cost, and it is the
  accurate statement of what is closed (ADR-049 F12).

## Deliberately not built yet

GitHub App · required checks · nightly scheduling · always-on runner ·
map-maintenance automation · web UI · native/mobile automation · fingerprint
carry-forward · diff-driven impact selection · dual-contract evaluation.

Each is earned by Phase-0/1 evidence rather than assumed up front.

## Layout

```text
src/
  cli.mjs          verify | manifest | doctor | plane | reap
  governance.mjs   which contract governs the verdict (base, never head)
  proofs.mjs       trusted precondition evidence, read from the run's own database
  plane.mjs        the untrusted side's server — executes, never decides
  exec.mjs         command execution, uid drop, environment scrubbing
  contract.mjs     .watson loader + validation + profile selection
  fingerprint.mjs  exact-HEAD identity, contract semantic diff
  environment.mjs  provision, identity service, launch, doctor, teardown
  driver.mjs       browser, step vocabulary, evidence capture
  checks.mjs       scoped runtime invariants, drift-vs-regression triage
  result.mjs       envelope, verdict/obligation mapping, marker, summary
schemas/           result + feature JSON Schemas
seccomp/           Docker's default profile, vendored, and what we derive from it
tools/             seccomp-profile.mjs — the derived profile, with an asserted delta
skills/            agent-facing instructions
```
