# ADR-001 — C4: what a green Watson result does and does not prove about the bytes that ran

**Status:** accepted
**Date:** 2026-09-30
**Scope:** the Watson engine. This is an engine limitation, not a consuming
product's decision, which is why it is recorded here rather than in `nsc-eval`.

---

## Context

`src/manifest.mjs` states the claim precisely:

> the materialised committed product source matched the trusted manifest for
> product HEAD X

That is a claim about **committed source**. It is not a claim about the bytes
loaded into the running process. `src/result.mjs` names the consequence and
does not soften it:

> C4 is required to be closed or consciously accepted before Watson becomes a
> required merge check.

Watson is currently a shadow verifier that gates nothing (ADR-039 D6). The
question becomes load-bearing only when it is proposed as a required merge
check, which is now being prepared. This ADR is the conscious acceptance that
precondition demands, and it records exactly how much of the gap was closed
rather than claiming the whole of it.

## The gap, enumerated

| # | Unmeasured by the manifest | Occurs |
| --- | --- | --- |
| **g1** | Generated build output — the bundle actually served is built from source, not measured | every run |
| **g2** | Dependencies — `node_modules` bytes are not in the manifest | every run |
| **g3** | Runtime mutation — code changed after the manifest and before or during execution | rare |
| **g4** | TOCTOU — the window between manifest computation and process start | rare |
| **g5** | Interpreter and container drift — Node, system libraries, base image | silently, always |

## What was investigated

Against `nsc-eval`, the only product Watson currently verifies, **g1
decomposes** — and the two halves are not alike:

| Bytes executed | How | Covered by the manifest? |
| --- | --- | --- |
| Server | `.watson/config.yaml` `launch.command` is `npm run start --workspace=server`, whose `start` script is `tsx src/index.ts` | **YES** — TypeScript source is executed directly. There is no server build artifact, and `server/dist` is never produced by `build` nor read by `start`. |
| Client | `build` runs `npm run build --workspace=client` (`vite build`) into `client/dist`, which `server/src/app.ts` serves via `express.static` | **NO** — this is g1 |

So for this product, g1 is **one directory**, not a general unmeasured mass:
the client bundle. That is a far smaller gap than "the manifest measures source,
not bytes" implies on its face, and it is worth stating because the honest size
of a risk governs what it is reasonable to accept.

## Decision

**C-then-B.** Narrow g1 where it can be narrowed with evidence, then accept the
residue explicitly.

### C — narrow g1, with an execution binding rather than an assertion

Hashing a build directory does **not** by itself close g1. A digest over an
unused directory proves nothing about what was served, and a control that
looks like evidence without being evidence is worse than a stated gap.

The engine therefore does three things, and the third is the one that matters:

1. **Digest the declared build artifact** after `build` and before
   `launch`, so the digest describes the state the application starts from.
2. **Re-digest after the run.** A difference means the served bytes changed
   while the run was executing — the build-output analogue of
   `changed_mid_run`, and a partial control on g3.
3. **Prove the digested directory is the served one.** The engine fetches a
   declared asset over HTTP from the running application and compares the
   received bytes against the corresponding file inside the digested
   directory. A match binds *what was measured* to *what was served*, through
   the product's real serving path, rather than trusting the contract's
   declaration of which directory that is.

Step 3 is what distinguishes this from hashing a directory and hoping. Without
it, the control rests on a human having correctly declared the served path; with
it, the running application demonstrates the binding itself.

**g1 is recorded as closed only for artifacts where step 3 succeeds.** Where the
binding cannot be demonstrated — no declared probe asset, a fetch failure, a
mismatch — the result records g1 as **open** for that artifact. The engine does
not report a control it did not exercise.

### B — accept g2 through g5, explicitly

They are accepted, not closed, and not silently.

> **A green Watson result does not prove that the interpreter, the
> dependencies, the container image, or runtime memory were immutable, or
> identical to committed source.**

It proves that the committed source materialised for the reported commit
matched the trusted manifest, that the declared build artifacts matched their
recorded digests before launch and after the run, and — where the binding was
demonstrated — that the bytes served came from those artifacts.

Closing g2–g5 properly means hashing and pinning every dependency, pinning the
base image by digest, and instrumenting the module loader. That is a larger
engineering programme than the merge gate it would support, and deferring it is
a deliberate trade made with the residual risk written down rather than
forgotten.

## Why this is acceptable *now*, and what would change that

The acceptance rests on the execution environment, not on the risk being
negligible in general:

- Runs execute in ephemeral CI containers built from a known image.
- The product verified is **first-party**, from a repository whose changes go
  through review.
- Dependencies are installed from a committed lockfile before the run and are
  not modified during it.
- Watson holds no GitHub write credential and gates nothing today.

**Reconsider this ADR if any of the following becomes true:**

1. Watson evaluates **untrusted or third-party repositories**. g2 becomes an
   execution path for arbitrary code chosen by the thing being verified.
2. The **execution environment becomes less controlled** — shared runners,
   long-lived hosts, or an unpinned base image.
3. **Dependencies can mutate during a run** — postinstall behaviour, network
   fetches at runtime, or hot-reloaded modules.
4. Watson is proposed as an **autonomous approval mechanism** rather than a
   blocking check with a human approver. A blocked merge with a wrong cause
   costs a cycle; an autonomous approval with a wrong cause costs the property
   the whole system exists to protect.

Any of those changes the risk calculus enough that this acceptance should not
be assumed to carry over.

## Consequences

- The merge-readiness gate may treat a green Watson axis as evidence about
  **committed source and served build artifacts**, and must not describe it as
  evidence that the executed bytes were the committed bytes.
- Documentation that summarises a green Watson result must carry the limitation
  above rather than paraphrasing it away.
- `result.json` records the build-artifact digests and whether the served
  binding was demonstrated, so a reader can tell which of g1's halves was
  actually controlled on any given run.

## Status of the control as of this ADR

**g1 is OPEN.** This ADR records the decision and the design; the digest and
the served-bytes probe are not yet implemented in the engine. It will be
amended to record g1 as narrowed only when the control exists and has been
exercised on a real run — not when it is merely specified.

Stating this rather than writing the ADR as though the work were done is the
point of the fourth requirement in the decision that commissioned it: if exact
execution binding cannot be demonstrated, say g1 remains open rather than
overstating the control.
