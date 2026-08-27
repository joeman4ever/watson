---
name: watson-verify
description: Run Watson against a product checkout and interpret the result. Use when asked to verify that a running application actually behaves correctly on an exact commit.
---

# Verify a running application with Watson

Watson answers one question: *does the running application behave correctly on
this exact SHA?* It does not review code — that is Sherlock's job — and it never
modifies the product.

## Run it

```bash
watson verify --repo <product-checkout> --sha <ref> --profile poc
```

Read `runs/<runId>/summary.md` for the human view and `result.json` for the
machine view.

## Interpret the verdict — read BOTH axes

`verdict` is what Watson learned. `check.obligation` is whether the verification
obligation was met. They are different questions and must not be collapsed.

- **`FAIL_PRODUCT`** — the application misbehaved. Read the failing step's
  `observed`, then the screenshot and ARIA snapshot. Report it; do not fix the
  contract to make it pass.
- **`FAIL_CONTRACT`** — the map named a handle or route that no longer exists.
  This is Watson's defect, not the product's. Either the product legitimately
  changed (fix the map, in its own PR) or it regressed (report it). Deciding
  which is the judgment call; make it explicitly rather than by default.
- **`BLOCKED_ENVIRONMENT`** — the environment was not worth driving. Read the
  doctor probes. Never report this as a product failure.
- **`INDETERMINATE`** — failed once, passed on a clean retry, uncorroborated.
  Record it. "Flake" is a symptom, never a root cause.

## Rules

- Never edit product code to make a verification pass.
- Never weaken a feature's expectations to clear a red. If an expectation is
  genuinely wrong, change it in its own PR and say what changed sign.
- A `304` is an authorized response. Only `401`/`403` mean unauthenticated.
- Absence of a link is not proof of denial — assert against the server's
  response, not against what the navigation chose to render.
