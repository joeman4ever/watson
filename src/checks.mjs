// Machine-checkable runtime rules.
//
// These are DETECTORS, not universal defects. A global heuristic applied
// globally generates false findings, and false findings are how a verifier
// loses its audience. So every rule is scoped by the product's own
// `.watson/invariants.yaml`, which declares where it applies, its known
// legitimate exceptions, and whether a violation is blocking or advisory.
//
// Default is ADVISORY during shadow mode. The exception is deliberate: rules
// that encode an explicit security or correctness guarantee are blocking from
// the start. An unauthorized 200, an unexpected 5xx, or the wrong season's data
// on screen are not style opinions that need a calibration period.

import { isAuthorized } from './driver.mjs';

const UUID_RE = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i;

/** Rules that are blocking regardless of shadow mode. */
export const SECURITY_RULES = new Set(['unauthorized-route-200', 'unexpected-5xx', 'wrong-season-context']);

function severityOf(rule, invariants) {
  const declared = invariants.find((i) => i.rule === rule);
  if (SECURITY_RULES.has(rule)) return 'blocking';
  return declared?.severity ?? 'advisory';
}

function isEnabled(rule, invariants, featureId) {
  const declared = invariants.find((i) => i.rule === rule);
  if (!declared) return SECURITY_RULES.has(rule);
  // A SECURITY RULE CANNOT BE SWITCHED OFF BY A CONTRACT, only by editing this
  // set — which is a change to the engine, reviewed as one.
  //
  // `severityOf` already forces these to `blocking` whatever the contract says,
  // so the intent was there; enablement was not, and enablement is what decides
  // whether the finding exists at all. Measured before the fix, on evidence
  // containing a real 500:
  //
  //     undeclared                    -> unexpected-5xx:blocking
  //     severity: off                 -> NO FINDING
  //     except_features: [thisOne]    -> NO FINDING
  //     applies_to_features: [other]  -> NO FINDING
  //
  // Three ways to silence a rule whose severity could not be lowered. Not a
  // pull-request-exploitable hole — `invariants` come from the BASE contract —
  // but `.watson/invariants.yaml` states that these cannot be switched off, and
  // a claim in a shipped file is either true or it is a defect.
  if (SECURITY_RULES.has(rule)) return true;
  if (declared.severity === 'off') return false;
  const only = declared.applies_to_features;
  if (Array.isArray(only) && only.length && !only.includes(featureId)) return false;
  const except = declared.except_features;
  if (Array.isArray(except) && except.includes(featureId)) return false;
  return true;
}

/**
 * Evaluate the rule set against one feature's collected evidence.
 * Returns findings; the caller decides how they roll into a verdict.
 */
/** Statuses that count as an authorization denial for correlation purposes. */
export const DENIAL_STATUSES = Object.freeze([401, 403]);

/** Chromium's resource-load failure message, with the status it reports. */
const RESOURCE_LOAD_FAILURE = /^Failed to load resource: the server responded with a status of (\d{3})/;

/**
 * Separate console errors that are artifacts of a denial the journey explicitly
 * declared from console errors that are evidence about the product.
 *
 * A journey that proves an authorization boundary makes the product's own in-page
 * fetches get denied on purpose, and Chromium logs each one. Those messages are
 * caused by Watson proving the boundary; treating them as product findings makes
 * every authorization journey permanently advisory, which teaches people to
 * ignore the rule everywhere else.
 *
 * Neutralisation requires FOUR independent positive facts, never timing:
 *
 *   1. the message is a resource-load failure, not arbitrary product output
 *   2. the status IN THAT MESSAGE is 401/403 — read from the very event being
 *      neutralised, so a 500 on a declared path stays a finding
 *   3. Chromium attributed the message to a resource URL
 *   4. that exact path was declared by an `expect_denied` step in this journey
 *
 * Anything short of all four stays a finding. The asymmetry is deliberate and
 * one-directional: uncertain correlation preserves evidence, only a confident
 * exact match removes it.
 */
export function classifyConsoleErrors(consoleEntries = [], expectedDenials = []) {
  const declared = new Set(expectedDenials.map((d) => d.path));
  const product = [];
  const expected = [];

  for (const entry of consoleEntries) {
    if (entry.type !== 'error') continue;
    const m = RESOURCE_LOAD_FAILURE.exec(entry.text ?? '');
    const status = m ? Number(m[1]) : null;
    if (
      status !== null
      && DENIAL_STATUSES.includes(status)
      && entry.resourcePath
      && declared.has(entry.resourcePath)
    ) {
      expected.push({ ...entry, status, classification: 'expected_denial_console' });
    } else {
      product.push(entry);
    }
  }
  return { product, expected };
}

export function evaluate({ featureId, evidence, invariants, pageText }) {
  const findings = [];
  const emit = (rule, summary, requiredAction, detail) => {
    if (!isEnabled(rule, invariants, featureId)) return;
    findings.push({
      rule,
      severity: severityOf(rule, invariants),
      feature: featureId,
      summary,
      required_action: requiredAction,
      detail,
      source: 'scripted',
    });
  };

  // --- security / correctness guarantees (blocking) ---------------------------
  const fivexx = evidence.requests.filter((r) => r.status >= 500);
  if (fivexx.length) {
    emit('unexpected-5xx',
      `${fivexx.length} server error response(s) during this journey.`,
      'Root-cause the 5xx; a server error is never an acceptable outcome of a mapped journey.',
      fivexx.slice(0, 5));
  }

  // --- non-security detectors (advisory unless the product says otherwise) -----
  // A page error is never neutralised: an uncaught exception is the product's
  // own failure, not an artifact of a denial Watson asked for.
  const { product: productConsole, expected: expectedConsole } =
    classifyConsoleErrors(evidence.console, evidence.expectedDenials);
  // Retained, not discarded. Watson observed these; they are simply not evidence
  // of a product defect. Keeping them auditable is what separates "correlated and
  // explained" from "quietly dropped".
  evidence.expectedDenialConsole = expectedConsole;
  const errs = [...evidence.pageErrors, ...productConsole];
  if (errs.length) {
    emit('console-errors',
      `${errs.length} uncaught console error(s)/page error(s).`,
      'Fix the error, or explain why it is expected for this journey.',
      errs.slice(0, 5));
  }

  const failed = evidence.failed.filter((f) => !String(f.url).startsWith('data:'));
  if (failed.length) {
    emit('failed-requests',
      `${failed.length} request(s) failed at the network layer.`,
      'Investigate the failed fetch; a broken request usually means a broken feature.',
      failed.slice(0, 5));
  }

  const unauthorized = evidence.requests.filter((r) => !isAuthorized(r.status) && ![401, 403, 404].includes(r.status));
  if (unauthorized.length) {
    emit('unexpected-4xx',
      `${unauthorized.length} unexpected client-error response(s).`,
      'Check the request the screen made; an unexpected 4xx is usually a contract mismatch.',
      unauthorized.slice(0, 5));
  }

  if (pageText && UUID_RE.test(pageText)) {
    emit('raw-uuid-visible',
      'A raw UUID is visible in the rendered page text.',
      'Resolve the id to a human-readable label, or scope this rule if this surface is a deliberate technical view.',
      { match: pageText.match(UUID_RE)[0] });
  }

  return findings;
}

/**
 * Steps that ADDRESS a named handle: they pick an element out of the DOM in order
 * to ACT on it. If one cannot find its target, the likeliest explanation is that
 * the MAP names something that no longer exists — contract drift, which is
 * Watson's own defect and must not be reported as a broken product.
 *
 * Everything else ASSERTS observable behavior. When one of those fails the
 * application did something the contract says it should not, and that is a
 * product failure.
 *
 * `wait_for_text` and `expect_count_at_most` used to be in this set and are
 * deliberately not any more. A negative control found the cost: with small-cohort
 * suppression disabled — a privacy regression — the prospective journey's
 * `wait_for_text: "too small to report"` failed and was reported as FAIL_CONTRACT,
 * i.e. "Watson's map is wrong". A real disclosure defect, filed as the verifier's
 * own paperwork problem, is exactly how a finding gets dismissed.
 *
 * Neither belongs here on its own terms either. `wait_for_text` asserts what the
 * application eventually SAYS; it addresses nothing. `expect_count_at_most` cannot
 * even fail on a missing handle — a selector that matches nothing counts zero,
 * which satisfies any maximum. It fails only when there is MORE than expected,
 * which is always behavioral.
 *
 * The tradeoff is real and accepted: text the product legitimately renames now
 * reads as FAIL_PRODUCT rather than drift. That direction is recoverable — a human
 * reads the diff and fixes the map. The other direction hides privacy regressions.
 */
const ADDRESSING_STEPS = new Set(['click', 'fill', 'select']);

/** Playwright's shape for "I could not find/act on that element". */
function isTargetMiss(message = '') {
  return /Timeout .* exceeded|waiting for locator|strict mode violation|no element|not visible|element is not/i.test(message);
}

/**
 * Classify a step failure. Watson cannot always distinguish drift from
 * regression — pstack names this exact triage problem — so the rule is
 * explicit and conservative rather than confident:
 *
 *   - a missing HANDLE, with no corroborating runtime signal   -> FAIL_CONTRACT
 *   - a missing ROUTE (expect_denied got 404)                  -> FAIL_CONTRACT
 *   - anything corroborated by a 5xx or console error          -> FAIL_PRODUCT
 *   - a failed behavioral assertion                            -> FAIL_PRODUCT
 *
 * FAIL_CONTRACT never blocks and opens a drift item; it says "Watson's map is
 * wrong", not "your product is broken".
 */
export function classifyFailure(stepFailure, findings) {
  const corroborated = findings.some((f) => ['unexpected-5xx', 'console-errors', 'failed-requests'].includes(f.rule));
  if (corroborated) {
    return { verdict: 'FAIL_PRODUCT', corroborated: true, reason: 'failure corroborated by a runtime signal' };
  }
  if (/expected .* to be denied \(401\/403\), got 404/.test(stepFailure.message)) {
    return { verdict: 'FAIL_CONTRACT', corroborated: false, reason: 'the route this step names does not exist' };
  }
  if (ADDRESSING_STEPS.has(stepFailure.action) && isTargetMiss(stepFailure.message)) {
    return { verdict: 'FAIL_CONTRACT', corroborated: false, reason: 'the handle this step names was not found' };
  }
  return { verdict: 'FAIL_PRODUCT', corroborated: false, reason: 'a behavioral assertion did not hold' };
}

/** Roll findings + step outcome into a per-feature verdict. */
export function featureVerdict({ stepFailure, findings }) {
  if (stepFailure) return classifyFailure(stepFailure, findings);
  if (findings.some((f) => f.severity === 'blocking')) {
    return { verdict: 'FAIL_PRODUCT', corroborated: true, reason: 'a blocking invariant was violated' };
  }
  if (findings.length) return { verdict: 'PASS_WITH_ADVISORIES', corroborated: false, reason: null };
  return { verdict: 'PASS', corroborated: false, reason: null };
}
