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
const SECURITY_RULES = new Set(['unauthorized-route-200', 'unexpected-5xx', 'wrong-season-context']);

function severityOf(rule, invariants) {
  const declared = invariants.find((i) => i.rule === rule);
  if (SECURITY_RULES.has(rule)) return 'blocking';
  return declared?.severity ?? 'advisory';
}

function isEnabled(rule, invariants, featureId) {
  const declared = invariants.find((i) => i.rule === rule);
  if (!declared) return SECURITY_RULES.has(rule);
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
  const errs = [...evidence.pageErrors, ...evidence.console.filter((c) => c.type === 'error')];
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
 * Steps that ADDRESS a named handle. If one of these cannot find its target,
 * the most likely explanation is that the MAP names something that no longer
 * exists — contract drift, which is Watson's own defect and must not be
 * reported as a broken product.
 *
 * Steps that ASSERT observable behavior (expect_text, expect_api, ...) are the
 * opposite: when they fail, the app did something the contract says it should
 * not, and that is a product failure.
 */
const ADDRESSING_STEPS = new Set(['click', 'fill', 'select', 'wait_for_text', 'expect_count_at_most']);

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
