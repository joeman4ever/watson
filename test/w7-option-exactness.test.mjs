// W7 — a forbidden value that is a PREFIX of a legitimate one.
//
// `expect_no_text` asks whether a string appears anywhere in the page's text, by raw
// substring containment. On nsc-eval #547 and #554 the journey `withdrawn-access-is-gone`
// asserted `expect_no_text: "Grade ${revokedGrade}"` with revokedGrade = 1, against a
// picker legitimately offering "… — Grade 10". "Grade 1" is a prefix of "Grade 10", the
// assertion failed, and Watson reported FAIL_PRODUCT against a correct product — twice,
// on a fixture draw, with the trusted doctor having already proven the revoked grant
// denied with 403.
//
// These are the controls for the replacement. They are deliberately over a PURE function
// rather than a driven browser: the defect was in the matching predicate, and a predicate
// is testable without Playwright, a database or a product. The browser-level behaviour
// (enumerating options, the empty-list guard) is exercised by the journey itself in CI.

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { offeredOptionExactly } from '../src/driver.mjs';

const season = 'watson-primarySeasonName-f4a1eb2384477294';
const label = (grade) => `${season} — Grade ${grade}`;

describe('W7: a forbidden label that prefixes an allowed one', () => {
  test('forbidden Grade 1, allowed Grade 10 — the exact case that produced two false FAIL_PRODUCT', () => {
    // Verbatim from the #547 aria snapshot at the failing step: the picker offered
    // Grade 10 and Grade K, and no Grade 1. The product was right.
    const offered = [label(10), label('K')];
    assert.equal(offeredOptionExactly(offered, label(1)), null,
      'Grade 1 is not offered; "Grade 10" must not satisfy the match');
  });

  test('forbidden Grade 1, allowed Grade 11 and Grade 12', () => {
    const offered = [label(11), label(12)];
    assert.equal(offeredOptionExactly(offered, label(1)), null);
  });

  test('forbidden Grade 1, allowed Grade 6 — the #554 draw', () => {
    const offered = [label(10), label(6)];
    assert.equal(offeredOptionExactly(offered, label(1)), null);
  });

  test('the forbidden option genuinely offered — this MUST match', () => {
    // The assertion still has to work. A fix that never matches would close the false
    // FAIL by making the journey prove nothing, which is the failure mode worth more
    // than the one being fixed.
    const offered = [label(10), label(1), label('K')];
    assert.equal(offeredOptionExactly(offered, label(1)), label(1));
  });

  test('forbidden absent while a prefix-related option is present — must not match', () => {
    const offered = [label(10), label(11), label(12), label(100)];
    assert.equal(offeredOptionExactly(offered, label(1)), null);
  });

  test('the reverse direction: forbidden Grade 10, only Grade 1 offered', () => {
    // Substring containment in the other direction. "Grade 10" is not inside "Grade 1",
    // so this direction never produced a false FAIL — but exactness must hold both ways
    // or the predicate is only accidentally correct.
    assert.equal(offeredOptionExactly([label(1)], label(10)), null);
  });
});

describe('W7: exactness is exactness', () => {
  test('surrounding whitespace is not significance', () => {
    assert.equal(offeredOptionExactly([`  ${label(1)}  `], label(1)), label(1));
  });

  test('an interior difference is a difference', () => {
    assert.equal(offeredOptionExactly([label(1)], `${season}  — Grade 1`), null);
  });

  test('a different season with the same grade is a different option', () => {
    // The season name is part of the identity. Two seasons can both offer Grade 1, and
    // revoking one must not appear to revoke the other.
    const other = 'watson-primarySeasonName-02e19f82b24d6b16';
    assert.equal(offeredOptionExactly([`${other} — Grade 1`], label(1)), null);
  });

  test('an empty offer list matches nothing', () => {
    // The step treats this as a failure rather than a pass; the predicate simply
    // reports no match, and the caller decides. Pinned so the two stay separable.
    assert.equal(offeredOptionExactly([], label(1)), null);
  });

  test('null and undefined entries do not throw and do not match', () => {
    assert.equal(offeredOptionExactly([null, undefined, label(10)], label(1)), null);
  });

  test('a null forbidden value matches only an empty label', () => {
    assert.equal(offeredOptionExactly([label(1)], null), null);
    assert.equal(offeredOptionExactly(['   '], null), '');
  });
});

describe('W7: the defect, stated as a test', () => {
  test('raw substring containment would have failed these — exact matching does not', () => {
    // The old predicate, reproduced, so the difference is visible rather than asserted.
    const old = (texts, forbidden) => texts.some((t) => String(t).includes(forbidden));
    const offered = [label(10), label('K')];

    assert.equal(old(offered, 'Grade 1'), true,
      'the old page-text predicate matches "Grade 1" inside "Grade 10" — this is W7');
    assert.equal(offeredOptionExactly(offered, label(1)), null,
      'the replacement does not');
  });
});
