// The browser driver: one Chromium, one authenticated context per identity.
//
// LAYERING (proven in Phase-0 feasibility, not assumed from API shape):
//   - Playwright LIBRARY owns lifecycle, auth, scripted steps and evidence.
//     Console/network listeners are always-on here because they are complete
//     and cheap, and because DevTools MCP only observes from the moment it
//     attaches — the library layer is what covers the pre-attach window.
//   - Playwright MCP and Chrome DevTools MCP attach to this same browser over
//     CDP (--cdp-endpoint / --browser-url) for the agentic and forensic layers.
//     `--remote-debugging-port` is opened here so they can.
//
// Verified: `extraHTTPHeaders` set on a library-created context survives the
// attach, so an MCP-driven navigation still authenticates as the same identity.

import { chromium } from 'playwright';
import fs from 'node:fs';
import path from 'node:path';
import { degenerateOperand } from './contract.mjs';

const UUID_RE = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i;

/**
 * The browser is part of the verifier, and the pages it loads come from the
 * thing under verification.
 *
 * That single sentence decides this whole function. Under the threat model
 * Watson operates in, the product controls the HTML and JavaScript Chromium
 * executes, so an unsandboxed browser is a hole in the same boundary that
 * protects the evidence — not a separate, lesser concern about the browser.
 *
 * Chromium refuses to start as root with its sandbox enabled. The response is
 * NOT to pass `--no-sandbox`: it is to refuse to be root. Watson's product
 * execution lives in its own container with its own unprivileged user, so the
 * verifier never needs root to do its own job.
 *
 * `--no-sandbox` is deliberately absent from this file. If it is ever needed
 * again, it needs a decision record, not a flag.
 */
export function browserSandbox() {
  return !(typeof process.getuid === 'function' && process.getuid() === 0);
}

/**
 * Chromium proper, not the headless shell.
 *
 * Playwright's default headless mode runs `chromium_headless_shell`, a separate
 * binary. Measured on GitHub's runners, the two do not report the same sandbox
 * state: full Chromium answers `chrome://sandbox` with "adequately sandboxed"
 * and the headless shell does not answer at all. Watson cannot prove a property
 * of a build that will not report it, and an unprovable sandbox is not one this
 * design gets to claim — so it drives the build that reports.
 */
export const BROWSER_CHANNEL = 'chromium';

export async function launchBrowser({ executablePath, cdpPort, headless = true, channel = BROWSER_CHANNEL } = {}) {
  if (!browserSandbox()) {
    throw new Error(
      'refusing to launch the browser as root: Chromium cannot enable its sandbox as root, and the ' +
        'pages it loads are served by the product under verification. Run the verifier as an ' +
        'unprivileged user; product execution belongs in its own container, not in this process tree.',
    );
  }
  return chromium.launch({
    executablePath,
    headless,
    // Explicit, so a caller that needs to know WHICH build it measured can say
    // so — and so nothing silently falls back to the headless shell.
    ...(channel ? { channel } : {}),
    args: [
      `--remote-debugging-port=${cdpPort}`,
      '--remote-debugging-address=127.0.0.1',
      '--disable-extensions',
    ],
  });
}

/**
 * Ask Chromium what its own sandbox is doing, rather than inferring it from the
 * absence of a flag.
 *
 * `chrome://sandbox` is Chromium's own status page; on Linux it reports the
 * namespace and seccomp-bpf sandboxes and whether the layer-1 sandbox is
 * effective. Best-effort: a Chromium build or headless mode that will not render
 * it returns `available: false`, and the caller records that rather than
 * inventing a claim. What the caller must NOT do is treat "no flag" as proof.
 */
export async function probeSandbox(browser) {
  let ctx;
  try {
    ctx = await browser.newContext();
    const page = await ctx.newPage();
    await page.goto('chrome://sandbox', { timeout: 10_000 });
    const text = (await page.evaluate(() => document.body.innerText)).trim();
    return {
      available: true,
      // Chromium prints "You are adequately sandboxed." when layer 1 is effective.
      effective: /adequately sandboxed/i.test(text),
      report: text.slice(0, 2000),
    };
  } catch (err) {
    return { available: false, effective: null, report: String(err.message ?? err).slice(0, 300) };
  } finally {
    await ctx?.close().catch(() => {});
  }
}

/** An authenticated context + page, with always-on evidence collectors. */
export async function openIdentity(browser, { baseUrl, token, viewport }) {
  const ctx = await browser.newContext({
    baseURL: baseUrl,
    extraHTTPHeaders: token ? { Authorization: `Bearer ${token}` } : {},
    viewport: viewport ?? { width: 1280, height: 800 },
  });
  const page = await ctx.newPage();

  // `expectedDenials` holds the RESOLVED paths a journey explicitly asserted are
  // denied for this identity. It is the declaration side of expected-denial
  // correlation: nothing may be neutralized that the journey did not first
  // positively declare here.
  const evidence = { console: [], pageErrors: [], requests: [], failed: [], expectedDenials: [] };
  page.on('console', (m) => {
    if (!['error', 'warning'].includes(m.type())) return;
    // The resource URL is what makes precise attribution possible: for a
    // resource-load failure Chromium reports the FAILING RESOURCE's url here,
    // while a product `console.error` reports the page's own url. Without it a
    // console error can only be correlated by timing, which is not evidence.
    let resourcePath = null;
    try {
      const u = new URL(m.location()?.url ?? '');
      resourcePath = u.pathname + u.search;
    } catch { /* no usable location — stays null, and stays a finding */ }
    evidence.console.push({ type: m.type(), text: m.text(), resourcePath });
  });
  page.on('pageerror', (e) => evidence.pageErrors.push({ type: 'pageerror', text: e.message }));
  page.on('requestfailed', (r) => evidence.failed.push({ url: r.url(), error: r.failure()?.errorText }));
  page.on('response', (r) => {
    let u;
    try { u = new URL(r.url()); } catch { return; }
    if (u.pathname.startsWith('/api') || u.pathname.startsWith('/auth')) {
      evidence.requests.push({ path: u.pathname + u.search, status: r.status(), method: r.request().method() });
    }
  });

  return { ctx, page, evidence };
}

// ------------------------------------------------------------- step vocabulary

/**
 * A deliberately small declarative step DSL. The vocabulary lives in the engine
 * (generic); the STEPS live in the product's feature files (product truth), so
 * the engine never learns NSC Eval and the map stays reviewable in the PR that
 * changes behavior.
 */
export const STEPS = [
  'goto', 'reload', 'back', 'click', 'fill', 'select', 'wait_for_text',
  'expect_text', 'expect_no_text', 'expect_no_uuid', 'expect_url_contains',
  'expect_api', 'expect_denied', 'expect_allowed', 'expect_json',
  'expect_count_at_most', 'expect_count_at_least',
  'set_viewport', 'expect_no_overflow',
];

/**
 * Steps whose operands are PROOF, not input.
 *
 * The distinction decides who is allowed to choose a value. A `fill` operand is
 * something Watson types into the product; the product may well have chosen it,
 * and nothing rests on it. An `expect_text` operand is the thing that makes the
 * assertion true — so if the product picks it, the product decides whether it
 * passes its own test.
 *
 * `wait_for_text` is here deliberately: it asserts what the application
 * eventually says, and a journey that waits for a string the product chose has
 * proved only that the product can echo itself.
 */
export const ASSERTION_STEPS = new Set([
  'wait_for_text', 'expect_text', 'expect_no_text', 'expect_url_contains',
  'expect_api', 'expect_denied', 'expect_allowed', 'expect_json',
  'expect_count_at_most', 'expect_count_at_least',
]);

function locator(page, sel) {
  if (typeof sel !== 'string') throw new Error(`selector must be a string, got ${JSON.stringify(sel)}`);
  if (sel.startsWith('testid=')) return page.getByTestId(sel.slice(7));
  if (sel.startsWith('text=')) return page.getByText(sel.slice(5), { exact: false });
  if (sel.startsWith('role=')) {
    const [role, name] = sel.slice(5).split('|');
    return name ? page.getByRole(role, { name, exact: false }) : page.getByRole(role);
  }
  return page.locator(sel);
}

/** A response is AUTHORIZED if it is 2xx or 304. Learned the hard way in the
 *  feasibility run: a repeat navigation returns 304 Not Modified, and asserting
 *  strictly on 200 produced a false failure. Only 401/403 mean unauthenticated. */
export function isAuthorized(status) {
  return (status >= 200 && status < 300) || status === 304;
}

export async function runStep(step, ctx) {
  const { page, evidence, vars, timeout = 15_000 } = ctx;
  const kind = Object.keys(step).find((k) => STEPS.includes(k));
  if (!kind) throw new Error(`unknown step: ${JSON.stringify(step)}`);
  const raw = step[kind];
  const arg = typeof raw === 'string' ? interp(raw, vars) : raw;
  const note = step.note ? ` (${step.note})` : '';

  switch (kind) {
    case 'goto': {
      await page.goto(arg, { waitUntil: 'networkidle', timeout });
      return `navigated to ${arg}${note}`;
    }
    case 'reload': {
      await page.reload({ waitUntil: 'networkidle', timeout });
      return `reloaded${note}`;
    }
    case 'back': {
      await page.goBack({ waitUntil: 'networkidle', timeout });
      return `went back${note}`;
    }
    case 'click': {
      await locator(page, arg).first().click({ timeout });
      await page.waitForLoadState('networkidle', { timeout }).catch(() => {});
      return `clicked ${arg}${note}`;
    }
    case 'fill': {
      await locator(page, interp(arg.selector, vars)).first().fill(interp(String(arg.value), vars), { timeout });
      return `filled ${arg.selector}${note}`;
    }
    case 'select': {
      const loc = locator(page, interp(arg.selector, vars));
      const before = page.url();
      await loc.first().selectOption(arg.label ? { label: interp(arg.label, vars) } : interp(String(arg.value), vars), { timeout });
      // A control MAY trigger a full-document navigation (nsc-eval's season picker
      // does) or may just update local state (its M3 grant picker does). We cannot
      // know which in advance, and waiting a fixed window for a navigation that is
      // never coming costs that window on every such step — 5s each, on every run of
      // the shadow campaign.
      //
      // So race the two: whichever of "navigated" or "settled quietly" happens first
      // ends the wait. Every downstream assertion (expect_url_contains, expect_api,
      // wait_for_text) polls to its own deadline, so a slow navigation that loses the
      // race is still caught there rather than papered over here.
      await Promise.race([
        page.waitForURL((u) => u.toString() !== before, { timeout: 5000 }).catch(() => {}),
        page.waitForLoadState('networkidle', { timeout: 5000 }).catch(() => {}),
      ]);
      await page.waitForLoadState('networkidle', { timeout }).catch(() => {});
      return `selected ${arg.label ?? arg.value} in ${arg.selector}${note}`;
    }
    case 'wait_for_text': {
      await page.getByText(arg, { exact: false }).first().waitFor({ timeout });
      return `saw "${arg}"${note}`;
    }
    case 'expect_text': {
      // An assertion about EVENTUAL state, so it polls — same reasoning as
      // `expect_url_contains` directly below, which this had simply never
      // adopted.
      //
      // Sampling once raced the render and produced a FALSE FAIL_PRODUCT: a
      // journey that selects a season sees the URL update synchronously via the
      // router, then asserted the new name before React had re-rendered it.
      // Render wins, PASS; assertion wins, the product is accused of a defect it
      // does not have. Observed non-deterministically on one HEAD — a pass and a
      // FAIL_PRODUCT from identical inputs.
      //
      // A product that never renders the text still fails, at the deadline.
      const seen = async () => (await page.evaluate(() => document.body.innerText)).includes(arg);
      const deadline = Date.now() + timeout;
      while (!(await seen()) && Date.now() < deadline) {
        await page.waitForTimeout(100);
      }
      if (!(await seen())) throw new Error(`expected page text to contain "${arg}"${note}`);
      return `page contains "${arg}"`;
    }
    case 'expect_no_text': {
      // Deliberately does NOT poll, unlike `expect_text` above. The asymmetry is
      // the point: polling a NEGATIVE assertion would mean "wait until the text
      // is absent", so a screen that briefly showed forbidden data and then hid
      // it would PASS. For a privacy assertion that is precisely backwards — the
      // leak already happened. A negative samples once, after the preceding step
      // has settled the page.
      const body = await page.evaluate(() => document.body.innerText);
      if (body.includes(arg)) throw new Error(`expected page text NOT to contain "${arg}"${note}`);
      return `page does not contain "${arg}"`;
    }
    case 'expect_no_uuid': {
      const body = await page.evaluate(() => document.body.innerText);
      const m = body.match(UUID_RE);
      if (m) throw new Error(`raw UUID visible in page text: ${m[0]}${note}`);
      return 'no raw UUID visible';
    }
    case 'expect_url_contains': {
      // An assertion about EVENTUAL state, so it polls rather than sampling
      // once. A product that never navigates still fails at the deadline.
      const deadline = Date.now() + timeout;
      while (!page.url().includes(arg) && Date.now() < deadline) {
        await page.waitForTimeout(100);
      }
      if (!page.url().includes(arg)) throw new Error(`expected URL to contain "${arg}", got ${page.url()}${note}`);
      return `url contains "${arg}"`;
    }
    case 'expect_api': {
      const want = interp(arg.path, vars);
      // Eventual state, like expect_url_contains: an in-page fetch triggered by a click has
      // no navigation for `networkidle` to wait on, so sampling once races the request. A
      // call that never happens still fails at the deadline.
      const match = () => evidence.requests.filter((r) => r.path.split('?')[0] === want.split('?')[0]);
      const deadline = Date.now() + timeout;
      while (!match().length && Date.now() < deadline) await page.waitForTimeout(100);
      const hits = match();
      if (!hits.length) {
        // Name what WAS seen — "saw none" alone sends the reader hunting for a cause the
        // evidence already has.
        const seen = evidence.requests.map((r) => `${r.path} ${r.status}`);
        throw new Error(
          `expected an API call to ${want}, saw none${note}. Observed ${seen.length} API call(s): ` +
            (seen.length ? seen.join(', ') : '(none at all)'),
        );
      }
      const bad = hits.filter((h) => !isAuthorized(h.status));
      if (bad.length) throw new Error(`${want} returned ${bad.map((b) => b.status).join(', ')}${note}`);
      return `${want} authorized (${[...new Set(hits.map((h) => h.status))].join(', ')})`;
    }
    case 'expect_denied': {
      const want = interp(arg.path ?? arg, vars);
      const res = await page.request.get(want, { failOnStatusCode: false });
      if (![401, 403].includes(res.status())) {
        throw new Error(`expected ${want} to be denied (401/403), got ${res.status()}${note}`);
      }
      evidence.requests.push({ path: want, status: res.status(), method: 'GET' });
      // Record the DECLARATION, not the probe's own traffic. The probe runs through
      // Playwright's APIRequestContext, which never reaches the renderer and so
      // never produces a console error itself. What this licenses is different: the
      // product's OWN in-page fetch to this same path, whose denial Chromium logs.
      evidence.expectedDenials.push({ path: want, status: res.status(), method: 'GET' });
      return `${want} denied ${res.status()}`;
    }
    case 'expect_allowed': {
      // The mirror of expect_denied, and the positive control a denial journey
      // needs. A map made only of denials passes perfectly against an application
      // that denies this identity EVERYTHING — including what it should be allowed
      // — which is a broken product, not a secure one. Without a step like this
      // there is no way to say "and this one must answer" except by driving the UI,
      // which conflates the authorization question with a rendering one.
      const want = interp(arg.path ?? arg, vars);
      const res = await page.request.get(want, { failOnStatusCode: false });
      evidence.requests.push({ path: want, status: res.status(), method: 'GET' });
      if (!isAuthorized(res.status())) {
        throw new Error(`expected ${want} to be allowed, got ${res.status()}${note}`);
      }
      return `${want} allowed ${res.status()}`;
    }
    case 'expect_json': {
      // Assert on what a route RESOLVED TO, not merely that it answered.
      //
      // The gap this closes is specific and was written down before it was built:
      // nsc-eval's scoring-form returns `state: 'unassigned'` or `'ambiguous'`
      // rather than erroring when routing cannot be determined — fail-closed, never
      // a guess (EF-05/ADR-020). So a completely broken routing chain answers 200,
      // and `expect_allowed` calls it healthy.
      //
      // Deliberately a SUBSET match on top-level keys rather than a full-body
      // comparison. A journey that pinned an entire response would break on every
      // additive field, and a contract that breaks on additions trains people to
      // stop reading it.
      const want = interp(arg.path ?? arg.url, vars);
      const res = await page.request.get(want, { failOnStatusCode: false });
      evidence.requests.push({ path: want, status: res.status(), method: 'GET' });
      if (!isAuthorized(res.status())) {
        throw new Error(`expected ${want} to answer, got ${res.status()}${note}`);
      }
      let body;
      try {
        body = await res.json();
      } catch {
        throw new Error(`expected ${want} to return JSON${note}`);
      }
      for (const [key, expected] of Object.entries(arg.contains ?? {})) {
        const actual = body?.[key];
        const want_ = interp(String(expected), vars);
        if (String(actual) !== want_) {
          throw new Error(
            `expected ${want} to return \`${key}: ${want_}\`, got \`${key}: ${JSON.stringify(actual)}\`${note}`,
          );
        }
      }
      return `${want} returned ${Object.keys(arg.contains ?? {}).map((k) => `${k}=${body?.[k]}`).join(', ')}`;
    }
    case 'expect_count_at_most': {
      const n = await locator(page, interp(arg.selector, vars)).count();
      if (n > arg.max) throw new Error(`expected at most ${arg.max} of ${arg.selector}, found ${n}${note}`);
      return `${arg.selector} count ${n} <= ${arg.max}`;
    }
    case 'expect_count_at_least': {
      // The other half of at_most, and the one that catches a screen rendering
      // NOTHING. A route whose component throws renders an error boundary or an
      // empty shell and still returns 200 with a quiet console, so "did not error"
      // is not evidence that anything was drawn. Polls, because the assertion is
      // about eventual state: a screen that fetches before it renders its heading
      // would otherwise fail on timing rather than on substance.
      const sel = interp(arg.selector, vars);
      const deadline = Date.now() + timeout;
      let n = 0;
      do {
        n = await locator(page, sel).count();
        if (n >= arg.min) return `${sel} count ${n} >= ${arg.min}`;
        await page.waitForTimeout(250);
      } while (Date.now() < deadline);
      throw new Error(`expected at least ${arg.min} of ${sel}, found ${n}${note}`);
    }
    case 'set_viewport': {
      await page.setViewportSize({ width: arg.width, height: arg.height });
      return `viewport ${arg.width}x${arg.height}`;
    }
    case 'expect_no_overflow': {
      const over = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
      if (over > 1) throw new Error(`horizontal overflow of ${over}px${note}`);
      return 'no horizontal overflow';
    }
    default:
      throw new Error(`unimplemented step ${kind}`);
  }
}

/**
 * Substitute `${name}` from the run's variables.
 *
 * FAIL-CLOSED on an unknown name. It used to leave the literal `${name}` in
 * place, which turns a map typo into an assertion against a string no page will
 * ever contain — reported as a product failure. And it is one small step from
 * the sibling bug the engine also had, where an unknown name became the EMPTY
 * string and the assertion became vacuously true.
 *
 * There is no safe default here. An expectation whose operand could not be
 * resolved is not an expectation, so the run says so.
 */
export function interp(str, vars) {
  return String(str).replace(/\$\{(\w+)\}/g, (_, k) => {
    const v = vars?.[k];
    if (v === undefined) {
      throw new Error(
        `\${${k}} could not be resolved to a value. An unresolved operand is not an ` +
          'expectation; refusing to assert against it.',
      );
    }
    // The SAME predicate `validateSeedValues` applies at the source. Two rules
    // for one variable namespace is how a value rejected in one place arrives
    // through the other — which is what happened when this accepted `" "` and
    // the source check rejected it.
    const bad = degenerateOperand(v);
    if (bad) throw new Error(`\${${k}} ${bad}`);
    return String(v);
  });
}

// ------------------------------------------------------------------- evidence

export async function captureFailure(page, runDir, featureId, stepIndex) {
  const files = [];
  const shot = path.join(runDir, 'evidence/screenshots', `${featureId}@step${stepIndex}.png`);
  try {
    await page.screenshot({ path: shot, fullPage: true });
    files.push(path.relative(runDir, shot));
  } catch { /* page may be gone */ }
  const aria = path.join(runDir, 'evidence/aria', `${featureId}@step${stepIndex}.txt`);
  try {
    const snap = await page.locator('body').ariaSnapshot();
    fs.writeFileSync(aria, snap);
    files.push(path.relative(runDir, aria));
  } catch { /* best effort */ }
  return files;
}
