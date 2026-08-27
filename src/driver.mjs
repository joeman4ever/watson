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

const UUID_RE = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i;

export async function launchBrowser({ executablePath, cdpPort, headless = true }) {
  return chromium.launch({
    executablePath,
    headless,
    args: [
      `--remote-debugging-port=${cdpPort}`,
      '--remote-debugging-address=127.0.0.1',
      '--disable-extensions',
    ],
  });
}

/** An authenticated context + page, with always-on evidence collectors. */
export async function openIdentity(browser, { baseUrl, token, viewport }) {
  const ctx = await browser.newContext({
    baseURL: baseUrl,
    extraHTTPHeaders: token ? { Authorization: `Bearer ${token}` } : {},
    viewport: viewport ?? { width: 1280, height: 800 },
  });
  const page = await ctx.newPage();

  const evidence = { console: [], pageErrors: [], requests: [], failed: [] };
  page.on('console', (m) => {
    if (['error', 'warning'].includes(m.type())) evidence.console.push({ type: m.type(), text: m.text() });
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
  'expect_api', 'expect_denied', 'expect_count_at_most', 'set_viewport', 'expect_no_overflow',
];

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
      // A control may trigger a FULL-DOCUMENT navigation (nsc-eval's season
      // picker does). Give it a bounded window to start, then settle — a user
      // waits for the page. If it never navigates, the assertion steps still
      // fail; this waits for the app, it does not paper over a missing one.
      await page.waitForURL((u) => u.toString() !== before, { timeout: 5000 }).catch(() => {});
      await page.waitForLoadState('networkidle', { timeout }).catch(() => {});
      return `selected ${arg.label ?? arg.value} in ${arg.selector}${note}`;
    }
    case 'wait_for_text': {
      await page.getByText(arg, { exact: false }).first().waitFor({ timeout });
      return `saw "${arg}"${note}`;
    }
    case 'expect_text': {
      const body = await page.evaluate(() => document.body.innerText);
      if (!body.includes(arg)) throw new Error(`expected page text to contain "${arg}"${note}`);
      return `page contains "${arg}"`;
    }
    case 'expect_no_text': {
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
      return `${want} denied ${res.status()}`;
    }
    case 'expect_count_at_most': {
      const n = await locator(page, interp(arg.selector, vars)).count();
      if (n > arg.max) throw new Error(`expected at most ${arg.max} of ${arg.selector}, found ${n}${note}`);
      return `${arg.selector} count ${n} <= ${arg.max}`;
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

export function interp(str, vars) {
  return String(str).replace(/\$\{(\w+)\}/g, (_, k) => (vars?.[k] ?? `\${${k}}`));
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
