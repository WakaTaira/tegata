/**
 * Handles the settle decision of stepwise login, obtaining the aria snapshot, and clearing the
 * fields that were filled.
 */

import {
  type ElementHandle,
  errors,
  type Frame,
  type Page,
  type Request,
} from "playwright-core";
import {
  clearFieldInPage,
  type RawAriaSnapshot,
  waitForDomQuietInPage,
} from "./snapshot.js";

/** Upper bound on waiting for domcontentloaded of the new document when a navigation occurs. */
export const SETTLE_NAVIGATION_MS = 10_000;
/** The page is considered settled when DOM changes stop for this long. */
export const SETTLE_QUIET_MS = 500;
/** Upper bound on waiting for DOM changes to stop. */
export const SETTLE_DOM_MAX_MS = 5_000;
const NAVIGATION_POLL_MS = 50;
// Upper bound on how many times to wait again when the next navigation starts during a wait.
const SETTLE_MAX_ROUNDS = 3;
// Margin before the Node side cuts off a wait inside the page that does not return because the page
// tampered with it.
const PAGE_EVALUATE_GRACE_MS = 1_000;
// Upper bound on waiting for the clearing of one field.
const CLEAR_FIELD_TIMEOUT_MS = 5_000;
/** Upper bound for ariaSnapshot. */
export const ARIA_SNAPSHOT_TIMEOUT_MS = 10_000;
// Upper bound on waiting to collect role attribute values from one frame.
const COLLECT_ROLES_TIMEOUT_MS = 5_000;

/** Observes navigations of the main frame. */
export type NavigationTracker = {
  /** Returns whether a navigation started or committed since the previous clearNavigation. */
  hasNavigation: () => boolean;
  clearNavigation: () => void;
  /** Returns whether a started navigation has neither committed nor been aborted. */
  navigationPending: () => boolean;
  dispose: () => void;
};

export function trackNavigation(page: Page): NavigationTracker {
  const mainFrame = page.mainFrame();
  const inFlight = new Set<Request>();
  let seen = false;
  let committedSinceRequest = true;
  const isMainNavigation = (request: Request): boolean => {
    try {
      return request.isNavigationRequest() && request.frame() === mainFrame;
    } catch {
      // Requests that have no frame, such as service worker requests, are excluded.
      return false;
    }
  };
  const onRequest = (request: Request): void => {
    if (!isMainNavigation(request)) return;
    inFlight.add(request);
    seen = true;
    committedSinceRequest = false;
  };
  const onRequestDone = (request: Request): void => {
    inFlight.delete(request);
  };
  const onFrameNavigated = (frame: Frame): void => {
    if (frame !== mainFrame) return;
    seen = true;
    committedSinceRequest = true;
  };
  page.on("request", onRequest);
  page.on("requestfinished", onRequestDone);
  page.on("requestfailed", onRequestDone);
  page.on("framenavigated", onFrameNavigated);
  return {
    hasNavigation: () => seen,
    clearNavigation: () => {
      seen = false;
    },
    navigationPending: () => inFlight.size > 0 && !committedSinceRequest,
    dispose: () => {
      page.off("request", onRequest);
      page.off("requestfinished", onRequestDone);
      page.off("requestfailed", onRequestDone);
      page.off("framenavigated", onFrameNavigated);
    },
  };
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Waits up to `ms` milliseconds for `promise` and returns `fallback` if it is not in time. The
 * failure of the side that was cut off is discarded.
 */
async function withTimeout<T>(
  promise: Promise<T>,
  ms: number,
  fallback: T,
): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  promise.catch(() => undefined);
  try {
    return await Promise.race([
      promise,
      new Promise<T>((resolve) => {
        timer = setTimeout(() => resolve(fallback), ms);
      }),
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

/**
 * Waits for a started navigation to commit, then waits for domcontentloaded of the new document.
 * Returns whether it was reached within the limit.
 */
async function waitForNewDocument(
  page: Page,
  tracker: NavigationTracker,
  budgetMs: number,
): Promise<boolean> {
  const deadline = Date.now() + budgetMs;
  while (tracker.navigationPending()) {
    if (Date.now() >= deadline) return false;
    await sleep(NAVIGATION_POLL_MS);
  }
  const remaining = deadline - Date.now();
  if (remaining <= 0) return false;
  try {
    await page.waitForLoadState("domcontentloaded", { timeout: remaining });
    return true;
  } catch (error) {
    if (error instanceof errors.TimeoutError) return false;
    throw error;
  }
}

async function waitForDomQuiet(page: Page, maxMs: number): Promise<boolean> {
  if (maxMs < SETTLE_QUIET_MS) return false;
  return withTimeout(
    page.evaluate(waitForDomQuietInPage, { quietMs: SETTLE_QUIET_MS, maxMs }),
    maxMs + PAGE_EVALUATE_GRACE_MS,
    false,
  ).then((quiet) => quiet === true);
}

/**
 * Waits for the page to settle after an action and returns whether it settled within the limit
 * (networkidle is not used).
 * If there was a navigation, it waits up to 10 s in total for domcontentloaded of the new document,
 * and then up to 5 s in total for
 * DOM changes to stop for 500 ms. If the next navigation starts during a wait, it waits again
 * within the remaining limit.
 */
export async function settlePage(
  page: Page,
  tracker: NavigationTracker,
): Promise<boolean> {
  let navigationBudget = SETTLE_NAVIGATION_MS;
  let domBudget = SETTLE_DOM_MAX_MS;
  let settled = true;
  for (let round = 0; round < SETTLE_MAX_ROUNDS; round += 1) {
    if (tracker.hasNavigation()) {
      const started = Date.now();
      if (!(await waitForNewDocument(page, tracker, navigationBudget))) {
        settled = false;
      }
      navigationBudget = Math.max(0, navigationBudget - (Date.now() - started));
      tracker.clearNavigation();
    }
    const started = Date.now();
    let quiet: boolean;
    try {
      quiet = await waitForDomQuiet(page, domBudget);
    } catch (error) {
      // If the execution context was destroyed by a navigation, the wait is for that notification,
      // and then the next round waits for the new document again.
      if (page.isClosed()) throw error;
      quiet = false;
      await sleep(NAVIGATION_POLL_MS);
    }
    domBudget = Math.max(0, domBudget - (Date.now() - started));
    if (tracker.hasNavigation()) continue;
    return settled && quiet;
  }
  return false;
}

/**
 * Empties those of the filled fields that are still in the document and have a non-empty value.
 * Fields detached from the document are ignored.
 */
export async function clearFilledFields(
  handles: readonly ElementHandle[],
): Promise<void> {
  for (const handle of handles) {
    await withTimeout(
      handle.evaluate(clearFieldInPage).catch(() => undefined),
      CLEAR_FIELD_TIMEOUT_MS,
      undefined,
    );
  }
}

export async function disposeHandles(
  handles: readonly ElementHandle[],
): Promise<void> {
  await Promise.all(
    handles.map((handle) => handle.dispose().catch(() => undefined)),
  );
}

// Fields with an explicit role, whose value may be emitted.
const EXPLICIT_ROLE_FIELDS = "input[role], textarea[role]";

/**
 * Collects the role attribute values of input[role] and textarea[role] in one frame. Element lookup
 * and attribute reads are done by Playwright's
 * locator in a context isolated from the page's JS, so the result does not change even if the page
 * replaces querySelectorAll or getAttribute.
 */
async function collectFrameRoles(frame: Frame): Promise<string[]> {
  const fields = await frame.locator(EXPLICIT_ROLE_FIELDS).all();
  const roles = await Promise.all(
    fields.map((field) =>
      field.getAttribute("role", { timeout: COLLECT_ROLES_TIMEOUT_MS }),
    ),
  );
  return roles.filter((role): role is string => role !== null);
}

/**
 * Collects the role attribute values of all frames. Returns undefined if even one frame fails (an
 * exception or exceeding the limit).
 */
async function collectExplicitRoles(page: Page): Promise<string[] | undefined> {
  const perFrame = await Promise.all(
    page.frames().map((frame) =>
      withTimeout<string[] | undefined>(
        collectFrameRoles(frame).catch(() => undefined),
        COLLECT_ROLES_TIMEOUT_MS,
        undefined,
      ),
    ),
  );
  if (perFrame.some((roles) => roles === undefined)) return undefined;
  return perFrame.flatMap((roles) => roles ?? []);
}

/**
 * Takes ariaSnapshot (ai mode) once, and returns it together with the role attribute values
 * collected before and after.
 * aria-ref is resolved against the result of this call, so ariaSnapshot must not be called for
 * other purposes until the next action is resolved.
 */
export async function captureAriaSnapshot(
  page: Page,
): Promise<RawAriaSnapshot> {
  const before = await collectExplicitRoles(page);
  const aria: unknown = await page.ariaSnapshot({
    mode: "ai",
    timeout: ARIA_SNAPSHOT_TIMEOUT_MS,
  });
  const after = await collectExplicitRoles(page);
  const title: unknown = await page.title();
  if (typeof aria !== "string") {
    throw new Error("the page returned a malformed snapshot");
  }
  return {
    url: page.url(),
    title: typeof title === "string" ? title : "",
    aria,
    // If the values could not be collected either before or after, all roles are made targets for
    // value removal.
    roles:
      before === undefined || after === undefined
        ? "all"
        : [...new Set([...before, ...after])],
  };
}
