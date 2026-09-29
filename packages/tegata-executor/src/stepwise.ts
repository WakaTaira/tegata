/** 段階ログインの settle 判定と、入力した欄の消去を行う。 */

import {
  type ElementHandle,
  errors,
  type Frame,
  type Page,
  type Request,
} from "playwright-core";
import {
  clearFieldInPage,
  type RawSnapshot,
  type RawSnapshotElement,
  SNAPSHOT_MAX_ELEMENTS,
  waitForDomQuietInPage,
} from "./snapshot.js";

/** ナビゲーションが起きた場合に、新しい文書の domcontentloaded を待つ上限。 */
export const SETTLE_NAVIGATION_MS = 10_000;
/** DOM の変更がこの時間途切れたら落ち着いたとみなす。 */
export const SETTLE_QUIET_MS = 500;
/** DOM の変更が途切れるのを待つ上限。 */
export const SETTLE_DOM_MAX_MS = 5_000;
const NAVIGATION_POLL_MS = 50;
// 待機中に次のナビゲーションが始まった場合に、待ち直す回数の上限。
const SETTLE_MAX_ROUNDS = 3;
// page 内の待機が page 側の改変で戻らない場合に、Node 側で打ち切るまでの余裕。
const PAGE_EVALUATE_GRACE_MS = 1_000;
// 1 つの欄の消去を待つ上限。
const CLEAR_FIELD_TIMEOUT_MS = 5_000;

/** main frame のナビゲーションを観測する。 */
export type NavigationTracker = {
  /** 前回の clearNavigation 以降にナビゲーションの開始または確定があったかを返す。 */
  hasNavigation: () => boolean;
  clearNavigation: () => void;
  /** 開始したナビゲーションが、確定も中断もしていないかを返す。 */
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
      // service worker の要求など、frame を持たない要求は対象外とする。
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

/** `promise` を最大 `ms` ミリ秒待ち、間に合わなければ `fallback` を返す。打ち切った側の失敗は捨てる。 */
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

/** 開始したナビゲーションの確定を待ち、新しい文書の domcontentloaded を待つ。上限内に達したかを返す。 */
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
 * action の後にページが落ち着くのを待ち、上限内に落ち着いたかを返す（networkidle は用いない）。
 * ナビゲーションがあれば新しい文書の domcontentloaded を合計 10 s まで、その後 DOM の変更が 500 ms 途切れるのを
 * 合計 5 s まで待つ。待機中に次のナビゲーションが始まった場合は、残りの上限の範囲で待ち直す。
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
      // ナビゲーションで実行文脈が破棄された場合は、その通知を待ってから次の回で新しい文書を待ち直す。
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

/** 入力した欄のうち、まだ文書にあって値が空でないものを空にする。文書から外れた欄は無視する。 */
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

const OPTIONAL_ELEMENT_KEYS = [
  "type",
  "id",
  "name",
  "role",
  "placeholder",
  "aria-label",
  "autocomplete",
  "href",
  "text",
] as const;

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function toRawElement(value: unknown): RawSnapshotElement | undefined {
  if (
    !isObject(value) ||
    typeof value.tag !== "string" ||
    typeof value.disabled !== "boolean" ||
    !Array.isArray(value.selectors)
  ) {
    return undefined;
  }
  const selectors = value.selectors.filter(
    (selector): selector is string =>
      typeof selector === "string" && selector !== "",
  );
  if (selectors.length === 0) return undefined;
  const element: RawSnapshotElement = {
    tag: value.tag,
    disabled: value.disabled,
    selectors,
  };
  for (const key of OPTIONAL_ELEMENT_KEYS) {
    const field = value[key];
    if (typeof field === "string" && field !== "") element[key] = field;
  }
  return element;
}

/**
 * page から受け取った値を、許可リストの項目だけを写した形に整える。page は組み込みオブジェクトを改変して
 * 任意の値を返しうるため、形の不正な要素は捨て、許可リストにない項目（value 等）は写さない。
 */
export function sanitizeRawSnapshot(value: unknown): RawSnapshot {
  if (
    !isObject(value) ||
    typeof value.title !== "string" ||
    typeof value.text !== "string" ||
    !Array.isArray(value.elements)
  ) {
    throw new Error("the page returned a malformed snapshot");
  }
  const elements = value.elements.flatMap((item) => {
    const element = toRawElement(item);
    return element === undefined ? [] : [element];
  });
  return {
    title: value.title,
    text: value.text,
    elements: elements.slice(0, SNAPSHOT_MAX_ELEMENTS),
  };
}
