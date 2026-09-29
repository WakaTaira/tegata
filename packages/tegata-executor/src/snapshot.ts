/** 段階ログインのスナップショットを page 内で組み立て、secret の検査と上限の適用を行う。 */

/** スナップショットの text（document.body.innerText）の上限（文字数）。 */
export const SNAPSHOT_TEXT_CHARS = 2000;
/** 各要素の text の上限（文字数）。 */
export const SNAPSHOT_ELEMENT_TEXT_CHARS = 200;
/** 要素数の上限。 */
export const SNAPSHOT_MAX_ELEMENTS = 200;
/** 直列化したスナップショットの上限（バイト）。 */
export const SNAPSHOT_MAX_BYTES = 64 * 1024;
/**
 * page から切り詰めずに受け取る余白（文字数）。切り詰めの境界を跨いで現れた secret を検査で見落とさないよう、
 * 出力する範囲より長い文字列に対して検査を行う。
 */
const INSPECTION_MARGIN_CHARS = 2048;
// 要素をすべて削っても上限を超える場合に、title と url を切り詰める長さ（文字数）。
const FALLBACK_TITLE_CHARS = 256;
const FALLBACK_URL_CHARS = 2048;

export const USERNAME_MASK = "[username]";

/** page 内で収集した要素。selectors は一意に解決することを確認済みの候補を優先順に並べたものである。 */
export type RawSnapshotElement = {
  tag: string;
  type?: string;
  id?: string;
  name?: string;
  role?: string;
  placeholder?: string;
  "aria-label"?: string;
  autocomplete?: string;
  href?: string;
  disabled: boolean;
  text?: string;
  selectors: string[];
};

export type RawSnapshot = {
  title: string;
  text: string;
  elements: RawSnapshotElement[];
};

export type SnapshotElement = Omit<RawSnapshotElement, "selectors"> & {
  selector: string;
};

export type Snapshot = {
  url: string;
  title: string;
  text: string;
  elements: SnapshotElement[];
  settled: boolean;
  truncated?: true;
};

export type SnapshotLimits = {
  maxElements: number;
  textChars: number;
  elementTextChars: number;
};

/** page 内で組み立てる際の上限。text は検査用の余白を含めて受け取る。 */
export const PAGE_SNAPSHOT_LIMITS: SnapshotLimits = {
  maxElements: SNAPSHOT_MAX_ELEMENTS,
  textChars: SNAPSHOT_TEXT_CHARS + INSPECTION_MARGIN_CHARS,
  elementTextChars: SNAPSHOT_ELEMENT_TEXT_CHARS + INSPECTION_MARGIN_CHARS,
};

/** スナップショットが既知の secret を含むために返せないことを表す。 */
export class SnapshotRejectedError extends Error {}

/**
 * page 内でスナップショットを組み立てる。page へシリアライズされるため、外部の識別子を参照してはならない。
 * input・textarea・select の値、value 属性、data-* 属性は読まない。許可リストの属性のみを読む。
 *
 * selector は Playwright の CSS の解決規則（open shadow root を貫通し、子結合子の親は shadow host とする）で
 * その要素 1 つにのみ一致するものだけを候補に入れる。一意な候補が無い要素は出力しない。
 */
export function buildSnapshotInPage(limits: SnapshotLimits): RawSnapshot {
  const TARGET =
    'button, a[href], input, select, textarea, [role="button"], [role="link"]';
  const FORM_CONTROLS = "input, select, textarea";
  const roots: Array<Document | ShadowRoot> = [];
  const candidates: Element[] = [];
  const walk = (root: Document | ShadowRoot): void => {
    roots.push(root);
    for (const element of Array.from(root.querySelectorAll("*"))) {
      if (element.matches(TARGET)) candidates.push(element);
      if (element.shadowRoot !== null) walk(element.shadowRoot);
    }
  };
  walk(document);

  const clean = (value: string, max: number): string =>
    value.replace(/\s+/gu, " ").trim().slice(0, max);
  const isVisible = (element: Element): boolean => {
    const rect = element.getBoundingClientRect();
    if (rect.width <= 0 || rect.height <= 0) return false;
    const style = getComputedStyle(element);
    return style.visibility !== "hidden" && style.visibility !== "collapse";
  };
  const parentOrHost = (element: Element): Element | null => {
    if (element.parentElement !== null) return element.parentElement;
    const parent = element.parentNode;
    return parent instanceof ShadowRoot ? parent.host : null;
  };
  const countSimple = (selector: string): number => {
    let count = 0;
    for (const root of roots) count += root.querySelectorAll(selector).length;
    return count;
  };
  // 子結合子で連ねた経路を、親を shadow host まで辿る規則で数える。
  const countPath = (steps: string[]): number => {
    const last = steps[steps.length - 1];
    let count = 0;
    for (const root of roots) {
      for (const element of Array.from(root.querySelectorAll(last))) {
        let parent = parentOrHost(element);
        let matched = true;
        for (let index = steps.length - 2; index >= 0; index -= 1) {
          if (parent === null || !parent.matches(steps[index])) {
            matched = false;
            break;
          }
          parent = parentOrHost(parent);
        }
        if (matched) count += 1;
      }
    }
    return count;
  };
  const isUnique = (count: () => number): boolean => {
    try {
      return count() === 1;
    } catch {
      return false;
    }
  };
  const idSelector = (element: Element): string | undefined => {
    const id = element.getAttribute("id");
    if (id === null || id === "") return undefined;
    const selector = `#${CSS.escape(id)}`;
    return isUnique(() => countSimple(selector)) ? selector : undefined;
  };
  const nthStep = (element: Element): string => {
    let index = 1;
    for (
      let sibling = element.previousElementSibling;
      sibling !== null;
      sibling = sibling.previousElementSibling
    ) {
      if (sibling.localName === element.localName) index += 1;
    }
    return `${CSS.escape(element.localName)}:nth-of-type(${index})`;
  };
  // 一意な id を持つ最も近い祖先を起点とする経路と、文書の根を起点とする経路を返す。
  const pathSelectors = (element: Element): string[] => {
    const steps: string[] = [];
    const selectors: string[] = [];
    let anchored = false;
    for (
      let current: Element | null = element;
      current !== null;
      current = parentOrHost(current)
    ) {
      if (current !== element && !anchored) {
        const anchor = idSelector(current);
        if (anchor !== undefined) {
          const anchoredSteps = [anchor, ...steps];
          if (isUnique(() => countPath(anchoredSteps))) {
            selectors.push(anchoredSteps.join(" > "));
          }
          anchored = true;
        }
      }
      if (current === document.documentElement) {
        steps.unshift("html");
        break;
      }
      steps.unshift(nthStep(current));
    }
    if (steps[0] === "html" && isUnique(() => countPath(steps))) {
      selectors.push(steps.join(" > "));
    }
    return selectors;
  };
  const selectorsOf = (element: Element): string[] => {
    const selectors: string[] = [];
    const byId = idSelector(element);
    if (byId !== undefined) selectors.push(byId);
    const name = element.getAttribute("name");
    if (name !== null && name !== "") {
      const byName = `${CSS.escape(element.localName)}[name="${CSS.escape(name)}"]`;
      if (isUnique(() => countSimple(byName))) selectors.push(byName);
    }
    return [...selectors, ...pathSelectors(element)];
  };
  // label の中の欄の内容（textarea の既定値・select の選択肢）を含めないよう、欄を除いた複製の文字列を読む。
  const labelText = (element: Element): string => {
    const labels = (element as HTMLInputElement).labels;
    if (labels === null || labels === undefined) return "";
    return Array.from(labels)
      .map((label) => {
        const copy = label.cloneNode(true) as Element;
        for (const control of Array.from(
          copy.querySelectorAll(FORM_CONTROLS),
        )) {
          control.remove();
        }
        return copy.textContent ?? "";
      })
      .join(" ");
  };
  const textOf = (element: Element): string =>
    element.matches(FORM_CONTROLS)
      ? labelText(element)
      : ((element as HTMLElement).innerText ?? "");
  const typeOf = (element: Element): string | null =>
    element instanceof HTMLInputElement || element instanceof HTMLButtonElement
      ? element.type
      : element.getAttribute("type");
  const describe = (element: Element): RawSnapshotElement | undefined => {
    const selectors = selectorsOf(element);
    if (selectors.length === 0) return undefined;
    const described: RawSnapshotElement = {
      tag: element.localName,
      disabled: element.matches(":disabled"),
      selectors,
    };
    const optional: Array<[keyof RawSnapshotElement, string | null]> = [
      ["type", typeOf(element)],
      ["id", element.getAttribute("id")],
      ["name", element.getAttribute("name")],
      ["role", element.getAttribute("role")],
      ["placeholder", element.getAttribute("placeholder")],
      ["aria-label", element.getAttribute("aria-label")],
      ["autocomplete", element.getAttribute("autocomplete")],
      ["href", element instanceof HTMLAnchorElement ? element.href : null],
      ["text", clean(textOf(element), limits.elementTextChars)],
    ];
    for (const [key, value] of optional) {
      if (value !== null && value !== "") {
        (described as Record<string, unknown>)[key] = value;
      }
    }
    return described;
  };

  const elements: RawSnapshotElement[] = [];
  for (const element of candidates) {
    if (elements.length >= limits.maxElements) break;
    if (!isVisible(element)) continue;
    const described = describe(element);
    if (described !== undefined) elements.push(described);
  }
  return {
    title: document.title,
    text: (document.body?.innerText ?? "").slice(0, limits.textChars),
    elements,
  };
}

/**
 * page 内で DOM の変更が `quietMs` 途切れるのを最大 `maxMs` 待つ。途切れた場合は true を返す。
 * page 側の組み込みオブジェクトの改変で例外が生じた場合は、落ち着いたと判定できないため false を返す。
 * page へシリアライズされるため、外部の識別子を参照してはならない。
 */
export function waitForDomQuietInPage({
  quietMs,
  maxMs,
}: {
  quietMs: number;
  maxMs: number;
}): Promise<boolean> {
  return new Promise<boolean>((resolve) => {
    try {
      let quietTimer: ReturnType<typeof setTimeout> | undefined;
      let observer: MutationObserver | undefined;
      const finish = (quiet: boolean): void => {
        observer?.disconnect();
        clearTimeout(quietTimer);
        clearTimeout(capTimer);
        resolve(quiet);
      };
      const capTimer = setTimeout(() => finish(false), maxMs);
      const restartQuietTimer = (): void => {
        clearTimeout(quietTimer);
        quietTimer = setTimeout(() => finish(true), quietMs);
      };
      observer = new MutationObserver(restartQuietTimer);
      observer.observe(document, {
        subtree: true,
        childList: true,
        attributes: true,
        characterData: true,
      });
      restartQuietTimer();
    } catch {
      resolve(false);
    }
  });
}

/**
 * page 内で、入力した欄がまだ文書にあって値が空でなければ空にし、input / change を発火する。
 * 値や例外の文言を page の外へ持ち出さないよう、戻り値は持たず例外はすべて捕捉する。
 * page へシリアライズされるため、外部の識別子を参照してはならない。
 */
export function clearFieldInPage(element: Element): void {
  try {
    if (!element.isConnected) return;
    const view = element.ownerDocument.defaultView;
    if (view === null) return;
    const prototype =
      element instanceof view.HTMLInputElement
        ? view.HTMLInputElement.prototype
        : element instanceof view.HTMLTextAreaElement
          ? view.HTMLTextAreaElement.prototype
          : undefined;
    if (prototype === undefined) return;
    const descriptor = Object.getOwnPropertyDescriptor(prototype, "value");
    if (descriptor?.get?.call(element) === "") return;
    descriptor?.set?.call(element, "");
    element.dispatchEvent(new view.Event("input", { bubbles: true }));
    element.dispatchEvent(new view.Event("change", { bubbles: true }));
  } catch {
    // 欄の消去の失敗は、呼び出し側でブラウザの破棄または以後の検査に委ねる。
  }
}

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function tryEncodeURIComponent(value: string): string | undefined {
  try {
    return encodeURIComponent(value);
  } catch {
    // 対になっていないサロゲートを含む値は符号化できないため、その形を検索しない。
    return undefined;
  }
}

function nonEmptyUnique(values: Array<string | undefined>): string[] {
  return [
    ...new Set(
      values.filter(
        (value): value is string => value !== undefined && value !== "",
      ),
    ),
  ];
}

/**
 * secret の検索に用いる形（生・HTML エスケープ・encodeURIComponent・全バイト percent 符号化・base64・hex）。
 * base64 は末尾の `=` を除いた形で検索し、padding の有無によらず一致させる。大小文字の区別がある符号化は両方を含める。
 */
export function secretForms(value: string): string[] {
  if (value === "") return [];
  const bytes = Buffer.from(value, "utf8");
  const percent = [...bytes]
    .map((byte) => `%${byte.toString(16).padStart(2, "0").toUpperCase()}`)
    .join("");
  const hex = bytes.toString("hex");
  return nonEmptyUnique([
    value,
    escapeHtml(value),
    tryEncodeURIComponent(value),
    percent,
    percent.toLowerCase(),
    bytes.toString("base64").replace(/=+$/u, ""),
    hex,
    hex.toUpperCase(),
  ]);
}

/** username のマスク対象の形（生・HTML エスケープ・URL 符号化）を長い順に返す。 */
function usernameForms(username: string): string[] {
  if (username === "") return [];
  return nonEmptyUnique([
    username,
    escapeHtml(username),
    tryEncodeURIComponent(username),
  ]).sort((left, right) => right.length - left.length);
}

/** username の完全一致を `[username]` に置換する。 */
export function maskUsername(value: string, username: string): string {
  return usernameForms(username).reduce(
    (masked, form) => masked.replaceAll(form, USERNAME_MASK),
    value,
  );
}

export type SnapshotSecrets = {
  username: string;
  password: string;
  totpCodes: readonly string[];
};

/** 検査対象の secret のうち、いずれかの形が文字列のいずれかに完全一致で含まれるかを返す。 */
export function containsSecret(
  values: readonly string[],
  secrets: readonly string[],
): boolean {
  const forms = secrets.flatMap(secretForms);
  return values.some((value) => forms.some((form) => value.includes(form)));
}

function stringsOf(snapshot: {
  url: string;
  title: string;
  text: string;
  elements: ReadonlyArray<Record<string, unknown>>;
}): string[] {
  const elementStrings = snapshot.elements.flatMap((element) =>
    Object.values(element).flatMap((value) =>
      typeof value === "string"
        ? [value]
        : Array.isArray(value)
          ? value.filter((item): item is string => typeof item === "string")
          : [],
    ),
  );
  return [snapshot.url, snapshot.title, snapshot.text, ...elementStrings];
}

function truncateChars(value: string, max: number): string {
  const characters = Array.from(value);
  return characters.length <= max ? value : characters.slice(0, max).join("");
}

/** username を含まない候補を優先して selector を選ぶ。含む候補しか無い場合はマスクされた先頭の候補となる。 */
function chooseSelector(selectors: string[], username: string): string {
  return (
    selectors.find(
      (selector) => maskUsername(selector, username) === selector,
    ) ?? selectors[0]
  );
}

function toSnapshotElement(
  element: RawSnapshotElement,
  username: string,
): SnapshotElement {
  const { selectors, text, ...attributes } = element;
  const masked: SnapshotElement = {
    ...attributes,
    selector: chooseSelector(selectors, username),
  };
  for (const [key, value] of Object.entries(masked)) {
    if (typeof value === "string") {
      (masked as Record<string, unknown>)[key] = maskUsername(value, username);
    }
  }
  if (text !== undefined) {
    masked.text = truncateChars(
      maskUsername(text, username),
      SNAPSHOT_ELEMENT_TEXT_CHARS,
    );
  }
  return masked;
}

function serializedBytes(snapshot: Snapshot): number {
  return Buffer.byteLength(JSON.stringify(snapshot), "utf8");
}

/** 64 KiB の上限を超える分を elements の末尾から削る。それでも超える場合は title と url を切り詰める。 */
function fitSnapshot(snapshot: Snapshot): Snapshot {
  if (serializedBytes(snapshot) <= SNAPSHOT_MAX_BYTES) return snapshot;
  const fitted: Snapshot = {
    ...snapshot,
    elements: [...snapshot.elements],
    truncated: true,
  };
  while (
    fitted.elements.length > 0 &&
    serializedBytes(fitted) > SNAPSHOT_MAX_BYTES
  ) {
    fitted.elements.pop();
  }
  if (serializedBytes(fitted) > SNAPSHOT_MAX_BYTES) {
    fitted.title = truncateChars(fitted.title, FALLBACK_TITLE_CHARS);
    fitted.url = truncateChars(fitted.url, FALLBACK_URL_CHARS);
  }
  return fitted;
}

/**
 * page から受け取ったスナップショットを検査し、username をマスクして上限を適用する。
 * password または入力した TOTP コードのいずれかの形が、マスク前・マスク後・直列化結果のいずれかに完全一致で
 * 含まれる場合は SnapshotRejectedError を送出する。部分一致は判定しない。
 */
export function finalizeSnapshot(
  raw: RawSnapshot,
  url: string,
  settled: boolean,
  secrets: SnapshotSecrets,
): Snapshot {
  const rejected = [secrets.password, ...secrets.totpCodes];
  const rawStrings = stringsOf({ ...raw, url });
  if (containsSecret(rawStrings, rejected)) throw new SnapshotRejectedError();
  const { username } = secrets;
  const snapshot = fitSnapshot({
    url: maskUsername(url, username),
    title: maskUsername(raw.title, username),
    text: truncateChars(maskUsername(raw.text, username), SNAPSHOT_TEXT_CHARS),
    elements: raw.elements.map((element) =>
      toSnapshotElement(element, username),
    ),
    settled,
  });
  if (
    containsSecret([...stringsOf(snapshot), JSON.stringify(snapshot)], rejected)
  ) {
    throw new SnapshotRejectedError();
  }
  return snapshot;
}
