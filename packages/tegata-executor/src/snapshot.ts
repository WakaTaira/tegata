/** 段階ログインのスナップショット（値を除いた aria スナップショット）を組み立て、secret の検査と上限の適用を行う。 */

/** 直列化したスナップショットの上限（バイト）。 */
export const SNAPSHOT_MAX_BYTES = 64 * 1024;
// page をすべて削っても上限を超える場合に、title と url を切り詰める長さ（文字数）。
const FALLBACK_TITLE_CHARS = 256;
const FALLBACK_URL_CHARS = 2048;

export const USERNAME_MASK = "[username]";
/** 値を除いた欄の見出し行に付ける印。 */
export const FILLED_MARK = " [filled]";

/**
 * 値を持つ役割。Playwright は input・textarea の値を explicit role によらず出力するため、page から集めた
 * input・textarea の role 属性値と合わせて値の除去の対象とする。
 */
export const VALUE_ROLES: readonly string[] = [
  "textbox",
  "searchbox",
  "spinbutton",
  "slider",
  "combobox",
];

/** ref の形式（`e<n>`、iframe 内は `f<n>e<n>`）。 */
export const REF_PATTERN = /^(?:f\d+)?e\d+$/u;
export const MAX_REF_LENGTH = 32;

export type Snapshot = {
  url: string;
  title: string;
  page: string;
  settled: boolean;
  truncated?: true;
};

/**
 * page から受け取ったスナップショットの素材。roles は page から集めた input・textarea の role 属性値であり、
 * 集められなかった場合の "all" は全ての役割を値の除去の対象とすることを表す。
 */
export type RawAriaSnapshot = {
  url: string;
  title: string;
  aria: string;
  roles: readonly string[] | "all";
};

/** 検査済みのスナップショットと、その page の見出し行が持つ ref の集合。 */
export type FinalizedSnapshot = {
  snapshot: Snapshot;
  refs: Set<string>;
};

/** スナップショットが既知の secret を含むか、未知の形式であるために返せないことを表す。 */
export class SnapshotRejectedError extends Error {}

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

/** aria スナップショットの 1 行。keyEnd は KEY の末尾（単引用符で包まれていれば閉じ `'` の位置）である。 */
export type SnapshotLine = {
  raw: string;
  indent: number;
  role: string;
  name?: string;
  attrs: string[];
  quoted: boolean;
  keyEnd: number;
  value?: string;
  opensChildren: boolean;
};

const LINE_PATTERN = /^( *)- ([\s\S]+)$/u;
// KEY は role( NAME)?( [attr])* であり、NAME は JSON 文字列か、引用なしの /…/ である。
const ROLE_PATTERN = /^\/?[a-z][a-z0-9-]*/u;
const JSON_NAME_PATTERN = /^ ("(?:[^"\\]|\\[\s\S])*")/u;
const ATTRS_PATTERN = /^(?: \[[a-z]+(?:=[A-Za-z0-9-]+)?\])*/u;
const ATTR_PATTERN = /\[([^\]]*)\]/gu;

type ParsedKey = { role: string; name?: string; attrs: string[] };
type KeyMatch = ParsedKey & { length: number };

/** KEY の後ろに続く部分が `: VALUE`・`:`・行末のいずれかであるかを返す。 */
function isLineTail(tail: string): boolean {
  return tail === "" || tail === ":" || /^: [\s\S]+$/u.test(tail);
}

/** 名前の後ろ（at 以降）の属性部を読み、その後ろが isTail を満たす場合に KEY を返す。 */
function keyWithAttrs(
  text: string,
  role: string,
  name: string | undefined,
  at: number,
  isTail: (tail: string) => boolean,
): KeyMatch | undefined {
  const attrsText = ATTRS_PATTERN.exec(text.slice(at))?.[0] ?? "";
  const length = at + attrsText.length;
  if (!isTail(text.slice(length))) return undefined;
  const attrs = Array.from(attrsText.matchAll(ATTR_PATTERN), (attr) => attr[1]);
  return { role, name, attrs, length };
}

/**
 * 引用なしの /…/ の名前を持つ KEY を読む。名前の終端は、その後ろが属性部と isTail に合う最初の `/` とする。
 * 引用なしの KEY では名前が `: ` を含まず（含めば KEY ごと単引用符で包まれる）、単引用符の KEY では後ろに何も続かないため、
 * 名前の内側の `/` を終端とすると、名前の末尾の `/` が属性部か isTail に掛かって合わない。よってこの終端は一意である。
 */
function regexNameKey(
  text: string,
  role: string,
  start: number,
  isTail: (tail: string) => boolean,
): KeyMatch | undefined {
  for (
    let end = text.indexOf("/", start);
    end !== -1;
    end = text.indexOf("/", end + 1)
  ) {
    const key = keyWithAttrs(
      text,
      role,
      text.slice(start, end + 1),
      end + 1,
      isTail,
    );
    if (key !== undefined) return key;
  }
  return undefined;
}

/** KEY を先頭から読み、読んだ長さとともに返す。KEY の後ろが isTail を満たさなければ undefined を返す。 */
function parseKeyPrefix(
  text: string,
  isTail: (tail: string) => boolean,
): KeyMatch | undefined {
  const role = ROLE_PATTERN.exec(text)?.[0];
  if (role === undefined) return undefined;
  const rest = text.slice(role.length);
  const json = JSON_NAME_PATTERN.exec(rest);
  if (json !== null) {
    let name: string;
    try {
      name = JSON.parse(json[1]) as string;
    } catch {
      return undefined;
    }
    return keyWithAttrs(text, role, name, role.length + json[0].length, isTail);
  }
  if (rest.startsWith(" /")) {
    return regexNameKey(text, role, role.length + 1, isTail);
  }
  return keyWithAttrs(text, role, undefined, role.length, isTail);
}

/** 単引用符で包まれた KEY の閉じ `'` の位置を返す。内側の `'` は `''` で表される。 */
function closingQuoteIndex(body: string): number | undefined {
  for (let index = 1; index < body.length; index += 1) {
    if (body[index] !== "'") continue;
    if (body[index + 1] === "'") {
      index += 1;
      continue;
    }
    return index;
  }
  return undefined;
}

/** `^(I)- KEY(: VALUE)?$` の形の行を読む。形に合わなければ undefined を返す。 */
export function parseSnapshotLine(raw: string): SnapshotLine | undefined {
  const match = LINE_PATTERN.exec(raw);
  if (match === null) return undefined;
  const indent = match[1].length;
  const body = match[2];
  const bodyStart = indent + 2;
  let key: ParsedKey;
  let tail: string;
  let keyEnd: number;
  const quoted = body.startsWith("'");
  if (quoted) {
    const close = closingQuoteIndex(body);
    if (close === undefined) return undefined;
    const inner = body.slice(1, close).replaceAll("''", "'");
    const parsed = parseKeyPrefix(inner, (rest) => rest === "");
    if (parsed === undefined) return undefined;
    key = parsed;
    tail = body.slice(close + 1);
    keyEnd = bodyStart + close;
  } else {
    const parsed = parseKeyPrefix(body, isLineTail);
    if (parsed === undefined) return undefined;
    key = parsed;
    tail = body.slice(parsed.length);
    keyEnd = bodyStart + parsed.length;
  }
  if (!isLineTail(tail)) return undefined;
  return {
    raw,
    indent,
    ...key,
    quoted,
    keyEnd,
    value: tail.startsWith(": ") ? tail.slice(2) : undefined,
    opensChildren: tail === ":",
  };
}

/** ariaSnapshot の出力を行に分ける。形に合わない行が 1 行でもあれば SnapshotRejectedError を送出する。 */
export function parseSnapshotLines(aria: string): SnapshotLine[] {
  if (aria === "") return [];
  return aria.split("\n").map((raw) => {
    const line = parseSnapshotLine(raw);
    if (line === undefined) throw new SnapshotRejectedError();
    return line;
  });
}

/** ノードの見出し行ではない行（`- text:` と `- /url:` 等の属性行）かを返す。 */
function isPseudoLine(line: SnapshotLine): boolean {
  return line.role === "text" || line.role.startsWith("/");
}

function isTextLine(line: SnapshotLine): boolean {
  return (
    line.role === "text" &&
    !line.quoted &&
    line.name === undefined &&
    line.attrs.length === 0 &&
    line.value !== undefined
  );
}

/** 値を除いた見出し行を書き戻す。inline の値は削り、filled なら KEY の末尾に印を付ける。 */
function renderValueHeading(line: SnapshotLine, filled: boolean): string {
  return `${line.raw.slice(0, line.keyEnd)}${filled ? FILLED_MARK : ""}${
    line.quoted ? "'" : ""
  }${line.opensChildren ? ":" : ""}`;
}

/**
 * 対象役割の見出し行から値を除く。inline の値を削り、子を持つ行では直下（インデント +2）の `- text:` 行を削る。
 * `- /…` の行・`- option` の行・それより深い行には触れない。空でない値を削った行に印を付ける。
 */
export function removeValues(
  lines: readonly SnapshotLine[],
  isValueRole: (role: string) => boolean,
): string[] {
  const isTarget = (line: SnapshotLine): boolean =>
    !isPseudoLine(line) && isValueRole(line.role);
  const filled = new Set<number>();
  const dropped = new Set<number>();
  // 子を持つ祖先の行の添字を、インデントの浅い順に積む。
  const ancestors: number[] = [];
  lines.forEach((line, index) => {
    while (
      ancestors.length > 0 &&
      lines[ancestors[ancestors.length - 1]].indent >= line.indent
    ) {
      ancestors.pop();
    }
    const parentIndex = ancestors[ancestors.length - 1];
    const parent = parentIndex === undefined ? undefined : lines[parentIndex];
    if (
      parent !== undefined &&
      isTarget(parent) &&
      line.indent === parent.indent + 2 &&
      isTextLine(line)
    ) {
      dropped.add(index);
      filled.add(parentIndex);
    }
    if (isTarget(line) && line.value !== undefined && line.value !== '""') {
      filled.add(index);
    }
    if (line.opensChildren) ancestors.push(index);
  });
  return lines.flatMap((line, index) => {
    if (dropped.has(index)) return [];
    return [
      isTarget(line) ? renderValueHeading(line, filled.has(index)) : line.raw,
    ];
  });
}

/** page の見出し行の KEY の属性部にある ref を集める。名前・値・`- text:` の中の `[ref=…]` は数えない。 */
export function collectRefs(page: string): Set<string> {
  const refs = new Set<string>();
  if (page === "") return refs;
  for (const raw of page.split("\n")) {
    const line = parseSnapshotLine(raw);
    if (line === undefined || isPseudoLine(line)) continue;
    for (const attr of line.attrs) {
      if (!attr.startsWith("ref=")) continue;
      const ref = attr.slice("ref=".length);
      if (ref.length <= MAX_REF_LENGTH && REF_PATTERN.test(ref)) refs.add(ref);
    }
  }
  return refs;
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

/** Playwright の空白の正規化（U+200B・U+00AD の除去、前後の空白の除去、連続する空白の 1 個への置換）。 */
function normalizeWhitespace(value: string): string {
  return value
    .replace(/[\u200b\u00ad]/gu, "")
    .trim()
    .replace(/\s+/gu, " ");
}

// Playwright の YAML 二重引用符のエスケープ。namedControls が偽なら、改行とタブ以外の制御文字を \xNN とする。
function yamlEscape(value: string, namedControls: boolean): string {
  const named: Record<string, string> = namedControls
    ? { "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t" }
    : { "\n": "\\n", "\t": "\\t" };
  let escaped = "";
  for (const character of value) {
    const code = character.charCodeAt(0);
    if (character === "\\") {
      escaped += "\\\\";
    } else if (character === '"') {
      escaped += '\\"';
    } else if (code <= 0x1f || (code >= 0x7f && code <= 0x9f)) {
      escaped += named[character] ?? `\\x${code.toString(16).padStart(2, "0")}`;
    } else {
      escaped += character;
    }
  }
  return escaped;
}

/**
 * aria スナップショットに表示される形（表示形）。N は空白の正規化、J は名前の位置の JSON 文字列の内側、
 * Y は値と `- text:` の位置の YAML 二重引用符の内側であり、それぞれの `'` を `''` にした単引用符キーの形を加える。
 * Y は Playwright の実装（\b・\f・\r を名前付きで表す）と、制御文字を \xNN で表す形の両方を含める。
 */
export function displayForms(value: string): string[] {
  const normalized = normalizeWhitespace(value);
  if (normalized === "") return [];
  const forms = [
    normalized,
    JSON.stringify(normalized).slice(1, -1),
    yamlEscape(normalized, true),
    yamlEscape(normalized, false),
  ];
  return nonEmptyUnique([
    ...forms,
    ...forms.map((form) => form.replaceAll("'", "''")),
  ]);
}

/** 検査に用いる形。従来の 8 形を生の値と正規化した値の両方に適用し、表示形を加える。 */
export function rejectionForms(value: string): string[] {
  if (value === "") return [];
  return nonEmptyUnique([
    ...secretForms(value),
    ...secretForms(normalizeWhitespace(value)),
    ...displayForms(value),
  ]);
}

/** username のマスク対象の形（生・HTML エスケープ・URL 符号化と表示形）を長い順に返す。 */
function usernameForms(username: string): string[] {
  if (username === "") return [];
  return nonEmptyUnique([
    username,
    escapeHtml(username),
    tryEncodeURIComponent(username),
    ...displayForms(username),
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
  const forms = secrets.flatMap(rejectionForms);
  return values.some((value) => forms.some((form) => value.includes(form)));
}

function truncateChars(value: string, max: number): string {
  const characters = Array.from(value);
  return characters.length <= max ? value : characters.slice(0, max).join("");
}

function serializedBytes(snapshot: Snapshot): number {
  return Buffer.byteLength(JSON.stringify(snapshot), "utf8");
}

/**
 * 64 KiB の上限を超える場合に、truncated を付けたうえで上限に収まるまで page を末尾から行単位で削る。
 * page をすべて削っても超える場合は title と url を切り詰める。
 */
function fitSnapshot(snapshot: Snapshot): Snapshot {
  if (serializedBytes(snapshot) <= SNAPSHOT_MAX_BYTES) return snapshot;
  const lines = snapshot.page === "" ? [] : snapshot.page.split("\n");
  const keep = (count: number): Snapshot => ({
    ...snapshot,
    page: lines.slice(0, count).join("\n"),
    truncated: true,
  });
  // 行数に対して直列化の長さは単調に増えるため、収まる最大の行数を二分探索で求める。
  let low = 0;
  let high = lines.length;
  while (low < high) {
    const middle = Math.ceil((low + high) / 2);
    if (serializedBytes(keep(middle)) <= SNAPSHOT_MAX_BYTES) {
      low = middle;
    } else {
      high = middle - 1;
    }
  }
  const fitted = keep(low);
  if (serializedBytes(fitted) > SNAPSHOT_MAX_BYTES) {
    fitted.title = truncateChars(fitted.title, FALLBACK_TITLE_CHARS);
    fitted.url = truncateChars(fitted.url, FALLBACK_URL_CHARS);
  }
  return fitted;
}

/** 値の除去の対象となる役割かを返す判定を作る。role 属性値は空白で区切られた個々の役割の名前に分ける。 */
function valueRoles(
  roles: RawAriaSnapshot["roles"],
): (role: string) => boolean {
  if (roles === "all") return () => true;
  const names = new Set([
    ...VALUE_ROLES,
    ...roles.flatMap((role) =>
      role.split(/\s+/u).filter((name) => name !== ""),
    ),
  ]);
  return (role) => names.has(role);
}

/**
 * ariaSnapshot の出力から値を除き、username をマスクして上限を適用し、page の見出し行が持つ ref を集める。
 * 形に合わない行がある場合と、password または入力した TOTP コードのいずれかの形が、マスク前・マスク後
 * （いずれも切り詰め前の全文）・直列化結果のいずれかに完全一致で含まれる場合は SnapshotRejectedError を送出する。
 * 部分一致は判定しない。
 */
export function finalizeSnapshot(
  raw: RawAriaSnapshot,
  settled: boolean,
  secrets: SnapshotSecrets,
): FinalizedSnapshot {
  const lines = parseSnapshotLines(raw.aria);
  const page = removeValues(lines, valueRoles(raw.roles)).join("\n");
  const rejected = [secrets.password, ...secrets.totpCodes];
  if (containsSecret([raw.url, raw.title, page], rejected)) {
    throw new SnapshotRejectedError();
  }
  const { username } = secrets;
  const masked = {
    url: maskUsername(raw.url, username),
    title: maskUsername(raw.title, username),
    page: maskUsername(page, username),
  };
  if (containsSecret([masked.url, masked.title, masked.page], rejected)) {
    throw new SnapshotRejectedError();
  }
  const snapshot = fitSnapshot({ ...masked, settled });
  if (
    containsSecret(
      [snapshot.url, snapshot.title, snapshot.page, JSON.stringify(snapshot)],
      rejected,
    )
  ) {
    throw new SnapshotRejectedError();
  }
  return { snapshot, refs: collectRefs(snapshot.page) };
}
