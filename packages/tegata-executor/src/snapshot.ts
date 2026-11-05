/**
 * Builds the stepwise login snapshot (an aria snapshot with values removed), checks it for secrets,
 * and applies the size limit.
 */

/** Upper bound on the serialized snapshot (bytes). */
export const SNAPSHOT_MAX_BYTES = 64 * 1024;
// Length (in characters) to which title and url are truncated when the limit is still exceeded
// after dropping all of page.
const FALLBACK_TITLE_CHARS = 256;
const FALLBACK_URL_CHARS = 2048;

export const USERNAME_MASK = "[username]";
/** Marker appended to the heading line of a field whose value was removed. */
export const FILLED_MARK = " [filled]";

/**
 * Roles that carry a value. Playwright emits the value of input and textarea regardless of explicit
 * role, so these are combined with the
 * role attribute values of input and textarea collected from the page as targets for value removal.
 */
export const VALUE_ROLES: readonly string[] = [
  "textbox",
  "searchbox",
  "spinbutton",
  "slider",
  "combobox",
];

/** Format of a ref (`e<n>`, or `f<n>e<n>` inside an iframe). */
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
 * Material for the snapshot received from the page. roles holds the role attribute values of input
 * and textarea collected from the page,
 * and "all", used when they could not be collected, means every role is a target for value removal.
 */
export type RawAriaSnapshot = {
  url: string;
  title: string;
  aria: string;
  roles: readonly string[] | "all";
};

/** The checked snapshot, and the set of refs held by the heading lines of its page. */
export type FinalizedSnapshot = {
  snapshot: Snapshot;
  refs: Set<string>;
};

/**
 * Indicates that the snapshot contains a known secret, or cannot be returned because its format is
 * unknown.
 */
export class SnapshotRejectedError extends Error {}

/**
 * Waits inside the page for up to `maxMs` for DOM changes to stop for `quietMs`. Returns true if
 * they stopped.
 * Returns false if an exception caused by tampering with the page's built-in objects occurs,
 * because settling cannot be determined.
 * It is serialized into the page, so it must not reference external identifiers.
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
 * Inside the page, clears the entered field if it is still in the document and its value is not
 * empty, then fires input / change.
 * It has no return value and catches every exception, so that neither the value nor exception text
 * is carried out of the page.
 * It is serialized into the page, so it must not reference external identifiers.
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
    // A failure to clear the field is left to the caller's browser teardown or subsequent checks.
  }
}

/**
 * One line of the aria snapshot. keyEnd is the end of KEY (the position of the closing `'` if it is
 * wrapped in single quotes).
 */
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
// KEY is role( NAME)?( [attr])*, and NAME is a JSON string or an unquoted /…/.
const ROLE_PATTERN = /^\/?[a-z][a-z0-9-]*/u;
const JSON_NAME_PATTERN = /^ ("(?:[^"\\]|\\[\s\S])*")/u;
const ATTRS_PATTERN = /^(?: \[[a-z]+(?:=[A-Za-z0-9-]+)?\])*/u;
const ATTR_PATTERN = /\[([^\]]*)\]/gu;

type ParsedKey = { role: string; name?: string; attrs: string[] };
type KeyMatch = ParsedKey & { length: number };

/** Returns whether what follows KEY is one of `: VALUE`, `:`, or end of line. */
function isLineTail(tail: string): boolean {
  return tail === "" || tail === ":" || /^: [\s\S]+$/u.test(tail);
}

/**
 * Reads the attribute section after the name (from at), and returns KEY if what follows satisfies
 * isTail.
 */
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
 * Reads a KEY whose name is an unquoted /…/. The name ends at the first `/` after which the
 * attribute section and isTail match.
 * In an unquoted KEY the name does not contain `: ` (if it did, the whole KEY would be wrapped in
 * single quotes), and in a single-quoted KEY nothing follows it,
 * so if a `/` inside the name were taken as the end, the trailing `/` of the name would fail to
 * match the attribute section or isTail. This end is therefore unique.
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

/**
 * Reads KEY from the start and returns it with the length read. Returns undefined if what follows
 * KEY does not satisfy isTail.
 */
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

/**
 * Returns the position of the closing `'` of a KEY wrapped in single quotes. An inner `'` is
 * represented as `''`.
 */
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

/**
 * Reads a line of the form `^(I)- KEY(: VALUE)?$`. Returns undefined if the line does not match.
 */
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

/**
 * Splits the ariaSnapshot output into lines. Throws SnapshotRejectedError if even one line does not
 * match the form.
 */
export function parseSnapshotLines(aria: string): SnapshotLine[] {
  if (aria === "") return [];
  return aria.split("\n").map((raw) => {
    const line = parseSnapshotLine(raw);
    if (line === undefined) throw new SnapshotRejectedError();
    return line;
  });
}

/**
 * Returns whether the line is not a node heading line (an attribute line such as `- text:` or `-
 * /url:`).
 */
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

/**
 * Writes back a heading line with its value removed. An inline value is dropped, and a filled field
 * gets a marker at the end of KEY.
 */
function renderValueHeading(line: SnapshotLine, filled: boolean): string {
  return `${line.raw.slice(0, line.keyEnd)}${filled ? FILLED_MARK : ""}${
    line.quoted ? "'" : ""
  }${line.opensChildren ? ":" : ""}`;
}

/**
 * Removes values from the heading lines of target roles. Drops an inline value, and for a line with
 * children drops the `- text:` line directly below (indent +2).
 * Lines `- /…`, lines `- option`, and deeper lines are left untouched. A line whose non-empty value
 * was dropped gets the marker.
 */
export function removeValues(
  lines: readonly SnapshotLine[],
  isValueRole: (role: string) => boolean,
): string[] {
  const isTarget = (line: SnapshotLine): boolean =>
    !isPseudoLine(line) && isValueRole(line.role);
  const filled = new Set<number>();
  const dropped = new Set<number>();
  // Stacks the indices of ancestor lines that have children, from shallowest indent.
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

/**
 * Collects the refs in the attribute section of KEY on the heading lines of the page. A `[ref=…]`
 * inside a name, value, or `- text:` is not counted.
 */
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
    // A value containing an unpaired surrogate cannot be encoded, so that form is not searched.
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
 * Forms used to search for a secret (raw, HTML-escaped, encodeURIComponent, percent-encoding of
 * every byte, base64, hex).
 * base64 is searched without the trailing `=` so that it matches regardless of padding.
 * Case-sensitive encodings include both cases.
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

/**
 * Playwright's whitespace normalization (removing U+200B and U+00AD, trimming leading and trailing
 * whitespace, and replacing runs of whitespace with one space).
 */
function normalizeWhitespace(value: string): string {
  return value
    .replace(/[\u200b\u00ad]/gu, "")
    .trim()
    .replace(/\s+/gu, " ");
}

// Playwright's YAML double-quote escaping. If namedControls is false, control characters other than
// newline and tab become \xNN.
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
 * Forms displayed in the aria snapshot (display forms). N is whitespace normalization, J is the
 * inside of a JSON string in the name position,
 * and Y is the inside of YAML double quotes in the value and `- text:` positions; the single-quoted
 * key forms with each `'` doubled to `''` are added.
 * Y includes both Playwright's implementation (which writes \b, \f, and \r by name) and the form
 * that writes control characters as \xNN.
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

/**
 * Forms used for the check. The previous 8 forms are applied to both the raw and the normalized
 * value, and the display forms are added.
 */
export function rejectionForms(value: string): string[] {
  if (value === "") return [];
  return nonEmptyUnique([
    ...secretForms(value),
    ...secretForms(normalizeWhitespace(value)),
    ...displayForms(value),
  ]);
}

/**
 * Returns the forms to mask for the username (raw, HTML-escaped, URL-encoded, and display forms) in
 * descending length.
 */
function usernameForms(username: string): string[] {
  if (username === "") return [];
  return nonEmptyUnique([
    username,
    escapeHtml(username),
    tryEncodeURIComponent(username),
    ...displayForms(username),
  ]).sort((left, right) => right.length - left.length);
}

/** Replaces exact occurrences of the username with `[username]`. */
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

/**
 * Returns whether any form of any scanned secret is contained, as an exact match, in any of the
 * strings.
 */
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
 * When the 64 KiB limit is exceeded, sets truncated and drops page from the end line by line until
 * it fits.
 * If it still exceeds the limit after dropping all of page, title and url are truncated.
 */
function fitSnapshot(snapshot: Snapshot): Snapshot {
  if (serializedBytes(snapshot) <= SNAPSHOT_MAX_BYTES) return snapshot;
  const lines = snapshot.page === "" ? [] : snapshot.page.split("\n");
  const keep = (count: number): Snapshot => ({
    ...snapshot,
    page: lines.slice(0, count).join("\n"),
    truncated: true,
  });
  // Serialized length grows monotonically with the line count, so the largest line count that fits
  // is found by binary search.
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

/**
 * Creates a predicate for whether a role is a target for value removal. A role attribute value is
 * split into individual role names by whitespace.
 */
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
 * Removes values from the ariaSnapshot output, masks the username, applies the limit, and collects
 * the refs held by the heading lines of the page.
 * Throws SnapshotRejectedError if a line does not match the form, or if any form of the password or
 * the entered TOTP code is contained as an exact match in the
 * pre-mask text, the post-mask text (both before truncation, in full), or the serialized result.
 * Partial matches are not checked.
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
