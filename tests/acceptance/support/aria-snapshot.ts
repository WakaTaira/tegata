/**
 * Issue #57 acceptance-test support (aria snapshot and refs). Owned by the
 * acceptance suite (gauntlet); do not modify during implementation.
 *
 * Everything in this file is a pinned implementation contract:
 *   - `snapshot.page` is the Playwright AI aria snapshot (YAML, one node per
 *     line, `^(I)- KEY(: VALUE)?$`, KEY = `role( "<JSON name>")?( [attr])*`
 *     or that whole KEY in single quotes with `'` doubled) with field values
 *     removed and `[filled]` added to the heading line of a filled field
 *   - elements are addressed by the `[ref=…]` of a heading line's KEY
 *     (`^(f\d+)?e\d+$`); "finding a line" means picking the one line of a
 *     role and name (e.g. `button "Next step"`) and reading that ref
 *   - `login_step` accepts exactly one of `ref` / `selector` for `click`,
 *     `wait_for`, `fill`, each `fill_submit` fill, and the `submit` object
 *     form (`{click: {ref}}`, `{press_enter: {selector}}`, …); the string form
 *     `{click: "<css>"}` stays a selector shorthand
 *   - the new error code `FILL_TARGET_REFUSED` (a fill into a frame whose URL
 *     origin differs from the main frame's) ends the stepwise login
 *   - the target fixture's `/trap/` pages (names, one-screen, remembered,
 *     frames, values, huge, huge/echo, echo) and `GET /trap/state` reporting
 *     `{requests, posts, inputs}` with every field value masked like the
 *     `/stepwise/` state; the planted `/trap/values/` defaults are
 *     `TRAP_VALUE_CANARIES`
 */
import { expect } from "vitest";
import type { TargetFixture } from "./harness.js";
import type {
  DoneResult,
  PendingResult,
  Snapshot,
  StepOutcome,
  StepwiseCaller,
} from "./stepwise-login.js";

/** One parsed line of `snapshot.page`. */
export interface SnapshotLine {
  /** Number of leading spaces. */
  indent: number;
  role: string;
  /** The accessible name (JSON-decoded), when the KEY carries one. */
  name?: string;
  /** Attribute bodies of the KEY, e.g. `ref=e3`, `level=1`, `filled`. */
  attrs: string[];
  /** The `[ref=…]` of the KEY's attribute part. */
  ref?: string;
  /** Text after `: `, when the line carries a value. */
  value?: string;
  /** True when the line ends with `:` (it has child lines). */
  opensChildren: boolean;
  /** Whether the KEY was wrapped in single quotes. */
  quotedKey: boolean;
  raw: string;
}

const KEY_PATTERN =
  /^([^\s":'[\]]+)(?: ("(?:[^"\\]|\\.)*"))?((?: \[[^\]]*\])*)/;

function parseKey(
  key: string,
): Pick<SnapshotLine, "role" | "name" | "attrs" | "ref"> & { rest: string } {
  const m = KEY_PATTERN.exec(key);
  if (m === null) throw new Error(`unparsable KEY: ${key}`);
  const attrs = (m[3].match(/\[[^\]]*\]/g) ?? []).map((a) => a.slice(1, -1));
  const refAttr = attrs.find((a) => a.startsWith("ref="));
  return {
    role: m[1],
    name: m[2] === undefined ? undefined : (JSON.parse(m[2]) as string),
    attrs,
    ref: refAttr?.slice("ref=".length),
    rest: key.slice(m[0].length),
  };
}

/** Parse one line, or return undefined when it does not fit the grammar. */
export function parseSnapshotLine(raw: string): SnapshotLine | undefined {
  const m = /^( *)- (.*)$/.exec(raw);
  if (m === null) return undefined;
  const indent = m[1].length;
  const body = m[2];
  try {
    let keyText: string;
    let tail: string;
    let quotedKey = false;
    if (body.startsWith("'")) {
      let i = 1;
      for (; i < body.length; i += 1) {
        if (body[i] !== "'") continue;
        if (body[i + 1] === "'") {
          i += 1;
          continue;
        }
        break;
      }
      if (i >= body.length) return undefined;
      keyText = body.slice(1, i).replaceAll("''", "'");
      tail = body.slice(i + 1);
      quotedKey = true;
    } else {
      const parsed = parseKey(body);
      keyText = body.slice(0, body.length - parsed.rest.length);
      tail = parsed.rest;
    }
    const key = parseKey(keyText);
    if (key.rest !== "") return undefined;
    if (tail !== "" && tail !== ":" && !tail.startsWith(": ")) return undefined;
    return {
      indent,
      role: key.role,
      name: key.name,
      attrs: key.attrs,
      ref: key.ref,
      value: tail.startsWith(": ") ? tail.slice(2) : undefined,
      opensChildren: tail === ":",
      quotedKey,
      raw,
    };
  } catch {
    return undefined;
  }
}

/** Every line of `snapshot.page`, raw. */
export function rawLines(snapshot: Snapshot): string[] {
  expect(
    typeof snapshot.page,
    `the snapshot has no page string: ${JSON.stringify(snapshot).slice(0, 400)}`,
  ).toBe("string");
  return snapshot.page.split("\n").filter((line) => line !== "");
}

/** Every line of `snapshot.page`, parsed; unparsable lines fail the test. */
export function snapshotLines(snapshot: Snapshot): SnapshotLine[] {
  return rawLines(snapshot).map((raw) => {
    const line = parseSnapshotLine(raw);
    expect(line, `a page line does not fit the grammar: ${raw}`).toBeDefined();
    return line as SnapshotLine;
  });
}

function excerpt(snapshot: Snapshot): string {
  const page = typeof snapshot.page === "string" ? snapshot.page : "";
  return page.length > 1500 ? `${page.slice(0, 1500)}…` : page;
}

/** The first line of `role` with exactly `name` (no name when undefined). */
export function findLine(
  snapshot: Snapshot,
  role: string,
  name?: string,
): SnapshotLine {
  const line = snapshotLines(snapshot).find(
    (l) => l.role === role && l.name === name,
  );
  expect(
    line,
    `no ${role}${name === undefined ? "" : ` ${JSON.stringify(name)}`} line in the snapshot of ${snapshot.url}:\n${excerpt(snapshot)}`,
  ).toBeDefined();
  return line as SnapshotLine;
}

/** The ref of the line of `role` and `name` (see `findLine`). */
export function refOf(snapshot: Snapshot, role: string, name?: string): string {
  const line = findLine(snapshot, role, name);
  expect(line.ref, `the line has no ref: ${line.raw}`).toMatch(/^(f\d+)?e\d+$/);
  return line.ref as string;
}

/** The ref of the `index`-th unnamed line of `role`, in document order. */
export function nthUnnamedRef(
  snapshot: Snapshot,
  role: string,
  index: number,
): string {
  const lines = snapshotLines(snapshot).filter(
    (l) => l.role === role && l.name === undefined && l.ref !== undefined,
  );
  expect(
    lines.length,
    `fewer than ${index + 1} unnamed ${role} lines in the snapshot of ${snapshot.url}:\n${excerpt(snapshot)}`,
  ).toBeGreaterThan(index);
  return lines[index].ref as string;
}

/** The lines directly under `line` (indent + 2), in order. */
export function directChildren(
  snapshot: Snapshot,
  line: SnapshotLine,
): SnapshotLine[] {
  const lines = snapshotLines(snapshot);
  const start = lines.findIndex((l) => l.raw === line.raw);
  expect(start, `line not in the snapshot: ${line.raw}`).toBeGreaterThanOrEqual(
    0,
  );
  const children: SnapshotLine[] = [];
  for (const next of lines.slice(start + 1)) {
    if (next.indent <= line.indent) break;
    if (next.indent === line.indent + 2) children.push(next);
  }
  return children;
}

/** Every ref the KEYs of `snapshot.page` carry. */
export function refsIn(snapshot: Snapshot): string[] {
  return snapshotLines(snapshot).flatMap((l) =>
    l.ref === undefined ? [] : [l.ref],
  );
}

export function expectPending(
  outcome: StepOutcome,
  what: string,
): PendingResult {
  expect(outcome.error, `${what} failed: ${outcome.raw}`).toBeUndefined();
  expect(outcome.result?.state, `${what}: ${outcome.raw}`).toBe("pending");
  return outcome.result as PendingResult;
}

export function expectDone(outcome: StepOutcome, what: string): DoneResult {
  expect(outcome.error, `${what} failed: ${outcome.raw}`).toBeUndefined();
  expect(outcome.result?.state, `${what}: ${outcome.raw}`).toBe("done");
  return outcome.result as DoneResult;
}

export interface FlowRun {
  /** Every `login_step` outcome, in order. */
  outcomes: StepOutcome[];
  /** The outcome of the final `fill_submit` (the TOTP), not yet checked. */
  last: StepOutcome;
}

/**
 * The Issue #46 AC-160 procedure on the fixture's `/stepwise/` site, from the
 * username page: fill the username, click Next, `fill_submit` the password,
 * click More options, click the authenticator app link, `fill_submit` the
 * TOTP. Every element is the ref of a line of the latest snapshot. Every step
 * but the last must answer `pending`; with `snapshotBetween`, a `snapshot`
 * action follows each of them. With `cssSubmit`, both `submit`s use the
 * string form `{click: "<css>"}` instead of `{click: {ref}}`.
 */
export async function driveFlow(
  call: StepwiseCaller,
  loginId: string,
  start: Snapshot,
  opts: { snapshotBetween?: boolean; cssSubmit?: boolean } = {},
): Promise<FlowRun> {
  const outcomes: StepOutcome[] = [];
  let snapshot = start;
  const step = async (what: string, action: Record<string, unknown>) => {
    const outcome = await call("login_step", { login_id: loginId, ...action });
    outcomes.push(outcome);
    snapshot = expectPending(outcome, what).snapshot;
    if (opts.snapshotBetween) {
      const again = await call("login_step", {
        login_id: loginId,
        action: "snapshot",
      });
      outcomes.push(again);
      snapshot = expectPending(again, `snapshot after ${what}`).snapshot;
    }
  };
  const submit = (css: string, role: string, name: string) =>
    opts.cssSubmit
      ? { click: css }
      : { click: { ref: refOf(snapshot, role, name) } };
  await step("fill the username", {
    action: "fill",
    ref: refOf(snapshot, "textbox", "Username or email address"),
    value: "{{username}}",
  });
  await step("click Next", {
    action: "click",
    ref: refOf(snapshot, "button", "Next"),
  });
  await step("fill_submit the password", {
    action: "fill_submit",
    fills: [
      { ref: refOf(snapshot, "textbox", "Password"), value: "{{password}}" },
    ],
    submit: submit("#sign-in", "button", "Sign in"),
  });
  await step("click More options", {
    action: "click",
    ref: refOf(snapshot, "button", "More options"),
  });
  await step("click the authenticator app link", {
    action: "click",
    ref: refOf(snapshot, "link", "Use your authenticator app"),
  });
  const last = await call("login_step", {
    login_id: loginId,
    action: "fill_submit",
    fills: [
      {
        ref: refOf(snapshot, "textbox", "Authentication code"),
        value: "{{totp}}",
      },
    ],
    submit: submit("#verify", "button", "Verify"),
  });
  outcomes.push(last);
  return { outcomes, last };
}

/** Default values planted on `/trap/values/` (mirrors the target fixture). */
export const TRAP_VALUE_CANARIES = {
  defaultValue: "trapval-default-value-4c1e9a",
  csrfToken: "trapval-hidden-csrf-token-8d2f71",
  dataAttribute: "trapval-data-attribute-5b7e03",
  scriptVariable: "trapval-inline-script-variable-a9c4d6",
  textarea: "trapval-textarea-default-31f8b2",
  explicitRole: "trapval-explicit-role-note-e60d5c",
  labeledText: "trapval-labeled-placeholder-text-7a3c19",
  labeledPassword: "trapval-labeled-placeholder-password-0f92e4",
} as const;

export interface TrapFixtureState {
  requests: Array<{ method: string; host: string; path: string }>;
  posts: Array<{ path: string; fields: Record<string, string> }>;
  inputs: Array<{ path: string; origin: string; field: string; value: string }>;
}

/** Read the `/trap/` pages' record. */
export async function trapState(
  fixture: TargetFixture,
): Promise<TrapFixtureState> {
  const res = await fetch(`${fixture.url}/trap/state`);
  if (!res.ok) throw new Error(`fixture trap state failed: ${res.status}`);
  return (await res.json()) as TrapFixtureState;
}

/** `login_begin` parameters for a `/trap/` page. */
export function trapBeginParams(
  fixture: TargetFixture,
  page: string,
  credId = "mock:trap-1",
): Record<string, unknown> {
  return {
    cred_id: credId,
    target_url: `${fixture.url}/trap/${page}`,
    success_selector: "#signed-in",
    failure_selector: "#login-error",
  };
}

function htmlEscape(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

/** The 8 encoded forms the snapshot check covers. */
function encodedSecretForms(value: string): string[] {
  const bytes = Buffer.from(value, "utf8");
  const percent = [...bytes]
    .map((b) => `%${b.toString(16).padStart(2, "0")}`)
    .join("");
  return [
    value,
    htmlEscape(value),
    encodeURIComponent(value),
    percent.toUpperCase(),
    percent.toLowerCase(),
    bytes.toString("base64").replace(/=+$/, ""),
    bytes.toString("hex").toLowerCase(),
    bytes.toString("hex").toUpperCase(),
  ];
}

/** Playwright's whitespace normalisation of a displayed string. */
function normalized(value: string): string {
  return value.replace(/[​­]/g, "").trim().replace(/\s+/g, " ");
}

/** Playwright's YAML double-quote escaping (inside the quotes). */
function yamlEscaped(value: string): string {
  let out = "";
  for (const ch of value) {
    const code = ch.codePointAt(0) as number;
    if (ch === "\\") out += "\\\\";
    else if (ch === '"') out += '\\"';
    else if (ch === "\n") out += "\\n";
    else if (ch === "\t") out += "\\t";
    else if (code < 0x20 || code === 0x7f)
      out += `\\x${code.toString(16).padStart(2, "0")}`;
    else out += ch;
  }
  return out;
}

/**
 * Every form of a secret a snapshot may show: the 8 encodings of the raw and
 * the normalised value, and the 6 display forms (N, J, Y and their
 * single-quote-doubled variants). Duplicates and empty forms are dropped.
 */
export function secretForms(value: string): string[] {
  const n = normalized(value);
  const j = JSON.stringify(n).slice(1, -1);
  const y = yamlEscaped(n);
  const sq = (s: string) => s.replaceAll("'", "''");
  const forms = [
    ...encodedSecretForms(value),
    ...encodedSecretForms(n),
    n,
    j,
    y,
    sq(n),
    sq(j),
    sq(y),
  ];
  return [...new Set(forms)].filter((f) => f !== "");
}

/** `label: form` for every form of `secret` found in `text`. */
export function secretHits(
  label: string,
  text: string,
  secret: string,
): string[] {
  return secretForms(secret)
    .filter((form) => text.includes(form))
    .map((form) => `${label}: ${JSON.stringify(form)}`);
}
