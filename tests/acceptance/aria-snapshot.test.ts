// AC-184 .. AC-201 — the stepwise login snapshot is the value-free AI aria
// snapshot (`snapshot.page`, YAML lines with `[ref=…]`): names come from the
// browser (aria-labelledby, SVG title, image alt, submit value), hidden
// elements and field values stay out (`[filled]` marks a filled field), the
// username is masked, iframes are included, the page is cut by whole lines
// at 64 KiB while the secret check covers the whole page, elements are
// addressed by `ref` (or `selector`, exactly one), only refs of the latest
// snapshot resolve, and values go only into frames of the main frame's
// origin (`FILL_TARGET_REFUSED` otherwise).
// Traceability: docs/secret/briefs/tegata-issue57-aria-snapshot.md
// acceptance condition AC-184 .. AC-201.

import fs from "node:fs";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { expect, test } from "vitest";
import {
  directChildren,
  driveFlow,
  expectDone,
  expectPending,
  findLine,
  rawLines,
  refOf,
  refsIn,
  secretHits,
  snapshotLines,
  TRAP_VALUE_CANARIES,
  trapBeginParams,
  trapState,
} from "./support/aria-snapshot.js";
import { bins, rawRpc } from "./support/harness.js";
import { readAuditRecords, waitUntil } from "./support/phase3.js";
import {
  beginParams,
  browserCount,
  maskedDigest,
  mcpCaller,
  type PendingResult,
  type Snapshot,
  type StepOutcome,
  type StepwiseCaller,
  type StepwiseStack,
  startStepwiseStack,
  stepwiseState,
  stopStepwiseStack,
  waitForBrowserCount,
} from "./support/stepwise-login.js";

/** The serialised snapshot limit. */
const SNAPSHOT_LIMIT_BYTES = 64 * 1024;

interface Begun {
  outcome: StepOutcome;
  pending: PendingResult;
}

async function begin(
  call: StepwiseCaller,
  params: Record<string, unknown>,
): Promise<Begun> {
  const outcome = await call("login_begin", params);
  return { outcome, pending: expectPending(outcome, "login_begin") };
}

function auditText(stack: StepwiseStack): string {
  return fs.existsSync(stack.daemon.auditLogPath)
    ? fs.readFileSync(stack.daemon.auditLogPath, "utf8")
    : "";
}

/** The fixture's trap records whose path starts with `prefix`. */
async function trapRecords(stack: StepwiseStack, prefix: string) {
  const state = await trapState(stack.fixture);
  return {
    posts: state.posts.filter((p) => p.path.startsWith(prefix)),
    inputs: state.inputs,
  };
}

test("AC-184: /trap/names/ is described by browser-computed names", async () => {
  // Given: /trap/names/
  const stack = await startStepwiseStack();
  try {
    // When: login_begin
    const outcome = await mcpCaller(stack)(
      "login_begin",
      trapBeginParams(stack.fixture, "names/"),
    );

    // Then: state "pending", and the snapshot has `page` and neither `text`
    // nor `elements`
    const { snapshot } = expectPending(outcome, "login_begin");
    expect(typeof snapshot.page, outcome.raw).toBe("string");
    expect(Object.keys(snapshot)).not.toContain("text");
    expect(Object.keys(snapshot)).not.toContain("elements");

    // Then: `page` has the lines button "Next step", button "Log in" and
    // button "Forgot password"
    findLine(snapshot, "button", "Next step");
    findLine(snapshot, "button", "Log in");
    findLine(snapshot, "button", "Forgot password");

    // Then: the username field's line is textbox "Phone, email, or
    // username", its name not doubled
    findLine(snapshot, "textbox", "Phone, email, or username");
    const label = "Phone, email, or username";
    for (const line of snapshotLines(snapshot)) {
      const name = line.name ?? "";
      expect(name.indexOf(label), line.raw).toBe(name.lastIndexOf(label));
    }
  } finally {
    await stopStepwiseStack(stack);
  }
});

test("AC-185: refs drive /trap/names/ through to done", async () => {
  // Given: /trap/names/
  const stack = await startStepwiseStack();
  try {
    const call = mcpCaller(stack);
    const begun = await begin(call, trapBeginParams(stack.fixture, "names/"));
    const loginId = begun.pending.login_id;
    let snapshot = begun.pending.snapshot;

    // When: find the username field's and "Log in"'s lines and fill_submit
    // with their refs (fills [{ref, "{{username}}"}], submit {click: {ref}})
    snapshot = expectPending(
      await call("login_step", {
        login_id: loginId,
        action: "fill_submit",
        fills: [
          {
            ref: refOf(snapshot, "textbox", "Phone, email, or username"),
            value: "{{username}}",
          },
        ],
        submit: { click: { ref: refOf(snapshot, "button", "Log in") } },
      }),
      "fill_submit the username",
    ).snapshot;

    // When: -> fill_submit with the refs of the next screen's password field
    // and submit button
    const last = await call("login_step", {
      login_id: loginId,
      action: "fill_submit",
      fills: [
        { ref: refOf(snapshot, "textbox", "Password"), value: "{{password}}" },
      ],
      submit: { click: { ref: refOf(snapshot, "button", "Sign in") } },
    });

    // Then: state "done", and the fixture received the right username and
    // password
    expectDone(last, "fill_submit the password");
    const { posts } = await trapRecords(stack, "/trap/names/");
    expect(
      posts.some(
        (p) =>
          p.path === "/trap/names/username" &&
          p.fields.username === "<username>",
      ),
      JSON.stringify(posts),
    ).toBe(true);
    expect(
      posts.some(
        (p) =>
          p.path === "/trap/names/password" &&
          p.fields.password === "<password>",
      ),
      JSON.stringify(posts),
    ).toBe(true);
  } finally {
    await stopStepwiseStack(stack);
  }
});

test("AC-186: the hidden duplicate form stays out of /trap/one-screen/", async () => {
  // Given: /trap/one-screen/
  const stack = await startStepwiseStack();
  try {
    const call = mcpCaller(stack);

    // When: login_begin
    const begun = await begin(
      call,
      trapBeginParams(stack.fixture, "one-screen/"),
    );
    const { snapshot } = begun.pending;

    // Then: `page` does not contain "Hidden duplicate sign in"
    expect(typeof snapshot.page, begun.outcome.raw).toBe("string");
    expect(snapshot.page).not.toContain("Hidden duplicate sign in");

    // When: -> one fill_submit with the refs of the username field, the
    // password field and the submit button
    const last = await call("login_step", {
      login_id: begun.pending.login_id,
      action: "fill_submit",
      fills: [
        { ref: refOf(snapshot, "textbox", "Username"), value: "{{username}}" },
        { ref: refOf(snapshot, "textbox", "Password"), value: "{{password}}" },
      ],
      submit: { click: { ref: refOf(snapshot, "button", "Sign in") } },
    });

    // Then: state "done"
    expectDone(last, "fill_submit");
  } finally {
    await stopStepwiseStack(stack);
  }
});

test("AC-187: a username shown as text is masked on /trap/remembered/", async () => {
  // Given: /trap/remembered/
  const stack = await startStepwiseStack();
  try {
    const call = mcpCaller(stack);

    // When: login_begin
    const begun = await begin(
      call,
      trapBeginParams(stack.fixture, "remembered/"),
    );
    const { snapshot } = begun.pending;

    // Then: `page` contains "[username]", and the raw username is not in
    // the answer
    expect(typeof snapshot.page, begun.outcome.raw).toBe("string");
    expect(snapshot.page).toContain("[username]");
    expect(begun.outcome.raw).not.toContain(stack.canaries.username);

    // When: -> fill_submit with the password field's ref
    const last = await call("login_step", {
      login_id: begun.pending.login_id,
      action: "fill_submit",
      fills: [
        { ref: refOf(snapshot, "textbox", "Password"), value: "{{password}}" },
      ],
      submit: { click: { ref: refOf(snapshot, "button", "Continue") } },
    });

    // Then: state "done"
    expectDone(last, "fill_submit the password");
  } finally {
    await stopStepwiseStack(stack);
  }
});

test("AC-188: f-refs fill a same-origin iframe's form", async () => {
  // Given: the same-origin iframe's form on /trap/frames/
  const stack = await startStepwiseStack();
  try {
    const call = mcpCaller(stack);
    const begun = await begin(call, trapBeginParams(stack.fixture, "frames/"));
    const { snapshot } = begun.pending;
    const user = refOf(snapshot, "textbox", "Frame username");
    const pass = refOf(snapshot, "textbox", "Frame password");
    const submit = refOf(snapshot, "button", "Frame sign in");
    for (const ref of [user, pass, submit]) expect(ref).toMatch(/^f\d+e\d+$/);

    // When: fill_submit the username and the password with refs that start
    // with "f"
    const last = await call("login_step", {
      login_id: begun.pending.login_id,
      action: "fill_submit",
      fills: [
        { ref: user, value: "{{username}}" },
        { ref: pass, value: "{{password}}" },
      ],
      submit: { click: { ref: submit } },
    });

    // Then: state "done"
    expectDone(last, "fill_submit into the iframe");
    const { posts } = await trapRecords(stack, "/trap/frames/");
    expect(posts, JSON.stringify(posts)).toEqual([
      {
        path: "/trap/frames/same/login",
        fields: { username: "<username>", password: "<password>" },
      },
    ]);
  } finally {
    await stopStepwiseStack(stack);
  }
});

test("AC-189: a fill into a cross-origin iframe is refused", async () => {
  // Given: /trap/frames/
  const stack = await startStepwiseStack();
  try {
    const call = mcpCaller(stack);
    const begun = await begin(call, trapBeginParams(stack.fixture, "frames/"));
    const loginId = begun.pending.login_id;
    const { snapshot } = begun.pending;

    // When: fill_submit with the cross-origin iframe's password field's ref
    // among the fills (after a same-origin field)
    const refused = await call("login_step", {
      login_id: loginId,
      action: "fill_submit",
      fills: [
        {
          ref: refOf(snapshot, "textbox", "Frame username"),
          value: "{{username}}",
        },
        {
          ref: refOf(snapshot, "textbox", "Partner password"),
          value: "{{password}}",
        },
      ],
      submit: { click: { ref: refOf(snapshot, "button", "Frame sign in") } },
    });
    const next = await call("login_step", {
      login_id: loginId,
      action: "snapshot",
    });

    // Then: FILL_TARGET_REFUSED
    expect(refused.error, refused.raw).toBe("FILL_TARGET_REFUSED");

    // Then: the fixture received no input into any field
    const records = await trapRecords(stack, "/trap/frames/");
    expect(records.inputs, JSON.stringify(records.inputs)).toEqual([]);
    expect(records.posts, JSON.stringify(records.posts)).toEqual([]);

    // Then: no browser is left
    await waitForBrowserCount(stack, 0);

    // Then: the audit's login_step record has outcome FILL_TARGET_REFUSED
    const stepRecord = () =>
      readAuditRecords(stack.daemon.auditLogPath).records.find(
        (r) =>
          r.method === "login_step" &&
          r.login_id === loginId &&
          r.action === "fill_submit",
      );
    await waitUntil(
      "the fill_submit login_step record",
      () => stepRecord() !== undefined,
      10_000,
    );
    expect(stepRecord()?.outcome).toBe("FILL_TARGET_REFUSED");

    // Then: the next login_step on the same login_id is NOT_FOUND
    expect(next.error, next.raw).toBe("NOT_FOUND");
  } finally {
    await stopStepwiseStack(stack);
  }
});

test("AC-190: planted values never reach the /trap/values/ snapshot", async () => {
  // Given: /trap/values/
  const stack = await startStepwiseStack();
  try {
    // When: login_begin
    const begun = await begin(
      mcpCaller(stack),
      trapBeginParams(stack.fixture, "values/"),
    );
    const { snapshot } = begun.pending;

    // Then: none of the planted canaries is in the answer (not even as a
    // `- text:` child line)
    const hits = Object.entries(TRAP_VALUE_CANARIES).filter(([, value]) =>
      begun.outcome.raw.includes(value),
    );
    expect(hits).toEqual([]);

    // Then: the heading lines of the fields with a default value carry
    // `[filled]`
    for (const [role, name] of [
      ["textbox", "Password"],
      ["textbox", "Display name"],
      ["textbox", "Referral code"],
      ["textbox", "Notes"],
      ["note", "Account note"],
    ]) {
      const line = findLine(snapshot, role, name);
      expect(line.attrs, line.raw).toContain("filled");
    }
  } finally {
    await stopStepwiseStack(stack);
  }
});

test("AC-191: a field the agent filled shows [filled] and no value", async () => {
  // Given: /trap/values/ (its username field starts empty)
  const stack = await startStepwiseStack();
  try {
    const call = mcpCaller(stack);
    const begun = await begin(call, trapBeginParams(stack.fixture, "values/"));
    const loginId = begun.pending.login_id;
    const before = findLine(begun.pending.snapshot, "textbox", "Username");
    expect(before.attrs, before.raw).not.toContain("filled");

    // When: fill ({{username}}) the username field's ref -> snapshot
    expectPending(
      await call("login_step", {
        login_id: loginId,
        action: "fill",
        ref: refOf(begun.pending.snapshot, "textbox", "Username"),
        value: "{{username}}",
      }),
      "fill the username",
    );
    const outcome = await call("login_step", {
      login_id: loginId,
      action: "snapshot",
    });
    const { snapshot } = expectPending(outcome, "snapshot");

    // Then: that field's heading line carries `[filled]`
    const line = findLine(snapshot, "textbox", "Username");
    expect(line.attrs, line.raw).toContain("filled");

    // Then: neither the line nor its direct `- text:` child lines carry the
    // value (including `[username]`)
    expect(line.value, line.raw).toBeUndefined();
    const texts = directChildren(snapshot, line).filter(
      (c) => c.role === "text",
    );
    for (const shown of [line, ...texts]) {
      expect(shown.raw).not.toContain("[username]");
      expect(shown.raw).not.toContain(stack.canaries.username);
    }
    expect(outcome.raw).not.toContain(stack.canaries.username);
  } finally {
    await stopStepwiseStack(stack);
  }
});

/** Every line parses and the page's known line kinds end where they should. */
function expectWholeLines(snapshot: Snapshot): void {
  for (const raw of rawLines(snapshot)) {
    const line = snapshotLines({ ...snapshot, page: raw })[0];
    if (line.role === "/url")
      expect(line.value, `a cut /url line: ${raw}`).toMatch(/\.html$/);
  }
}

test("AC-192: a huge page is cut by whole lines and cut refs do not resolve", async () => {
  // Given: /trap/huge/ (the form is near the end)
  const stack = await startStepwiseStack();
  try {
    const call = mcpCaller(stack);

    // When: login_begin
    const begun = await begin(call, trapBeginParams(stack.fixture, "huge/"));
    const loginId = begun.pending.login_id;
    const first = begun.pending.snapshot;

    // Then: truncated: true, the serialised snapshot is at most 64 KiB, and
    // `page` is not cut in the middle of a line
    expect(first.truncated, begun.outcome.raw.slice(0, 400)).toBe(true);
    expect(
      Buffer.byteLength(JSON.stringify(first), "utf8"),
    ).toBeLessThanOrEqual(SNAPSHOT_LIMIT_BYTES);
    expectWholeLines(first);
    expect(
      snapshotLines(first).some(
        (l) => l.role === "button" && l.name === "Sign in",
      ),
      "the form near the end was cut",
    ).toBe(false);

    // (The ref of a line that the cut removes is learned while the archive
    // is collapsed, then the archive is expanded again so the latest
    // snapshot cuts that line.)
    const collapsed = expectPending(
      await call("login_step", {
        login_id: loginId,
        action: "click",
        ref: refOf(first, "button", "Collapse archive"),
      }),
      "click Collapse archive",
    ).snapshot;
    const signIn = refOf(collapsed, "button", "Sign in");
    const expanded = expectPending(
      await call("login_step", {
        login_id: loginId,
        action: "click",
        ref: refOf(collapsed, "button", "Expand archive"),
      }),
      "click Expand archive",
    ).snapshot;
    expect(expanded.truncated).toBe(true);
    expectWholeLines(expanded);
    expect(refsIn(expanded)).not.toContain(signIn);

    // Then: a click on a ref of a cut line is SELECTOR_NOT_FOUND
    const click = await call("login_step", {
      login_id: loginId,
      action: "click",
      ref: signIn,
    });
    expect(click.error, click.raw).toBe("SELECTOR_NOT_FOUND");
    const { posts } = await trapRecords(stack, "/trap/huge/");
    expect(posts).toEqual([]);
  } finally {
    await stopStepwiseStack(stack);
  }
});

test("AC-193: a password past the cut still rejects the snapshot", async () => {
  // Given: /trap/huge/echo/ (after the submit, the password is shown past
  // the cut)
  const stack = await startStepwiseStack();
  try {
    const call = mcpCaller(stack);
    const begun = await begin(
      call,
      trapBeginParams(stack.fixture, "huge/echo/"),
    );
    const { snapshot } = begun.pending;

    // When: fill_submit with the right credential
    const rejected = await call("login_step", {
      login_id: begun.pending.login_id,
      action: "fill_submit",
      fills: [
        { ref: refOf(snapshot, "textbox", "Username"), value: "{{username}}" },
        { ref: refOf(snapshot, "textbox", "Password"), value: "{{password}}" },
      ],
      submit: { click: { ref: refOf(snapshot, "button", "Sign in") } },
    });

    // Then: SNAPSHOT_REJECTED, and no browser is left
    expect(rejected.error, rejected.raw.slice(0, 400)).toBe(
      "SNAPSHOT_REJECTED",
    );
    await waitForBrowserCount(stack, 0);
    // The page did receive the password it shows.
    const { posts } = await trapRecords(stack, "/trap/huge/echo/");
    expect(posts.map((p) => p.fields.password)).toEqual(["<password>"]);
  } finally {
    await stopStepwiseStack(stack);
  }
});

test("AC-194: a ref outside the latest snapshot keeps the login going", async () => {
  // Given: a stepwise login
  const stack = await startStepwiseStack();
  try {
    const call = mcpCaller(stack);
    const begun = await begin(call, trapBeginParams(stack.fixture, "names/"));
    const loginId = begun.pending.login_id;
    const { snapshot } = begun.pending;
    expect(refsIn(snapshot)).not.toContain("e99999");

    // When: click a ref the latest snapshot lacks (e99999) -> go on with a
    // valid ref
    const missing = await call("login_step", {
      login_id: loginId,
      action: "click",
      ref: "e99999",
    });
    const valid = await call("login_step", {
      login_id: loginId,
      action: "click",
      ref: refOf(snapshot, "button", "Forgot password"),
    });

    // Then: SELECTOR_NOT_FOUND first, state "pending" second
    expect(missing.error, missing.raw).toBe("SELECTOR_NOT_FOUND");
    expectPending(valid, "click Forgot password");
  } finally {
    await stopStepwiseStack(stack);
  }
});

test("AC-195: ref and selector together are refused on both surfaces", async () => {
  // Given: a stepwise login (the fixture's /stepwise/ username page, whose
  // Next button posts the form)
  const stack = await startStepwiseStack();
  try {
    const call = mcpCaller(stack);
    const begun = await begin(call, beginParams(stack.fixture));
    const both = {
      login_id: begun.pending.login_id,
      action: "click",
      ref: refOf(begun.pending.snapshot, "button", "Next"),
      selector: "#next",
    };
    const before = await stepwiseState(stack.fixture);

    // When: a click with both ref and selector, through MCP and straight to
    // the socket
    const viaMcp = await stack.mcp.callTool("login_step", both);
    const viaRpc = await rawRpc(stack.daemon.socketPath, "login_step", both);
    stack.observe("rpc:login_step", viaRpc);
    // The daemon's existing answer to invalid params, for comparison.
    const invalidParams = await rawRpc(stack.daemon.socketPath, "login", {});
    stack.observe("rpc:login", invalidParams);

    // Then: MCP refuses with "Input validation error"
    expect(viaMcp.isError, viaMcp.text).toBe(true);
    expect(viaMcp.text).toContain("Input validation error");

    // Then: the socket refuses like the existing invalid step
    expect(invalidParams.error).toBeDefined();
    expect(viaRpc.result, JSON.stringify(viaRpc)).toBeUndefined();
    expect(viaRpc.error?.code).toBe(invalidParams.error?.code);
    expect(viaRpc.error?.message).toBe(invalidParams.error?.message);

    // Then: neither touched the page (the Next button posts the form)
    const after = await stepwiseState(stack.fixture);
    expect(after.posts.length).toBe(before.posts.length);
    expect(after.requests.length).toBe(before.requests.length);
  } finally {
    await stopStepwiseStack(stack);
  }
});

test("AC-196: the string form of submit still reaches done", async () => {
  // Given: the existing /stepwise/ flow
  const stack = await startStepwiseStack();
  try {
    const call = mcpCaller(stack);
    const begun = await begin(call, beginParams(stack.fixture));

    // When: fill_submit with submit in the string form ({"click": "<css>"})
    // (every other element is addressed by ref)
    const flow = await driveFlow(
      call,
      begun.pending.login_id,
      begun.pending.snapshot,
      { cssSubmit: true },
    );

    // Then: state "done", as before
    expectDone(flow.last, "fill_submit the TOTP");
    const state = await stepwiseState(stack.fixture);
    expect(state.totp.some((t) => t.valid)).toBe(true);
  } finally {
    await stopStepwiseStack(stack);
  }
});

interface JsonSchema {
  $ref?: string;
  type?: string | string[];
  properties?: Record<string, JsonSchema>;
  required?: string[];
  additionalProperties?: boolean | JsonSchema;
  items?: JsonSchema;
  anyOf?: JsonSchema[];
  oneOf?: JsonSchema[];
  allOf?: JsonSchema[];
  enum?: unknown[];
  const?: unknown;
  minItems?: number;
  maxItems?: number;
  minLength?: number;
  maxLength?: number;
  pattern?: string;
}

function resolvePointer(root: JsonSchema, ref: string): JsonSchema {
  if (!ref.startsWith("#")) throw new Error(`unsupported $ref: ${ref}`);
  let node: unknown = root;
  for (const part of ref.slice(1).split("/").filter(Boolean)) {
    const key = decodeURIComponent(part)
      .replaceAll("~1", "/")
      .replaceAll("~0", "~");
    node = (node as Record<string, unknown>)[key];
  }
  if (node === undefined) throw new Error(`unresolved $ref: ${ref}`);
  return node as JsonSchema;
}

function typeOf(value: unknown): string {
  if (value === null) return "null";
  if (Array.isArray(value)) return "array";
  if (typeof value === "number")
    return Number.isInteger(value) ? "integer" : "number";
  return typeof value;
}

/** A small JSON Schema check, enough for the published tool schemas. */
function accepts(
  root: JsonSchema,
  schema: JsonSchema,
  value: unknown,
): boolean {
  if (schema.$ref !== undefined)
    return accepts(root, resolvePointer(root, schema.$ref), value);
  if (schema.allOf && !schema.allOf.every((s) => accepts(root, s, value)))
    return false;
  if (schema.anyOf && !schema.anyOf.some((s) => accepts(root, s, value)))
    return false;
  if (schema.oneOf && !schema.oneOf.some((s) => accepts(root, s, value)))
    return false;
  if (schema.const !== undefined && schema.const !== value) return false;
  if (schema.enum && !schema.enum.includes(value)) return false;
  if (schema.type !== undefined) {
    const types = Array.isArray(schema.type) ? schema.type : [schema.type];
    const actual = typeOf(value);
    if (
      !types.includes(actual) &&
      !(actual === "integer" && types.includes("number"))
    )
      return false;
  }
  if (typeof value === "string") {
    if (schema.minLength !== undefined && value.length < schema.minLength)
      return false;
    if (schema.maxLength !== undefined && value.length > schema.maxLength)
      return false;
    if (schema.pattern !== undefined && !new RegExp(schema.pattern).test(value))
      return false;
  }
  if (Array.isArray(value)) {
    if (schema.minItems !== undefined && value.length < schema.minItems)
      return false;
    if (schema.maxItems !== undefined && value.length > schema.maxItems)
      return false;
    const items = schema.items;
    if (items && !value.every((v) => accepts(root, items, v))) return false;
  } else if (typeOf(value) === "object") {
    const record = value as Record<string, unknown>;
    for (const key of schema.required ?? []) if (!(key in record)) return false;
    const props = schema.properties ?? {};
    for (const [key, v] of Object.entries(record)) {
      const prop = props[key];
      if (prop !== undefined) {
        if (!accepts(root, prop, v)) return false;
      } else if (schema.additionalProperties === false) {
        return false;
      } else if (typeof schema.additionalProperties === "object") {
        if (!accepts(root, schema.additionalProperties, v)) return false;
      }
    }
  }
  return true;
}

test("AC-197: the login_step inputSchema shows ref and both submit forms", async () => {
  // Given: MCP tools/list (the daemon is not needed to list tools, so
  // TEGATA_SOCKET is a dummy path)
  const transport = new StdioClientTransport({
    command: "node",
    args: [bins().mcpEntry],
    env: {
      ...process.env,
      TEGATA_SOCKET: "/nonexistent/tegata-ac197.sock",
    } as Record<string, string>,
  });
  const client = new Client({ name: "acceptance", version: "0.0.0" });
  try {
    await client.connect(transport);

    // When: read login_step's inputSchema
    const { tools } = await client.listTools();
    const loginStep = tools.find((t) => t.name === "login_step");
    expect(loginStep, "login_step must be listed").toBeDefined();
    const schema = loginStep?.inputSchema as JsonSchema;
    const props = schema.properties ?? {};

    // Then: it has `ref`
    expect(Object.keys(props)).toContain("ref");
    expect(accepts(schema, props.ref, "e9")).toBe(true);
    expect(accepts(schema, props.ref, "f1e3")).toBe(true);

    // Then: an element of `fills` can carry `ref`
    expect(props.fills, "login_step.properties.fills").toBeDefined();
    expect(
      accepts(schema, props.fills, [{ ref: "e4", value: "{{username}}" }]),
      JSON.stringify(props.fills),
    ).toBe(true);
    expect(
      accepts(schema, props.fills, [
        { selector: "#user", value: "{{username}}" },
      ]),
      JSON.stringify(props.fills),
    ).toBe(true);

    // Then: `submit` accepts the string form and the object form
    expect(props.submit, "login_step.properties.submit").toBeDefined();
    for (const submit of [
      { click: "#next" },
      { press_enter: "#x" },
      { click: { ref: "e9" } },
      { click: { selector: "#next" } },
      { press_enter: { ref: "f1e3" } },
      { press_enter: { selector: "#x" } },
    ])
      expect(
        accepts(schema, props.submit, submit),
        `${JSON.stringify(submit)} against ${JSON.stringify(props.submit)}`,
      ).toBe(true);
  } finally {
    await client.close();
  }
});

test("AC-198: {{password}} into a text field by ref is refused like by selector", async () => {
  // Given: /trap/one-screen/
  const stack = await startStepwiseStack();
  try {
    const call = mcpCaller(stack);

    // (For comparison: the same operation by selector, in its own stepwise
    // login under another credential.)
    const bySelector = await begin(
      call,
      trapBeginParams(stack.fixture, "one-screen/", "mock:trap-1"),
    );
    const selectorOutcome = await call("login_step", {
      login_id: bySelector.pending.login_id,
      action: "fill_submit",
      fills: [{ selector: "#user", value: "{{password}}" }],
      submit: { click: "#sign-in" },
    });
    expect(selectorOutcome.error, selectorOutcome.raw).toBeDefined();
    await waitForBrowserCount(stack, 0);

    // When: fill_submit {{password}} into the ref of the username field
    // (type=text)
    const byRef = await begin(
      call,
      trapBeginParams(stack.fixture, "one-screen/", "mock:trap-2"),
    );
    const { snapshot } = byRef.pending;
    const refOutcome = await call("login_step", {
      login_id: byRef.pending.login_id,
      action: "fill_submit",
      fills: [
        { ref: refOf(snapshot, "textbox", "Username"), value: "{{password}}" },
      ],
      submit: { click: { ref: refOf(snapshot, "button", "Sign in") } },
    });

    // Then: refused with the same error as by selector
    expect(refOutcome.error, refOutcome.raw).toBe(selectorOutcome.error);

    // Then: the fixture received no value
    const records = await trapRecords(stack, "/trap/one-screen/");
    expect(records.inputs, JSON.stringify(records.inputs)).toEqual([]);
    expect(records.posts, JSON.stringify(records.posts)).toEqual([]);
  } finally {
    await stopStepwiseStack(stack);
  }
});

test("AC-199: a quoted password echoed in every position is rejected", async () => {
  // Given: /trap/echo/ and the test credential whose password holds `'`,
  // `"`, `\`, `: ` and a run of spaces
  const stack = await startStepwiseStack();
  try {
    const call = mcpCaller(stack);
    const password = stack.quotedPassword;
    for (const piece of ["'", '"', "\\", ": ", "   "])
      expect(password).toContain(piece);
    const begun = await begin(
      call,
      trapBeginParams(stack.fixture, "echo/", "mock:trap-quoted"),
    );
    const { snapshot } = begun.pending;

    // When: fill_submit with the right credential
    const rejected = await call("login_step", {
      login_id: begun.pending.login_id,
      action: "fill_submit",
      fills: [
        { ref: refOf(snapshot, "textbox", "Username"), value: "{{username}}" },
        { ref: refOf(snapshot, "textbox", "Password"), value: "{{password}}" },
      ],
      submit: { click: { ref: refOf(snapshot, "button", "Sign in") } },
    });

    // Then: SNAPSHOT_REJECTED, and no browser is left
    expect(rejected.error, rejected.raw.slice(0, 400)).toBe(
      "SNAPSHOT_REJECTED",
    );
    await waitForBrowserCount(stack, 0);
    // The page did receive that password (masked as its digest).
    const { posts } = await trapRecords(stack, "/trap/echo/");
    expect(posts.map((p) => p.fields.password)).toEqual([
      maskedDigest(password),
    ]);

    // Then: neither the answers nor the audit hold any form of the password
    expect([
      ...secretHits("login_begin", begun.outcome.raw, password),
      ...secretHits("fill_submit", rejected.raw, password),
      ...secretHits("audit", auditText(stack), password),
    ]).toEqual([]);
  } finally {
    await stopStepwiseStack(stack);
  }
});

test("AC-200: an f-ref of a removed iframe is SELECTOR_NOT_FOUND", async () => {
  // Given: the line of the removable iframe's button (an f-ref) on
  // /trap/frames/, then the operation that removes that iframe (a click on
  // a main-frame ref)
  const stack = await startStepwiseStack();
  try {
    const call = mcpCaller(stack);
    const begun = await begin(call, trapBeginParams(stack.fixture, "frames/"));
    const loginId = begun.pending.login_id;
    const { snapshot } = begun.pending;
    const widget = refOf(snapshot, "button", "Widget action");
    expect(widget).toMatch(/^f\d+e\d+$/);
    const remove = refOf(snapshot, "button", "Remove widget frame");
    expect(remove).toMatch(/^e\d+$/);
    expectPending(
      await call("login_step", {
        login_id: loginId,
        action: "click",
        ref: remove,
      }),
      "click Remove widget frame",
    );

    // When: click the f-ref found before
    const stale = await call("login_step", {
      login_id: loginId,
      action: "click",
      ref: widget,
    });
    const next = await call("login_step", {
      login_id: loginId,
      action: "snapshot",
    });

    // Then: SELECTOR_NOT_FOUND (the login goes on), and the next snapshot is
    // state "pending"
    expect(stale.error, stale.raw).toBe("SELECTOR_NOT_FOUND");
    expectPending(next, "snapshot");
  } finally {
    await stopStepwiseStack(stack);
  }
});

test("AC-201: srcdoc and ownerDocument-spoofing iframes are refused", async () => {
  // Given: /trap/frames/
  const stack = await startStepwiseStack();
  try {
    const call = mcpCaller(stack);
    const cases = [
      { label: "srcdoc", field: "Embedded password", cred: "mock:trap-1" },
      { label: "spoofed", field: "Spoofed password", cred: "mock:trap-2" },
    ];
    for (const { label, field, cred } of cases) {
      const begun = await begin(
        call,
        trapBeginParams(stack.fixture, "frames/", cred),
      );
      const { snapshot } = begun.pending;

      // When: fill_submit with that iframe's password field's ref among the
      // fills (each in its own stepwise login)
      const refused = await call("login_step", {
        login_id: begun.pending.login_id,
        action: "fill_submit",
        fills: [
          {
            ref: refOf(snapshot, "textbox", "Frame username"),
            value: "{{username}}",
          },
          { ref: refOf(snapshot, "textbox", field), value: "{{password}}" },
        ],
        submit: {
          click: { ref: refOf(snapshot, "button", "Frame sign in") },
        },
      });

      // Then: FILL_TARGET_REFUSED, the fixture received no input into any
      // field, and no browser is left
      expect(refused.error, `${label}: ${refused.raw}`).toBe(
        "FILL_TARGET_REFUSED",
      );
      const records = await trapRecords(stack, "/trap/frames/");
      expect(records.inputs, `${label}: ${JSON.stringify(records)}`).toEqual(
        [],
      );
      expect(records.posts, `${label}: ${JSON.stringify(records)}`).toEqual([]);
      await waitForBrowserCount(stack, 0);
      expect(browserCount(stack)).toBe(0);
    }
  } finally {
    await stopStepwiseStack(stack);
  }
}, 180_000);
