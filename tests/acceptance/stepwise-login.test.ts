// AC-159 .. AC-172 — stepwise login: `login_begin` / `login_step` walk a
// multi-screen login one action at a time, each answer carrying a snapshot
// that tegata builds and checks (no field values, the username masked,
// echoed secrets rejected), with secrets filled only inside `fill_submit`,
// no CDP endpoint before the handoff, a principal-bound `login_id`, idle
// expiry, one approval and one rate-limit attempt per stepwise login, and
// the Issue #45 cookie restore.
// Traceability: docs/secret/briefs/tegata-issue46-stepwise-login.md
// acceptance condition AC-159 .. AC-172.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { chromium } from "playwright-core";
import { expect, test } from "vitest";
import { rawRpc } from "./support/harness.js";
import { cookieStoreFiles } from "./support/persistent-cookies.js";
import { readAuditRecords, waitUntil } from "./support/phase3.js";
import { issuePeer, sleep, tcpRpc } from "./support/phase4.js";
import {
  beginParams,
  browserCount,
  type DoneResult,
  maskedDigest,
  mcpCaller,
  type PendingResult,
  rpcCaller,
  type Snapshot,
  type SnapshotElement,
  type StepOutcome,
  type StepwiseCaller,
  type StepwiseStack,
  startStepwiseStack,
  stepwiseState,
  stopStepwiseStack,
  waitForBrowserCount,
} from "./support/stepwise-login.js";

/** Value attribute of the visible checkbox on the fixture's username page. */
const VALUE_MARKER = "stepwise-value-attribute-marker";

function expectPending(outcome: StepOutcome, what: string): PendingResult {
  expect(outcome.error, `${what} failed: ${outcome.raw}`).toBeUndefined();
  expect(outcome.result?.state, `${what}: ${outcome.raw}`).toBe("pending");
  return outcome.result as PendingResult;
}

function expectDone(outcome: StepOutcome, what: string): DoneResult {
  expect(outcome.error, `${what} failed: ${outcome.raw}`).toBeUndefined();
  expect(outcome.result?.state, `${what}: ${outcome.raw}`).toBe("done");
  return outcome.result as DoneResult;
}

const byName =
  (name: string) =>
  (e: SnapshotElement): boolean =>
    e.name === name;

const byText =
  (text: string) =>
  (e: SnapshotElement): boolean =>
    (e.text ?? "").trim() === text;

const isAuthenticatorLink = (e: SnapshotElement): boolean =>
  e.tag.toLowerCase() === "a" && /authenticator app/i.test(e.text ?? "");

/** The tegata-generated selector of the element the agent would pick. */
function selectorOf(
  snapshot: Snapshot,
  what: string,
  match: (e: SnapshotElement) => boolean,
): string {
  const element = snapshot.elements.find(match);
  expect(
    element,
    `no ${what} in the snapshot of ${snapshot.url}`,
  ).toBeDefined();
  const selector = element?.selector;
  expect(typeof selector, `${what} has no selector`).toBe("string");
  return selector as string;
}

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

interface FlowRun {
  /** Every `login_step` outcome, in order. */
  outcomes: StepOutcome[];
  /** The outcome of the final `fill_submit` (the TOTP), not yet checked. */
  last: StepOutcome;
}

/**
 * The AC-160 procedure from the username page: fill the username, click
 * Next, `fill_submit` the password, click More options, click the
 * authenticator app link, `fill_submit` the TOTP. Every selector comes from
 * the latest snapshot. Every step but the last must answer `pending`; with
 * `snapshotBetween`, a `snapshot` action follows each of them.
 */
async function driveFlow(
  call: StepwiseCaller,
  loginId: string,
  start: Snapshot,
  opts: { snapshotBetween?: boolean } = {},
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
  await step("fill the username", {
    action: "fill",
    selector: selectorOf(snapshot, "username field", byName("username")),
    value: "{{username}}",
  });
  await step("click Next", {
    action: "click",
    selector: selectorOf(snapshot, "Next button", byText("Next")),
  });
  await step("fill_submit the password", {
    action: "fill_submit",
    fills: [
      {
        selector: selectorOf(snapshot, "password field", byName("password")),
        value: "{{password}}",
      },
    ],
    submit: {
      click: selectorOf(snapshot, "Sign in button", byText("Sign in")),
    },
  });
  await step("click More options", {
    action: "click",
    selector: selectorOf(
      snapshot,
      "More options button",
      byText("More options"),
    ),
  });
  await step("click the authenticator app link", {
    action: "click",
    selector: selectorOf(
      snapshot,
      "authenticator app link",
      isAuthenticatorLink,
    ),
  });
  const last = await call("login_step", {
    login_id: loginId,
    action: "fill_submit",
    fills: [
      {
        selector: selectorOf(snapshot, "code field", byName("otp")),
        value: "{{totp}}",
      },
    ],
    submit: { click: selectorOf(snapshot, "Verify button", byText("Verify")) },
  });
  outcomes.push(last);
  return { outcomes, last };
}

/** Logout over the UNIX socket and wait until that browser is gone. */
async function logout(stack: StepwiseStack, sessionId: string) {
  const browsers = browserCount(stack);
  const res = await rawRpc(stack.daemon.socketPath, "logout", {
    session_id: sessionId,
  });
  stack.observe("rpc:logout", res);
  expect(
    res.error,
    `logout failed: ${JSON.stringify(res.error)}`,
  ).toBeUndefined();
  await waitForBrowserCount(stack, browsers - 1);
  return res;
}

function auditText(stack: StepwiseStack): string {
  return fs.existsSync(stack.daemon.auditLogPath)
    ? fs.readFileSync(stack.daemon.auditLogPath, "utf8")
    : "";
}

/** The raw value and its common encodings. */
function encodedForms(value: string): string[] {
  const bytes = Buffer.from(value, "utf8");
  return [
    value,
    encodeURIComponent(value),
    bytes.toString("base64"),
    bytes.toString("hex"),
  ];
}

interface Surface {
  label: string;
  text: string;
}

/** `label: needle-label` for every surface that contains one of the needles. */
function hitsIn(
  surfaces: Surface[],
  needles: Array<{ label: string; test: (text: string) => boolean }>,
): string[] {
  return surfaces.flatMap((s) =>
    needles.filter((n) => n.test(s.text)).map((n) => `${s.label}: ${n.label}`),
  );
}

function literal(label: string, value: string) {
  return encodedForms(value).map((form) => ({
    label,
    test: (text: string) => text.includes(form),
  }));
}

/** A TOTP code as a standalone digit run (not part of a longer number). */
function totpCode(code: string) {
  const pattern = new RegExp(`(?<![0-9])${code}(?![0-9])`);
  return {
    label: `totp code ${code}`,
    test: (text: string) => pattern.test(text),
  };
}

test("AC-159: login_begin answers pending with a value-free snapshot", async () => {
  // Given: fixture (1)
  const stack = await startStepwiseStack();
  try {
    // When: login_begin
    const outcome = await mcpCaller(stack)(
      "login_begin",
      beginParams(stack.fixture),
    );

    // Then: state "pending" with a login_id, and snapshot.elements holds the
    // username field and the Next button, each with a selector
    const pending = expectPending(outcome, "login_begin");
    expect(typeof pending.login_id).toBe("string");
    expect(pending.login_id.length).toBeGreaterThan(0);
    const { elements } = pending.snapshot;
    const username = elements.find(byName("username"));
    const next = elements.find(byText("Next"));
    expect(username, "username field").toBeDefined();
    expect(typeof username?.selector).toBe("string");
    expect(next, "Next button").toBeDefined();
    expect(typeof next?.selector).toBe("string");

    // Then: no element carries a value field (the page has a visible
    // checkbox whose value attribute is a marker; it is listed, its value
    // is not)
    expect(
      elements.find(byName("remember")),
      "remember checkbox",
    ).toBeDefined();
    for (const element of elements)
      expect(Object.keys(element)).not.toContain("value");
    expect(outcome.raw).not.toContain(VALUE_MARKER);

    // Then: the response holds none of the credential canaries
    const { username: user, password, totpSeed } = stack.canaries;
    for (const canary of [user, password, totpSeed])
      expect(outcome.raw.includes(canary)).toBe(false);
  } finally {
    await stopStepwiseStack(stack);
  }
});

test("AC-160: the full stepwise flow hands off a signed-in CDP session", async () => {
  // Given: fixture (1)
  const stack = await startStepwiseStack();
  try {
    // When: fill {{username}} -> click Next -> fill_submit {{password}} ->
    // click More options -> click the authenticator app link ->
    // fill_submit {{totp}}
    const call = mcpCaller(stack);
    const begun = await begin(call, beginParams(stack.fixture));
    const flow = await driveFlow(
      call,
      begun.pending.login_id,
      begun.pending.snapshot,
    );

    // Then: the last answer is state "done" with a CDP endpoint
    const done = expectDone(flow.last, "fill_submit the TOTP");
    expect(done.channel.kind).toBe("cdp");
    expect(done.channel.endpoint).toMatch(/^ws:\/\//);

    // Then: the page opened over CDP is the signed-in page
    const browser = await chromium.connectOverCDP(done.channel.endpoint);
    try {
      const page = browser
        .contexts()
        .flatMap((c) => c.pages())
        .find((p) => p.url().startsWith(`${stack.fixture.url}/stepwise/home`));
      expect(page, "no signed-in page over CDP").toBeDefined();
      const signedIn = await page?.evaluate(
        () => document.querySelector("#signed-in") !== null,
      );
      expect(signedIn).toBe(true);
    } finally {
      await browser.close();
    }

    // Then: the fixture's TOTP check succeeded
    const state = await stepwiseState(stack.fixture);
    expect(state.totp.some((t) => t.valid)).toBe(true);

    // Then: no answer before the last one carries a CDP endpoint
    for (const outcome of [begun.outcome, ...flow.outcomes.slice(0, -1)]) {
      expect(outcome.raw).not.toContain("ws://");
      expect(outcome.result).not.toHaveProperty("channel");
    }
  } finally {
    await stopStepwiseStack(stack);
  }
});

test("AC-161: lone secret fills and literal values are refused", async () => {
  // Given: a stepwise login on fixture (1), advanced to the password page
  const stack = await startStepwiseStack();
  try {
    const call = mcpCaller(stack);
    const begun = await begin(call, beginParams(stack.fixture));
    const loginId = begun.pending.login_id;
    let snapshot = begun.pending.snapshot;
    snapshot = expectPending(
      await call("login_step", {
        login_id: loginId,
        action: "fill",
        selector: selectorOf(snapshot, "username field", byName("username")),
        value: "{{username}}",
      }),
      "fill the username",
    ).snapshot;
    snapshot = expectPending(
      await call("login_step", {
        login_id: loginId,
        action: "click",
        selector: selectorOf(snapshot, "Next button", byText("Next")),
      }),
      "click Next",
    ).snapshot;
    const passwordField = selectorOf(
      snapshot,
      "password field",
      byName("password"),
    );
    const signIn = selectorOf(snapshot, "Sign in button", byText("Sign in"));
    const before = await stepwiseState(stack.fixture);
    // The fixture's input recorder works (the username fill was recorded).
    expect(before.inputs.map((i) => i.value)).toContain("<username>");

    // When: login_step with a lone fill of {{password}}, or with fills
    // carrying a non-placeholder value, through MCP and straight to the socket
    const literalValue = "stepwise-literal-not-a-placeholder";
    const loneFill = {
      login_id: loginId,
      action: "fill",
      selector: passwordField,
      value: "{{password}}",
    };
    const literalFill = {
      login_id: loginId,
      action: "fill_submit",
      fills: [{ selector: passwordField, value: literalValue }],
      submit: { click: signIn },
    };
    const mcpLone = await stack.mcp.callTool("login_step", loneFill);
    const mcpLiteral = await stack.mcp.callTool("login_step", literalFill);
    const rpcLone = await rawRpc(
      stack.daemon.socketPath,
      "login_step",
      loneFill,
    );
    stack.observe("rpc:login_step", rpcLone);
    const rpcLiteral = await rawRpc(
      stack.daemon.socketPath,
      "login_step",
      literalFill,
    );
    stack.observe("rpc:login_step", rpcLiteral);
    // The daemon's existing answer to invalid params, for comparison.
    const invalidParams = await rawRpc(stack.daemon.socketPath, "login", {});
    stack.observe("rpc:login", invalidParams);

    // Then: MCP refuses both by schema
    for (const res of [mcpLone, mcpLiteral]) {
      expect(res.isError).toBe(true);
      expect(res.text).toContain("Input validation error");
    }

    // Then: the socket answers both with the daemon's invalid-params error
    expect(invalidParams.error).toBeDefined();
    for (const res of [rpcLone, rpcLiteral]) {
      expect(res.result).toBeUndefined();
      expect(res.error?.code).toBe(invalidParams.error?.code);
      expect(res.error?.message).toBe(invalidParams.error?.message);
    }

    // Then: the fixture recorded neither an input of those values nor a POST
    const after = await stepwiseState(stack.fixture);
    const newInputs = after.inputs
      .slice(before.inputs.length)
      .map((i) => i.value);
    expect(newInputs).not.toContain("<password>");
    expect(newInputs).not.toContain(maskedDigest(literalValue));
    expect(after.posts.length).toBe(before.posts.length);
  } finally {
    await stopStepwiseStack(stack);
  }
});

test("AC-162: the username in a snapshot is masked as [username]", async () => {
  // Given: the AC-160 flow with a success_selector the signed-in page lacks
  const stack = await startStepwiseStack();
  try {
    const call = mcpCaller(stack);
    const begun = await begin(
      call,
      beginParams(stack.fixture, { success_selector: "#never-present" }),
    );
    const loginId = begun.pending.login_id;
    const flow = await driveFlow(call, loginId, begun.pending.snapshot);
    expectPending(flow.last, "fill_submit the TOTP");

    // When: snapshot after reaching the signed-in page
    const outcome = await call("login_step", {
      login_id: loginId,
      action: "snapshot",
    });

    // Then: snapshot.text contains "[username]" and not the raw username
    const { snapshot } = expectPending(outcome, "snapshot");
    expect(snapshot.url).toContain("/stepwise/home");
    expect(snapshot.text).toContain("[username]");
    expect(snapshot.text).not.toContain(stack.canaries.username);
    expect(outcome.raw).not.toContain(stack.canaries.username);
  } finally {
    await stopStepwiseStack(stack);
  }
});

test("AC-163: a page echoing the password is rejected and torn down", async () => {
  // Given: fixture (2) for each echo kind (text, attribute, URL query)
  const stack = await startStepwiseStack();
  try {
    const call = mcpCaller(stack);
    const surfaces: Surface[] = [];
    for (const kind of ["text", "attr", "query"]) {
      const begun = await begin(call, {
        cred_id: `mock:echo-${kind}`,
        target_url: `${stack.fixture.url}/stepwise/echo/?kind=${kind}`,
        success_selector: "#signed-in",
      });
      surfaces.push({ label: `login_begin ${kind}`, text: begun.outcome.raw });
      const loginId = begun.pending.login_id;
      const snapshot = begun.pending.snapshot;

      // When: fill_submit with {{password}}
      const rejected = await call("login_step", {
        login_id: loginId,
        action: "fill_submit",
        fills: [
          {
            selector: selectorOf(
              snapshot,
              "username field",
              byName("username"),
            ),
            value: "{{username}}",
          },
          {
            selector: selectorOf(
              snapshot,
              "password field",
              byName("password"),
            ),
            value: "{{password}}",
          },
        ],
        submit: {
          click: selectorOf(snapshot, "Sign in button", byText("Sign in")),
        },
      });
      surfaces.push({ label: `fill_submit ${kind}`, text: rejected.raw });
      const after = await call("login_step", {
        login_id: loginId,
        action: "snapshot",
      });
      surfaces.push({ label: `snapshot ${kind}`, text: after.raw });

      // Then: SNAPSHOT_REJECTED, the next login_step on that login_id is
      // NOT_FOUND, and no browser is left
      expect(rejected.error, `${kind}: ${rejected.raw}`).toBe(
        "SNAPSHOT_REJECTED",
      );
      expect(after.error, `${kind}: ${after.raw}`).toBe("NOT_FOUND");
      await waitForBrowserCount(stack, 0);
      // The page did receive the password it echoes.
      const state = await stepwiseState(stack.fixture);
      expect(
        state.posts.some(
          (p) => p.kind === kind && p.fields.password === "<password>",
        ),
      ).toBe(true);
    }

    // Then: the answers, the audit log and the daemon stderr hold no
    // password canary
    surfaces.push({ label: "audit", text: auditText(stack) });
    surfaces.push({ label: "stderr", text: stack.daemon.stderr() });
    expect(
      hitsIn(surfaces, literal("password", stack.canaries.password)),
    ).toEqual([]);
  } finally {
    await stopStepwiseStack(stack);
  }
}, 240_000);

test("AC-164: filled fields are cleared after fill_submit", async () => {
  // Given: fixture (3)
  const stack = await startStepwiseStack();
  try {
    const call = mcpCaller(stack);
    const begun = await begin(call, {
      cred_id: "mock:site-badpass",
      target_url: `${stack.fixture.url}/stepwise/sticky/`,
      success_selector: "#welcome",
    });
    const loginId = begun.pending.login_id;
    let snapshot = begun.pending.snapshot;

    // When: fill_submit with the wrong-password credential -> click (any
    // element)
    const submitted = await call("login_step", {
      login_id: loginId,
      action: "fill_submit",
      fills: [
        {
          selector: selectorOf(snapshot, "username field", byName("username")),
          value: "{{username}}",
        },
        {
          selector: selectorOf(snapshot, "password field", byName("password")),
          value: "{{password}}",
        },
      ],
      submit: {
        click: selectorOf(snapshot, "Sign in button", byText("Sign in")),
      },
    });

    // Then: the fill_submit answer is a pending snapshot
    snapshot = expectPending(submitted, "fill_submit").snapshot;
    const clicked = await call("login_step", {
      login_id: loginId,
      action: "click",
      selector: selectorOf(snapshot, "Help button", byText("Help")),
    });
    expectPending(clicked, "click Help");

    // Then: the page kept the wrong password on re-render, and the value it
    // reported at the later click is empty
    const state = await stepwiseState(stack.fixture);
    const rerender = state.sticky_reports.filter((r) => r.when === "rerender");
    expect(rerender.length).toBeGreaterThan(0);
    expect(rerender[0].password_length).toBeGreaterThan(0);
    const helpClicks = state.sticky_reports.filter(
      (r) => r.when === "click" && r.target === "help",
    );
    expect(helpClicks.length).toBeGreaterThan(0);
    for (const report of helpClicks) expect(report.password_length).toBe(0);
  } finally {
    await stopStepwiseStack(stack);
  }
});

test("AC-165: a missing selector keeps the stepwise login going", async () => {
  // Given: a stepwise login on fixture (1)
  const stack = await startStepwiseStack();
  try {
    const call = mcpCaller(stack);
    const begun = await begin(call, beginParams(stack.fixture));
    const loginId = begun.pending.login_id;

    // When: click a missing selector -> snapshot -> go on with the right ones
    const missing = await call("login_step", {
      login_id: loginId,
      action: "click",
      selector: "#does-not-exist",
    });
    const again = await call("login_step", {
      login_id: loginId,
      action: "snapshot",
    });

    // Then: SELECTOR_NOT_FOUND first, then state "pending", then the AC-160
    // procedure reaches "done"
    expect(missing.error, missing.raw).toBe("SELECTOR_NOT_FOUND");
    const { snapshot } = expectPending(again, "snapshot");
    const flow = await driveFlow(call, loginId, snapshot);
    expectDone(flow.last, "fill_submit the TOTP");
  } finally {
    await stopStepwiseStack(stack);
  }
});

test("AC-166: a stepwise login counts once against the rate limit", async () => {
  // Given: one credential and one principal
  const stack = await startStepwiseStack();
  try {
    const call = mcpCaller(stack);

    // When: one stepwise login with 10+ login_step calls reaches "done"
    const first = await begin(call, beginParams(stack.fixture));
    const flow = await driveFlow(
      call,
      first.pending.login_id,
      first.pending.snapshot,
      { snapshotBetween: true },
    );

    // Then: those login_step calls are not rate limited
    expect(flow.outcomes.length).toBeGreaterThanOrEqual(10);
    for (const outcome of flow.outcomes)
      expect(outcome.error, outcome.raw).not.toBe("RATE_LIMITED");
    const done = expectDone(flow.last, "fill_submit the TOTP");

    // When: (after that session ends, so nothing is shared) login_begin
    // twice more, then a fourth login_begin
    await logout(stack, done.session_id);
    await begin(call, beginParams(stack.fixture));
    await begin(call, beginParams(stack.fixture));
    const fourth = await call("login_begin", beginParams(stack.fixture));

    // Then: the fourth login_begin is RATE_LIMITED
    expect(fourth.error, fourth.raw).toBe("RATE_LIMITED");
  } finally {
    await stopStepwiseStack(stack);
  }
}, 240_000);

test("AC-167: an idle stepwise login expires", async () => {
  // Given: stepwise_idle_secs = 2
  const stack = await startStepwiseStack({ top: { stepwiseIdleSecs: 2 } });
  try {
    // When: login_begin -> wait 3 s -> login_step
    const call = mcpCaller(stack);
    const begun = await begin(call, beginParams(stack.fixture));
    expect(browserCount(stack)).toBe(1);
    await sleep(3_000);
    const late = await call("login_step", {
      login_id: begun.pending.login_id,
      action: "snapshot",
    });

    // Then: NOT_FOUND, no browser is left, and one stepwise_expired record
    expect(late.error, late.raw).toBe("NOT_FOUND");
    await waitForBrowserCount(stack, 0);
    const expired = () =>
      readAuditRecords(stack.daemon.auditLogPath).records.filter(
        (r) => r.method === "stepwise_expired",
      );
    await waitUntil(
      "a stepwise_expired record",
      () => expired().length > 0,
      10_000,
    );
    expect(expired()).toHaveLength(1);
  } finally {
    await stopStepwiseStack(stack);
  }
});

test("AC-168: a login_id is bound to its principal", async () => {
  // Given: a stepwise login of principal P1 (UNIX socket uid)
  const stack = await startStepwiseStack({ tcp: true });
  try {
    const call = mcpCaller(stack);
    const begun = await begin(call, beginParams(stack.fixture));
    const loginId = begun.pending.login_id;
    const p2 = await issuePeer(stack.daemon.socketPath, "p2");

    // When: another principal P2 (peer token) calls login_step on that login_id
    const foreign = await tcpRpc(
      stack.daemon.tcpPort as number,
      p2.token,
      "login_step",
      { login_id: loginId, action: "snapshot" },
    );
    stack.observe("tcp:login_step", foreign);

    // Then: NOT_FOUND, and P1 carries on to "done"
    expect(foreign.preamble).toBeUndefined();
    expect(foreign.error?.message).toBe("NOT_FOUND");
    const flow = await driveFlow(call, loginId, begun.pending.snapshot);
    expectDone(flow.last, "fill_submit the TOTP");
  } finally {
    await stopStepwiseStack(stack);
  }
});

test("AC-169: login_begin is approved once; login_step is not gated", async () => {
  // Given: an approve_cmd that denies (control file), counting its calls
  const hookDir = fs.mkdtempSync(path.join(os.tmpdir(), "tegata-sw-hook-"));
  const control = path.join(hookDir, "control");
  const calls = path.join(hookDir, "calls");
  fs.writeFileSync(control, "deny\n");
  const hook = [
    `printf 'call\\n' >> ${JSON.stringify(calls)}`,
    `if [ "$(cat ${JSON.stringify(control)} 2>/dev/null)" = allow ]; then exit 0; fi`,
    "exit 1",
  ].join("; ");
  const hookCalls = () =>
    fs.existsSync(calls)
      ? fs
          .readFileSync(calls, "utf8")
          .split("\n")
          .filter((l) => l !== "").length
      : 0;
  const stack = await startStepwiseStack({ top: { approveCmd: hook } });
  try {
    const call = mcpCaller(stack);

    // When: login_begin
    const denied = await call("login_begin", beginParams(stack.fixture));

    // Then: APPROVAL_DENIED, and no browser was started
    expect(denied.error, denied.raw).toBe("APPROVAL_DENIED");
    expect(browserCount(stack)).toBe(0);
    expect((await stepwiseState(stack.fixture)).requests).toEqual([]);

    // Given: the approve_cmd now approves
    fs.writeFileSync(control, "allow\n");
    const before = hookCalls();

    // When: login_begin and the whole stepwise flow
    const begun = await begin(call, beginParams(stack.fixture));
    const flow = await driveFlow(
      call,
      begun.pending.login_id,
      begun.pending.snapshot,
    );
    expectDone(flow.last, "fill_submit the TOTP");

    // Then: the hook ran once for the stepwise login (not per login_step)
    expect(hookCalls() - before).toBe(1);
  } finally {
    await stopStepwiseStack(stack);
    fs.rmSync(hookDir, { recursive: true, force: true });
  }
});

test("AC-170: restored cookies finish login_begin without a snapshot", async () => {
  // Given: persist_cookies = ["*"], one stepwise login reached "done" and
  // was logged out
  const stack = await startStepwiseStack({ persistCookies: ["*"] });
  try {
    const call = mcpCaller(stack);
    const first = await begin(call, beginParams(stack.fixture));
    const flow = await driveFlow(
      call,
      first.pending.login_id,
      first.pending.snapshot,
    );
    const firstDone = expectDone(flow.last, "fill_submit the TOTP");
    await logout(stack, firstDone.session_id);
    await waitUntil(
      "the cookies to be stored",
      () => cookieStoreFiles(stack.daemon.stateDir).length > 0,
      10_000,
    );
    const postsBefore = (await stepwiseState(stack.fixture)).posts.length;

    // When: the same credential and principal call login_begin
    const again = await call("login_begin", beginParams(stack.fixture));

    // Then: state "done" without a snapshot, and no form was posted
    const done = expectDone(again, "login_begin");
    expect(again.result).not.toHaveProperty("snapshot");
    expect(done.channel.endpoint).toMatch(/^ws:\/\//);
    expect((await stepwiseState(stack.fixture)).posts.length).toBe(postsBefore);

    // Then: the audit record is cookies "restored", steps_skipped true
    const record = readAuditRecords(stack.daemon.auditLogPath).records.find(
      (r) => r.method === "login_begin" && r.cookies === "restored",
    );
    expect(record, "a restored login_begin record").toBeDefined();
    expect(record?.steps_skipped).toBe(true);
    expect(record?.stepwise).toBe(true);
  } finally {
    await stopStepwiseStack(stack);
  }
}, 180_000);

test("AC-171: abort ends the stepwise login", async () => {
  // Given: a stepwise login
  const stack = await startStepwiseStack();
  try {
    const call = mcpCaller(stack);
    const begun = await begin(call, beginParams(stack.fixture));
    const loginId = begun.pending.login_id;
    expect(browserCount(stack)).toBe(1);

    // When: login_step {action: "abort"} -> snapshot on the same login_id
    const aborted = await call("login_step", {
      login_id: loginId,
      action: "abort",
    });
    const after = await call("login_step", {
      login_id: loginId,
      action: "snapshot",
    });

    // Then: state "aborted", then NOT_FOUND, and no browser is left
    expect(aborted.error, aborted.raw).toBeUndefined();
    expect(aborted.result).toEqual({ state: "aborted" });
    expect(after.error, after.raw).toBe("NOT_FOUND");
    await waitForBrowserCount(stack, 0);
  } finally {
    await stopStepwiseStack(stack);
  }
});

test("AC-172: no secret or raw username reaches any surface of the flow", async () => {
  // Given: the whole AC-160 run, once through MCP and once through the socket
  const stack = await startStepwiseStack();
  try {
    const surfaces: Surface[] = [];
    const answers: Surface[] = [];
    const record = (label: string, outcomes: StepOutcome[]) => {
      for (const o of outcomes) answers.push({ label, text: o.raw });
    };

    const mcp = mcpCaller(stack);
    const viaMcp = await begin(mcp, beginParams(stack.fixture));
    const mcpFlow = await driveFlow(
      mcp,
      viaMcp.pending.login_id,
      viaMcp.pending.snapshot,
    );
    record("mcp", [viaMcp.outcome, ...mcpFlow.outcomes]);
    const mcpDone = expectDone(mcpFlow.last, "MCP fill_submit the TOTP");
    const loggedOut = await logout(stack, mcpDone.session_id);
    answers.push({ label: "rpc:logout", text: JSON.stringify(loggedOut) });

    const rpc = rpcCaller(stack);
    const viaRpc = await begin(rpc, beginParams(stack.fixture));
    const rpcFlow = await driveFlow(
      rpc,
      viaRpc.pending.login_id,
      viaRpc.pending.snapshot,
    );
    record("rpc", [viaRpc.outcome, ...rpcFlow.outcomes]);
    expectDone(rpcFlow.last, "RPC fill_submit the TOTP");

    // When: the MCP answers, RPC answers, audit log and daemon stderr are scanned
    surfaces.push(...answers);
    surfaces.push({ label: "audit", text: auditText(stack) });
    surfaces.push({ label: "stderr", text: stack.daemon.stderr() });
    const codes = (await stepwiseState(stack.fixture)).totp
      .filter((t) => t.valid)
      .map((t) => t.code);
    expect(codes.length).toBeGreaterThanOrEqual(2);

    // Then: no password, TOTP seed or entered TOTP code anywhere
    const { username, password, totpSeed } = stack.canaries;
    expect(
      hitsIn(surfaces, [
        ...literal("password", password),
        ...literal("totp seed", totpSeed),
        ...codes.map(totpCode),
      ]),
    ).toEqual([]);

    // Then: the answers never carry the raw username
    expect(hitsIn(answers, literal("username", username))).toEqual([]);
  } finally {
    await stopStepwiseStack(stack);
  }
}, 240_000);
