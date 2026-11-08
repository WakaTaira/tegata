// AC-212, AC-213, AC-214, AC-215 — with approve_cmd configured, a start that
// is already over the startup limit (three per credential in ten minutes) is
// refused before the hook runs, unless it can join an existing browser; the
// limit reached while an approval is pending still refuses the start.
// Traceability: GitHub issue #68.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { expect, test } from "vitest";
import { rawRpc } from "./support/harness.js";
import { waitUntil } from "./support/phase3.js";
import {
  type LoginResult,
  loginParams,
  type Phase4Stack,
  startPhase4Stack,
  stopPhase4Stack,
} from "./support/phase4.js";
import {
  beginParams,
  rpcCaller,
  startStepwiseStack,
  stopStepwiseStack,
} from "./support/stepwise-login.js";

interface Hook {
  root: string;
  calls: string;
  open: string;
  command: string;
}

/**
 * An approve_cmd that records each run and approves once the `open` file
 * exists. The file is created up front, so the hook approves at once until a
 * test removes it.
 */
function blockingHook(): Hook {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "tegata-limit-hook-"));
  const calls = path.join(root, "calls");
  const open = path.join(root, "open");
  fs.writeFileSync(open, "");
  const command = [
    `echo "$TEGATA_CRED_ID" >> ${JSON.stringify(calls)}`,
    `while [ ! -f ${JSON.stringify(open)} ]; do sleep 0.1; done`,
    "exit 0",
  ].join("; ");
  return { root, calls, open, command };
}

function hookRuns(hook: Hook): number {
  if (!fs.existsSync(hook.calls)) return 0;
  return fs
    .readFileSync(hook.calls, "utf8")
    .split("\n")
    .filter((line) => line.trim() !== "").length;
}

async function login(
  stack: Phase4Stack,
  extra: Record<string, unknown> = {},
): Promise<{ result?: LoginResult; error?: string }> {
  const res = await rawRpc(
    stack.daemon.socketPath,
    "login",
    loginParams(stack.fixture.url, "mock:site", extra),
  );
  stack.observe("rpc:login", res);
  return {
    result: res.result as LoginResult | undefined,
    error: res.error?.message,
  };
}

/** Three successful exclusive logins: the startup limit is reached and nothing is shared. */
async function useUpExclusiveStarts(stack: Phase4Stack, count = 3) {
  for (let i = 0; i < count; i++) {
    const started = await login(stack, { exclusive: true });
    expect(started.error, `exclusive login ${i + 1}`).toBeUndefined();
  }
}

test("AC-212: Given approve_cmd and three starts of a credential in ten minutes with nothing to join / When login is called again / Then it is RATE_LIMITED and approve_cmd does not run", {
  timeout: 120_000,
}, async () => {
  const hook = blockingHook();
  const stack = await startPhase4Stack({ approveCmd: hook.command });
  try {
    await useUpExclusiveStarts(stack);
    expect(hookRuns(hook)).toBe(3);

    const over = await login(stack);

    expect(over.error).toBe("RATE_LIMITED");
    expect(hookRuns(hook)).toBe(3);
    expect(stack.fixture.loginPosts()).toBe(3);
  } finally {
    await stopPhase4Stack(stack);
    fs.rmSync(hook.root, { recursive: true, force: true });
  }
});

test("AC-213: Given approve_cmd, a shared browser, and three starts of its credential / When a non-exclusive login is called / Then approve_cmd runs and the login joins the shared browser", {
  timeout: 120_000,
}, async () => {
  const hook = blockingHook();
  const stack = await startPhase4Stack({ approveCmd: hook.command });
  try {
    const shared = await login(stack);
    expect(shared.error).toBeUndefined();
    await useUpExclusiveStarts(stack, 2);
    expect(hookRuns(hook)).toBe(3);

    const joined = await login(stack);

    expect(joined.error).toBeUndefined();
    expect(hookRuns(hook)).toBe(4);
    expect(joined.result?.channel.endpoint).toBe(
      shared.result?.channel.endpoint,
    );
    expect(stack.fixture.loginPosts()).toBe(3);
  } finally {
    await stopPhase4Stack(stack);
    fs.rmSync(hook.root, { recursive: true, force: true });
  }
});

test("AC-214: Given approve_cmd and two starts of a credential / When two exclusive logins wait for approval and are then approved together / Then one starts and the other is RATE_LIMITED", {
  timeout: 120_000,
}, async () => {
  const hook = blockingHook();
  const stack = await startPhase4Stack({ approveCmd: hook.command });
  try {
    await useUpExclusiveStarts(stack, 2);
    fs.rmSync(hook.open);

    const pending = [
      login(stack, { exclusive: true }),
      login(stack, { exclusive: true }),
    ];
    await waitUntil("both approvals to be pending", () => hookRuns(hook) === 4);
    fs.writeFileSync(hook.open, "");
    const outcomes = await Promise.all(pending);

    expect(outcomes.map(({ error }) => error ?? "ok").sort()).toEqual([
      "RATE_LIMITED",
      "ok",
    ]);
    expect(stack.fixture.loginPosts()).toBe(3);
  } finally {
    await stopPhase4Stack(stack);
    fs.rmSync(hook.root, { recursive: true, force: true });
  }
});

test("AC-215: Given approve_cmd and three login_begin starts of a credential with nothing to join / When login_begin is called again / Then it is RATE_LIMITED and approve_cmd does not run", {
  timeout: 120_000,
}, async () => {
  const hook = blockingHook();
  const stack = await startStepwiseStack({ top: { approveCmd: hook.command } });
  try {
    const call = rpcCaller(stack);
    for (let i = 0; i < 3; i++) {
      const begun = await call(
        "login_begin",
        beginParams(stack.fixture, { exclusive: true }),
      );
      expect(begun.error, begun.raw).toBeUndefined();
    }
    expect(hookRuns(hook)).toBe(3);

    const over = await call("login_begin", beginParams(stack.fixture));

    expect(over.error, over.raw).toBe("RATE_LIMITED");
    expect(hookRuns(hook)).toBe(3);
  } finally {
    await stopStepwiseStack(stack);
    fs.rmSync(hook.root, { recursive: true, force: true });
  }
});
