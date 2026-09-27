// AC-113, AC-114, AC-115 — the browser's absolute lifetime and the limit of what
// tegata guarantees about session cookies. AC-115 is not a leak-prevention test:
// it pins down the limit that docs/security.md states.

import { type Browser, chromium } from "playwright-core";
import { expect, test } from "vitest";
import { rawRpc } from "./support/harness.js";
import { readAuditRecords, waitUntil } from "./support/phase3.js";
import {
  CdpClient,
  countExecutors,
  type LoginResult,
  type Phase4Stack,
  sleep,
  startPhase4Stack,
  stopPhase4Stack,
  unixLogin,
} from "./support/phase4.js";

async function logout(stack: Phase4Stack, sessionId: string): Promise<void> {
  const res = await rawRpc(stack.daemon.socketPath, "logout", {
    session_id: sessionId,
  });
  stack.observe("rpc:logout", res);
  expect(
    res.error,
    `logout failed: ${JSON.stringify(res.error)}`,
  ).toBeUndefined();
}

function expiredSessionIds(stack: Phase4Stack): string[] {
  return readAuditRecords(stack.daemon.auditLogPath)
    .records.filter((record) => record.method === "session_expired")
    .flatMap((record) =>
      typeof record.session_id === "string" ? [record.session_id] : [],
    );
}

test("AC-113: the browser absolute lifetime expires every shared lease", async () => {
  // Given: a browser with an 8 s absolute lifetime and 6 s lease TTL
  const stack = await startPhase4Stack({
    sessionTtlSecs: 6,
    browserMaxLifetimeSecs: 8,
  });
  let browser: Browser | undefined;
  try {
    // When: s1 logs in, the CDP connection is opened, and s2 joins after 4 s
    const s1 = await unixLogin(stack);
    const t0 = Date.now();
    browser = await chromium.connectOverCDP(s1.channel.endpoint);
    await sleep(4_000);
    const s2 = await unixLogin(stack);

    // Then: s2 expires at the absolute deadline (t0 + 8 s), before its own TTL (t0 + 10 s)
    expect(s2.channel.endpoint).toBe(s1.channel.endpoint);
    await waitUntil(
      "the session_expired audit record for s2",
      () => expiredSessionIds(stack).includes(s2.session_id),
      10_000,
    );
    expect(Date.now()).toBeLessThanOrEqual(t0 + 9_500);
    await waitUntil(
      "all browsers to shut down at the absolute deadline",
      () => countExecutors(stack.daemon.pid) === 0,
      5_000,
    );
    await waitUntil(
      "the original CDP connection to close",
      () => !browser?.isConnected(),
      5_000,
    );
  } finally {
    await browser?.close().catch(() => {});
    await stopPhase4Stack(stack);
  }
});

test("AC-114: login after the browser deadline starts a new browser", async () => {
  // Given: a browser with a 3 s absolute lifetime and 6 s lease TTL
  const stack = await startPhase4Stack({
    sessionTtlSecs: 6,
    browserMaxLifetimeSecs: 3,
  });
  try {
    // When: s1 logs in and the absolute deadline expires
    const s1 = await unixLogin(stack);
    await waitUntil(
      "the session_expired audit record for s1 before the lease TTL",
      () => expiredSessionIds(stack).includes(s1.session_id),
      5_000,
    );
    await waitUntil(
      "the browser to shut down at the absolute deadline",
      () => countExecutors(stack.daemon.pid) === 0,
      2_000,
    );

    // Then: a later login succeeds through a different browser endpoint
    const s2 = await unixLogin(stack);
    expect(s2.channel.endpoint).not.toBe(s1.channel.endpoint);
  } finally {
    await stopPhase4Stack(stack);
  }
});

test("AC-115: a session cookie remains valid after logout closes the browser", async () => {
  // Given: the default Phase 4 stack and a logged-in fixture page
  const stack = await startPhase4Stack();
  let client: CdpClient | undefined;
  try {
    // When: the agent reads the HttpOnly session cookie through browser CDP
    const login: LoginResult = await unixLogin(stack);
    client = await CdpClient.connect(login.channel.endpoint);
    const { targetInfos } = await client.send("Target.getTargets");
    const loginTarget = (
      targetInfos as Array<{ targetId: string; browserContextId?: string }>
    ).find((target) => target.targetId === login.target_id);
    if (loginTarget?.browserContextId === undefined) {
      throw new Error("the login target's browser context was not found");
    }
    const result = await client.send("Storage.getCookies", {
      browserContextId: loginTarget.browserContextId,
    });
    const cookies = result.cookies as Array<{
      name: string;
      value: string;
      httpOnly?: boolean;
    }>;
    const sessionCookie = cookies.find(
      (cookie) => cookie.name === "session" && cookie.httpOnly === true,
    );
    expect(sessionCookie).toBeDefined();
    if (sessionCookie === undefined) {
      throw new Error("CDP did not return an HttpOnly session cookie");
    }
    client.close();
    client = undefined;
    await logout(stack, login.session_id);
    await waitUntil(
      "the browser to shut down after logout",
      () => countExecutors(stack.daemon.pid) === 0,
      5_000,
    );

    // Then: another HTTP client is still authenticated with the cookie
    const response = await fetch(`${stack.fixture.url}/`, {
      headers: { Cookie: `session=${sessionCookie.value}` },
    });
    expect(response.ok).toBe(true);
    expect(await response.text()).toContain("login-ok");
  } finally {
    client?.close();
    await stopPhase4Stack(stack);
  }
});
