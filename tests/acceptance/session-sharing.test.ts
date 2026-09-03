// AC-56, AC-57, AC-59, AC-60, AC-61, AC-69, AC-70 — one browser per
// (principal, namespace, cred_id), one lease per login: joining a live
// browser, exclusive opt-out, lease-scoped logout and TTL, single-flight
// start-up, a tab per lease, and the status counters.
// Traceability: docs/secret/briefs/tegata-phase4.md acceptance condition
// AC-56, AC-57, AC-59, AC-60, AC-61, AC-69, AC-70.

import { chromium } from "playwright-core";
import { expect, test } from "vitest";
import { rawRpc } from "./support/harness.js";
import { readAuditRecords, waitUntil } from "./support/phase3.js";
import {
  CdpClient,
  countExecutors,
  type LoginResult,
  loginParams,
  type Phase4Stack,
  sleep,
  startPhase4Stack,
  stopPhase4Stack,
  unixLogin,
} from "./support/phase4.js";

/** Login through the MCP tool (the agent-facing surface). */
async function mcpLogin(
  stack: Phase4Stack,
  credId = "mock:site",
  extra: Record<string, unknown> = {},
): Promise<LoginResult> {
  const res = await stack.mcp.callTool(
    "login",
    loginParams(stack.fixture.url, credId, extra),
  );
  expect(res.isError, `login failed: ${res.text}`).toBe(false);
  return res.json as LoginResult;
}

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

test("AC-56: a second login by the same principal joins the live browser", async () => {
  // Given: mock provider の cred X と、同一 principal（テスト uid の UNIX socket）
  const stack = await startPhase4Stack();
  try {
    // When: login(X) を 2 回呼ぶ（exclusive 省略）
    const first = await mcpLogin(stack);
    const second = await mcpLogin(stack);

    // Then: 2 回目は同じ endpoint と異なる session_id を返し、ブラウザは
    // 1 つ、fixture への POST /login は 1 回
    expect(second.channel.endpoint).toBe(first.channel.endpoint);
    expect(second.session_id).not.toBe(first.session_id);
    expect(countExecutors(stack.daemon.pid)).toBe(1);
    expect(stack.fixture.loginPosts()).toBe(1);
  } finally {
    await stopPhase4Stack(stack);
  }
});

test("AC-57: exclusive: true gets a private browser that nobody joins", async () => {
  // Given: X の非 exclusive ブラウザが 1 つある
  const stack = await startPhase4Stack();
  try {
    const shared = await mcpLogin(stack);

    // When: login(X, exclusive: true)、続いて login(X) を呼ぶ
    const exclusive = await mcpLogin(stack, "mock:site", { exclusive: true });
    const joined = await mcpLogin(stack);

    // Then: exclusive は別の endpoint、3 回目は 1 回目と同じ endpoint
    // （exclusive には相乗りしない）、ブラウザは 2 つ
    expect(exclusive.channel.endpoint).not.toBe(shared.channel.endpoint);
    expect(joined.channel.endpoint).toBe(shared.channel.endpoint);
    expect(countExecutors(stack.daemon.pid)).toBe(2);
    expect(stack.fixture.loginPosts()).toBe(2);
  } finally {
    await stopPhase4Stack(stack);
  }
});

test("AC-59: logout returns one lease; the browser closes with the last one", async () => {
  // Given: 同一 principal の 2 リース s1 / s2 が 1 ブラウザを共有している
  const stack = await startPhase4Stack();
  try {
    const s1 = await unixLogin(stack);
    const s2 = await unixLogin(stack);
    expect(s2.channel.endpoint).toBe(s1.channel.endpoint);

    // When: logout(s1)
    await logout(stack, s1.session_id);
    await sleep(1_500);

    // Then: ブラウザは 1 つのまま、s2 の endpoint に接続できる
    expect(countExecutors(stack.daemon.pid)).toBe(1);
    const browser = await chromium.connectOverCDP(s2.channel.endpoint, {
      timeout: 5_000,
    });
    await browser.close();

    // When: 続けて logout(s2)
    await logout(stack, s2.session_id);

    // Then: 5 s 以内にブラウザが 0 になる
    await waitUntil(
      "the browser to shut down after the last lease",
      () => countExecutors(stack.daemon.pid) === 0,
      5_000,
    );
  } finally {
    await stopPhase4Stack(stack);
  }
});

test("AC-60: lease TTLs expire one by one; the browser survives until the last", async () => {
  // Given: session_ttl_secs = 6、リース s1 の 3 s 後に同一鍵のリース s2
  const stack = await startPhase4Stack({ sessionTtlSecs: 6 });
  try {
    const s1 = await unixLogin(stack);
    await sleep(3_000);
    const s2 = await unixLogin(stack);
    expect(s2.channel.endpoint).toBe(s1.channel.endpoint);
    const expiredIds = () =>
      readAuditRecords(stack.daemon.auditLogPath)
        .records.filter((r) => r.method === "session_expired")
        .map((r) => r.session_id);

    // When: s1 の TTL が切れる
    await waitUntil(
      "session_expired for the first lease",
      () => expiredIds().includes(s1.session_id),
      15_000,
    );

    // Then: session_expired は s1 だけで、ブラウザは 1 つのまま
    expect(expiredIds()).not.toContain(s2.session_id);
    expect(countExecutors(stack.daemon.pid)).toBe(1);

    // When: s2 の TTL も切れる
    await waitUntil(
      "session_expired for the second lease",
      () => expiredIds().includes(s2.session_id),
      15_000,
    );

    // Then: ブラウザが 0 になる
    await waitUntil(
      "the browser to shut down after the last lease expired",
      () => countExecutors(stack.daemon.pid) === 0,
      5_000,
    );
  } finally {
    await stopPhase4Stack(stack);
  }
});

test("AC-61: concurrent logins on the same key start exactly one browser", async () => {
  // Given: X のブラウザが無い
  const stack = await startPhase4Stack();
  try {
    // When: 同一 principal が login(X) を 3 本同時に呼ぶ
    const results = await Promise.all(
      [0, 1, 2].map(() =>
        rawRpc(
          stack.daemon.socketPath,
          "login",
          loginParams(stack.fixture.url, "mock:site"),
        ),
      ),
    );
    for (const res of results) {
      stack.observe("rpc:login", res);
      expect(
        res.error,
        `login failed: ${JSON.stringify(res.error)}`,
      ).toBeUndefined();
    }
    const logins = results.map((r) => r.result as LoginResult);

    // Then: 3 つの異なる session_id、同じ endpoint、POST /login は 1 回、
    // ブラウザは 1 つ
    expect(new Set(logins.map((l) => l.session_id)).size).toBe(3);
    expect(new Set(logins.map((l) => l.channel.endpoint)).size).toBe(1);
    expect(stack.fixture.loginPosts()).toBe(1);
    expect(countExecutors(stack.daemon.pid)).toBe(1);
  } finally {
    await stopPhase4Stack(stack);
  }
});

test("AC-69: each lease gets its own tab, closed when the lease ends", async () => {
  // Given: 同一鍵の 2 リース s1 / s2
  const stack = await startPhase4Stack();
  let client: CdpClient | undefined;
  try {
    const s1 = await unixLogin(stack);
    const s2 = await unixLogin(stack);

    // When: login の結果とブラウザの target 一覧を見る
    // Then: 両方に異なる target_id があり、どちらも page target として存在する
    expect(typeof s1.target_id).toBe("string");
    expect(typeof s2.target_id).toBe("string");
    expect(s2.target_id).not.toBe(s1.target_id);
    client = await CdpClient.connect(s1.channel.endpoint);
    const before = await client.pageTargetIds();
    expect(before).toContain(s1.target_id);
    expect(before).toContain(s2.target_id);

    // When: logout(s2)
    await logout(stack, s2.session_id);

    // Then: 2 s 以内に s2 の target が消え、s1 の target は残り、ブラウザは 1 つ
    const cdp = client;
    await waitUntil(
      "the second lease's tab to close",
      async () => !(await cdp.pageTargetIds()).includes(s2.target_id as string),
      2_000,
    );
    expect(await client.pageTargetIds()).toContain(s1.target_id);
    expect(countExecutors(stack.daemon.pid)).toBe(1);
  } finally {
    client?.close();
    await stopPhase4Stack(stack);
  }
});

test("AC-70: status reports the browser and lease counts", async () => {
  // Given: ブラウザ 2 つ（X の共有ブラウザに 2 リース、Y に 1 リース）
  const stack = await startPhase4Stack();
  try {
    await unixLogin(stack, "mock:site");
    await unixLogin(stack, "mock:site");
    await unixLogin(stack, "mock:site-no-totp");

    // When: status
    const status = await rawRpc(stack.daemon.socketPath, "status", {});

    // Then: {ok: true, browsers: 2, leases: 3}
    expect(status.result).toEqual({ ok: true, browsers: 2, leases: 3 });
  } finally {
    await stopPhase4Stack(stack);
  }
});
