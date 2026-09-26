import { randomBytes } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { expect, test } from "vitest";
import {
  type ApiProxyFixture,
  type ApiProxySpec,
  type ApiProxyStack,
  runApiProxyDaemonUntilExit,
  startApiProxyStack,
  stopApiProxyStack,
} from "./support/api-proxy.js";
import {
  type CanarySet,
  defaultEntries,
  type McpResult,
  rawRpc,
} from "./support/harness.js";
import { readAuditRecords, waitUntil } from "./support/phase3.js";
import { sleep } from "./support/phase4.js";

const API_PROXY_HEADER = "Authorization";
const API_PROXY_VALUE = "Bearer {{secret}}";

interface OpenApiProxy {
  session_id: string;
  base_url: string;
}

interface OpenApiProxyCall {
  mcp: McpResult;
  session: OpenApiProxy;
}

interface HttpTextResponse {
  status: number;
  headers: Record<string, string>;
  text: string;
}

function proxySpec(name: string, upstream: string): ApiProxySpec {
  return {
    name,
    cred_id: "mock:site",
    upstream,
    header: API_PROXY_HEADER,
    value: API_PROXY_VALUE,
  };
}

function singleProxyStack(
  top: Parameters<typeof startApiProxyStack>[0]["top"] = {},
): Promise<ApiProxyStack> {
  return startApiProxyStack({
    top,
    apiProxies: (fixture) => [proxySpec("fx", fixture.url)],
  });
}

async function openProxy(
  stack: ApiProxyStack,
  name: string,
): Promise<OpenApiProxyCall> {
  const mcp = await stack.mcp.callTool("open_api_proxy", { name });
  expect(mcp.isError, mcp.text).toBe(false);
  const session = mcp.json as Partial<OpenApiProxy>;
  expect(typeof session.session_id).toBe("string");
  expect(typeof session.base_url).toBe("string");
  expect(session.base_url).toMatch(/^http:\/\/127\.0\.0\.1:\d+\/[^/]+$/);
  return { mcp, session: session as OpenApiProxy };
}

async function fetchText(
  url: string,
  init: RequestInit = {},
): Promise<HttpTextResponse> {
  const response = await fetch(url, init);
  return {
    status: response.status,
    headers: Object.fromEntries(response.headers.entries()),
    text: await response.text(),
  };
}

async function whoamiCount(fixture: ApiProxyFixture): Promise<number> {
  const response = await fetch(`${fixture.url}/api/whoami/count`);
  expect(response.status).toBe(200);
  const value = (await response.json()) as { count?: unknown };
  expect(typeof value.count).toBe("number");
  return value.count as number;
}

async function fetchWithTimeout(
  url: string,
  timeoutMs: number,
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

/** 終了済みプロキシの接続拒否または 404 を 2 秒以内に確認する。 */
async function expectProxyUnavailable(baseUrl: string): Promise<void> {
  const deadline = Date.now() + 2_000;
  let lastStatus = "接続結果なし";
  while (Date.now() < deadline) {
    try {
      const response = await fetchWithTimeout(
        `${baseUrl}/api/whoami`,
        Math.min(300, Math.max(50, deadline - Date.now())),
      );
      lastStatus = `HTTP ${response.status}`;
      await response.text();
      if (response.status === 404) return;
    } catch (error) {
      if ((error as { name?: unknown }).name !== "AbortError") return;
    }
    await sleep(50);
  }
  throw new Error(`proxy remained available for 2 seconds (${lastStatus})`);
}

function throwawayCanaries(): CanarySet {
  const random = () => randomBytes(12).toString("hex");
  return {
    username: `user_${random()}`,
    password: `pass_${random()}`,
    totpSeed: `seed_${random()}`,
    wrongPassword: `wrong_${random()}`,
  };
}

// Given: [[api_proxy]] name = "fx"（upstream = fixture、cred X）
// When: open_api_proxy {name: "fx"} の base_url + "/api/whoami" へ GET
// Then: HTTP 200 で、本文が {"user":"fixture"}
test("AC-98: open_api_proxy injects cred X for the fixture whoami request", async () => {
  const stack = await singleProxyStack();
  let sessionId: string | undefined;
  try {
    const opened = await openProxy(stack, "fx");
    sessionId = opened.session.session_id;
    const response = await fetchText(`${opened.session.base_url}/api/whoami`);
    expect(response.status).toBe(200);
    expect(JSON.parse(response.text)).toEqual({ user: "fixture" });
  } finally {
    if (sessionId !== undefined)
      await stack.mcp
        .callTool("logout", { session_id: sessionId })
        .catch(() => {});
    await stopApiProxyStack(stack);
  }
});

// Given: AC-98 のプロキシ
// When: secret を欠いた path と、別の secret の path で "/api/whoami" へ GET
// Then: どちらも HTTP 404 で、fixture の "/api/whoami" 受信数は増えない
test("AC-99: api-proxy paths without the issued secret never reach upstream", async () => {
  const stack = await singleProxyStack();
  let sessionId: string | undefined;
  try {
    const opened = await openProxy(stack, "fx");
    sessionId = opened.session.session_id;
    const proxyOrigin = new URL(opened.session.base_url).origin;
    const before = await whoamiCount(stack.fixture);
    const missingSecret = await fetchText(`${proxyOrigin}/api/whoami`);
    const otherSecret = await fetchText(
      `${proxyOrigin}/different-secret/api/whoami`,
    );
    expect(missingSecret.status).toBe(404);
    expect(otherSecret.status).toBe(404);
    expect(await whoamiCount(stack.fixture)).toBe(before);
  } finally {
    if (sessionId !== undefined)
      await stack.mcp
        .callTool("logout", { session_id: sessionId })
        .catch(() => {});
    await stopApiProxyStack(stack);
  }
});

// Given: AC-98 のプロキシ
// When: agent が Authorization: Bearer wrong を付けて "/api/whoami" へ GET
// Then: 注入値で置換されて HTTP 200、応答ヘッダ・本文・MCP 出力・leak guard 走査で cred X の password が 0 件
test("AC-100: caller authorization is replaced and the credential stays out of observed surfaces", async () => {
  const stack = await singleProxyStack();
  let sessionId: string | undefined;
  try {
    const opened = await openProxy(stack, "fx");
    sessionId = opened.session.session_id;
    const response = await fetchText(`${opened.session.base_url}/api/whoami`, {
      headers: { Authorization: "Bearer wrong" },
    });
    const observedResponse = JSON.stringify({
      headers: response.headers,
      body: response.text,
    });
    stack.guard.observe("api-proxy-response", observedResponse);
    expect(response.status).toBe(200);
    expect(JSON.parse(response.text)).toEqual({ user: "fixture" });
    expect(observedResponse).not.toContain(stack.canaries.password);
    expect(opened.mcp.text).not.toContain(stack.canaries.password);
    expect(await stack.guard.collectLeaks()).toEqual([]);
  } finally {
    if (sessionId !== undefined)
      await stack.mcp
        .callTool("logout", { session_id: sessionId })
        .catch(() => {});
    await stopApiProxyStack(stack);
  }
});

// Given: プロキシ s1
// When: logout {session_id: s1}
// Then: 2 秒以内に base_url への GET が接続拒否または HTTP 404
// Given: プロキシ s2
// When: lock_vault
// Then: 2 秒以内に base_url への GET が接続拒否または HTTP 404
// Given: トップレベル session_ttl_secs = 3 のプロキシ s3
// When: 4 秒待つ
// Then: 2 秒以内に base_url への GET が接続拒否または HTTP 404、監査に s3 の session_expired
test("AC-101: logout, lock_vault, and proxy TTL terminate their sessions", async () => {
  const logoutStack = await singleProxyStack();
  try {
    const opened = await openProxy(logoutStack, "fx");
    const logout = await logoutStack.mcp.callTool("logout", {
      session_id: opened.session.session_id,
    });
    expect(logout.isError, logout.text).toBe(false);
    await expectProxyUnavailable(opened.session.base_url);
  } finally {
    await stopApiProxyStack(logoutStack);
  }

  const lockStack = await singleProxyStack();
  try {
    const opened = await openProxy(lockStack, "fx");
    const locked = await lockStack.mcp.callTool("lock_vault", {
      namespace: "mock",
    });
    expect(locked.isError, locked.text).toBe(false);
    await expectProxyUnavailable(opened.session.base_url);
  } finally {
    await stopApiProxyStack(lockStack);
  }

  const ttlStack = await startApiProxyStack({
    top: { sessionTtlSecs: 3 },
    apiProxies: (fixture) => [proxySpec("s3", fixture.url)],
  });
  try {
    const opened = await openProxy(ttlStack, "s3");
    await sleep(4_000);
    await expectProxyUnavailable(opened.session.base_url);
    await waitUntil(
      "s3 session_expired audit record",
      () => {
        const { records } = readAuditRecords(ttlStack.daemon.auditLogPath);
        return records.some(
          (record) =>
            record.method === "session_expired" &&
            record.session_id === opened.session.session_id,
        );
      },
      2_000,
    );
    const { records } = readAuditRecords(ttlStack.daemon.auditLogPath);
    expect(
      records.some(
        (record) =>
          record.method === "session_expired" &&
          record.session_id === opened.session.session_id,
      ),
    ).toBe(true);
  } finally {
    await stopApiProxyStack(ttlStack);
  }
});

// Given: 未定義の name
// When: open_api_proxy {name: "nope"}
// Then: NOT_FOUND
// Given: upstream = "http://example.com" の config
// When: daemon を起動
// Then: exit code 非ゼロで stderr に upstream の理由がある
test("AC-102: unknown proxies fail closed and non-loopback upstreams refuse startup", async () => {
  const stack = await singleProxyStack();
  try {
    const response = await rawRpc(stack.daemon.socketPath, "open_api_proxy", {
      name: "nope",
    });
    stack.guard.observe("rpc:open_api_proxy:unknown", response);
    expect(response.error?.message).toBe("NOT_FOUND");
  } finally {
    await stopApiProxyStack(stack);
  }

  const entries = defaultEntries(throwawayCanaries());
  const exit = await runApiProxyDaemonUntilExit({
    entries,
    apiProxies: [proxySpec("external", "http://example.com")],
  });
  expect(
    exit.code,
    `daemon kept running; stderr: ${exit.stderr}`,
  ).not.toBeNull();
  expect(exit.code).not.toBe(0);
  expect(exit.stderr).toMatch(/upstream/i);
  expect(exit.stderr).toMatch(/example\.com|loopback|allowlist|local/i);
});

// Given: AC-98 の GET（query ?q=secretish 付き）
// When: 監査ログを読む
// Then: open_api_proxy 行（target_url = upstream）と api_proxy_request 行（proxy = "fx"、GET、path = "/api/whoami"、status = 200、principal あり）があり、secretish・password・path secret は 0 件
test("AC-103: api-proxy audit records describe the request without secret material", async () => {
  const stack = await singleProxyStack();
  let sessionId: string | undefined;
  try {
    const opened = await openProxy(stack, "fx");
    sessionId = opened.session.session_id;
    const requestUrl = new URL(
      `${opened.session.base_url}/api/whoami?q=secretish`,
    );
    const response = await fetchText(requestUrl.toString());
    expect(response.status).toBe(200);

    await waitUntil("api-proxy audit records", () => {
      const { records } = readAuditRecords(stack.daemon.auditLogPath);
      return (
        records.some((record) => record.method === "open_api_proxy") &&
        records.some((record) => record.method === "api_proxy_request")
      );
    });
    const { records } = readAuditRecords(stack.daemon.auditLogPath);
    const openRecord = records.find(
      (record) => record.method === "open_api_proxy",
    );
    expect(openRecord?.target_url).toBe(stack.fixture.url);
    const requestRecord = records.find(
      (record) => record.method === "api_proxy_request",
    );
    expect(requestRecord?.proxy).toBe("fx");
    expect(requestRecord?.http_method).toBe("GET");
    expect(requestRecord?.path).toBe("/api/whoami");
    expect(requestRecord?.status).toBe(200);
    expect(typeof requestRecord?.principal).toBe("string");

    const auditText = JSON.stringify(records);
    expect(auditText).not.toContain("secretish");
    expect(auditText).not.toContain(stack.canaries.password);
    expect(auditText).not.toContain(new URL(opened.session.base_url).pathname);
  } finally {
    if (sessionId !== undefined)
      await stack.mcp
        .callTool("logout", { session_id: sessionId })
        .catch(() => {});
    await stopApiProxyStack(stack);
  }
});

// Given: approve_cmd が env をファイルへ書いて exit 1 するスクリプト
// When: open_api_proxy {name: "fx"}
// Then: APPROVAL_DENIED となり、ファイルに TEGATA_METHOD=open_api_proxy と TEGATA_TARGET_URL=<upstream> がある
test("AC-104: approve_cmd receives api-proxy references and can deny the call", async () => {
  const scratch = fs.mkdtempSync(
    path.join(os.tmpdir(), "tegata-api-proxy-hitl-"),
  );
  const envFile = path.join(scratch, "approve-env.txt");
  const stack = await startApiProxyStack({
    top: { approveCmd: `env > ${envFile}; exit 1` },
    apiProxies: (fixture) => [proxySpec("fx", fixture.url)],
  });
  try {
    const opened = await stack.mcp.callTool("open_api_proxy", { name: "fx" });
    expect(opened.isError).toBe(true);
    expect(opened.text).toBe("APPROVAL_DENIED");
    const env = fs.readFileSync(envFile, "utf8");
    stack.guard.observe("api-proxy-approve-env", env);
    expect(env).toContain("TEGATA_METHOD=open_api_proxy");
    expect(env).toContain(`TEGATA_TARGET_URL=${stack.fixture.url}`);
    expect(env).not.toContain(stack.canaries.password);
  } finally {
    await stopApiProxyStack(stack);
    fs.rmSync(scratch, { recursive: true, force: true });
  }
});
