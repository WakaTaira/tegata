import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createLeakGuard, type LeakGuard } from "@tegata/leak-guard";
import { expect, test } from "vitest";
import {
  type ApiProxyDaemon,
  type ApiProxyOAuthSpec,
  type ApiProxySpec,
  runApiProxyDaemonUntilExit,
  startApiProxyDaemon,
} from "./support/api-proxy.js";
import {
  bins,
  type CanarySet,
  connectMcp,
  defaultEntries,
  listFiles,
  type McpResult,
  type McpSession,
  rawRpc,
  startTargetFixture,
  type TargetFixture,
} from "./support/harness.js";
import { readAuditRecords, waitUntil } from "./support/phase3.js";
import { sleep } from "./support/phase4.js";

const API_PROXY_VALUE = "Bearer {{secret}}";

interface OpenApiProxy {
  session_id: string;
  base_url: string;
}

interface HttpTextResponse {
  status: number;
  text: string;
}

interface OAuthState {
  grants: {
    device_code: number;
    refresh_token: number;
  };
  issued: number;
  revoked: number;
  access_tokens: string[];
  refresh_tokens: string[];
}

interface OAuthStack {
  guard: LeakGuard;
  canaries: CanarySet;
  daemon: ApiProxyDaemon;
  fixture: TargetFixture;
  mcp: McpSession;
  agentDir: string;
}

function oauthProxySpec(
  upstream: string,
  oauth: Partial<ApiProxyOAuthSpec> = {},
): ApiProxySpec {
  return {
    name: "fxo",
    upstream,
    header: "Authorization",
    value: API_PROXY_VALUE,
    oauth: {
      client_id: "tegata-test",
      device_authorization_url: `${upstream}/oauth/device_authorization`,
      token_url: `${upstream}/oauth/token`,
      revocation_url: `${upstream}/oauth/revoke`,
      login_cred_id: "mock:site",
      success_selector: "#device-ok",
      failure_selector: "#device-error",
      ...oauth,
    },
  };
}

async function startOAuthStack(
  makeProxies: (fixture: TargetFixture) => ApiProxySpec[],
): Promise<OAuthStack> {
  const agentDir = fs.mkdtempSync(path.join(os.tmpdir(), "tegata-agent-"));
  const guard = await createLeakGuard({
    leakscanBin: bins().leakscan,
    agentVisibleRoots: [agentDir, process.cwd()],
    psSampleIntervalMs: 200,
  });
  const canaries: CanarySet = {
    username: guard.canary("username"),
    password: guard.canary("password"),
    totpSeed: guard.canary("totp_seed"),
    wrongPassword: guard.canary("wrong_password"),
  };
  let fixture: TargetFixture | undefined;
  let daemon: ApiProxyDaemon | undefined;
  let mcp: McpSession | undefined;
  try {
    fixture = await startTargetFixture({
      username: canaries.username,
      password: canaries.password,
    });
    const entries = defaultEntries(canaries).map((entry) => ({
      ...entry,
      uri: fixture?.url ?? entry.uri,
    }));
    daemon = await startApiProxyDaemon({
      entries,
      apiProxies: makeProxies(fixture),
      captureStderr: true,
    });
    mcp = await connectMcp(daemon.socketPath, (label, value) =>
      guard.observe(label, value),
    );
    return { guard, canaries, daemon, fixture, mcp, agentDir };
  } catch (error) {
    await mcp?.close().catch(() => {});
    await daemon?.stop().catch(() => {});
    await fixture?.stop().catch(() => {});
    await guard.dispose().catch(() => {});
    fs.rmSync(agentDir, { recursive: true, force: true });
    throw error;
  }
}

async function stopOAuthStack(stack: OAuthStack): Promise<void> {
  await stack.mcp.close().catch(() => {});
  await stack.daemon.stop().catch(() => {});
  await stack.fixture.stop().catch(() => {});
  try {
    await stack.guard.assertNoLeaks();
  } finally {
    await stack.guard.dispose();
    fs.rmSync(stack.agentDir, { recursive: true, force: true });
  }
}

async function openProxy(
  stack: OAuthStack,
): Promise<{ mcp: McpResult; session: OpenApiProxy }> {
  const mcp = await stack.mcp.callTool("open_api_proxy", { name: "fxo" });
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
  return { status: response.status, text: await response.text() };
}

async function oauthState(fixture: TargetFixture): Promise<OAuthState> {
  const response = await fetch(`${fixture.url}/oauth/state`);
  expect(response.status).toBe(200);
  return (await response.json()) as OAuthState;
}

async function configureOAuth(
  fixture: TargetFixture,
  config: Record<string, unknown>,
): Promise<void> {
  const response = await fetch(`${fixture.url}/oauth/config`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(config),
  });
  expect(response.status).toBe(200);
  await response.text();
}

async function expectProxyUnavailable(
  baseUrl: string,
  timeoutMs: number,
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`${baseUrl}/api/me`, {
        signal: AbortSignal.timeout(Math.min(500, deadline - Date.now())),
      });
      await response.text();
      if (response.status === 404) return;
    } catch (error) {
      if ((error as { name?: unknown }).name !== "TimeoutError") return;
    }
    await sleep(50);
  }
  throw new Error(`proxy remained available for ${timeoutMs} ms`);
}

function fixedCanaries(): CanarySet {
  return {
    username: "oauth-invalid-user",
    password: "oauth-invalid-password",
    totpSeed: "oauth-invalid-seed",
    wrongPassword: "oauth-invalid-wrong-password",
  };
}

test("AC-129: Given an OAuth proxy for the fixture / When open_api_proxy serves /api/me / Then the fixture user is returned and one device grant is issued", {
  timeout: 120_000,
}, async () => {
  const stack = await startOAuthStack((fixture) => [
    oauthProxySpec(fixture.url),
  ]);
  let sessionId: string | undefined;
  try {
    const opened = await openProxy(stack);
    sessionId = opened.session.session_id;
    const response = await fetchText(`${opened.session.base_url}/api/me`);
    expect(response.status).toBe(200);
    expect(JSON.parse(response.text)).toEqual({ user: "fixture" });

    const state = await oauthState(stack.fixture);
    expect(state.grants.device_code).toBe(1);
    expect(state.issued).toBe(1);
  } finally {
    if (sessionId !== undefined)
      await stack.mcp
        .callTool("logout", { session_id: sessionId })
        .catch(() => {});
    await stopOAuthStack(stack);
  }
});

test("AC-130: Given a four-second OAuth token lifetime / When the proxy is open for seven seconds / Then refresh keeps /api/me successful and the audit records issued and refreshed", {
  timeout: 120_000,
}, async () => {
  const stack = await startOAuthStack((fixture) => [
    oauthProxySpec(fixture.url),
  ]);
  let sessionId: string | undefined;
  try {
    await configureOAuth(stack.fixture, { expires_in: 4 });
    const opened = await openProxy(stack);
    sessionId = opened.session.session_id;
    await sleep(7_000);

    const response = await fetchText(`${opened.session.base_url}/api/me`);
    expect(response.status).toBe(200);
    expect(JSON.parse(response.text)).toEqual({ user: "fixture" });

    const state = await oauthState(stack.fixture);
    expect(state.grants.refresh_token).toBeGreaterThanOrEqual(1);
    await waitUntil("OAuth issued and refreshed audit records", () => {
      const { records } = readAuditRecords(stack.daemon.auditLogPath);
      const actions = records
        .filter((record) => record.method === "api_proxy_oauth")
        .map((record) => record.oauth_action);
      return actions.includes("issued") && actions.includes("refreshed");
    });
  } finally {
    if (sessionId !== undefined)
      await stack.mcp
        .callTool("logout", { session_id: sessionId })
        .catch(() => {});
    await stopOAuthStack(stack);
  }
});

test("AC-131: Given an open OAuth proxy / When its session is logged out / Then its token is revoked within five seconds and the proxy is unavailable", {
  timeout: 120_000,
}, async () => {
  const stack = await startOAuthStack((fixture) => [
    oauthProxySpec(fixture.url),
  ]);
  try {
    const opened = await openProxy(stack);
    const before = await oauthState(stack.fixture);
    const logout = await stack.mcp.callTool("logout", {
      session_id: opened.session.session_id,
    });
    expect(logout.isError, logout.text).toBe(false);

    await waitUntil(
      "OAuth token revocation",
      async () => (await oauthState(stack.fixture)).revoked > before.revoked,
      5_000,
    );
    await expectProxyUnavailable(opened.session.base_url, 5_000);
    await waitUntil(
      "OAuth revoked audit record",
      () => {
        const { records } = readAuditRecords(stack.daemon.auditLogPath);
        return records.some(
          (record) =>
            record.method === "api_proxy_oauth" &&
            record.oauth_action === "revoked",
        );
      },
      5_000,
    );
  } finally {
    await stopOAuthStack(stack);
  }
});

test("AC-132: Given an OAuth token endpoint configured to deny access / When open_api_proxy runs / Then OAUTH_GRANT_FAILED is returned without a browser or lease", {
  timeout: 120_000,
}, async () => {
  const stack = await startOAuthStack((fixture) => [
    oauthProxySpec(fixture.url),
  ]);
  try {
    await configureOAuth(stack.fixture, { deny: true });
    const response = await stack.mcp.callTool("open_api_proxy", {
      name: "fxo",
    });
    expect(response.isError).toBe(true);
    expect(response.text).toBe("OAUTH_GRANT_FAILED");

    const status = await rawRpc(stack.daemon.socketPath, "status", {});
    expect(status.result).toEqual(
      expect.objectContaining({ browsers: 0, leases: 0 }),
    );
  } finally {
    await stopOAuthStack(stack);
  }
});

test("AC-133: Given the OAuth proxy flows / When MCP output, audit, stderr, and agent-visible surfaces are scanned / Then access tokens, refresh tokens, and the login password are absent", {
  timeout: 120_000,
}, async () => {
  const stack = await startOAuthStack((fixture) => [
    oauthProxySpec(fixture.url),
  ]);
  const mcpOutput: McpResult[] = [];
  try {
    await configureOAuth(stack.fixture, { expires_in: 4 });
    const opened = await openProxy(stack);
    mcpOutput.push(opened.mcp);
    const first = await fetchText(`${opened.session.base_url}/api/me`);
    expect(first.status).toBe(200);
    await sleep(7_000);
    const second = await fetchText(`${opened.session.base_url}/api/me`);
    expect(second.status).toBe(200);
    const logout = await stack.mcp.callTool("logout", {
      session_id: opened.session.session_id,
    });
    mcpOutput.push(logout);

    const state = await oauthState(stack.fixture);
    expect(state.access_tokens.length).toBeGreaterThan(0);
    expect(state.refresh_tokens.length).toBeGreaterThan(0);
    await waitUntil("OAuth revocation audit record", () => {
      const { records } = readAuditRecords(stack.daemon.auditLogPath);
      return records.some(
        (record) =>
          record.method === "api_proxy_oauth" &&
          record.oauth_action === "revoked",
      );
    });

    const auditText = fs.readFileSync(stack.daemon.auditLogPath, "utf8");
    const agentText = listFiles(stack.agentDir)
      .map((file) => fs.readFileSync(file, "utf8"))
      .join("\n");
    const surfaces = {
      mcp: mcpOutput,
      responses: [first, second],
      audit: auditText,
      stderr: stack.daemon.stderr(),
      agent: agentText,
    };
    const surfaceText = JSON.stringify(surfaces);
    stack.guard.observe("oauth-leak-surfaces", surfaces);

    expect(surfaceText).not.toContain(stack.canaries.password);
    for (const token of [...state.access_tokens, ...state.refresh_tokens]) {
      expect(surfaceText).not.toContain(token);
      expect(auditText).not.toContain(token);
      expect(stack.daemon.stderr()).not.toContain(token);
    }
    expect(await stack.guard.collectLeaks()).toEqual([]);
  } finally {
    await stopOAuthStack(stack);
  }
});

test("AC-134: Given an external token URL or both cred_id and oauth / When the daemon starts / Then it exits non-zero and explains the invalid configuration", {
  timeout: 120_000,
}, async () => {
  const entries = defaultEntries(fixedCanaries());
  const externalUrl = await runApiProxyDaemonUntilExit({
    entries,
    apiProxies: [
      oauthProxySpec("http://127.0.0.1:32123", {
        token_url: "http://example.com/token",
      }),
    ],
  });
  expect(externalUrl.code).not.toBeNull();
  expect(externalUrl.code).not.toBe(0);
  expect(externalUrl.stderr).toMatch(
    /token_url|example\.com|loopback|allowlist|local/i,
  );

  const bothCredentials = oauthProxySpec("http://127.0.0.1:32123");
  bothCredentials.cred_id = "mock:site";
  const both = await runApiProxyDaemonUntilExit({
    entries,
    apiProxies: [bothCredentials],
  });
  expect(both.code).not.toBeNull();
  expect(both.code).not.toBe(0);
  expect(both.stderr).toMatch(/cred_id|oauth|either|exclusive|one/i);
});
