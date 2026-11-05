// AC-206, AC-207, AC-208 — rename `logout` to `disconnect`.
// The old name reads as if it signed out of the site, but it only closes the tegata
// browser session; the site-side session and the stored cookies remain.
// `logout` remains as a deprecated alias.

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { chromium } from "playwright-core";
import { expect, test } from "vitest";
import { bins, defaultEntries, fixtureSteps } from "./support/harness.js";
import {
  readAuditRecords,
  startPhase3Stack,
  stopPhase3Stack,
  waitUntil,
} from "./support/phase3.js";

interface LoginResult {
  session_id: string;
  channel: { kind: string; endpoint: string };
}

/**
 * Returns whether the CDP endpoint accepts a connection. A successful connection is closed
 * immediately.
 */
async function canConnectCdp(endpoint: string): Promise<boolean> {
  try {
    const browser = await chromium.connectOverCDP(endpoint, { timeout: 2_000 });
    await browser.close().catch(() => {});
    return true;
  } catch {
    return false;
  }
}

/** Lists tools without needing a daemon. As in AC-183, TEGATA_SOCKET is a dummy. */
async function listToolDescriptions(): Promise<Map<string, string>> {
  const transport = new StdioClientTransport({
    command: "node",
    args: [bins().mcpEntry],
    env: {
      ...process.env,
      TEGATA_SOCKET: "/nonexistent/tegata-disconnect.sock",
    } as Record<string, string>,
  });
  const client = new Client({ name: "acceptance", version: "0.0.0" });
  try {
    await client.connect(transport);
    const { tools } = await client.listTools();
    return new Map(tools.map((t) => [t.name, t.description ?? ""]));
  } finally {
    await client.close();
  }
}

function startStack() {
  return startPhase3Stack({
    makeProviders: (canaries) => [
      { type: "mock", namespace: "mock", entries: defaultEntries(canaries) },
    ],
  });
}

async function loginFixture(
  stack: Awaited<ReturnType<typeof startStack>>,
): Promise<LoginResult> {
  const login = await stack.mcp.callTool("login", {
    cred_id: "mock:site",
    target_url: stack.fixture.url,
    ...fixtureSteps(),
  });
  expect(login.isError, `login failed: ${login.text}`).toBe(false);
  return login.json as LoginResult;
}

test("AC-206: disconnect ends the session, closes the browser, is audited, and a second call is NOT_FOUND", async () => {
  // Given: a logged-in session
  const stack = await startStack();
  try {
    const login = await loginFixture(stack);
    await waitUntil(
      "the CDP endpoint to accept connections before disconnect",
      () => canConnectCdp(login.channel.endpoint),
      10_000,
    );

    // When: the MCP tool disconnect is called with the session_id
    const first = await stack.mcp.callTool("disconnect", {
      session_id: login.session_id,
    });

    // Then: the result is { ok: true }
    expect(first.isError, first.text).toBe(false);
    expect(first.json).toEqual({ ok: true });

    // Then: the session's CDP endpoint no longer accepts connections
    await waitUntil(
      "the CDP endpoint to refuse connections after disconnect",
      async () => !(await canConnectCdp(login.channel.endpoint)),
      10_000,
    );

    // Then: a second disconnect with the same session_id is NOT_FOUND
    const second = await stack.mcp.callTool("disconnect", {
      session_id: login.session_id,
    });
    expect(second.isError).toBe(true);
    expect(second.text).toBe("NOT_FOUND");

    // Then: the audit log has a disconnect record carrying the session_id
    const { records } = readAuditRecords(stack.daemon.auditLogPath);
    const record = records.find((r) => r.method === "disconnect");
    expect(record?.session_id).toBe(login.session_id);
  } finally {
    await stopPhase3Stack(stack);
  }
});

test("AC-207: the disconnect description says it does not sign out and that cookies remain", async () => {
  // Given: the MCP server's tool listing
  // When: the description of disconnect is read
  const descriptions = await listToolDescriptions();
  const description = descriptions.get("disconnect");

  // Then: it states the site is not signed out and the saved cookies remain
  expect(description, "disconnect must be listed").toBeDefined();
  expect(description).toMatch(/does not sign (you )?out/i);
  expect(description).toMatch(/cookie/i);
});

test("AC-208: the deprecated logout alias still ends the session and its description points to disconnect", async () => {
  // Given: a logged-in session
  const stack = await startStack();
  try {
    const login = await loginFixture(stack);

    // When: the deprecated alias logout is called with the session_id
    const first = await stack.mcp.callTool("logout", {
      session_id: login.session_id,
    });

    // Then: the result is { ok: true } and the session has ended
    expect(first.isError, first.text).toBe(false);
    expect(first.json).toEqual({ ok: true });
    const second = await stack.mcp.callTool("logout", {
      session_id: login.session_id,
    });
    expect(second.isError).toBe(true);
    expect(second.text).toBe("NOT_FOUND");

    // Then: the listed logout description says deprecated and names disconnect
    const description = (await listToolDescriptions()).get("logout");
    expect(description, "logout must remain listed").toBeDefined();
    expect(description).toMatch(/deprecated/i);
    expect(description).toContain("disconnect");
  } finally {
    await stopPhase3Stack(stack);
  }
});
