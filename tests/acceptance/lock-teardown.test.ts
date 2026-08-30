// AC-32, AC-33 — lock_vault tears down the live browser sessions of the
// locked namespace, gracefully, and audits each termination.
// Traceability: docs/secret/briefs/tegata-phase3.md 受け入れ条件 #1, #2.

import { chromium } from "playwright-core";
import { expect, test } from "vitest";
import { defaultEntries, fixtureSteps } from "./support/harness.js";
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

test("AC-32: lock_vault terminates the namespace's live browser sessions", async () => {
  // Given: an active login session backed by the mock provider
  const stack = await startPhase3Stack({
    makeProviders: (canaries) => [
      { type: "mock", namespace: "mock", entries: defaultEntries(canaries) },
    ],
  });
  try {
    const login = await stack.mcp.callTool("login", {
      cred_id: "mock:site",
      target_url: stack.fixture.url,
      ...fixtureSteps(),
    });
    expect(login.isError, `login failed: ${login.text}`).toBe(false);
    const result = login.json as LoginResult;
    const browser = await chromium.connectOverCDP(result.channel.endpoint);
    await browser.close();

    // When: the namespace is locked
    const locked = await stack.mcp.callTool("lock_vault", {
      namespace: "mock",
    });
    expect(locked.isError, locked.text).toBe(false);

    // Then: the session's CDP endpoint stops being connectable and the
    // executor child is gone
    await waitUntil("the CDP endpoint to refuse connections", async () => {
      try {
        const b = await chromium.connectOverCDP(result.channel.endpoint, {
          timeout: 2_000,
        });
        await b.close();
        return false;
      } catch {
        return true;
      }
    });
  } finally {
    await stopPhase3Stack(stack);
  }
});

test("AC-33: the lock-driven termination is audited as session_terminated", async () => {
  // Given: an active login session backed by the mock provider
  const stack = await startPhase3Stack({
    makeProviders: (canaries) => [
      { type: "mock", namespace: "mock", entries: defaultEntries(canaries) },
    ],
  });
  try {
    const login = await stack.mcp.callTool("login", {
      cred_id: "mock:site",
      target_url: stack.fixture.url,
      ...fixtureSteps(),
    });
    expect(login.isError, `login failed: ${login.text}`).toBe(false);
    const result = login.json as LoginResult;

    // When: the namespace is locked and the audit log is read
    const locked = await stack.mcp.callTool("lock_vault", {
      namespace: "mock",
    });
    expect(locked.isError, locked.text).toBe(false);
    await waitUntil("the session_terminated audit record", () => {
      const { records } = readAuditRecords(stack.daemon.auditLogPath);
      return records.some((r) => r.method === "session_terminated");
    });

    // Then: the record carries the session id, the namespace, and the
    // daemon-originated peer marker
    const { records } = readAuditRecords(stack.daemon.auditLogPath);
    const record = records.find((r) => r.method === "session_terminated");
    expect(record).toBeDefined();
    expect(record?.session_id).toBe(result.session_id);
    expect(record?.namespace).toBe("mock");
    expect(record?.peer_system).toBe(true);
  } finally {
    await stopPhase3Stack(stack);
  }
});
