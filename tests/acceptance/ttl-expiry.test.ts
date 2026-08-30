// AC-36 — browser-session TTL expiry terminates the executor and is audited.
// Traceability: docs/secret/briefs/tegata-phase3.md 受け入れ条件 #5.

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

test("AC-36: session TTL expiry is audited and shuts the executor down", async () => {
  // Given: an active session under a short browser TTL
  const stack = await startPhase3Stack({
    top: { sessionTtlSecs: 2 },
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

    // When: the TTL runs out
    await waitUntil(
      "the session_expired audit record",
      () => {
        const { records } = readAuditRecords(stack.daemon.auditLogPath);
        return records.some((r) => r.method === "session_expired");
      },
      20_000,
    );

    // Then: the record names the expired session with the daemon-originated
    // peer marker, and the executor's CDP endpoint is gone
    const { records } = readAuditRecords(stack.daemon.auditLogPath);
    const record = records.find((r) => r.method === "session_expired");
    expect(record?.session_id).toBe(result.session_id);
    expect(record?.peer_system).toBe(true);
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
