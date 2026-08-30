// AC-45, AC-46 — audit log maturation: size-based single-generation rotation,
// and session_id / namespace recorded for logout and lock_vault.
// Traceability: docs/secret/briefs/tegata-phase3.md 受け入れ条件 #14, #15.

import { expect, test } from "vitest";
import { defaultEntries, fixtureSteps, rawRpc } from "./support/harness.js";
import {
  readAuditRecords,
  startPhase3Stack,
  stopPhase3Stack,
} from "./support/phase3.js";

interface LoginResult {
  session_id: string;
  channel: { kind: string; endpoint: string };
}

test("AC-45: exceeding audit_log_max_bytes rotates one generation", async () => {
  // Given: a daemon with a small audit size cap
  const stack = await startPhase3Stack({
    top: { auditLogMaxBytes: 600 },
    makeProviders: (canaries) => [
      { type: "mock", namespace: "mock", entries: defaultEntries(canaries) },
    ],
    withFixture: false,
  });
  try {
    // When: enough RPCs run to exceed the cap
    for (let i = 0; i < 12; i++) {
      const res = await rawRpc(stack.daemon.socketPath, "status", {});
      expect(res.result).toBeDefined();
    }

    // Then: the rotated file exists and no record was lost across the pair
    const { records, rotatedExists } = readAuditRecords(
      stack.daemon.auditLogPath,
    );
    expect(rotatedExists).toBe(true);
    expect(
      records.filter((r) => r.method === "status").length,
    ).toBeGreaterThanOrEqual(12);
  } finally {
    await stopPhase3Stack(stack);
  }
});

test("AC-46: logout and lock_vault records carry their identifiers", async () => {
  // Given: a completed login
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

    // When: logout and lock_vault run and the audit log is read
    const logout = await stack.mcp.callTool("logout", {
      session_id: result.session_id,
    });
    expect(logout.isError, logout.text).toBe(false);
    const locked = await stack.mcp.callTool("lock_vault", {
      namespace: "mock",
    });
    expect(locked.isError, locked.text).toBe(false);

    // Then: the logout record names the session and the lock_vault record
    // names the namespace
    const { records } = readAuditRecords(stack.daemon.auditLogPath);
    const logoutRecord = records.find((r) => r.method === "logout");
    expect(logoutRecord?.session_id).toBe(result.session_id);
    const lockRecord = records.find((r) => r.method === "lock_vault");
    expect(lockRecord?.namespace).toBe("mock");
  } finally {
    await stopPhase3Stack(stack);
  }
});
