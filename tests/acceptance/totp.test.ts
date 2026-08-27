// AC-08, AC-09, AC-10 — TOTP code exposure: opt-in, short-lived, rate-limited.
// Traceability: docs/secret/briefs/tegata-phase1.md 受け入れ条件 #8-#10.
import { expect, test } from "vitest";
import { startStack, stopStack } from "./support/stack.js";

test("AC-08: get_totp returns a 6-digit code and expiry, never the seed", async () => {
  // Given: a credential entry with totp_exposable = true
  const stack = await startStack({ withFixture: false });
  try {
    // When: the agent calls get_totp
    const res = await stack.mcp.callTool("get_totp", { cred_id: "mock:site" });

    // Then: a 6-digit code with expires_in (1..30s) is returned and the
    // TOTP seed canary appears nowhere in the response
    expect(res.isError, res.text).toBe(false);
    const body = res.json as { code: string; expires_in: number };
    expect(body.code).toMatch(/^\d{6}$/);
    expect(body.expires_in).toBeGreaterThanOrEqual(1);
    expect(body.expires_in).toBeLessThanOrEqual(30);
    expect(res.text).not.toContain(stack.canaries.totpSeed);
  } finally {
    await stopStack(stack);
  }
});

test("AC-09: get_totp on a non-exposable entry is refused", async () => {
  // Given: a credential entry without totp_exposable opt-in
  const stack = await startStack({ withFixture: false });
  try {
    // When: the agent calls get_totp on it
    const res = await stack.mcp.callTool("get_totp", {
      cred_id: "mock:site-no-totp",
    });

    // Then: the call is refused with the classification code
    expect(res.isError).toBe(true);
    expect(res.text).toBe("TOTP_NOT_EXPOSABLE");
  } finally {
    await stopStack(stack);
  }
});

test("AC-10: a second get_totp within 30 seconds is rate-limited", async () => {
  // Given: a get_totp call that just succeeded
  const stack = await startStack({ withFixture: false });
  try {
    const first = await stack.mcp.callTool("get_totp", {
      cred_id: "mock:site",
    });
    expect(first.isError, first.text).toBe(false);

    // When: the same credential is asked again immediately
    const second = await stack.mcp.callTool("get_totp", {
      cred_id: "mock:site",
    });

    // Then: RATE_LIMITED is returned
    expect(second.isError).toBe(true);
    expect(second.text).toBe("RATE_LIMITED");
  } finally {
    await stopStack(stack);
  }
});
