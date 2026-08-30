// AC-01 — credential catalog projection.
// Traceability: docs/secret/briefs/tegata-phase1.md acceptance condition #1.
import { expect, test } from "vitest";
import { startStack, stopStack } from "./support/stack.js";

test("AC-01: list_credentials exposes metadata only, never canary values", async () => {
  // Given: a vault holding canary credentials and a running tegatad
  const stack = await startStack({ withFixture: false });
  try {
    // When: the agent calls the MCP tool list_credentials
    const res = await stack.mcp.callTool("list_credentials", {});

    // Then: every item carries exactly {id, name, uri, kind, source, status}
    // and no canary value appears anywhere in the response (the guard also
    // re-scans the full response, including encoded variants, at teardown).
    expect(res.isError).toBe(false);
    const items = res.json as Array<Record<string, unknown>>;
    expect(Array.isArray(items)).toBe(true);
    expect(items.length).toBeGreaterThanOrEqual(3);
    for (const item of items) {
      expect(Object.keys(item).sort()).toEqual(
        ["id", "kind", "name", "source", "status", "uri"].sort(),
      );
      expect(item.source).toBe("mock");
      expect(String(item.id)).toMatch(/^mock:/);
    }
    const flat = JSON.stringify(items);
    for (const value of Object.values(stack.canaries)) {
      expect(flat).not.toContain(value);
    }
  } finally {
    await stopStack(stack);
  }
});
