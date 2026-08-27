// AC-12 — the boundary RPC accepts only allowlisted methods.
// Traceability: docs/secret/briefs/tegata-phase1.md 受け入れ条件 #12.
import { expect, test } from "vitest";
import { rawRpc } from "./support/harness.js";
import { startStack, stopStack } from "./support/stack.js";

test("AC-12: a non-allowlisted method sent straight to the socket is rejected", async () => {
  // Given: direct access to the daemon's UNIX socket (bypassing MCP)
  const stack = await startStack({ withFixture: false });
  try {
    // When: an internal-sounding method outside the allowlist is invoked
    const res = await rawRpc(stack.daemon.socketPath, "resolve", {
      ref_id: "mock:site",
    });

    // Then: it is rejected with JSON-RPC method-not-found (-32601) and no
    // result — the allowlist, not the MCP layer, is the gate
    expect(res.result).toBeUndefined();
    expect(res.error?.code).toBe(-32601);
    expect(JSON.stringify(res)).not.toContain(stack.canaries.password);
  } finally {
    await stopStack(stack);
  }
});
