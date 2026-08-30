// AC-11 — vault locking semantics.
// Traceability: docs/secret/briefs/tegata-phase1.md acceptance condition #11.
import { expect, test } from "vitest";
import { fixtureSteps } from "./support/harness.js";
import { startStack, stopStack } from "./support/stack.js";

test("AC-11: after lock_vault, login fails and the catalog lists names only", async () => {
  // Given: an unlocked namespace
  const stack = await startStack();
  try {
    const locked = await stack.mcp.callTool("lock_vault", {
      namespace: "mock",
    });
    expect(locked.isError, locked.text).toBe(false);
    expect((locked.json as { ok: boolean }).ok).toBe(true);

    // When: the agent tries to log in after lock_vault
    const res = await stack.mcp.callTool("login", {
      cred_id: "mock:site",
      target_url: stack.fixture.url,
      ...fixtureSteps(),
    });

    // Then: VAULT_LOCKED is returned...
    expect(res.isError).toBe(true);
    expect(res.text).toBe("VAULT_LOCKED");

    // ...and list_credentials still enumerates the namespace, but as names
    // only with status "locked" (no uri/kind projection while locked)
    const list = await stack.mcp.callTool("list_credentials", {});
    expect(list.isError).toBe(false);
    const items = list.json as Array<Record<string, unknown>>;
    expect(items.length).toBeGreaterThanOrEqual(3);
    for (const item of items) {
      expect(item.status).toBe("locked");
      expect(Object.keys(item).sort()).toEqual(
        ["id", "name", "source", "status"].sort(),
      );
    }
  } finally {
    await stopStack(stack);
  }
});
