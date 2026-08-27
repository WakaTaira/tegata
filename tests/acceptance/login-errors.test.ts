// AC-06, AC-07 — failure classification without information leakage.
// Traceability: docs/secret/briefs/tegata-phase1.md 受け入れ条件 #6-#7.
import { expect, test } from "vitest";
import { fixtureSteps } from "./support/harness.js";
import { startStack, stopStack } from "./support/stack.js";

test("AC-06: a missing selector yields SELECTOR_NOT_FOUND and nothing else", async () => {
  // Given: login steps referencing a selector that does not exist
  const stack = await startStack();
  try {
    // When: the agent calls login with those steps
    const res = await stack.mcp.callTool("login", {
      cred_id: "mock:site",
      target_url: stack.fixture.url,
      steps: [
        { action: "fill", selector: "#does-not-exist", value: "{{username}}" },
        { action: "fill", selector: "#password", value: "{{password}}" },
        { action: "click", selector: "#submit" },
      ],
      success_selector: "#welcome",
      failure_selector: "#login-error",
    });

    // Then: the error text is exactly the classification code — no canary,
    // no DOM fragment, no stack trace
    expect(res.isError).toBe(true);
    expect(res.text).toBe("SELECTOR_NOT_FOUND");
  } finally {
    await stopStack(stack);
  }
});

test("AC-07: a wrong password yields INVALID_CREDENTIAL and nothing else", async () => {
  // Given: a credential entry whose password the fixture rejects
  const stack = await startStack();
  try {
    // When: the agent logs in with that entry
    const res = await stack.mcp.callTool("login", {
      cred_id: "mock:site-badpass",
      target_url: stack.fixture.url,
      ...fixtureSteps(),
    });

    // Then: the error text is exactly INVALID_CREDENTIAL and the response
    // carries no canary (teardown re-scans every observed response)
    expect(res.isError).toBe(true);
    expect(res.text).toBe("INVALID_CREDENTIAL");
  } finally {
    await stopStack(stack);
  }
});
