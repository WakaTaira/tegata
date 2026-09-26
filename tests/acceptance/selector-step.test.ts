import { expect, test } from "vitest";
import { startStack, stopStack } from "./support/stack.js";

test("AC-108: a missing middle login step is reported by zero-based index", async () => {
  // Given: three explicit login steps whose second selector does not exist
  const stack = await startStack();
  try {
    // When: the agent calls login with those steps
    const res = await stack.mcp.callTool("login", {
      cred_id: "mock:site",
      target_url: stack.fixture.url,
      steps: [
        { action: "fill", selector: "#username", value: "{{username}}" },
        {
          action: "fill",
          selector: "#does-not-exist",
          value: "{{password}}",
        },
        { action: "click", selector: "#submit" },
      ],
      success_selector: "#welcome",
      failure_selector: "#login-error",
    });

    // Then: text remains the error code and structured content identifies step 1
    expect(res.isError).toBe(true);
    expect(res.text).toBe("SELECTOR_NOT_FOUND");
    expect(res.structured).toEqual({
      error: "SELECTOR_NOT_FOUND",
      step: 1,
    });
  } finally {
    await stopStack(stack);
  }
});

test("AC-109: a missing first login step is reported as step zero", async () => {
  // Given: an explicit login whose first selector does not exist
  const stack = await startStack();
  try {
    // When: the agent calls login with that step list
    const res = await stack.mcp.callTool("login", {
      cred_id: "mock:site",
      target_url: stack.fixture.url,
      steps: [
        { action: "click", selector: "#does-not-exist" },
        { action: "fill", selector: "#password", value: "{{password}}" },
      ],
      success_selector: "#welcome",
      failure_selector: "#login-error",
    });

    // Then: the structured result records the zero-based first step
    expect(res.isError).toBe(true);
    expect(res.text).toBe("SELECTOR_NOT_FOUND");
    expect(res.structured).toEqual({
      error: "SELECTOR_NOT_FOUND",
      step: 0,
    });
  } finally {
    await stopStack(stack);
  }
});
