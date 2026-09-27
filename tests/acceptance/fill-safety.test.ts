import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createLeakGuard } from "@tegata/leak-guard";
import { expect, test } from "vitest";
import {
  bins,
  type CanarySet,
  connectMcp,
  defaultEntries,
  fixtureSteps,
  startDaemon,
  startTargetFixture,
} from "./support/harness.js";
import { type Stack, startStack, stopStack } from "./support/stack.js";

type MutatingFillState = {
  nickname: string;
  password_length: number;
};

async function receivedUsername(stack: Stack): Promise<string | null> {
  const response = await fetch(`${stack.fixture.url}/received-submission`);
  expect(response.ok).toBe(true);
  const body = (await response.json()) as { username: string | null };
  return body.username;
}

async function waitForMutatingFillState(
  stack: Stack,
): Promise<MutatingFillState> {
  const deadline = Date.now() + 5_000;
  while (Date.now() < deadline) {
    const response = await fetch(`${stack.fixture.url}/mutating-fill-state`);
    expect(response.ok).toBe(true);
    const body = (await response.json()) as {
      nickname: unknown;
      password_length: unknown;
    };
    if (
      typeof body.nickname === "string" &&
      typeof body.password_length === "number"
    ) {
      return {
        nickname: body.nickname,
        password_length: body.password_length,
      };
    }
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error("timed out waiting for mutating fill state");
}

test("AC-142: a focus-moving password field does not corrupt the username", async () => {
  // Given: a fixture whose password field moves focus to the username field
  const stack = await startStack();
  try {
    // When: the agent logs in with explicit username, password, and submit steps
    const result = await stack.mcp.callTool("login", {
      cred_id: "mock:site",
      target_url: `${stack.fixture.url}/focus-thief/`,
      steps: fixtureSteps().steps,
      success_selector: "#welcome",
      failure_selector: "#login-error",
    });

    // Then: login succeeds and the fixture received exactly the credential's username
    expect(result.isError, `login failed: ${result.text}`).toBe(false);
    expect(await receivedUsername(stack)).toBe(stack.canaries.username);
  } finally {
    await stopStack(stack);
  }
});

test("AC-143: a password placeholder rejects a non-password input", async () => {
  // Given: a fixture whose password field is a text input
  const stack = await startStack();
  try {
    // When: the agent logs in with explicit username, password, and submit steps
    const result = await stack.mcp.callTool("login", {
      cred_id: "mock:site",
      target_url: `${stack.fixture.url}/password-as-text/`,
      steps: fixtureSteps().steps,
      success_selector: "#welcome",
      failure_selector: "#login-error",
    });

    // Then: step 1 fails with FILL_MISMATCH and nothing is submitted to the fixture
    expect(result.isError).toBe(true);
    expect(result.text).toBe("FILL_MISMATCH");
    expect(result.structured).toEqual({ error: "FILL_MISMATCH", step: 1 });
    expect(await receivedUsername(stack)).toBeNull();
  } finally {
    await stopStack(stack);
  }
});

test("AC-144: a fill-time mutation is reported and cleared", async () => {
  // Given: a fixture whose password input listener writes "tampered" into another input
  const stack = await startStack();
  try {
    // When: the agent logs in with explicit username, password, and submit steps
    const result = await stack.mcp.callTool("login", {
      cred_id: "mock:site",
      target_url: `${stack.fixture.url}/mutating-fill/`,
      steps: fixtureSteps().steps,
      success_selector: "#welcome",
      failure_selector: "#login-error",
    });

    // Then: step 1 fails with FILL_MISMATCH and nothing is submitted to the fixture
    expect(result.isError).toBe(true);
    expect(result.text).toBe("FILL_MISMATCH");
    expect(result.structured).toEqual({ error: "FILL_MISMATCH", step: 1 });
    expect(await receivedUsername(stack)).toBeNull();

    // Then: both the password and the tampered nickname were cleared
    await expect(waitForMutatingFillState(stack)).resolves.toEqual({
      nickname: "",
      password_length: 0,
    });
  } finally {
    await stopStack(stack);
  }
});

test("AC-145a: wait_for waits for a delayed password field", async () => {
  // Given: a fixture that shows the password field 2 s after #next is clicked
  const stack = await startStack();
  try {
    // When: the steps fill the username, click next, wait for the password field, fill it, and submit
    const result = await stack.mcp.callTool("login", {
      cred_id: "mock:site",
      target_url: `${stack.fixture.url}/delayed-step/`,
      steps: [
        { action: "fill", selector: "#username", value: "{{username}}" },
        { action: "click", selector: "#next" },
        { action: "wait_for", selector: "#password" },
        { action: "fill", selector: "#password", value: "{{password}}" },
        { action: "click", selector: "#submit" },
      ],
      success_selector: "#welcome",
      failure_selector: "#login-error",
    });

    // Then: login succeeds
    expect(result.isError, `login failed: ${result.text}`).toBe(false);
  } finally {
    await stopStack(stack);
  }
});

test("AC-145b: a missing wait_for selector reports its zero-based step", async () => {
  // Given: the delayed-step fixture with a step 2 wait_for selector that never appears
  const stack = await startStack();
  try {
    // When: the agent logs in with that step list
    const result = await stack.mcp.callTool("login", {
      cred_id: "mock:site",
      target_url: `${stack.fixture.url}/delayed-step/`,
      steps: [
        { action: "fill", selector: "#username", value: "{{username}}" },
        { action: "click", selector: "#next" },
        { action: "wait_for", selector: "#never" },
      ],
      success_selector: "#welcome",
      failure_selector: "#login-error",
    });

    // Then: SELECTOR_NOT_FOUND is reported with zero-based step 2
    expect(result.isError).toBe(true);
    expect(result.text).toBe("SELECTOR_NOT_FOUND");
    expect(result.structured).toEqual({
      error: "SELECTOR_NOT_FOUND",
      step: 2,
    });
  } finally {
    await stopStack(stack);
  }
});

test("AC-146: the password canary stays out of fill mismatch surfaces", async () => {
  // Given: a stack that records MCP output, the audit log, and daemon/executor stderr
  const agentDir = fs.mkdtempSync(path.join(os.tmpdir(), "tegata-agent-"));
  const guard = await createLeakGuard({
    leakscanBin: bins().leakscan,
    agentVisibleRoots: [agentDir, process.cwd()],
    psSampleIntervalMs: 200,
  });
  const canaries: CanarySet = {
    username: guard.canary("username"),
    password: guard.canary("password"),
    totpSeed: guard.canary("totp_seed"),
    wrongPassword: guard.canary("wrong_password"),
  };
  const daemon = await startDaemon(defaultEntries(canaries), {
    captureStderr: true,
  });
  const fixture = await startTargetFixture({
    username: canaries.username,
    password: canaries.password,
  });
  const mcp = await connectMcp(daemon.socketPath, (label, value) =>
    guard.observe(label, value),
  );
  try {
    // When: the agent fills a password into the password-as-text fixture
    const result = await mcp.callTool("login", {
      cred_id: "mock:site",
      target_url: `${fixture.url}/password-as-text/`,
      steps: fixtureSteps().steps,
      success_selector: "#welcome",
      failure_selector: "#login-error",
    });
    const auditText = fs.readFileSync(
      path.join(daemon.stateDir, "audit.log"),
      "utf8",
    );

    // Then: the password canary appears in none of MCP text/structured output, the audit log, or stderr
    expect(result.isError).toBe(true);
    expect(result.text).not.toContain(canaries.password);
    expect(JSON.stringify(result.structured ?? null)).not.toContain(
      canaries.password,
    );
    expect(auditText).not.toContain(canaries.password);
    expect(daemon.stderr?.() ?? "").not.toContain(canaries.password);
  } finally {
    await mcp.close().catch(() => {});
    await fixture.stop().catch(() => {});
    await daemon.stop().catch(() => {});
    try {
      await guard.assertNoLeaks();
    } finally {
      await guard.dispose();
      fs.rmSync(agentDir, { recursive: true, force: true });
    }
  }
});
