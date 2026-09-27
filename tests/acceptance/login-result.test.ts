import { randomUUID } from "node:crypto";
import { expect, test } from "vitest";
import {
  type CanarySet,
  connectMcp,
  type Daemon,
  defaultEntries,
  type McpSession,
  startDaemon,
  startTargetFixture,
  type TargetFixture,
} from "./support/harness.js";
import { type Stack, startStack, stopStack } from "./support/stack.js";

const TEST_TIMEOUT_MS = 60_000;

function busyLoginArgs(stack: Stack, credId = "mock:site") {
  return {
    cred_id: credId,
    target_url: `${stack.fixture.url}/busy/`,
  };
}

function busyCredentials(): CanarySet {
  const suffix = randomUUID().replaceAll("-", "");
  return {
    username: `login-result-user-${suffix}`,
    password: `login-result-password-${suffix}`,
    totpSeed: `login-result-totp-${suffix}`,
    wrongPassword: `login-result-wrong-${suffix}`,
  };
}

async function waitForDiagnostic(
  daemon: Daemon,
  timeoutMs = 5_000,
): Promise<string> {
  const readStderr = daemon.stderr;
  if (readStderr === undefined) {
    throw new Error("daemon stderr capture is not enabled");
  }
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const stderr = readStderr();
    if (stderr.includes("tegatad: executor tegata-executor: error ")) {
      return stderr;
    }
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  return readStderr();
}

test(
  "AC-117: Given a busy fixture / When login runs without selectors / Then it succeeds in under 15 s",
  async () => {
    const stack = await startStack();
    try {
      const startedAt = performance.now();
      const result = await stack.mcp.callTool("login", busyLoginArgs(stack));
      const elapsedMs = performance.now() - startedAt;

      expect(result.isError, result.text).toBe(false);
      expect(elapsedMs).toBeLessThan(15_000);
    } finally {
      await stopStack(stack);
    }
  },
  TEST_TIMEOUT_MS,
);

test(
  "AC-118: Given a busy fixture with a wrong password / When login runs without selectors / Then it returns INVALID_CREDENTIAL in under 15 s",
  async () => {
    const stack = await startStack();
    try {
      const startedAt = performance.now();
      const result = await stack.mcp.callTool(
        "login",
        busyLoginArgs(stack, "mock:site-badpass"),
      );
      const elapsedMs = performance.now() - startedAt;

      expect(result.isError).toBe(true);
      expect(result.text).toBe("INVALID_CREDENTIAL");
      expect(elapsedMs).toBeLessThan(15_000);
    } finally {
      await stopStack(stack);
    }
  },
  TEST_TIMEOUT_MS,
);

test(
  "AC-119: Given a busy fixture / When login runs with missing success and failure selectors / Then it returns LOGIN_RESULT_TIMEOUT rather than INTERNAL",
  async () => {
    const stack = await startStack();
    try {
      const result = await stack.mcp.callTool("login", {
        ...busyLoginArgs(stack),
        success_selector: "#never-appears",
        failure_selector: "#never-appears-either",
      });

      expect(result.isError).toBe(true);
      expect(result.text).toBe("LOGIN_RESULT_TIMEOUT");
      expect(result.text).not.toBe("INTERNAL");
    } finally {
      await stopStack(stack);
    }
  },
  TEST_TIMEOUT_MS,
);

test(
  "AC-120: Given the AC-119 daemon with a new MCP broker / When MCP login runs / Then it returns LOGIN_RESULT_TIMEOUT",
  async () => {
    const stack = await startStack();
    let mcp: McpSession | undefined;
    try {
      await stack.mcp.close();
      mcp = await connectMcp(stack.daemon.socketPath, (label, value) =>
        stack.guard.observe(label, value),
      );
      const result = await mcp.callTool("login", {
        ...busyLoginArgs(stack),
        success_selector: "#never-appears",
        failure_selector: "#never-appears-either",
      });

      expect(result.isError).toBe(true);
      expect(result.text).toBe("LOGIN_RESULT_TIMEOUT");
    } finally {
      if (mcp !== undefined) await mcp.close().catch(() => {});
      await stopStack(stack);
    }
  },
  TEST_TIMEOUT_MS,
);

test(
  "AC-121: Given the AC-119 spawn path / When daemon stderr is read / Then it contains a credential-free executor diagnostic line",
  async () => {
    const canaries = busyCredentials();
    let daemon: Daemon | undefined;
    let fixture: TargetFixture | undefined;
    let mcp: McpSession | undefined;
    try {
      fixture = await startTargetFixture({
        username: canaries.username,
        password: canaries.password,
      });
      daemon = await startDaemon(defaultEntries(canaries), {
        captureStderr: true,
      });
      mcp = await connectMcp(daemon.socketPath);
      const result = await mcp.callTool("login", {
        cred_id: "mock:site",
        target_url: `${fixture.url}/busy/`,
        success_selector: "#never-appears",
        failure_selector: "#never-appears-either",
      });

      expect(result.isError).toBe(true);
      expect(result.text).toBe("LOGIN_RESULT_TIMEOUT");

      const stderr = await waitForDiagnostic(daemon);
      const diagnosticLines = stderr
        .split(/\r?\n/)
        .filter((line) =>
          line.includes("tegatad: executor tegata-executor: error "),
        );
      expect(diagnosticLines.length).toBeGreaterThanOrEqual(1);
      expect(
        diagnosticLines.some((line) =>
          line.includes('"code":"LOGIN_RESULT_TIMEOUT"'),
        ),
      ).toBe(true);
      expect(stderr).not.toContain(canaries.username);
      expect(stderr).not.toContain(canaries.password);
    } finally {
      if (mcp !== undefined) await mcp.close().catch(() => {});
      await fixture?.stop().catch(() => {});
      await daemon?.stop().catch(() => {});
    }
  },
  TEST_TIMEOUT_MS,
);
