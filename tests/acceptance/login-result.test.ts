import { type ChildProcess, spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { once } from "node:events";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { expect, test } from "vitest";
import {
  bins,
  type CanarySet,
  connectMcp,
  type Daemon,
  defaultEntries,
  type McpSession,
  rawRpc,
  renderDaemonConfig,
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

async function stopChild(child: ChildProcess): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return;
  const exited = once(child, "exit").catch(() => {});
  child.kill("SIGTERM");
  const timer = setTimeout(() => child.kill("SIGKILL"), 3_000);
  await exited;
  clearTimeout(timer);
}

interface CapturedDaemon extends Pick<Daemon, "socketPath" | "stop"> {
  stderr(): string;
}

async function startCapturedDaemon(
  entries: ReturnType<typeof defaultEntries>,
): Promise<CapturedDaemon> {
  const daemonDir = fs.mkdtempSync(
    path.join(os.tmpdir(), "tegatad-login-result-"),
  );
  const socketPath = path.join(daemonDir, "tegatad.sock");
  const stateDir = path.join(daemonDir, "state");
  fs.mkdirSync(stateDir, { mode: 0o700 });
  const configPath = path.join(daemonDir, "config.toml");
  fs.writeFileSync(
    configPath,
    renderDaemonConfig({
      socketPath,
      stateDir,
      auditLogPath: path.join(stateDir, "audit.log"),
      allowedUids: [os.userInfo().uid],
      entries,
    }),
    { mode: 0o600 },
  );

  let stderr = "";
  const child = spawn(bins().tegatad, ["--config", configPath], {
    stdio: ["ignore", "ignore", "pipe"],
    cwd: daemonDir,
  });
  child.stderr?.setEncoding("utf8");
  child.stderr?.on("data", (chunk: string) => {
    stderr += chunk;
  });

  try {
    const deadline = Date.now() + 15_000;
    let ready = false;
    while (Date.now() < deadline) {
      if (child.exitCode !== null) {
        throw new Error(
          `tegatad exited before becoming ready (code ${child.exitCode}); stderr: ${stderr}`,
        );
      }
      if (fs.existsSync(socketPath)) {
        try {
          const response = await rawRpc(socketPath, "status", {});
          if (response.result !== undefined) {
            ready = true;
            break;
          }
        } catch {
          // 起動途中のソケット接続失敗は、次の試行で確認します。
        }
      }
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    if (!ready) {
      throw new Error(`timed out waiting for tegatad; stderr: ${stderr}`);
    }
  } catch (error) {
    await stopChild(child);
    fs.rmSync(daemonDir, { recursive: true, force: true });
    throw error;
  }

  return {
    socketPath,
    stderr: () => stderr,
    stop: async () => {
      await stopChild(child);
      fs.rmSync(daemonDir, { recursive: true, force: true });
    },
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
  daemon: CapturedDaemon,
  timeoutMs = 5_000,
): Promise<string> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const stderr = daemon.stderr();
    if (stderr.includes("tegatad: executor tegata-executor: error ")) {
      return stderr;
    }
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  return daemon.stderr();
}

test(
  "AC-117: Given busy fixture / When target_url を busy にして login / Then 成功し、応答まで 15 s 未満",
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
  "AC-118: Given busy fixture と誤ったパスワード / When target_url を busy にして login / Then INVALID_CREDENTIAL で、応答まで 15 s 未満",
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
  "AC-119: Given busy fixture / When success_selector と failure_selector に存在しない値を指定して login / Then LOGIN_RESULT_TIMEOUT で、INTERNAL ではない",
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
  "AC-120: Given AC-119 の状態のデーモンに MCP broker を接続 / When MCP の login / Then ツール結果が LOGIN_RESULT_TIMEOUT",
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
  "AC-121: Given AC-119 の spawn 経路の実行 / When デーモンの stderr を読む / Then executor の診断行があり資格情報を含まない",
  async () => {
    const canaries = busyCredentials();
    let daemon: CapturedDaemon | undefined;
    let fixture: TargetFixture | undefined;
    let mcp: McpSession | undefined;
    try {
      fixture = await startTargetFixture({
        username: canaries.username,
        password: canaries.password,
      });
      daemon = await startCapturedDaemon(defaultEntries(canaries));
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
