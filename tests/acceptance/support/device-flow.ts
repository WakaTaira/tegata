import { type ChildProcess, spawn } from "node:child_process";
import { once } from "node:events";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createLeakGuard, type LeakGuard } from "@tegata/leak-guard";
import {
  bins,
  type CanarySet,
  defaultEntries,
  rawRpc,
  startTargetFixture,
  type TargetFixture,
} from "./harness.js";
import { renderPhase4Config } from "./phase4.js";

export interface DeviceFlowDaemon {
  socketPath: string;
  stateDir: string;
  daemonDir: string;
  auditLogPath: string;
  pid: number;
  stdout(): string;
  stop(): Promise<void>;
}

export interface DeviceFlowStack {
  guard: LeakGuard;
  canaries: CanarySet;
  daemon: DeviceFlowDaemon;
  fixture: TargetFixture;
  agentDir: string;
  observe(label: string, value: unknown): void;
}

function stopProcess(child: ChildProcess): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null)
    return Promise.resolve();
  child.kill("SIGTERM");
  const timer = setTimeout(() => child.kill("SIGKILL"), 3_000);
  return once(child, "exit")
    .then(
      () => undefined,
      () => undefined,
    )
    .finally(() => clearTimeout(timer));
}

function renderDeviceFlowConfig(opts: {
  socketPath: string;
  stateDir: string;
  auditLogPath: string;
  entries: ReturnType<typeof defaultEntries>;
  approveCmd?: string;
}): string {
  const config = renderPhase4Config({
    socketPath: opts.socketPath,
    stateDir: opts.stateDir,
    auditLogPath: opts.auditLogPath,
    allowedUids: [os.userInfo().uid],
    operatorUids: [os.userInfo().uid],
    entries: opts.entries,
  });
  if (opts.approveCmd === undefined) return config;
  const marker = `audit_log_path = ${JSON.stringify(opts.auditLogPath)}\n`;
  return config.replace(
    marker,
    `${marker}approve_cmd = ${JSON.stringify(opts.approveCmd)}\n`,
  );
}

async function startDeviceFlowDaemon(opts: {
  entries: ReturnType<typeof defaultEntries>;
  approveCmd?: string;
}): Promise<DeviceFlowDaemon> {
  const daemonDir = fs.mkdtempSync(path.join(os.tmpdir(), "tegatad-device-"));
  const socketPath = path.join(daemonDir, "tegatad.sock");
  const stateDir = path.join(daemonDir, "state");
  fs.mkdirSync(stateDir, { mode: 0o700 });
  const auditLogPath = path.join(stateDir, "audit.log");
  const configPath = path.join(daemonDir, "config.toml");
  fs.writeFileSync(
    configPath,
    renderDeviceFlowConfig({
      socketPath,
      stateDir,
      auditLogPath,
      entries: opts.entries,
      approveCmd: opts.approveCmd,
    }),
    { mode: 0o600 },
  );
  const child = spawn(bins().tegatad, ["--config", configPath], {
    stdio: ["ignore", "pipe", "inherit"],
    cwd: daemonDir,
  });
  let stdout = "";
  child.stdout?.setEncoding("utf8");
  child.stdout?.on("data", (chunk: string) => {
    stdout += chunk;
  });
  const exited = new Promise<never>((_, reject) => {
    child.once("exit", (code) =>
      reject(new Error(`tegatad exited early (code ${code})`)),
    );
  });
  try {
    const deadline = Date.now() + 15_000;
    await Promise.race([
      (async () => {
        for (;;) {
          if (Date.now() > deadline)
            throw new Error("timed out waiting for the tegatad socket");
          if (fs.existsSync(socketPath)) {
            try {
              const res = await rawRpc(socketPath, "status", {});
              if (res.result !== undefined) return;
            } catch {
              // ソケットが受付可能になるまで待機します。
            }
          }
          await new Promise((resolve) => setTimeout(resolve, 100));
        }
      })(),
      exited,
    ]);
  } catch (error) {
    await stopProcess(child).catch(() => {});
    fs.rmSync(daemonDir, { recursive: true, force: true });
    throw error;
  }
  child.removeAllListeners("exit");
  if (child.pid === undefined) throw new Error("tegatad has no pid");
  return {
    socketPath,
    stateDir,
    daemonDir,
    auditLogPath,
    pid: child.pid,
    stdout: () => stdout,
    stop: async () => {
      await stopProcess(child);
      fs.rmSync(daemonDir, { recursive: true, force: true });
    },
  };
}

export async function startDeviceFlowStack(
  opts: { approveCmd?: string } = {},
): Promise<DeviceFlowStack> {
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
  let fixture: TargetFixture | undefined;
  let daemon: DeviceFlowDaemon | undefined;
  try {
    fixture = await startTargetFixture({
      username: canaries.username,
      password: canaries.password,
    });
    const entries = defaultEntries(canaries).map((entry) => ({
      ...entry,
      uri: fixture?.url ?? entry.uri,
    }));
    daemon = await startDeviceFlowDaemon({
      entries,
      approveCmd: opts.approveCmd,
    });
    return {
      guard,
      canaries,
      daemon,
      fixture,
      agentDir,
      observe: (label, value) => guard.observe(label, value),
    };
  } catch (error) {
    await daemon?.stop().catch(() => {});
    await fixture?.stop().catch(() => {});
    await guard.dispose().catch(() => {});
    fs.rmSync(agentDir, { recursive: true, force: true });
    throw error;
  }
}

export async function stopDeviceFlowStack(
  stack: DeviceFlowStack,
): Promise<void> {
  await stack.fixture.stop().catch(() => {});
  await stack.daemon.stop().catch(() => {});
  try {
    await stack.guard.assertNoLeaks();
  } finally {
    await stack.guard.dispose();
    fs.rmSync(stack.agentDir, { recursive: true, force: true });
  }
}
