/**
 * Full-stack composition used by most acceptance tests: leak guard + mock
 * daemon + target fixture + MCP session, torn down (and leak-checked) in
 * reverse order. Owned by the acceptance suite (gauntlet); do not modify
 * during implementation.
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createLeakGuard, type LeakGuard } from "@tegata/leak-guard";
import {
  bins,
  type CanarySet,
  connectMcp,
  type Daemon,
  defaultEntries,
  type McpSession,
  startDaemon,
  startTargetFixture,
  type TargetFixture,
} from "./harness.js";

export interface Stack {
  guard: LeakGuard;
  canaries: CanarySet;
  daemon: Daemon;
  fixture: TargetFixture;
  mcp: McpSession;
  /** Agent-visible scratch dir; part of the guard's scan roots. */
  agentDir: string;
}

export interface StackOptions {
  /** Skip starting the fixture web server (for tests that never log in). */
  withFixture?: boolean;
}

export async function startStack(opts: StackOptions = {}): Promise<Stack> {
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
  const daemon = await startDaemon(defaultEntries(canaries));
  const fixture =
    opts.withFixture === false
      ? ({
          port: 0,
          url: "http://127.0.0.1:0",
          stop: async () => {},
        } as TargetFixture)
      : await startTargetFixture({
          username: canaries.username,
          password: canaries.password,
        });
  const mcp = await connectMcp(daemon.socketPath, (label, value) =>
    guard.observe(label, value),
  );
  return { guard, canaries, daemon, fixture, mcp, agentDir };
}

/**
 * Tear down and enforce the leak check. Every test that ran a stack finishes
 * through here, so any canary that reached an agent-visible surface fails
 * that test even when it is not the test's primary assertion.
 */
export async function stopStack(stack: Stack): Promise<void> {
  await stack.mcp.close().catch(() => {});
  await stack.fixture.stop().catch(() => {});
  await stack.daemon.stop().catch(() => {});
  try {
    await stack.guard.assertNoLeaks();
  } finally {
    await stack.guard.dispose();
    fs.rmSync(stack.agentDir, { recursive: true, force: true });
  }
}
