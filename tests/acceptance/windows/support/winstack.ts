/**
 * Full-stack composition for the Windows/WSL rig E2E tests: leak guard (with
 * the WMI command-line sampler) + throwaway vaultwarden + target fixture +
 * tegata-bridge + MCP session in bridge mode, torn down (and leak-checked)
 * in reverse order. Owned by the acceptance suite (gauntlet); do not modify
 * during implementation.
 * Revised under the Phase 3 brief (approved 2026-08-30): failure-path teardown.
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createLeakGuard, type LeakGuard } from "@tegata/leak-guard";
import {
  bins,
  type CanarySet,
  connectMcp,
  type McpSession,
  startTargetFixture,
  type TargetFixture,
} from "../../support/harness.js";
import {
  type Bridge,
  ensureServiceRunning,
  provisionVault,
  requireRig,
  restartService,
  startBridge,
  startVaultwarden,
  type TestVault,
  winAgentTempWsl,
  wmiPsSampleCommand,
} from "./winrig.js";

/** The item name provisioned into the rig vault for the login E2E. */
export const RIG_ITEM_NAME = "Acceptance Test Site";

export interface WinStack {
  guard: LeakGuard;
  canaries: CanarySet;
  vault: TestVault;
  fixture: TargetFixture;
  bridge: Bridge;
  mcp: McpSession;
  /** Agent-visible scratch dir; part of the guard's scan roots. */
  agentDir: string;
  /** The namespaced credential id of the provisioned item. */
  credId: string;
}

export async function startWinStack(): Promise<WinStack> {
  requireRig();
  await ensureServiceRunning();
  const agentDir = fs.mkdtempSync(path.join(os.tmpdir(), "tegata-agent-"));
  let guard: LeakGuard | undefined;
  let vault: TestVault | undefined;
  let fixture: TargetFixture | undefined;
  let bridge: Bridge | undefined;
  let mcp: McpSession | undefined;
  try {
    const winTemp = await winAgentTempWsl();
    guard = await createLeakGuard({
      leakscanBin: bins().leakscan,
      // The interop user's Windows %TEMP% is agent-reachable through /mnt/c,
      // so it is part of the agent-visible filesystem surface on this rig.
      agentVisibleRoots: [agentDir, process.cwd(), winTemp],
      psSampleIntervalMs: 200,
      psSampleCommands: [["ps", "-eo", "args"], wmiPsSampleCommand()],
    });
    const canaries: CanarySet = {
      username: guard.canary("username"),
      password: guard.canary("password"),
      totpSeed: guard.canary("totp_seed"),
      wrongPassword: guard.canary("wrong_password"),
    };
    vault = await startVaultwarden();
    fixture = await startTargetFixture({
      username: canaries.username,
      password: canaries.password,
    });
    await provisionVault([
      {
        name: RIG_ITEM_NAME,
        uri: fixture.url,
        username: canaries.username,
        password: canaries.password,
        totp_seed: canaries.totpSeed,
      },
    ]);
    // Force the service to build a fresh provider session against the vault
    // that was just provisioned (the previous run left stale bw state behind).
    await restartService();
    bridge = await startBridge();
    mcp = await connectMcp(
      bridge.socketPath,
      (label, value) => guard?.observe(label, value),
      { TEGATA_BRIDGE: "1" },
    );
    const res = await mcp.callTool("list_credentials", {});
    if (res.isError) throw new Error(`list_credentials failed: ${res.text}`);
    const items = res.json as Array<{ id: string; name: string }>;
    const item = items.find((i) => i.name === RIG_ITEM_NAME);
    if (!item)
      throw new Error(
        `provisioned item "${RIG_ITEM_NAME}" not found in list_credentials`,
      );
    return {
      guard,
      canaries,
      vault,
      fixture,
      bridge,
      mcp,
      agentDir,
      credId: item.id,
    };
  } catch (error) {
    await mcp?.close().catch(() => {});
    await bridge?.stop().catch(() => {});
    await fixture?.stop().catch(() => {});
    await vault?.stop().catch(() => {});
    if (guard) {
      await guard.assertNoLeaks().catch(() => {});
      await guard.dispose().catch(() => {});
    }
    fs.rmSync(agentDir, { recursive: true, force: true });
    throw error;
  }
}

/**
 * Tear down and enforce the leak check. Every test that ran a win-stack
 * finishes through here, so any canary that reached an agent-visible surface
 * fails that test even when it is not the test's primary assertion.
 */
export async function stopWinStack(stack: WinStack): Promise<void> {
  await stack.mcp.close().catch(() => {});
  await stack.bridge.stop().catch(() => {});
  await stack.fixture.stop().catch(() => {});
  await stack.vault.stop().catch(() => {});
  try {
    await stack.guard.assertNoLeaks();
  } finally {
    await stack.guard.dispose();
    fs.rmSync(stack.agentDir, { recursive: true, force: true });
  }
}
