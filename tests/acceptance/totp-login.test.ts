// AC-48, AC-49 — login-time TOTP: the daemon computes the current code from
// the seed on the isolated side and the executor fills {{totp}}; a step
// referencing {{totp}} without a seed fails with MFA_REQUIRED.
// Traceability: docs/secret/briefs/tegata-phase3.md acceptance condition #17, #18.

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
  startDaemon,
  startTargetFixture,
} from "./support/harness.js";

function totpSteps() {
  return {
    steps: [
      { action: "fill", selector: "#username", value: "{{username}}" },
      { action: "fill", selector: "#password", value: "{{password}}" },
      { action: "fill", selector: "#totp", value: "{{totp}}" },
      { action: "click", selector: "#submit" },
    ],
    success_selector: "#welcome",
    failure_selector: "#login-error",
  };
}

test("AC-48: a {{totp}} step logs in against a TOTP-validating site", async () => {
  // Given: the fixture in TOTP mode (canary seed) and a seeded mock entry
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
  const fixture = await startTargetFixture({
    username: canaries.username,
    password: canaries.password,
    totp_seed: canaries.totpSeed,
  });
  const mcp = await connectMcp(daemon.socketPath, (label, value) =>
    guard.observe(label, value),
  );
  try {
    // When: login runs with steps that fill {{totp}}
    const login = await mcp.callTool("login", {
      cred_id: "mock:site",
      target_url: fixture.url,
      ...totpSteps(),
    });

    // Then: the login succeeds (the fixture accepted the computed code)
    expect(login.isError, `login failed: ${login.text}`).toBe(false);
    const result = login.json as { session_id: string };
    expect(result.session_id).toBeTruthy();
    const logout = await mcp.callTool("logout", {
      session_id: result.session_id,
    });
    expect(logout.isError, logout.text).toBe(false);
  } finally {
    await mcp.close().catch(() => {});
    await fixture.stop().catch(() => {});
    await daemon.stop().catch(() => {});
    try {
      // And: no canary (the seed above all) reached an agent-visible surface
      await guard.assertNoLeaks();
    } finally {
      await guard.dispose();
      fs.rmSync(agentDir, { recursive: true, force: true });
    }
  }
});

test("AC-49: a {{totp}} step without a seed fails with MFA_REQUIRED", async () => {
  // Given: an entry that has no TOTP seed
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
  const fixture = await startTargetFixture({
    username: canaries.username,
    password: canaries.password,
  });
  const mcp = await connectMcp(daemon.socketPath, (label, value) =>
    guard.observe(label, value),
  );
  try {
    // When: login runs with steps that reference {{totp}}
    // (defaultEntries' "site-badpass" carries no totp_seed)
    const login = await mcp.callTool("login", {
      cred_id: "mock:site-badpass",
      target_url: fixture.url,
      ...totpSteps(),
    });

    // Then: the classification is MFA_REQUIRED, nothing else
    expect(login.isError).toBe(true);
    expect(login.text).toBe("MFA_REQUIRED");
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
