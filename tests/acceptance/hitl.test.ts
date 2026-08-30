// AC-37, AC-38, AC-39, AC-40 — the human-in-the-loop approval hook: a
// configured approve_cmd gates login on exit status, times out into a
// denial that reaps its whole process group, and receives only references.
// Traceability: docs/secret/briefs/tegata-phase3.md acceptance condition #6, #7, #8, #9.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { expect, test } from "vitest";
import { defaultEntries, fixtureSteps } from "./support/harness.js";
import {
  readAuditRecords,
  startPhase3Stack,
  stopPhase3Stack,
  waitUntil,
} from "./support/phase3.js";

test("AC-37: an approving approve_cmd lets login through", async () => {
  // Given: an approve_cmd that exits 0
  const stack = await startPhase3Stack({
    top: { approveCmd: "exit 0" },
    makeProviders: (canaries) => [
      { type: "mock", namespace: "mock", entries: defaultEntries(canaries) },
    ],
  });
  try {
    // When: login is called
    const login = await stack.mcp.callTool("login", {
      cred_id: "mock:site",
      target_url: stack.fixture.url,
      ...fixtureSteps(),
    });

    // Then: the login succeeds
    expect(login.isError, `login failed: ${login.text}`).toBe(false);
  } finally {
    await stopPhase3Stack(stack);
  }
});

test("AC-38: a denying approve_cmd refuses login with APPROVAL_DENIED", async () => {
  // Given: an approve_cmd that exits non-zero
  const stack = await startPhase3Stack({
    top: { approveCmd: "exit 1" },
    makeProviders: (canaries) => [
      { type: "mock", namespace: "mock", entries: defaultEntries(canaries) },
    ],
  });
  try {
    // When: login is called
    const login = await stack.mcp.callTool("login", {
      cred_id: "mock:site",
      target_url: stack.fixture.url,
      ...fixtureSteps(),
    });

    // Then: the call fails with the bare classification code, no session
    // exists, and the audit outcome records the denial
    expect(login.isError).toBe(true);
    expect(login.text).toBe("APPROVAL_DENIED");
    const { records } = readAuditRecords(stack.daemon.auditLogPath);
    const record = records.find((r) => r.method === "login");
    expect(record?.outcome).toBe("APPROVAL_DENIED");
  } finally {
    await stopPhase3Stack(stack);
  }
});

test("AC-39: an approve_cmd past its timeout is denied and fully reaped", async () => {
  // Given: a one-second approval timeout and an approve_cmd whose grandchild
  // records its own pid and then sleeps far beyond the timeout
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "tegata-hitl-"));
  const pidFile = path.join(scratch, "grandchild.pid");
  const stack = await startPhase3Stack({
    top: {
      approveCmd: `sh -c 'echo $$ > ${pidFile}; exec sleep 300' & wait`,
      approveTimeoutSecs: 1,
    },
    makeProviders: (canaries) => [
      { type: "mock", namespace: "mock", entries: defaultEntries(canaries) },
    ],
  });
  try {
    // When: login is called
    const login = await stack.mcp.callTool("login", {
      cred_id: "mock:site",
      target_url: stack.fixture.url,
      ...fixtureSteps(),
    });

    // Then: the call fails with APPROVAL_TIMEOUT and the grandchild process
    // is reaped along with the process group
    expect(login.isError).toBe(true);
    expect(login.text).toBe("APPROVAL_TIMEOUT");
    await waitUntil("the grandchild pid file", () => fs.existsSync(pidFile));
    const pid = Number(fs.readFileSync(pidFile, "utf8").trim());
    expect(Number.isInteger(pid) && pid > 0).toBe(true);
    await waitUntil("the grandchild process to be gone", () => {
      try {
        process.kill(pid, 0);
        return false;
      } catch {
        return true;
      }
    });
  } finally {
    fs.rmSync(scratch, { recursive: true, force: true });
    await stopPhase3Stack(stack);
  }
});

test("AC-40: approve_cmd sees references in its environment, never values", async () => {
  // Given: an approve_cmd that dumps its environment and approves
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "tegata-hitl-"));
  const envFile = path.join(scratch, "approve-env.txt");
  const stack = await startPhase3Stack({
    top: { approveCmd: `env > ${envFile}` },
    makeProviders: (canaries) => [
      { type: "mock", namespace: "mock", entries: defaultEntries(canaries) },
    ],
  });
  try {
    // When: login is called
    const login = await stack.mcp.callTool("login", {
      cred_id: "mock:site",
      target_url: stack.fixture.url,
      ...fixtureSteps(),
    });
    expect(login.isError, `login failed: ${login.text}`).toBe(false);

    // Then: the environment carried the credential reference and target, and
    // no canary value (the dump is fed to the leak guard for teardown scan)
    const env = fs.readFileSync(envFile, "utf8");
    stack.guard.observe("approve-env", env);
    expect(env).toContain("TEGATA_CRED_ID=mock:site");
    expect(env).toContain(`TEGATA_TARGET_URL=${stack.fixture.url}`);
    expect(env).toMatch(/^TEGATA_PEER=\d+$/m);
    expect(env).not.toContain(stack.canaries.username);
    expect(env).not.toContain(stack.canaries.password);
  } finally {
    fs.rmSync(scratch, { recursive: true, force: true });
    await stopPhase3Stack(stack);
  }
});
