// AC-95 — operator approval is a Windows-only configuration feature.
// Given / When / Then correspond 1:1 to AC-95 in the design document.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { expect, test } from "vitest";
import { runDaemonUntilExit } from "./support/phase4.js";

test("AC-95: approve_operator is rejected on Linux because it is Windows-only", async () => {
  // Given: a config containing `approve_operator = true`
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tegata-approval-"));
  const state = path.join(dir, "state");
  fs.mkdirSync(state, { mode: 0o700 });
  const config = path.join(dir, "config.toml");
  fs.writeFileSync(
    config,
    [
      `socket_path = ${JSON.stringify(path.join(dir, "tegatad.sock"))}`,
      `state_dir = ${JSON.stringify(state)}`,
      `audit_log_path = ${JSON.stringify(path.join(state, "audit.log"))}`,
      `allowed_uids = [${os.userInfo().uid}]`,
      "approve_operator = true",
      "[[providers]]",
      'namespace = "mock"',
      'type = "mock"',
    ].join("\n") + "\n",
  );
  try {
    // When: start the daemon
    const exit = await runDaemonUntilExit(config, dir);

    // Then: non-zero exit code, and stderr gives the reason that `approve_operator` is Windows-only
    expect(exit.code).not.toBeNull();
    expect(exit.code).not.toBe(0);
    expect(exit.stderr).toMatch(/approve_operator/);
    expect(exit.stderr).toMatch(/Windows.*only|only.*Windows|Windows.*専用/i);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
