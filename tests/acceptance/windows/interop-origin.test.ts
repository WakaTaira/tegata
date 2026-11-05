// AC-93 / AC-94 — audit the WSL interop pipe caller and reject admin RPCs.
// Traceability: docs/secret/briefs/tegata-issue13-interop-admin.md.

import { randomBytes } from "node:crypto";
import { beforeAll, expect, test } from "vitest";
import {
  pipeRpc,
  readForegroundAudit,
  startForegroundPhase4Daemon,
} from "./support/phase4.js";
import { currentWindowsSid, requireRig } from "./support/winrig.js";

let mySid: string;

beforeAll(async () => {
  requireRig();
  mySid = await currentWindowsSid();
});

test("AC-93: interop status audit records peer_pid and wsl_interop origin", async () => {
  // Given: a foreground daemon
  const daemon = await startForegroundPhase4Daemon({
    allowedSids: [mySid],
    legacyToken: randomBytes(32).toString("base64url"),
  });
  try {
    // When: `status` from the WSL interop pipe client (`pipeRpc`)
    const response = await pipeRpc(daemon.pipeName, "status", {});
    expect(response.error, JSON.stringify(response.error)).toBeUndefined();

    // Then: the audit line has `peer_pid` (a positive integer) and `peer_origin: "wsl_interop"`
    const audit = readForegroundAudit(daemon.stateDirWsl);
    const record = audit.find((entry) => entry.method === "status");
    expect(record, JSON.stringify(audit)).toBeDefined();
    expect(record?.peer_pid).toEqual(expect.any(Number));
    expect(record?.peer_pid).toBeGreaterThan(0);
    expect(record?.peer_origin).toBe("wsl_interop");
  } finally {
    await daemon.stop();
  }
});

test("AC-94: interop admin_peer_list is rejected and audited as wsl_interop", async () => {
  // Given: the same daemon
  const daemon = await startForegroundPhase4Daemon({
    allowedSids: [mySid],
    legacyToken: randomBytes(32).toString("base64url"),
  });
  try {
    // When: `admin_peer_list` from the interop pipe client
    const response = await pipeRpc(daemon.pipeName, "admin_peer_list", {});

    // Then: `ADMIN_REQUIRED` (rejected whether elevated or via interop, so it does not regress),
    // and the audit line's `peer_origin` is `"wsl_interop"`
    expect(response.error?.message).toBe("ADMIN_REQUIRED");
    const audit = readForegroundAudit(daemon.stateDirWsl);
    const record = audit.find((entry) => entry.method === "admin_peer_list");
    expect(record, JSON.stringify(audit)).toBeDefined();
    expect(record?.peer_origin).toBe("wsl_interop");
  } finally {
    await daemon.stop();
  }
});
