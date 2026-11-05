// AC-96, AC-97 — Windows operator approval is observable through the pipe.
// Given / When / Then correspond 1:1 to each acceptance criterion.

import { beforeEach, expect, test } from "vitest";
import { fixtureSteps } from "../support/harness.js";
import {
  type ApprovalDaemon,
  startApprovalDaemon,
  startApprovalVault,
} from "./support/operator-approval.js";
import { pipeRpc, readForegroundAudit } from "./support/phase4.js";
import { currentWindowsSid, requireRig } from "./support/winrig.js";

beforeEach(() => requireRig());

/** Failure context: the RPC response and the daemon's stderr. */
function context(response: unknown, daemon: ApprovalDaemon): string {
  return `response: ${JSON.stringify(response)}\ndaemon stderr:\n${daemon.stderr()}`;
}

test("AC-96: login times out after approval timeout and is audited", async () => {
  // Given: a foreground daemon with `approve_operator = true` and `approve_timeout_secs = 3`
  const vault = await startApprovalVault();
  let daemon: ApprovalDaemon | undefined;
  try {
    daemon = await startApprovalDaemon({
      allowedSids: [await currentWindowsSid()],
      approveTimeoutSecs: 3,
    });
    const credId = await daemon.credId();

    // When: `login` from the interop pipe client
    const started = Date.now();
    const response = await pipeRpc(daemon.pipeName, "login", {
      cred_id: credId,
      target_url: vault.fixture.url,
      ...fixtureSteps(),
    });
    const elapsed = Date.now() - started;

    // Then: `APPROVAL_TIMEOUT` after 3 s or more, an `approval pending` line in stderr, and the
    // outcome of the audit login line is `APPROVAL_TIMEOUT`
    expect(response.error?.message, context(response, daemon)).toBe(
      "APPROVAL_TIMEOUT",
    );
    expect(elapsed, context(response, daemon)).toBeGreaterThanOrEqual(3_000);
    expect(daemon.stderr()).toMatch(/approval pending/);
    expect(readForegroundAudit(daemon.stateDirWsl)).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          method: "login",
          outcome: "APPROVAL_TIMEOUT",
        }),
      ]),
    );
  } finally {
    await daemon?.stop();
    await vault.stop();
  }
});

test("AC-97: interop cannot approve a pending login", async () => {
  // Given: a daemon with `approve_operator = true` and `approve_timeout_secs = 20`, with a `login`
  // from interop pending
  const vault = await startApprovalVault();
  let daemon: ApprovalDaemon | undefined;
  try {
    daemon = await startApprovalDaemon({
      allowedSids: [await currentWindowsSid()],
      approveTimeoutSecs: 20,
    });
    const credId = await daemon.credId();
    const login = pipeRpc(daemon.pipeName, "login", {
      cred_id: credId,
      target_url: vault.fixture.url,
      ...fixtureSteps(),
    });
    // Confirm the pending registration through the pending line in stderr before moving on.
    // A daemon without the approval gate settles the login first, so proceed in that case too.
    const pending = await Promise.race([
      daemon.waitForStderr(/approval pending (\d{6})/, 60_000),
      login.then(() => undefined),
    ]);
    const id = pending?.[1] ?? "000000";

    // When: `admin_approval_list` and `admin_approval_decide {id, allow: true}` from another
    // interop pipe client
    const listed = await pipeRpc(daemon.pipeName, "admin_approval_list", {});
    const decided = await pipeRpc(daemon.pipeName, "admin_approval_decide", {
      id,
      allow: true,
    });

    // Then: both are `ADMIN_REQUIRED`, and the pending login ends up as `APPROVAL_TIMEOUT` (interop
    // cannot forge an approval)
    expect(listed.error?.message, context(listed, daemon)).toBe(
      "ADMIN_REQUIRED",
    );
    expect(decided.error?.message, context(decided, daemon)).toBe(
      "ADMIN_REQUIRED",
    );
    const loggedIn = await login;
    expect(loggedIn.error?.message, context(loggedIn, daemon)).toBe(
      "APPROVAL_TIMEOUT",
    );
  } finally {
    await daemon?.stop();
    await vault.stop();
  }
});
