// AC-96, AC-97 — Windows operator approval is observable through the pipe.
// Given / When / Then は各受け入れ条件と 1:1 で対応する。

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
  // Given: `approve_operator = true`、`approve_timeout_secs = 3` の foreground デーモン
  const vault = await startApprovalVault();
  let daemon: ApprovalDaemon | undefined;
  try {
    daemon = await startApprovalDaemon({
      allowedSids: [await currentWindowsSid()],
      approveTimeoutSecs: 3,
    });
    const credId = await daemon.credId();

    // When: interop の pipe client から `login`
    const started = Date.now();
    const response = await pipeRpc(daemon.pipeName, "login", {
      cred_id: credId,
      target_url: vault.fixture.url,
      ...fixtureSteps(),
    });
    const elapsed = Date.now() - started;

    // Then: 3 s 以上経ってから `APPROVAL_TIMEOUT`、stderr に `approval pending` 行、監査の login 行の outcome が `APPROVAL_TIMEOUT`
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
  // Given: `approve_operator = true`、`approve_timeout_secs = 20` のデーモンに interop から `login` が保留中
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
    // 保留の登録を stderr の pending 行で確かめてから次へ進む。承認ゲートを
    // 持たないデーモンでは login が先に決着するため、その場合も先へ進む。
    const pending = await Promise.race([
      daemon.waitForStderr(/approval pending (\d{6})/, 60_000),
      login.then(() => undefined),
    ]);
    const id = pending?.[1] ?? "000000";

    // When: 別の interop pipe client から `admin_approval_list` と `admin_approval_decide {id, allow: true}`
    const listed = await pipeRpc(daemon.pipeName, "admin_approval_list", {});
    const decided = await pipeRpc(daemon.pipeName, "admin_approval_decide", {
      id,
      allow: true,
    });

    // Then: どちらも `ADMIN_REQUIRED`、保留中の login は最終的に `APPROVAL_TIMEOUT`（interop は承認を偽造できない）
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
