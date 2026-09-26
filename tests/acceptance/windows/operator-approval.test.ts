// AC-96, AC-97 — Windows operator approval is observable through the pipe.
// Given / When / Then は各受け入れ条件と 1:1 で対応する。

import { beforeEach, expect, test } from "vitest";
import { fixtureSteps } from "../support/harness.js";
import { startApprovalDaemon } from "./support/operator-approval.js";
import { pipeRpc, readForegroundAudit } from "./support/phase4.js";
import { currentWindowsSid, requireRig } from "./support/winrig.js";
import { startWinStack, stopWinStack } from "./support/winstack.js";

beforeEach(() => requireRig());

test("AC-96: login times out after approval timeout and is audited", async () => {
  // Given: `approve_operator = true`、`approve_timeout_secs = 3` の foreground デーモン
  const stack = await startWinStack();
  const daemon = await startApprovalDaemon({
    allowedSids: [await currentWindowsSid()],
    approveTimeoutSecs: 3,
    credId: stack.credId,
    targetUrl: stack.fixture.url,
  });
  try {
    // When: interop の pipe client から `login`
    const started = Date.now();
    const response = await pipeRpc(daemon.pipeName, "login", {
      cred_id: stack.credId,
      target_url: stack.fixture.url,
      ...fixtureSteps(),
    });
    const elapsed = Date.now() - started;

    // Then: 3 s 以上経ってから `APPROVAL_TIMEOUT`、stderr に `approval pending` 行、監査の login 行の outcome が `APPROVAL_TIMEOUT`
    expect(elapsed).toBeGreaterThanOrEqual(3_000);
    expect(response.error?.message).toBe("APPROVAL_TIMEOUT");
    expect(daemon.stderr()).toMatch(/approval pending/);
    expect(readForegroundAudit(daemon.stateDirWsl)).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          event: "login",
          outcome: "APPROVAL_TIMEOUT",
        }),
      ]),
    );
  } finally {
    await daemon.stop();
    await stopWinStack(stack);
  }
});

test("AC-97: interop cannot approve a pending login", async () => {
  // Given: `approve_operator = true`、`approve_timeout_secs = 20` のデーモンに interop から `login` が保留中
  const stack = await startWinStack();
  const daemon = await startApprovalDaemon({
    allowedSids: [await currentWindowsSid()],
    approveTimeoutSecs: 20,
    credId: stack.credId,
    targetUrl: stack.fixture.url,
  });
  try {
    const login = pipeRpc(daemon.pipeName, "login", {
      cred_id: stack.credId,
      target_url: stack.fixture.url,
      ...fixtureSteps(),
    });
    await new Promise((resolve) => setTimeout(resolve, 500));
    // When: 別の interop pipe client から `admin_approval_list` と `admin_approval_decide {id, allow: true}`
    const listed = await pipeRpc(daemon.pipeName, "admin_approval_list", {});
    const id =
      /approval pending (\d{6})/.exec(daemon.stderr())?.[1] ?? "000000";
    const decided = await pipeRpc(daemon.pipeName, "admin_approval_decide", {
      id,
      allow: true,
    });

    // Then: どちらも `ADMIN_REQUIRED`、保留中の login は最終的に `APPROVAL_TIMEOUT`（interop は承認を偽造できない）
    expect(listed.error?.message).toBe("ADMIN_REQUIRED");
    expect(decided.error?.message).toBe("ADMIN_REQUIRED");
    expect((await login).error?.message).toBe("APPROVAL_TIMEOUT");
  } finally {
    await daemon.stop();
    await stopWinStack(stack);
  }
});
