// AC-62 — a failing key backs off (2 s -> 5 s -> 15 s) and is capped at
// three browser start-ups per ten minutes; the excess answers RATE_LIMITED
// without touching the target site.
// Traceability: docs/secret/briefs/tegata-phase4.md acceptance condition AC-62.

import { expect, test } from "vitest";
import { rawRpc } from "./support/harness.js";
import {
  loginParams,
  type Phase4Stack,
  sleep,
  startPhase4Stack,
  stopPhase4Stack,
} from "./support/phase4.js";

/** login(F) over the UNIX socket; returns the classification code. */
async function loginCode(stack: Phase4Stack): Promise<string | undefined> {
  const res = await rawRpc(
    stack.daemon.socketPath,
    "login",
    loginParams(stack.fixture.url, "mock:site-badpass"),
  );
  stack.observe("rpc:login", res);
  return res.error?.message;
}

test("AC-62: repeated failures on one key back off and are rate limited", async () => {
  // Given: fixture が常に拒否する cred F（mock:site-badpass）
  const stack = await startPhase4Stack();
  try {
    // When: login(F)（試行 1、失敗）
    expect(await loginCode(stack)).toBe("INVALID_CREDENTIAL");
    expect(stack.fixture.loginPosts()).toBe(1);

    // When: 直後に login(F)
    // Then: バックオフ中なので RATE_LIMITED、POST /login は増えない
    expect(await loginCode(stack)).toBe("RATE_LIMITED");
    expect(stack.fixture.loginPosts()).toBe(1);

    // When: 2 s 待って login(F)（試行 2、失敗）
    await sleep(2_500);
    expect(await loginCode(stack)).toBe("INVALID_CREDENTIAL");
    expect(stack.fixture.loginPosts()).toBe(2);

    // When: 5 s 待って login(F)（試行 3、失敗）
    await sleep(5_500);
    expect(await loginCode(stack)).toBe("INVALID_CREDENTIAL");
    expect(stack.fixture.loginPosts()).toBe(3);

    // When: 15 s 待って login(F)
    // Then: 10 分窓で 4 回目の起動になるため RATE_LIMITED、POST /login は
    // 合計 3 回のまま
    await sleep(15_500);
    expect(await loginCode(stack)).toBe("RATE_LIMITED");
    expect(stack.fixture.loginPosts()).toBe(3);
  } finally {
    await stopPhase4Stack(stack);
  }
});
