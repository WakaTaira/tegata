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
  // Given: cred F (mock:site-badpass), which the fixture always rejects
  const stack = await startPhase4Stack();
  try {
    // When: login(F) (attempt 1, fails)
    expect(await loginCode(stack)).toBe("INVALID_CREDENTIAL");
    expect(stack.fixture.loginPosts()).toBe(1);

    // When: login(F) immediately afterwards
    // Then: RATE_LIMITED because of the backoff, and POST /login does not increase
    expect(await loginCode(stack)).toBe("RATE_LIMITED");
    expect(stack.fixture.loginPosts()).toBe(1);

    // When: wait 2 s, then login(F) (attempt 2, fails)
    await sleep(2_500);
    expect(await loginCode(stack)).toBe("INVALID_CREDENTIAL");
    expect(stack.fixture.loginPosts()).toBe(2);

    // When: wait 5 s, then login(F) (attempt 3, fails)
    await sleep(5_500);
    expect(await loginCode(stack)).toBe("INVALID_CREDENTIAL");
    expect(stack.fixture.loginPosts()).toBe(3);

    // When: wait 15 s, then login(F)
    // Then: RATE_LIMITED because this would be the fourth launch in the 10-minute window,
    // and POST /login stays at 3 in total
    await sleep(15_500);
    expect(await loginCode(stack)).toBe("RATE_LIMITED");
    expect(stack.fixture.loginPosts()).toBe(3);
  } finally {
    await stopPhase4Stack(stack);
  }
});
