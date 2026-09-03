// AC-68 — on the rig service, a named-pipe caller (SID) and a TCP peer are
// different principals: they do not share a browser for the same credential,
// and neither can log the other out.
// Traceability: docs/secret/briefs/tegata-phase4.md acceptance condition AC-68.

import { expect, test } from "vitest";
import { fixtureSteps } from "../support/harness.js";
import { pipeRpc, rigPipeName } from "./support/phase4.js";
import { bridgeRpc } from "./support/winrig.js";
import {
  startWinStack,
  stopWinStack,
  type WinStack,
} from "./support/winstack.js";

interface LoginResult {
  session_id: string;
  channel: { kind: string; endpoint: string };
}

function loginArgs(stack: WinStack): Record<string, unknown> {
  return {
    cred_id: stack.credId,
    target_url: stack.fixture.url,
    ...fixtureSteps(),
  };
}

test("AC-68: the pipe SID and a TCP peer own separate sessions", async () => {
  // Given: リグのサービス、bridge（TCP peer）、pipe client（interop SID）
  const stack = await startWinStack();
  const pipeName = rigPipeName();
  try {
    // When: pipe から login（s1）、bridge から同じ cred で login（s2）
    const viaPipe = await pipeRpc(pipeName, "login", loginArgs(stack));
    stack.guard.observe("pipe:login", viaPipe);
    expect(viaPipe.error, JSON.stringify(viaPipe.error)).toBeUndefined();
    const s1 = viaPipe.result as LoginResult;
    const viaBridge = await stack.mcp.callTool("login", loginArgs(stack));
    expect(viaBridge.isError, `login failed: ${viaBridge.text}`).toBe(false);
    const s2 = viaBridge.json as LoginResult;

    // Then: 別のブラウザ（endpoint の path = ブラウザ id が異なる。bridge は
    // ポートだけを書き換えるので path で比較できる）
    expect(new URL(s1.channel.endpoint).pathname).not.toBe(
      new URL(s2.channel.endpoint).pathname,
    );

    // When: TCP peer が logout(s1)、pipe が logout(s2) を呼ぶ
    const crossFromBridge = await bridgeRpc(stack.bridge.socketPath, "logout", {
      session_id: s1.session_id,
    });
    const crossFromPipe = await pipeRpc(pipeName, "logout", {
      session_id: s2.session_id,
    });

    // Then: どちらも NOT_FOUND
    expect(crossFromBridge.error?.message).toBe("NOT_FOUND");
    expect(crossFromPipe.error?.message).toBe("NOT_FOUND");

    // And: 自分のリースの logout は通る
    const ownPipe = await pipeRpc(pipeName, "logout", {
      session_id: s1.session_id,
    });
    expect(ownPipe.result).toEqual({ ok: true });
    const ownBridge = await bridgeRpc(stack.bridge.socketPath, "logout", {
      session_id: s2.session_id,
    });
    expect(ownBridge.result).toEqual({ ok: true });
  } finally {
    await stopWinStack(stack);
  }
});
