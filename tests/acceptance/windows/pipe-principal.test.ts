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
  // Given: the rig service, the bridge (TCP peer), and a pipe client (interop SID)
  const stack = await startWinStack();
  const pipeName = rigPipeName();
  try {
    // When: login from the pipe (s1), and login with the same cred from the bridge (s2)
    const viaPipe = await pipeRpc(pipeName, "login", loginArgs(stack));
    stack.guard.observe("pipe:login", viaPipe);
    expect(viaPipe.error, JSON.stringify(viaPipe.error)).toBeUndefined();
    const s1 = viaPipe.result as LoginResult;
    const viaBridge = await stack.mcp.callTool("login", loginArgs(stack));
    expect(viaBridge.isError, `login failed: ${viaBridge.text}`).toBe(false);
    const s2 = viaBridge.json as LoginResult;

    // Then: different browsers (the endpoint path = the browser id differs. The bridge
    // rewrites only the port, so the paths can be compared)
    expect(new URL(s1.channel.endpoint).pathname).not.toBe(
      new URL(s2.channel.endpoint).pathname,
    );

    // When: the TCP peer calls disconnect(s1), and the pipe calls disconnect(s2)
    const crossFromBridge = await bridgeRpc(
      stack.bridge.socketPath,
      "disconnect",
      {
        session_id: s1.session_id,
      },
    );
    const crossFromPipe = await pipeRpc(pipeName, "disconnect", {
      session_id: s2.session_id,
    });

    // Then: both are NOT_FOUND
    expect(crossFromBridge.error?.message).toBe("NOT_FOUND");
    expect(crossFromPipe.error?.message).toBe("NOT_FOUND");

    // And: disconnect of one's own lease succeeds
    const ownPipe = await pipeRpc(pipeName, "disconnect", {
      session_id: s1.session_id,
    });
    expect(ownPipe.result).toEqual({ ok: true });
    const ownBridge = await bridgeRpc(stack.bridge.socketPath, "disconnect", {
      session_id: s2.session_id,
    });
    expect(ownBridge.result).toEqual({ ok: true });
  } finally {
    await stopWinStack(stack);
  }
});
