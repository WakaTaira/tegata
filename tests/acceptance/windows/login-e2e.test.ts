// AC-23, AC-25, AC-26, AC-27 — end-to-end login across the WSL->Windows
// boundary: sealed auto-unseal, the tunneled CDP handoff, leak-freedom, and
// the tunnel target restriction.
// Traceability: docs/secret/briefs/tegata-phase2.md acceptance condition #5, #7, #8, #9.

import { chromium } from "playwright-core";
import { expect, test } from "vitest";
import { fixtureSteps } from "../support/harness.js";
import { bridgeRpc, restartService } from "./support/winrig.js";
import {
  startWinStack,
  stopWinStack,
  type WinStack,
} from "./support/winstack.js";

interface LoginResult {
  session_id: string;
  channel: { kind: string; endpoint: string };
}

async function login(stack: WinStack): Promise<LoginResult> {
  const res = await stack.mcp.callTool("login", {
    cred_id: stack.credId,
    target_url: stack.fixture.url,
    ...fixtureSteps(),
  });
  expect(res.isError, `login failed: ${res.text}`).toBe(false);
  return res.json as LoginResult;
}

test("AC-23: a sealed service logs in after restart with no password prompt", async () => {
  // Given: a sealed service (the rig's master password is DPAPI-sealed)
  const stack = await startWinStack();
  try {
    // When: the operator restarts the service and a login is issued — no
    // interactive password entry happens anywhere in this flow
    await restartService();
    const result = await login(stack);

    // Then: login succeeds (the daemon auto-unsealed the master password)
    expect(result.channel.kind).toBe("cdp");
    expect(result.session_id).toBeTruthy();
  } finally {
    await stopWinStack(stack);
  }
});

test("AC-25: login returns a WSL-local CDP endpoint that is connectable", async () => {
  // Given: a canary vault and the target fixture running inside WSL
  const stack = await startWinStack();
  try {
    // When: the agent calls MCP login through the bridge
    const result = await login(stack);

    // Then: the endpoint is a WSL-local loopback URL (the tunnel entrance),
    // not the Windows-side port, and it carries no canary
    expect(result.channel.endpoint).toMatch(/^ws:\/\/127\.0\.0\.1:\d+\//);
    for (const value of Object.values(stack.canaries)) {
      expect(result.channel.endpoint).not.toContain(value);
    }

    // And: connecting over CDP from WSL reaches the logged-in page
    const browser = await chromium.connectOverCDP(result.channel.endpoint);
    try {
      const page = browser
        .contexts()
        .flatMap((c) => c.pages())
        .find((p) => p.url().startsWith(stack.fixture.url));
      expect(page, "no page on the fixture origin").toBeDefined();
      const hasWelcome = await page?.evaluate(
        () => document.querySelector("#welcome") !== null,
      );
      expect(hasWelcome).toBe(true);
    } finally {
      await browser.close();
    }
  } finally {
    await stopWinStack(stack);
  }
});

test("AC-26: no canary reaches any agent-observable surface during login", async () => {
  // Given: the whole duration of a login flow under leak-guard observation
  // (RPC responses, WSL filesystem, WSL ps, /mnt/c Temp diff, WMI cmdline)
  const stack = await startWinStack();
  try {
    const result = await login(stack);
    const browser = await chromium.connectOverCDP(result.channel.endpoint);
    try {
      const page = browser
        .contexts()
        .flatMap((c) => c.pages())
        .find((p) => p.url().startsWith(stack.fixture.url));
      stack.guard.observe("dom", await page?.content());
    } finally {
      await browser.close();
    }

    // When: the leak-guard runs its full teardown inspection
    const hits = await stack.guard.collectLeaks();

    // Then: no canary (including base64/url/hex/json variants) is found
    expect(hits).toEqual([]);
  } finally {
    await stopWinStack(stack);
  }
});

test("AC-27: a tunnel to a non-CDP port is refused", async () => {
  // Given: an active session (so the daemon knows its real CDP port)
  const stack = await startWinStack();
  try {
    const result = await login(stack);
    // A port that is not this session's CDP port. The daemon must reject the
    // tunnel rather than splice to an arbitrary Windows-side port.
    const bogusPort = 9;

    // When: bridge_open_tunnel is asked to reach a non-CDP port
    const res = await bridgeRpc(stack.bridge.socketPath, "bridge_open_tunnel", {
      session_id: result.session_id,
      port: bogusPort,
    });

    // Then: the request is refused
    expect(res.error).toBeDefined();
    expect(res.result).toBeUndefined();
  } finally {
    await stopWinStack(stack);
  }
});
