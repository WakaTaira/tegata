// AC-02, AC-03, AC-04, AC-05 — login handoff and leak-free session delivery.
// Traceability: docs/secret/briefs/tegata-phase1.md 受け入れ条件 #2-#5.
import { expect, test } from "vitest";
import { chromium } from "playwright-core";
import {
  FORBIDDEN_ARTIFACTS,
  fixtureSteps,
  listFiles,
} from "./support/harness.js";
import { type Stack, startStack, stopStack } from "./support/stack.js";

interface LoginResult {
  session_id: string;
  channel: { kind: string; endpoint: string };
}

async function login(stack: Stack): Promise<LoginResult> {
  const res = await stack.mcp.callTool("login", {
    cred_id: "mock:site",
    target_url: stack.fixture.url,
    ...fixtureSteps(),
  });
  expect(res.isError, `login failed: ${res.text}`).toBe(false);
  return res.json as LoginResult;
}

test("AC-02: login returns a CDP channel without canary material", async () => {
  // Given: the target fixture running with canary credentials
  const stack = await startStack();
  try {
    // When: the agent calls MCP login(cred_id, target_url)
    const result = await login(stack);

    // Then: a {kind: "cdp", endpoint} channel is returned and the endpoint
    // string contains no canary
    expect(result.channel.kind).toBe("cdp");
    expect(result.channel.endpoint).toMatch(/^ws:\/\//);
    expect(result.session_id).toBeTruthy();
    for (const value of Object.values(stack.canaries)) {
      expect(result.channel.endpoint).not.toContain(value);
    }
  } finally {
    await stopStack(stack);
  }
});

test("AC-03: the handed-off session is actually logged in", async () => {
  // Given: an endpoint obtained from a successful login
  const stack = await startStack();
  try {
    const result = await login(stack);

    // When: the agent connects over CDP and reads the page DOM
    const browser = await chromium.connectOverCDP(result.channel.endpoint);
    try {
      const page = browser
        .contexts()
        .flatMap((c) => c.pages())
        .find((p) => p.url().startsWith(stack.fixture.url));
      expect(page, "no page on the fixture origin").toBeDefined();

      // Then: the logged-in marker element (#welcome) exists
      const hasWelcome = await page?.evaluate(
        () => document.querySelector("#welcome") !== null,
      );
      expect(hasWelcome).toBe(true);
    } finally {
      await browser.close();
    }
  } finally {
    await stopStack(stack);
  }
});

test("AC-04: no canary reaches any agent-observable surface during login", async () => {
  // Given: the whole duration of a login flow under leak-guard observation
  const stack = await startStack();
  try {
    const result = await login(stack);
    const browser = await chromium.connectOverCDP(result.channel.endpoint);
    try {
      const page = browser
        .contexts()
        .flatMap((c) => c.pages())
        .find((p) => p.url().startsWith(stack.fixture.url));
      // The post-handoff DOM is part of the observed surface.
      stack.guard.observe("dom", await page?.content());
    } finally {
      await browser.close();
    }

    // When: the leak-guard runs its full teardown inspection
    const hits = await stack.guard.collectLeaks();

    // Then: no canary (including base64/url/hex/json variants) is found in
    // MCP responses, agent-visible filesystem diffs, ps samples, or the DOM
    expect(hits).toEqual([]);
  } finally {
    await stopStack(stack);
  }
});

test("AC-05: no browser trace/video/HAR/screenshot artifacts are produced", async () => {
  // Given: a completed login
  const stack = await startStack();
  try {
    await login(stack);

    // When: scanning every file created on either side of the harness
    const files = [
      ...listFiles(stack.daemon.daemonDir),
      ...listFiles(stack.agentDir),
    ];

    // Then: no Playwright trace / video / HAR / screenshot file exists
    const offenders = files.filter((f) => FORBIDDEN_ARTIFACTS.test(f));
    expect(offenders).toEqual([]);
  } finally {
    await stopStack(stack);
  }
});
