// AC-106, AC-107 — headless Chromium uses a headful browser User-Agent in
// the login page and in later tabs created in the same browser context.

import { chromium } from "playwright-core";
import { expect, test } from "vitest";
import { fixtureSteps } from "./support/harness.js";
import { CdpClient } from "./support/phase4.js";
import { type Stack, startStack, stopStack } from "./support/stack.js";

interface LoginResult {
  session_id: string;
  channel: { kind: string; endpoint: string };
}

async function login(stack: Stack): Promise<LoginResult> {
  const res = await stack.mcp.callTool("login", {
    cred_id: "mock:site",
    target_url: `${stack.fixture.url}/ua-gated/`,
    ...fixtureSteps(),
  });
  expect(res.isError, `login failed: ${res.text}`).toBe(false);
  return res.json as LoginResult;
}

test("AC-106: login succeeds on the User-Agent-gated route", async () => {
  // Given: a login route that answers HTTP 403 to a HeadlessChrome User-Agent
  const stack = await startStack();
  try {
    // When: the agent logs in against the User-Agent-gated route
    const result = await login(stack);

    // Then: login succeeds and returns a CDP endpoint
    expect(result.channel.kind).toBe("cdp");
    expect(result.channel.endpoint).toMatch(/^ws:\/\//);
  } finally {
    await stopStack(stack);
  }
});

test("AC-107: the headful User-Agent is inherited by later tabs", async () => {
  // Given: a successful login on the User-Agent-gated route
  const stack = await startStack();
  let client: CdpClient | undefined;
  try {
    const result = await login(stack);
    const browser = await chromium.connectOverCDP(result.channel.endpoint);
    try {
      // When: the agent evaluates navigator.userAgent on the logged-in page
      const context = browser.contexts()[0];
      if (context === undefined) throw new Error("browser context not found");
      const page = context
        .pages()
        .find((candidate) => candidate.url().startsWith(stack.fixture.url));
      if (page === undefined) throw new Error("logged-in page not found");
      const loggedInUserAgent = await page.evaluate(() => navigator.userAgent);

      // And: a new target is created in the same browser context
      client = await CdpClient.connect(result.channel.endpoint);
      const { targetInfos } = await client.send("Target.getTargets");
      const loggedInTarget = (
        targetInfos as Array<{
          type: string;
          url: string;
          browserContextId?: string;
        }>
      ).find(
        (target) =>
          target.type === "page" && target.url.startsWith(stack.fixture.url),
      );
      if (loggedInTarget?.browserContextId === undefined) {
        throw new Error("browser context id not found");
      }
      const newPagePromise = context.waitForEvent("page");
      await client.send("Target.createTarget", {
        url: `${stack.fixture.url}/ua-gated/`,
        browserContextId: loggedInTarget.browserContextId,
      });
      const newPage = await newPagePromise;
      await newPage.waitForLoadState("domcontentloaded");
      const newTabUserAgent = await newPage.evaluate(() => navigator.userAgent);

      // Then: the new tab passed the gate and is logged in, and both tabs
      // identify as Chrome without a Headless token
      expect(await newPage.locator("#welcome").count()).toBe(1);
      for (const userAgent of [loggedInUserAgent, newTabUserAgent]) {
        expect(userAgent).not.toContain("Headless");
        expect(userAgent).toContain("Chrome/");
      }
    } finally {
      client?.close();
      await browser.close();
    }
  } finally {
    await stopStack(stack);
  }
});
