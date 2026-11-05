// AC-202, AC-203, AC-204 — the login browser does not announce itself as
// automated or headless, and the daemon refuses to start without the full
// Chromium build.
// Traceability: docs/secret/briefs/tegata-issue60-browser-not-announcing.md
// acceptance conditions AC-202..AC-204 (Issue #60). AC-205 lives in the
// NixOS boundary test (nix/vm-test.nix).

import { expect, test } from "vitest";
import {
  type FingerprintObservation,
  type FingerprintRequest,
  fingerprintState,
  headlessShellOnlyBrowsersPath,
  layOutSpawnModeDaemon,
  runDaemonWithEnvUntilExit,
  waitForFingerprint,
} from "./support/browser-identity.js";
import { fixtureSteps } from "./support/harness.js";
import { CdpClient } from "./support/phase4.js";
import { type Stack, startStack, stopStack } from "./support/stack.js";

interface LoginResult {
  session_id: string;
  channel: { kind: string; endpoint: string };
}

async function loginToFingerprint(stack: Stack): Promise<LoginResult> {
  const res = await stack.mcp.callTool("login", {
    cred_id: "mock:site",
    target_url: `${stack.fixture.url}/fingerprint/`,
    ...fixtureSteps(),
  });
  expect(res.isError, `login failed: ${res.text}`).toBe(false);
  return res.json as LoginResult;
}

/** Checks the document-request side of the AC-202 Then (User-Agent and Sec-CH-UA). */
function expectRequestNotAnnouncing(request: FingerprintRequest): void {
  const context = JSON.stringify(request);
  expect(request.user_agent, context).not.toBeNull();
  expect(request.user_agent, context).not.toContain("Headless");
  expect(request.sec_ch_ua, context).not.toBeNull();
  expect(request.sec_ch_ua, context).not.toContain("Headless");
}

/** Checks the page-observation side of the AC-202 Then. */
function expectObservationNotAnnouncing(
  observation: FingerprintObservation,
): void {
  const context = JSON.stringify(observation);
  expect(observation.webdriver, context).toBe(false);
  expect(observation.plugins_length, context).toBeGreaterThanOrEqual(1);
  expect(observation.chrome_type, context).toBe("object");
  expect(observation.user_agent, context).not.toContain("Headless");
  expect(observation.screen_width, context).toBeGreaterThan(
    observation.outer_width,
  );
  expect(observation.screen_height, context).toBeGreaterThan(
    observation.outer_height,
  );
  expect(observation.outer_height, context).toBeGreaterThan(
    observation.inner_height,
  );
  expect(observation.brands, context).not.toBeNull();
  expect(observation.brands?.length ?? 0, context).toBeGreaterThanOrEqual(2);
}

test("AC-202: the logged-in page sees a browser that does not announce automation", async () => {
  // Given: the fixture login page, and a credential that navigates to /fingerprint/ after login
  const stack = await startStack();
  try {
    // When: log in and record the observed values on the post-login page
    const result = await loginToFingerprint(stack);
    expect(result.channel.kind).toBe("cdp");
    const { request, observation } = await waitForFingerprint(
      stack.fixture.url,
      "an observation from the logged-in /fingerprint/ page",
      (state) => {
        const observation = state.observations.find(
          (candidate) => candidate.logged_in === true,
        );
        if (observation === undefined) return undefined;
        const request = state.requests.find(
          (candidate) => candidate.nonce === observation.nonce,
        );
        return request === undefined ? undefined : { request, observation };
      },
    );

    // Then: the recorded values satisfy all of the following: webdriver is false,
    // plugins is 1 or more, window.chrome is an object, none of the JS UA,
    // the User-Agent header, and the Sec-CH-UA header contain Headless, screen is
    // larger than the window, outerHeight is greater than innerHeight, and brands
    // has 2 or more entries
    expectRequestNotAnnouncing(request);
    expectObservationNotAnnouncing(observation);
  } finally {
    await stopStack(stack);
  }
});

test("AC-203: a tab created by raw CDP Target.createTarget with a URL does not announce automation from its first request", async () => {
  // Given: logged in under the same conditions as AC-202, with the returned CDP endpoint
  const stack = await startStack();
  let client: CdpClient | undefined;
  try {
    const result = await loginToFingerprint(stack);
    expect(result.channel.kind).toBe("cdp");
    const before = await fingerprintState(stack.fixture.url);
    const requestsBefore = before.requests.length;

    // When: the agent calls Target.createTarget({ url: <the fixture's /fingerprint/> })
    // over raw CDP to create a new tab with a URL
    client = await CdpClient.connect(result.channel.endpoint);
    await client.send("Target.createTarget", {
      url: `${stack.fixture.url}/fingerprint/`,
    });
    const { firstRequest, observations } = await waitForFingerprint(
      stack.fixture.url,
      "the new tab's first document request and its page observation",
      (state) => {
        const newRequests = state.requests.slice(requestsBefore);
        const firstRequest = newRequests[0];
        if (firstRequest === undefined) return undefined;
        const newNonces = new Set(newRequests.map(({ nonce }) => nonce));
        const observations = state.observations.filter(({ nonce }) =>
          newNonces.has(nonce),
        );
        return observations.length === 0
          ? undefined
          : { firstRequest, observations };
      },
    );

    // Then: the headers of the first document request and the page observations both satisfy all
    // the AC-202 conditions
    expectRequestNotAnnouncing(firstRequest);
    for (const observation of observations) {
      expectObservationNotAnnouncing(observation);
    }
  } finally {
    client?.close();
    await stopStack(stack);
  }
});

test("AC-204: the daemon refuses to start when only the Chromium headless shell is installed", async () => {
  // Given: PLAYWRIGHT_BROWSERS_PATH points to a directory that contains only
  // chromium_headless_shell-* and no full chromium-*
  const browsers = headlessShellOnlyBrowsersPath();
  const layout = layOutSpawnModeDaemon();
  try {
    expect(
      browsers.entries.every((name) =>
        name.startsWith("chromium_headless_shell-"),
      ),
    ).toBe(true);

    // When: start the daemon
    const exit = await runDaemonWithEnvUntilExit(layout, {
      PLAYWRIGHT_BROWSERS_PATH: browsers.dir,
    });

    // Then: the daemon fails to start and exits non-zero, and stderr states that
    // full Chromium is required and contains the string --only-shell
    expect(
      exit.code,
      `daemon kept running without the full Chromium; stderr: ${exit.stderr}`,
    ).not.toBeNull();
    expect(exit.code).not.toBe(0);
    expect(exit.stderr).toMatch(/chromium/i);
    expect(exit.stderr).toMatch(/requir|need|must/i);
    expect(exit.stderr).toContain("--only-shell");
  } finally {
    layout.cleanup();
    browsers.cleanup();
  }
});
