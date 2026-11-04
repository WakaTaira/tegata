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

/** AC-202 の Then の文書リクエスト側（User-Agent と Sec-CH-UA）を検査する。 */
function expectRequestNotAnnouncing(request: FingerprintRequest): void {
  const context = JSON.stringify(request);
  expect(request.user_agent, context).not.toBeNull();
  expect(request.user_agent, context).not.toContain("Headless");
  expect(request.sec_ch_ua, context).not.toBeNull();
  expect(request.sec_ch_ua, context).not.toContain("Headless");
}

/** AC-202 の Then のページ観測値側を検査する。 */
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
  // Given: fixture のログインページと、ログイン後に /fingerprint/ へ遷移する資格がある
  const stack = await startStack();
  try {
    // When: login を行い、ログイン後のページで観測値を記録する
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

    // Then: 記録された値が、webdriver が false、plugins が 1 以上、
    // window.chrome が object、JS の UA・User-Agent ヘッダ・Sec-CH-UA ヘッダの
    // いずれにも Headless を含まない、screen がウィンドウより大きい、
    // outerHeight が innerHeight より大きい、brands が 2 つ以上、の全部を満たす
    expectRequestNotAnnouncing(request);
    expectObservationNotAnnouncing(observation);
  } finally {
    await stopStack(stack);
  }
});

test("AC-203: a tab created by raw CDP Target.createTarget with a URL does not announce automation from its first request", async () => {
  // Given: AC-202 と同じ条件でログインし、返された CDP エンドポイントがある
  const stack = await startStack();
  let client: CdpClient | undefined;
  try {
    const result = await loginToFingerprint(stack);
    expect(result.channel.kind).toBe("cdp");
    const before = await fingerprintState(stack.fixture.url);
    const requestsBefore = before.requests.length;

    // When: エージェントが生の CDP で Target.createTarget({ url: <fixture の /fingerprint/> })
    // を呼び、URL 付きで新しいタブを作る
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

    // Then: 初回の文書リクエストのヘッダと、ページの観測値が、AC-202 の条件を全部満たす
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
  // Given: PLAYWRIGHT_BROWSERS_PATH が chromium_headless_shell-* だけを含み、
  // 完全版 chromium-* を含まないディレクトリを指している
  const browsers = headlessShellOnlyBrowsersPath();
  const layout = layOutSpawnModeDaemon();
  try {
    expect(
      browsers.entries.every((name) =>
        name.startsWith("chromium_headless_shell-"),
      ),
    ).toBe(true);

    // When: デーモンを起動する
    const exit = await runDaemonWithEnvUntilExit(layout, {
      PLAYWRIGHT_BROWSERS_PATH: browsers.dir,
    });

    // Then: デーモンは起動に失敗して非 0 で終了し、標準エラーに完全版 Chromium が
    // 必要である旨と --only-shell の文字列が含まれる
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
