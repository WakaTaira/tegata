import { randomUUID } from "node:crypto";
import { expect, test } from "vitest";
import {
  type ColdStartCanaries,
  type FakeBwMode,
  startColdStartDaemon,
} from "./support/cold-start.js";
import { connectMcp, rawRpc } from "./support/harness.js";

function scenarioCanaries(): ColdStartCanaries {
  const id = randomUUID().replaceAll("-", "");
  return {
    email: `cold-start-email-${id}@example.invalid`,
    masterPassword: `cold-start-master-${id}`,
    sessionKey: `cold-start-session-${id}`,
    itemId: `cold-start-item-id-${id}`,
    itemName: `cold-start-item-name-${id}`,
  };
}

function daemonOptions(mode: FakeBwMode, canaries: ColdStartCanaries) {
  const id = canaries.itemId.replace("cold-start-item-id-", "");
  return {
    mode,
    namespace: `cold_start_${id}`,
    serverUrl: "https://bitwarden-cold-start.invalid",
    canaries,
  };
}

test("AC-87: Given the fake bw's first `list items` exits 1 and the second returns valid JSON / When `list_credentials` runs right after daemon startup / Then it succeeds and returns the item, `list items` is recorded twice, and the response takes at least 2 s", async () => {
  // Given: the first `list items` of the fake bw exits 1, and the second returns valid JSON
  const canaries = scenarioCanaries();
  const daemon = await startColdStartDaemon(
    daemonOptions("fail-until:1", canaries),
  );
  try {
    // When: `list_credentials` right after daemon start
    const startedAt = performance.now();
    const response = await rawRpc(daemon.socketPath, "list_credentials", {});
    const elapsedMs = performance.now() - startedAt;

    // Then: succeeds and returns items, `list items` is recorded twice, and the response takes 2 s
    // or more
    expect(response.error).toBeUndefined();
    expect(response.result).toEqual([
      expect.objectContaining({
        id: `${daemon.namespace}:${canaries.itemId}`,
        name: canaries.itemName,
        source: daemon.namespace,
        status: "unlocked",
      }),
    ]);
    expect(daemon.listItemsCalls()).toHaveLength(2);
    expect(elapsedMs).toBeGreaterThanOrEqual(2_000);
  } finally {
    await daemon.stop();
  }
});

test("AC-88: Given the fake bw's `list items` always exits 1 / When `list_credentials` runs right after startup / Then the error code is `PROVIDER_UNAVAILABLE` and `list items` is recorded twice", async () => {
  // Given: `list items` of the fake bw always exits 1
  const canaries = scenarioCanaries();
  const daemon = await startColdStartDaemon(
    daemonOptions("always-fail", canaries),
  );
  try {
    // When: `list_credentials` right after start
    const response = await rawRpc(daemon.socketPath, "list_credentials", {});

    // Then: error code `PROVIDER_UNAVAILABLE`, and `list items` is recorded twice
    expect(response.error?.message).toBe("PROVIDER_UNAVAILABLE");
    expect(daemon.listItemsCalls()).toHaveLength(2);
  } finally {
    await daemon.stop();
  }
});

test("AC-89: Given the fake bw's `list items` returns invalid JSON / When `list_credentials` runs right after startup / Then the error is `INTERNAL` and `list items` is recorded once (no retry)", async () => {
  // Given: `list items` of the fake bw returns invalid JSON
  const canaries = scenarioCanaries();
  const daemon = await startColdStartDaemon(
    daemonOptions("invalid-json", canaries),
  );
  try {
    // When: `list_credentials` right after start
    const response = await rawRpc(daemon.socketPath, "list_credentials", {});

    // Then: `INTERNAL`, and `list items` is recorded once (no retry)
    expect(response.error?.message).toBe("INTERNAL");
    expect(daemon.listItemsCalls()).toHaveLength(1);
  } finally {
    await daemon.stop();
  }
});

test("AC-90: Given `list items` always exits 1 after a first `list_credentials` succeeded and filled the catalog / When a second `list_credentials` runs / Then the error is `PROVIDER_UNAVAILABLE` and the second call adds one `list items` record (a warm call does not retry)", async () => {
  // Given: after the first `list_credentials` succeeds and fills the catalog, `list items` always
  // exits 1
  const canaries = scenarioCanaries();
  const daemon = await startColdStartDaemon(daemonOptions("success", canaries));
  try {
    const first = await rawRpc(daemon.socketPath, "list_credentials", {});
    expect(first.error).toBeUndefined();
    const beforeSecondCall = daemon.listItemsCalls().length;
    daemon.setBwMode("always-fail");

    // When: the second `list_credentials`
    const response = await rawRpc(daemon.socketPath, "list_credentials", {});

    // Then: `PROVIDER_UNAVAILABLE`, and `list items` is recorded once more by the second call (warm
    // does not retry)
    expect(response.error?.message).toBe("PROVIDER_UNAVAILABLE");
    expect(daemon.listItemsCalls().length - beforeSecondCall).toBe(1);
  } finally {
    await daemon.stop();
  }
});

test('AC-91: Given the AC-87 run / When the daemon stderr is read / Then there is one `tegatad: bw_version` line and as many `tegatad: bw_diag {JSON}` lines as bw calls, the failed `list_items` line has `attempt: 1`, `cold_start: true`, `failure: "exit"`, and `exit_code: 1`, the retry line has `attempt: 2`, every bw_diag line has `rpc_id`, `namespace`, and `elapsed_ms`, and stderr contains no canary (email, master password, session key, item name)', async () => {
  // Given: the AC-87 run
  const canaries = scenarioCanaries();
  const daemon = await startColdStartDaemon(
    daemonOptions("fail-until:1", canaries),
  );
  try {
    const response = await rawRpc(daemon.socketPath, "list_credentials", {});
    expect(response.error).toBeUndefined();
    expect(daemon.listItemsCalls()).toHaveLength(2);
    const bwCallCount = daemon.callLog().length;

    // When: read the daemon stderr
    await daemon.stop();
    const stderr = daemon.stderr();
    const versionLines = stderr
      .split(/\r?\n/)
      .filter((line) => line.startsWith("tegatad: bw_version "));
    const diagLines = stderr
      .split(/\r?\n/)
      .filter((line) => line.startsWith("tegatad: bw_diag "));
    const diagnostics = diagLines.map(
      (line) =>
        JSON.parse(line.slice("tegatad: bw_diag ".length)) as Record<
          string,
          unknown
        >,
    );

    // Then: one `tegatad: bw_version` line; as many `tegatad: bw_diag {JSON}` lines as bw
    // invocations; the failed `list_items` line has `attempt: 1`, `cold_start: true`, `failure:
    // "exit"`, and `exit_code: 1`; the retry line has `attempt: 2`; every bw_diag line has
    // `rpc_id`, `namespace`, and `elapsed_ms`. The canaries (email, master password, session key,
    // item name) appear 0 times in stderr.
    expect(versionLines).toHaveLength(1);
    expect(diagLines).toHaveLength(bwCallCount);
    expect(diagnostics).not.toHaveLength(0);
    for (const diagnostic of diagnostics) {
      expect(diagnostic.rpc_id).not.toBeNull();
      expect(diagnostic.rpc_id).toBeDefined();
      expect(diagnostic.namespace).toBe(daemon.namespace);
      expect(diagnostic.elapsed_ms).toEqual(expect.any(Number));
    }
    expect(
      diagnostics.some(
        (diagnostic) =>
          diagnostic.op === "list_items" &&
          diagnostic.attempt === 1 &&
          diagnostic.cold_start === true &&
          diagnostic.failure === "exit" &&
          diagnostic.exit_code === 1,
      ),
    ).toBe(true);
    expect(
      diagnostics.some(
        (diagnostic) =>
          diagnostic.op === "list_items" && diagnostic.attempt === 2,
      ),
    ).toBe(true);
    for (const canary of Object.values(canaries)) {
      expect(stderr).not.toContain(canary);
    }
  } finally {
    await daemon.stop();
  }
});

test("AC-92: Given an MCP broker connected to a daemon in the AC-88 state / When MCP `list_credentials` runs / Then the tool result's error code is `PROVIDER_UNAVAILABLE` (not normalized to `INTERNAL`)", async () => {
  // Given: an MCP broker connected to a daemon in the AC-88 state
  const canaries = scenarioCanaries();
  const daemon = await startColdStartDaemon(
    daemonOptions("always-fail", canaries),
  );
  let mcp: Awaited<ReturnType<typeof connectMcp>> | undefined;
  try {
    mcp = await connectMcp(daemon.socketPath);

    // When: MCP `list_credentials`
    const result = await mcp.callTool("list_credentials", {});

    // Then: the tool result error code is `PROVIDER_UNAVAILABLE` (not normalized to `INTERNAL`)
    expect(result.isError).toBe(true);
    expect(result.text).toBe("PROVIDER_UNAVAILABLE");
  } finally {
    if (mcp !== undefined) await mcp.close().catch(() => {});
    await daemon.stop();
  }
});

// #59: a rejected refresh token. Once the cached server config is stale, `bw unlock` crashes on
// `invalid_grant`; the daemon signs in afresh within the same request.
test.each(["grant-rejected", "grant-rejected-stays-logged-in"] as const)(
  "AC-209: Given `bw unlock` fails with invalid_grant (%s) / When `list_credentials` runs / Then the daemon logs out and logs in once and the same request succeeds",
  async (mode) => {
    // Given: an existing login whose unlock fails with invalid_grant
    const canaries = scenarioCanaries();
    const daemon = await startColdStartDaemon(daemonOptions(mode, canaries));
    try {
      // When: `list_credentials`
      const response = await rawRpc(daemon.socketPath, "list_credentials", {});

      // Then: the same request succeeds through one unlock, one logout, and one login
      expect(response.error).toBeUndefined();
      expect(response.result).toEqual([
        expect.objectContaining({ name: canaries.itemName }),
      ]);
      expect(daemon.callsNamed("unlock")).toHaveLength(1);
      expect(daemon.callsNamed("logout")).toHaveLength(1);
      expect(daemon.loginCalls()).toHaveLength(1);

      // And: the diagnostic lines keep the email, master password, and session key masked
      expect(daemon.stderr()).toContain("invalid_grant");
      expect(daemon.stderr()).not.toContain(canaries.email);
      expect(daemon.stderr()).not.toContain(canaries.masterPassword);
      expect(daemon.stderr()).not.toContain(canaries.sessionKey);
    } finally {
      await daemon.stop();
    }
  },
);

test("AC-210: Given `bw unlock` fails without invalid_grant / When `list_credentials` runs / Then the error is `PROVIDER_UNAVAILABLE` and the login is kept", async () => {
  // Given: an unlock failure that is not a rejected grant (a wrong master password)
  const canaries = scenarioCanaries();
  const daemon = await startColdStartDaemon(
    daemonOptions("unlock-fail", canaries),
  );
  try {
    // When: `list_credentials`
    const response = await rawRpc(daemon.socketPath, "list_credentials", {});

    // Then: it fails as before, with no logout and no login
    expect(response.error?.message).toBe("PROVIDER_UNAVAILABLE");
    expect(daemon.callsNamed("logout")).toHaveLength(0);
    expect(daemon.loginCalls()).toHaveLength(0);
  } finally {
    await daemon.stop();
  }
});

test("AC-211: Given the login after a rejected grant also answers invalid_grant / When `list_credentials` runs / Then the error is `PROVIDER_UNAVAILABLE` and no further logout runs", async () => {
  // Given: unlock fails with invalid_grant, and so does the login that follows
  const canaries = scenarioCanaries();
  const daemon = await startColdStartDaemon(
    daemonOptions("grant-rejected-relogin-fails", canaries),
  );
  try {
    // When: `list_credentials`, which a cold start tries twice
    const response = await rawRpc(daemon.socketPath, "list_credentials", {});

    // Then: it fails. invalid_grant on login is a plain failure, so only the unlock led to a logout
    expect(response.error?.message).toBe("PROVIDER_UNAVAILABLE");
    expect(daemon.callsNamed("unlock")).toHaveLength(1);
    expect(daemon.callsNamed("logout")).toHaveLength(1);
    expect(daemon.loginCalls()).toHaveLength(2);
  } finally {
    await daemon.stop();
  }
});
