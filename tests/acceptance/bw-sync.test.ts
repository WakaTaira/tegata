import { randomUUID } from "node:crypto";
import { expect, test } from "vitest";
import {
  type ColdStartCanaries,
  type FakeBwMode,
  startColdStartDaemon,
} from "./support/cold-start.js";
import { rawRpc } from "./support/harness.js";

function scenarioCanaries(): ColdStartCanaries {
  const id = randomUUID().replaceAll("-", "");
  return {
    email: `bw-sync-email-${id}@example.invalid`,
    masterPassword: `bw-sync-master-${id}`,
    sessionKey: `bw-sync-session-${id}`,
    itemId: `bw-sync-item-id-${id}`,
    itemName: `bw-sync-item-name-${id}`,
  };
}

function daemonOptions(
  mode: FakeBwMode,
  canaries: ColdStartCanaries,
  env?: Record<string, string>,
) {
  const id = canaries.itemId.replace("bw-sync-item-id-", "");
  return {
    mode,
    namespace: `bw_sync_${id}`,
    serverUrl: "https://bitwarden-bw-sync.invalid",
    canaries,
    env,
  };
}

test("AC-110: Given a renamed remote item / When list_credentials runs again / Then it returns the synced name", async () => {
  // Given: fake bw serves the initial item and the resync interval is shortened
  const canaries = scenarioCanaries();
  const daemon = await startColdStartDaemon(
    daemonOptions("success", canaries, {
      TEGATA_BW_RESYNC_INTERVAL_MS: "0",
    }),
  );
  try {
    const first = await rawRpc(daemon.socketPath, "list_credentials", {});
    expect(first.error).toBeUndefined();
    daemon.setBwItemName(`${canaries.itemName}-renamed`);

    // When: list_credentials runs after the item is renamed on the vault side
    const response = await rawRpc(daemon.socketPath, "list_credentials", {});

    // Then: the periodic sync returns the new name without waiting 60 s
    expect(response.error).toBeUndefined();
    expect(response.result).toEqual([
      expect.objectContaining({
        id: `${daemon.namespace}:${canaries.itemId}`,
        name: `${canaries.itemName}-renamed`,
      }),
    ]);
    expect(daemon.syncCalls()).toHaveLength(2);
  } finally {
    await daemon.stop();
  }
});

test("AC-111: Given a hanging initial sync / When list_credentials establishes a session / Then it returns PROVIDER_UNAVAILABLE without a second login", async () => {
  // Given: fake bw hangs on sync and the sync timeout is shortened
  const canaries = scenarioCanaries();
  const daemon = await startColdStartDaemon(
    daemonOptions("sync-hang", canaries, {
      TEGATA_BW_SYNC_TIMEOUT_MS: "100",
    }),
  );
  try {
    // When: list_credentials establishes a new session
    const startedAt = performance.now();
    const response = await rawRpc(daemon.socketPath, "list_credentials", {});
    const elapsedMs = performance.now() - startedAt;

    // Then: the sync timeout is PROVIDER_UNAVAILABLE and login is not retried
    expect(response.error?.message).toBe("PROVIDER_UNAVAILABLE");
    expect(daemon.loginCalls()).toHaveLength(1);
    expect(daemon.syncCalls()).toHaveLength(1);
    expect(elapsedMs).toBeLessThan(2_000);
  } finally {
    await daemon.stop();
  }
});

test("AC-112: Given an established session and a failed periodic sync / When list_credentials runs / Then cached items are returned successfully", async () => {
  // Given: the catalog was filled before the periodic sync starts failing
  const canaries = scenarioCanaries();
  const daemon = await startColdStartDaemon(
    daemonOptions("success", canaries, {
      TEGATA_BW_RESYNC_INTERVAL_MS: "0",
    }),
  );
  try {
    const first = await rawRpc(daemon.socketPath, "list_credentials", {});
    expect(first.error).toBeUndefined();
    daemon.setBwMode("sync-fail");

    // When: list_credentials runs while the periodic sync fails
    const response = await rawRpc(daemon.socketPath, "list_credentials", {});

    // Then: the local cache is served and the failing sync was tried once
    expect(response.error).toBeUndefined();
    expect(response.result).toEqual([
      expect.objectContaining({
        id: `${daemon.namespace}:${canaries.itemId}`,
        name: canaries.itemName,
      }),
    ]);
    expect(daemon.syncCalls()).toHaveLength(2);
  } finally {
    await daemon.stop();
  }
});
