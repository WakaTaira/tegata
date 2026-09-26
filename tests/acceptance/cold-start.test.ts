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

test("AC-87: Given 偽 bw の最初の `list items` が exit 1、2 回目は正常な JSON / When デーモン起動直後に `list_credentials` / Then 成功し item が返る、`list items` の記録は 2 回、応答まで 2 s 以上", async () => {
  // Given: 偽 bw の最初の `list items` が exit 1、2 回目は正常な JSON
  const canaries = scenarioCanaries();
  const daemon = await startColdStartDaemon(
    daemonOptions("fail-until:1", canaries),
  );
  try {
    // When: デーモン起動直後に `list_credentials`
    const startedAt = performance.now();
    const response = await rawRpc(daemon.socketPath, "list_credentials", {});
    const elapsedMs = performance.now() - startedAt;

    // Then: 成功し item が返る、`list items` の記録は 2 回、応答まで 2 s 以上
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

test("AC-88: Given 偽 bw の `list items` が常に exit 1 / When 起動直後に `list_credentials` / Then エラーコード `PROVIDER_UNAVAILABLE`、`list items` の記録は 2 回", async () => {
  // Given: 偽 bw の `list items` が常に exit 1
  const canaries = scenarioCanaries();
  const daemon = await startColdStartDaemon(
    daemonOptions("always-fail", canaries),
  );
  try {
    // When: 起動直後に `list_credentials`
    const response = await rawRpc(daemon.socketPath, "list_credentials", {});

    // Then: エラーコード `PROVIDER_UNAVAILABLE`、`list items` の記録は 2 回
    expect(response.error?.message).toBe("PROVIDER_UNAVAILABLE");
    expect(daemon.listItemsCalls()).toHaveLength(2);
  } finally {
    await daemon.stop();
  }
});

test("AC-89: Given 偽 bw の `list items` が不正な JSON を返す / When 起動直後に `list_credentials` / Then `INTERNAL`、`list items` の記録は 1 回（再試行しない）", async () => {
  // Given: 偽 bw の `list items` が不正な JSON を返す
  const canaries = scenarioCanaries();
  const daemon = await startColdStartDaemon(
    daemonOptions("invalid-json", canaries),
  );
  try {
    // When: 起動直後に `list_credentials`
    const response = await rawRpc(daemon.socketPath, "list_credentials", {});

    // Then: `INTERNAL`、`list items` の記録は 1 回（再試行しない）
    expect(response.error?.message).toBe("INTERNAL");
    expect(daemon.listItemsCalls()).toHaveLength(1);
  } finally {
    await daemon.stop();
  }
});

test("AC-90: Given 1 回目の `list_credentials` が成功して catalog が埋まった後、`list items` が常に exit 1 になる / When 2 回目の `list_credentials` / Then `PROVIDER_UNAVAILABLE`、2 回目の呼び出しで増えた `list items` の記録は 1 回（warm は再試行しない）", async () => {
  // Given: 1 回目の `list_credentials` が成功して catalog が埋まった後、`list items` が常に exit 1 になる
  const canaries = scenarioCanaries();
  const daemon = await startColdStartDaemon(daemonOptions("success", canaries));
  try {
    const first = await rawRpc(daemon.socketPath, "list_credentials", {});
    expect(first.error).toBeUndefined();
    const beforeSecondCall = daemon.listItemsCalls().length;
    daemon.setBwMode("always-fail");

    // When: 2 回目の `list_credentials`
    const response = await rawRpc(daemon.socketPath, "list_credentials", {});

    // Then: `PROVIDER_UNAVAILABLE`、2 回目の呼び出しで増えた `list items` の記録は 1 回（warm は再試行しない）
    expect(response.error?.message).toBe("PROVIDER_UNAVAILABLE");
    expect(daemon.listItemsCalls().length - beforeSecondCall).toBe(1);
  } finally {
    await daemon.stop();
  }
});

test('AC-91: Given AC-87 の実行 / When デーモンの stderr を読む / Then `tegatad: bw_version` 行が 1 行、`tegatad: bw_diag {JSON}` 行が bw 呼び出し回数と同数あり、失敗した `list_items` の行に `attempt: 1`・`cold_start: true`・`failure: "exit"`・`exit_code: 1`、再試行の行に `attempt: 2`、全 bw_diag 行に `rpc_id`・`namespace`・`elapsed_ms` がある。stderr にカナリア（email・master password・session key・item 名）が 0 件。', async () => {
  // Given: AC-87 の実行
  const canaries = scenarioCanaries();
  const daemon = await startColdStartDaemon(
    daemonOptions("fail-until:1", canaries),
  );
  try {
    const response = await rawRpc(daemon.socketPath, "list_credentials", {});
    expect(response.error).toBeUndefined();
    expect(daemon.listItemsCalls()).toHaveLength(2);
    const bwCallCount = daemon.callLog().length;

    // When: デーモンの stderr を読む
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

    // Then: `tegatad: bw_version` 行が 1 行、`tegatad: bw_diag {JSON}` 行が bw 呼び出し回数と同数あり、失敗した `list_items` の行に `attempt: 1`・`cold_start: true`・`failure: "exit"`・`exit_code: 1`、再試行の行に `attempt: 2`、全 bw_diag 行に `rpc_id`・`namespace`・`elapsed_ms` がある。stderr にカナリア（email・master password・session key・item 名）が 0 件。
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

test("AC-92: Given AC-88 の状態のデーモンに MCP broker を接続 / When MCP の `list_credentials` / Then ツール結果のエラーコードが `PROVIDER_UNAVAILABLE`（`INTERNAL` に正規化されない）", async () => {
  // Given: AC-88 の状態のデーモンに MCP broker を接続
  const canaries = scenarioCanaries();
  const daemon = await startColdStartDaemon(
    daemonOptions("always-fail", canaries),
  );
  let mcp: Awaited<ReturnType<typeof connectMcp>> | undefined;
  try {
    mcp = await connectMcp(daemon.socketPath);

    // When: MCP の `list_credentials`
    const result = await mcp.callTool("list_credentials", {});

    // Then: ツール結果のエラーコードが `PROVIDER_UNAVAILABLE`（`INTERNAL` に正規化されない）
    expect(result.isError).toBe(true);
    expect(result.text).toBe("PROVIDER_UNAVAILABLE");
  } finally {
    if (mcp !== undefined) await mcp.close().catch(() => {});
    await daemon.stop();
  }
});
