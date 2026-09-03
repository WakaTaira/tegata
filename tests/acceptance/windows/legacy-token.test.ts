// AC-67 — the single Windows token of the token_hash file is imported at
// start-up as the named peer "legacy": the old token keeps working over TCP,
// peers.json lists it, and the audit log names it.
// Traceability: docs/secret/briefs/tegata-phase4.md acceptance condition AC-67.

import { randomBytes } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { beforeAll, expect, test } from "vitest";
import {
  pipeRpc,
  readForegroundAudit,
  startForegroundPhase4Daemon,
  winLoopbackExchange,
} from "./support/phase4.js";
import { currentWindowsSid, requireRig } from "./support/winrig.js";

let mySid: string;

beforeAll(async () => {
  requireRig();
  mySid = await currentWindowsSid();
});

test("AC-67: an existing token_hash file becomes the legacy peer", async () => {
  // Given: `token issue` 相当の旧 token_hash ファイル（既知トークンの sha256）
  // を state に置いた foreground daemon 構成
  const token = randomBytes(32).toString("base64url");
  const daemon = await startForegroundPhase4Daemon({
    allowedSids: [mySid],
    legacyToken: token,
  });
  try {
    // When: デーモンが起動を終えている（ready 行まで待った）
    const peersPath = path.join(daemon.stateDirWsl, "peers.json");

    // Then: peers.json に peer_id = "legacy" があり、旧ファイルは .imported に
    // リネームされている
    expect(fs.existsSync(peersPath), "peers.json was not created").toBe(true);
    const peers = JSON.parse(fs.readFileSync(peersPath, "utf8")) as Array<{
      peer_id: string;
      label: string;
    }>;
    expect(
      peers.some((p) => p.peer_id === "legacy" && p.label === "legacy"),
      JSON.stringify(peers),
    ).toBe(true);
    expect(
      fs.existsSync(path.join(daemon.stateDirWsl, "token_hash.imported")),
    ).toBe(true);
    expect(fs.existsSync(path.join(daemon.stateDirWsl, "token_hash"))).toBe(
      false,
    );

    // And: 旧トークンで preamble が通り、status が JSON-RPC の result を返す
    const lines = await winLoopbackExchange(daemon.tcpPort, [
      JSON.stringify({ v: 1, auth: token }),
      JSON.stringify({ jsonrpc: "2.0", id: 1, method: "status", params: {} }),
    ]);
    const parsed = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
    const rpc = parsed.find((l) => l.jsonrpc === "2.0");
    expect(rpc?.result, JSON.stringify(parsed)).toBeDefined();

    // And: 監査の status 行は principal "peer:legacy" と peer_id "legacy" を持つ
    const audit = readForegroundAudit(daemon.stateDirWsl);
    const record = audit.find(
      (r) => r.method === "status" && r.peer_id === "legacy",
    );
    expect(record, JSON.stringify(audit)).toBeDefined();
    expect(record?.principal).toBe("peer:legacy");

    // And: 同じデーモンへ pipe から status を呼ぶと principal は SID
    const viaPipe = await pipeRpc(daemon.pipeName, "status", {});
    expect(viaPipe.result).toBeDefined();
    const pipeRecord = readForegroundAudit(daemon.stateDirWsl).find(
      (r) => r.method === "status" && r.principal === `sid:${mySid}`,
    );
    expect(pipeRecord).toBeDefined();
  } finally {
    await daemon.stop();
  }
});
