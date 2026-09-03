// AC-66 — the TCP front accepts per connection: silent clients do not stall
// authenticated ones, and unauthenticated connections beyond
// max_pending_connections (default 8) are closed at once.
// Traceability: docs/secret/briefs/tegata-phase4.md acceptance condition AC-66.

import { once } from "node:events";
import net from "node:net";
import { expect, test } from "vitest";
import {
  issuePeer,
  sleep,
  startPhase4Stack,
  stopPhase4Stack,
  tcpRpc,
} from "./support/phase4.js";

async function openSilent(port: number): Promise<net.Socket> {
  const sock = net.connect(port, "127.0.0.1");
  sock.on("error", () => {});
  await once(sock, "connect");
  return sock;
}

test("AC-66: silent connections neither stall real clients nor pile up", async () => {
  // Given: TCP 口と、無言のまま張った接続 7 本（上限 8 の内側）
  const stack = await startPhase4Stack({ tcp: true });
  const held: net.Socket[] = [];
  try {
    const tcpPort = stack.daemon.tcpPort as number;
    const peer = await issuePeer(stack.daemon.socketPath, "probe");
    for (let i = 0; i < 7; i++) held.push(await openSilent(tcpPort));

    // When: 正規の preamble + status を送る
    const started = Date.now();
    const res = await tcpRpc(tcpPort, peer.token, "status", {}, 15_000);
    const elapsed = Date.now() - started;

    // Then: 2 s 以内に応答を得る（無言接続の 10 s 待ちに巻き込まれない）
    expect(res.preamble).toBeUndefined();
    expect(res.result, JSON.stringify(res)).toBeDefined();
    expect(elapsed).toBeLessThan(2_000);

    // When: 8 本目の無言接続で上限に達した状態で、9 本目を開く
    held.push(await openSilent(tcpPort));
    const ninth = await openSilent(tcpPort);
    held.push(ninth);
    const closedWithinASecond = await Promise.race([
      once(ninth, "close").then(() => true),
      sleep(1_000).then(() => false),
    ]);

    // Then: 9 本目は 1 s 以内に切断される
    expect(closedWithinASecond).toBe(true);
  } finally {
    for (const sock of held) sock.destroy();
    await stopPhase4Stack(stack);
  }
});
