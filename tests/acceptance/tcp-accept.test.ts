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
  // Given: a TCP port, and 7 connections opened and left silent (within the limit of 8)
  const stack = await startPhase4Stack({ tcp: true });
  const held: net.Socket[] = [];
  try {
    const tcpPort = stack.daemon.tcpPort as number;
    const peer = await issuePeer(stack.daemon.socketPath, "probe");
    for (let i = 0; i < 7; i++) held.push(await openSilent(tcpPort));

    // When: send a valid preamble + status
    const started = Date.now();
    const res = await tcpRpc(tcpPort, peer.token, "status", {}, 15_000);
    const elapsed = Date.now() - started;

    // Then: a response arrives within 2 s (it is not caught up in the 10 s wait of the silent
    // connections)
    expect(res.preamble).toBeUndefined();
    expect(res.result, JSON.stringify(res)).toBeDefined();
    expect(elapsed).toBeLessThan(2_000);

    // When: with the limit reached by an 8th silent connection, open a 9th
    held.push(await openSilent(tcpPort));
    const ninth = await openSilent(tcpPort);
    held.push(ninth);
    const closedWithinASecond = await Promise.race([
      once(ninth, "close").then(() => true),
      sleep(1_000).then(() => false),
    ]);

    // Then: the 9th is disconnected within 1 s
    expect(closedWithinASecond).toBe(true);
  } finally {
    for (const sock of held) sock.destroy();
    await stopPhase4Stack(stack);
  }
});
