// AC-19, AC-20, AC-21, AC-30 — TCP transport authentication and the
// classification-only error surface across the bridge.
// Traceability: docs/secret/briefs/tegata-phase2.md 受け入れ条件 #1, #2, #3, #12.

import { afterAll, beforeAll, expect, test } from "vitest";
import { ERROR_CODES } from "../support/harness.js";
import {
  type Bridge,
  bridgeRpc,
  daemonExchange,
  ensureServiceRunning,
  requireRig,
  startBridge,
  startService,
  stopService,
} from "./support/winrig.js";

let bridge: Bridge;

beforeAll(async () => {
  requireRig();
  await ensureServiceRunning();
  bridge = await startBridge();
});

afterAll(async () => {
  await bridge?.stop().catch(() => {});
});

test("AC-19: a correct token over the bridge reaches the daemon", async () => {
  // Given: a running service and the correct token file (rig default)
  // When: status is called through the bridge
  const res = await bridgeRpc(bridge.socketPath, "status", {});

  // Then: a normal response is returned
  expect(
    res.error,
    `status errored: ${JSON.stringify(res.error)}`,
  ).toBeUndefined();
  expect(res.result).toBeDefined();
});

test("AC-20: a wrong token is rejected and no method runs", async () => {
  // Given: a preamble carrying a wrong token, followed by a status request
  const bad = `LEAK_CANARY_wrongtoken_${"0".repeat(32)}`;
  const exchange = await daemonExchange([
    JSON.stringify({ v: 1, auth: bad }),
    JSON.stringify({ jsonrpc: "2.0", id: 1, method: "status", params: {} }),
  ]);

  // Then: exactly one line — the auth rejection — is returned and the socket
  // is closed; the status method never produced a JSON-RPC response
  expect(exchange.closed).toBe(true);
  expect(exchange.lines.length).toBe(1);
  const first = JSON.parse(exchange.lines[0]);
  expect(first.ok).toBe(false);
  expect(first.error).toBe("UNAUTHORIZED");
  for (const line of exchange.lines) {
    expect(line).not.toContain('"result"');
    expect(line).not.toContain('"jsonrpc"');
  }
});

test("AC-21: a missing token is rejected before any request", async () => {
  // Given: a preamble with no auth field, followed by a status request
  const exchange = await daemonExchange([
    JSON.stringify({ v: 1 }),
    JSON.stringify({ jsonrpc: "2.0", id: 1, method: "status", params: {} }),
  ]);

  // Then: the connection is closed with an auth rejection and no RPC runs
  expect(exchange.closed).toBe(true);
  expect(exchange.lines.length).toBe(1);
  const first = JSON.parse(exchange.lines[0]);
  expect(first.ok).toBe(false);
  expect(first.error).toBe("UNAUTHORIZED");
});

test("AC-30: a stopped service surfaces a classification code only", async () => {
  // Given: the service is stopped
  await stopService();
  try {
    // When: an RPC is issued through the bridge
    const res = await bridgeRpc(bridge.socketPath, "status", {});

    // Then: a classification-only error is returned with no stack trace or
    // internal path in the message
    expect(res.error).toBeDefined();
    const message = res.error?.message ?? "";
    expect(ERROR_CODES).toContain(message);
    expect(message).not.toMatch(/\s/); // a bare code, nothing appended
    expect(message).not.toMatch(/[/\\]|\.rs|\.ts|panic|at /i);
    // The daemon is unreachable, so INTERNAL is the expected code here.
    expect(message).toBe("INTERNAL");
  } finally {
    await startService();
  }
});
