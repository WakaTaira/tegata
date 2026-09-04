// AC-71 — an outsider container on the tegata bridge network (no token) gets
// nothing from the host: a silent connection is dropped, a forged token is
// UNAUTHORIZED, and the browser's CDP port is unreachable from the network.
// Traceability: docs/secret/briefs/tegata-phase4.md acceptance condition AC-71.
//
// Needs a rootful docker (`${TEGATA_DOCKER} info` must succeed); otherwise
// the test is skipped.

import { afterAll, beforeAll, describe, expect, test } from "vitest";
import { endpointPort, preambleLine } from "../support/phase4.js";
import {
  type Container,
  dockerAvailable,
  runContainer,
} from "./support/docker.js";
import {
  type ContainerStack,
  hostLogin,
  hostLogout,
  probeMounts,
  startContainerStack,
  stopContainerStack,
  tcpProbe,
} from "./support/stack.js";

describe.skipIf(!dockerAvailable())("AC-71 (docker)", () => {
  let stack: ContainerStack | undefined;
  let outsider: Container | undefined;

  beforeAll(async () => {
    stack = await startContainerStack();
    outsider = runContainer({
      network: stack.network.name,
      mounts: probeMounts(),
    });
  });

  afterAll(async () => {
    outsider?.remove();
    if (stack !== undefined) await stopContainerStack(stack);
  });

  test("AC-71: an outsider container without a token is refused everywhere", async () => {
    // Given: ホストのデーモンが docker bridge のゲートウェイ IP に bind、
    //        トークン無しの outsider コンテナ
    if (stack === undefined || outsider === undefined)
      throw new Error("stack not started");
    const { gateway } = stack.network;
    const daemonPort = stack.daemon.tcpPort as number;

    // When: preamble 無しで接続
    const silent = await tcpProbe(outsider, gateway, daemonPort);

    // Then: 10 s 以内に切断（preamble の待ち 10 s に 2 s の猶予を足して判定）
    expect(silent.connected, JSON.stringify(silent)).toBe(true);
    expect(silent.closed, JSON.stringify(silent)).toBe(true);
    expect(silent.ms).toBeLessThan(12_000);

    // When: 偽トークンで preamble
    const forged = await tcpProbe(
      outsider,
      gateway,
      daemonPort,
      preambleLine("forged-token"),
    );

    // Then: UNAUTHORIZED
    expect(forged.lines.length, JSON.stringify(forged)).toBeGreaterThan(0);
    expect(JSON.parse(forged.lines[0])).toEqual({
      ok: false,
      error: "UNAUTHORIZED",
    });

    // When: ホストの 127.0.0.1 の CDP ポートへ接続（コンテナからホストへ届く
    //       唯一の経路であるゲートウェイ IP と、コンテナ自身の 127.0.0.1 の両方）
    const login = await hostLogin(stack);
    try {
      const cdpPort = endpointPort(login.channel.endpoint);
      const viaGateway = await tcpProbe(
        outsider,
        gateway,
        cdpPort,
        undefined,
        5_000,
      );
      const viaLoopback = await tcpProbe(
        outsider,
        "127.0.0.1",
        cdpPort,
        undefined,
        5_000,
      );

      // Then: 到達不可（ECONNREFUSED または timeout）
      expect(viaGateway.connected, JSON.stringify(viaGateway)).toBe(false);
      expect(["ECONNREFUSED", "EHOSTUNREACH", "timeout"]).toContain(
        viaGateway.error,
      );
      expect(viaLoopback.connected, JSON.stringify(viaLoopback)).toBe(false);
    } finally {
      await hostLogout(stack, login.session_id);
    }
  });
});
