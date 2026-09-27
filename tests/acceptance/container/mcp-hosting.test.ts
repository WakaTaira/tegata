import os from "node:os";
import { describe, expect, test } from "vitest";
import {
  connectRunner,
  type HostedMcpStack,
  type RunnerSession,
  sha256Hex,
  startHostedMcpStack,
  stopHostedMcpStack,
} from "../support/mcp-hosting.js";
import { freeTcpPort, issuePeer } from "../support/phase4.js";
import { startBridge } from "./support/api-proxy-stack.js";
import {
  type Container,
  createTestNetwork,
  dockerAvailable,
  runContainer,
  type TestNetwork,
} from "./support/docker.js";
import { agentMounts, IN_CONTAINER, NODE } from "./support/stack.js";

/** agent コンテナ内のランナー entry（`packages/tegata-mcp` の mount 先）。 */
const IN_CONTAINER_RUNNER = `${IN_CONTAINER.mcpPackage}/dist/run.js`;

describe("AC-141 (docker)", () => {
  test("AC-141: Given tegata-bridge in the agent container with TEGATA_BRIDGE=1 / When tegata-mcp-run fake calls whoami inside the container / Then the result is the sha256 of the credential password", async () => {
    if (!dockerAvailable())
      throw new Error("Docker daemon is unavailable for AC-141");
    // Given: gateway へ bind した daemon（偽 MCP サーバー "fake"）と、peer の token で動く agent コンテナの bridge
    let network: TestNetwork | undefined;
    let stack: HostedMcpStack | undefined;
    let agent: Container | undefined;
    let runner: RunnerSession | undefined;
    try {
      network = createTestNetwork();
      const tcpPort = await freeTcpPort(network.gateway);
      stack = await startHostedMcpStack({
        daemon: {
          transport: "listen",
          tcpBind: network.gateway,
          tcpPort,
          operatorUids: [os.userInfo().uid],
        },
      });
      const peer = await issuePeer(stack.daemon.socketPath, "container-mcp");
      agent = runContainer({ network: network.name, mounts: agentMounts() });
      await startBridge(agent, peer, `${network.gateway}:${tcpPort}`);

      // When: コンテナ内でランナーを bridge 経由で起動し whoami を呼ぶ
      runner = await connectRunner({
        socketPath: IN_CONTAINER.bridgeSocket,
        name: "fake",
        observe: stack.observe,
        spawnAs: agent.execCommandLine([NODE, IN_CONTAINER_RUNNER, "fake"], {
          TEGATA_SOCKET: IN_CONTAINER.bridgeSocket,
          TEGATA_BRIDGE: "1",
        }),
      });
      const whoami = await runner.callTool("whoami", {}, 30_000);

      // Then: 結果は password の sha256 で、password そのものは現れない
      expect(whoami.isError, whoami.text).toBe(false);
      expect(whoami.text).toBe(sha256Hex(stack.canaries.password));
      expect(whoami.text).not.toContain(stack.canaries.password);
    } finally {
      if (runner !== undefined) {
        await runner.close().catch(() => {});
        stack?.observe("runner:stderr", runner.stderr());
      }
      agent?.remove();
      try {
        if (stack !== undefined) await stopHostedMcpStack(stack);
      } finally {
        network?.remove();
      }
    }
  });
});
