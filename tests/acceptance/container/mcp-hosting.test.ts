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

/** Runner entry inside the agent container (the mount target of `packages/tegata-mcp`). */
const IN_CONTAINER_RUNNER = `${IN_CONTAINER.mcpPackage}/dist/run.js`;

describe("AC-141 (docker)", () => {
  test("AC-141: Given tegata-bridge in the agent container with TEGATA_BRIDGE=1 / When tegata-mcp-run fake calls whoami inside the container / Then the result is the sha256 of the credential password", async () => {
    if (!dockerAvailable())
      throw new Error("Docker daemon is unavailable for AC-141");
    // Given: a daemon bound to the gateway (with the fake MCP server "fake"), and a bridge in the
    // agent container running with the peer token
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

      // When: start the runner inside the container through the bridge and call whoami
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

      // Then: the result is the sha256 of the password, and the password itself does not appear
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
