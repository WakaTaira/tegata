import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createLeakGuard, type LeakGuard } from "@tegata/leak-guard";
import {
  type ApiProxyDaemon,
  type ApiProxyFixture,
  type ApiProxySpec,
  startApiProxyDaemon,
  startApiProxyFixture,
} from "../../support/api-proxy.js";
import {
  bins,
  type CanarySet,
  connectMcp,
  defaultEntries,
  type McpSession,
} from "../../support/harness.js";
import {
  freeTcpPort,
  issuePeer,
  type Peer,
  sleep,
} from "../../support/phase4.js";
import {
  type Container,
  createTestNetwork,
  runContainer,
  type TestNetwork,
} from "./docker.js";
import { agentMounts, IN_CONTAINER, NODE } from "./stack.js";

export interface ApiProxyContainerStack {
  guard: LeakGuard;
  canaries: CanarySet;
  network: TestNetwork;
  daemon: ApiProxyDaemon;
  fixture: ApiProxyFixture;
  peer: Peer;
  daemonAddr: string;
  agent: Container;
  mcp: McpSession;
  agentDir: string;
  observe(label: string, value: unknown): void;
}

export async function startBridge(
  agent: Container,
  peer: Peer,
  daemonAddr: string,
): Promise<void> {
  await agent.exec(
    [
      "sh",
      "-c",
      `umask 077 && mkdir -p ${IN_CONTAINER.runDir} && cat > ${IN_CONTAINER.tokenFile}`,
    ],
    { input: `${peer.token}\n` },
  );
  agent.execDetached([
    "sh",
    "-c",
    `exec ${IN_CONTAINER.bridge} --socket ${IN_CONTAINER.bridgeSocket} --token-file ${IN_CONTAINER.tokenFile} --daemon-addr ${daemonAddr} > ${IN_CONTAINER.bridgeLog} 2>&1`,
  ]);
  const deadline = Date.now() + 15_000;
  while (Date.now() < deadline) {
    const probe = await agent.exec(["test", "-S", IN_CONTAINER.bridgeSocket], {
      allowFailure: true,
    });
    if (probe.status === 0) return;
    await sleep(200);
  }
  const log = (
    await agent.exec(["cat", IN_CONTAINER.bridgeLog], { allowFailure: true })
  ).stdout;
  throw new Error(`tegata-bridge did not open its socket: ${log}`);
}

/** API proxy の container スイート用に、host daemon と agent bridge を構成する。 */
export async function startApiProxyContainerStack(): Promise<ApiProxyContainerStack> {
  const agentDir = fs.mkdtempSync(path.join(os.tmpdir(), "tegata-agent-"));
  const guard = await createLeakGuard({
    leakscanBin: bins().leakscan,
    agentVisibleRoots: [agentDir, process.cwd()],
    psSampleIntervalMs: 200,
  });
  const canaries: CanarySet = {
    username: guard.canary("username"),
    password: guard.canary("password"),
    totpSeed: guard.canary("totp_seed"),
    wrongPassword: guard.canary("wrong_password"),
  };
  const observe = (label: string, value: unknown) =>
    guard.observe(label, value);
  let network: TestNetwork | undefined;
  let daemon: ApiProxyDaemon | undefined;
  let fixture: ApiProxyFixture | undefined;
  let agent: Container | undefined;
  let mcp: McpSession | undefined;
  try {
    network = createTestNetwork();
    fixture = await startApiProxyFixture({
      username: canaries.username,
      password: canaries.password,
    });
    const tcpPort = await freeTcpPort(network.gateway);
    const proxy: ApiProxySpec = {
      name: "fx",
      cred_id: "mock:site",
      upstream: fixture.url,
      header: "Authorization",
      value: "Bearer {{secret}}",
    };
    daemon = await startApiProxyDaemon({
      entries: defaultEntries(canaries),
      apiProxies: [proxy],
      transport: "listen",
      tcpBind: network.gateway,
      tcpPort,
      operatorUids: [os.userInfo().uid],
    });
    const peer = await issuePeer(daemon.socketPath, "container-api-proxy");
    const daemonAddr = `${network.gateway}:${tcpPort}`;
    agent = runContainer({ network: network.name, mounts: agentMounts() });
    await startBridge(agent, peer, daemonAddr);
    mcp = await connectMcp(
      IN_CONTAINER.bridgeSocket,
      observe,
      undefined,
      agent.execCommandLine([NODE, IN_CONTAINER.mcpEntry], {
        TEGATA_SOCKET: IN_CONTAINER.bridgeSocket,
        TEGATA_BRIDGE: "1",
      }),
    );
    return {
      guard,
      canaries,
      network,
      daemon,
      fixture,
      peer,
      daemonAddr,
      agent,
      mcp,
      agentDir,
      observe,
    };
  } catch (error) {
    await mcp?.close().catch(() => {});
    agent?.remove();
    await fixture?.stop().catch(() => {});
    await daemon?.stop().catch(() => {});
    network?.remove();
    await guard.dispose().catch(() => {});
    fs.rmSync(agentDir, { recursive: true, force: true });
    throw error;
  }
}

/** container 内 MCP と host 側資源を逆順に停止する。 */
export async function stopApiProxyContainerStack(
  stack: ApiProxyContainerStack,
): Promise<void> {
  await stack.mcp.close().catch(() => {});
  stack.agent.remove();
  await stack.fixture.stop().catch(() => {});
  await stack.daemon.stop().catch(() => {});
  stack.network.remove();
  try {
    await stack.guard.assertNoLeaks();
  } finally {
    await stack.guard.dispose();
    fs.rmSync(stack.agentDir, { recursive: true, force: true });
  }
}
