/**
 * Full-stack composition for the Phase 4b container suite. Owned by the
 * acceptance suite (gauntlet); do not modify during implementation.
 *
 * Host side: leak guard + Phase 4 daemon (mock provider, operator uid = the
 * test uid, TCP front bound to the test network's gateway) + the counting
 * fixture + a named peer p1 issued over the UNIX socket.
 *
 * Container side (`agent: true`): a plain container on the test network that
 * runs `tegata-bridge` with p1's token (a 0600 file, never an environment
 * variable) and the MCP server in bridge mode (`TEGATA_BRIDGE=1`,
 * `TEGATA_SOCKET` = the bridge's UNIX socket), driven from the host through
 * `docker exec -i`. The container sees the daemon only as
 * `<gateway>:<port>`; the browser's CDP port stays on the host's loopback and
 * is reached through the bridge's tunnel.
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createLeakGuard, type LeakGuard } from "@tegata/leak-guard";
import {
  bins,
  type CanarySet,
  connectMcp,
  defaultEntries,
  type McpSession,
  REPO_ROOT,
  rawRpc,
} from "../../support/harness.js";
import {
  type CountingFixture,
  issuePeer,
  type LoginResult,
  loginParams,
  type Peer,
  type Phase4Daemon,
  sleep,
  startCountingFixture,
  startPhase4Daemon,
} from "../../support/phase4.js";
import {
  type Container,
  closureMounts,
  createTestNetwork,
  type Mount,
  runContainer,
  type TestNetwork,
} from "./docker.js";

/** The node binary containers run (a Nix store path shared read-only). */
export const NODE = process.execPath;

/** Host directory of the probe scripts mounted into containers. */
export const PROBE_DIR = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "probe",
);

/** Paths inside the containers. */
export const IN_CONTAINER = {
  nodeModules: "/app/node_modules",
  mcpPackage: "/app/packages/tegata-mcp",
  mcpEntry: "/app/packages/tegata-mcp/dist/index.js",
  probe: "/app/probe",
  bridge: "/app/bin/tegata-bridge",
  leakscan: "/app/bin/leakscan",
  runDir: "/run/tegata-bridge",
  bridgeSocket: "/run/tegata-bridge/bridge.sock",
  tokenFile: "/run/tegata-bridge/token",
  bridgeLog: "/tmp/tegata-bridge.log",
} as const;

/** Mounts for an outsider container: node and the probe scripts only. */
export function probeMounts(): Mount[] {
  return [
    ...closureMounts([NODE]),
    { host: PROBE_DIR, container: IN_CONTAINER.probe },
  ];
}

/** Mounts for the agent container: node, bridge, leakscan, MCP and probes. */
export function agentMounts(): Mount[] {
  const b = bins();
  return [
    ...closureMounts([NODE, b.bridge, b.leakscan]),
    { host: b.bridge, container: IN_CONTAINER.bridge },
    { host: b.leakscan, container: IN_CONTAINER.leakscan },
    {
      host: path.join(REPO_ROOT, "node_modules"),
      container: IN_CONTAINER.nodeModules,
    },
    {
      host: path.join(REPO_ROOT, "packages/tegata-mcp"),
      container: IN_CONTAINER.mcpPackage,
    },
    { host: PROBE_DIR, container: IN_CONTAINER.probe },
  ];
}

export interface TcpProbeReport {
  connected: boolean;
  error: string | null;
  lines: string[];
  closed: boolean;
  /** Milliseconds from the connect attempt to close (or to the timeout). */
  ms: number;
}

/** Run `probe/tcp-probe.mjs` inside a container against host:port. */
export async function tcpProbe(
  container: Container,
  host: string,
  port: number,
  line?: string,
  timeoutMs = 15_000,
): Promise<TcpProbeReport> {
  const res = await container.exec(
    [
      NODE,
      `${IN_CONTAINER.probe}/tcp-probe.mjs`,
      host,
      String(port),
      line ?? "",
      String(timeoutMs),
    ],
    { timeoutMs: timeoutMs + 30_000 },
  );
  return JSON.parse(res.stdout.trim()) as TcpProbeReport;
}

/** Write p1's token (0600) and start the bridge inside the agent container. */
async function startBridge(
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

export interface ContainerStack {
  guard: LeakGuard;
  canaries: CanarySet;
  network: TestNetwork;
  daemon: Phase4Daemon;
  fixture: CountingFixture;
  /** Named peer whose token the agent container holds. */
  peer: Peer;
  /** `<gateway>:<port>` — the daemon as seen from the network. */
  daemonAddr: string;
  /** Present with `agent: true`. */
  agent?: Container;
  /** MCP session running inside the agent container (with `agent: true`). */
  mcp?: McpSession;
  /** Agent-visible scratch dir on the host; part of the guard's scan roots. */
  agentDir: string;
  observe(label: string, value: unknown): void;
}

export async function startContainerStack(
  opts: { agent?: boolean } = {},
): Promise<ContainerStack> {
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
  let daemon: Phase4Daemon | undefined;
  let fixture: CountingFixture | undefined;
  let agent: Container | undefined;
  let mcp: McpSession | undefined;
  try {
    network = createTestNetwork();
    daemon = await startPhase4Daemon({
      entries: defaultEntries(canaries),
      operatorUids: [os.userInfo().uid],
      tcp: true,
      tcpBind: network.gateway,
    });
    fixture = await startCountingFixture({
      username: canaries.username,
      password: canaries.password,
    });
    const peer = await issuePeer(daemon.socketPath, "container-p1");
    const daemonAddr = `${network.gateway}:${daemon.tcpPort}`;
    if (opts.agent === true) {
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
    }
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

/** Tear down in reverse order and enforce the host-side leak check. */
export async function stopContainerStack(stack: ContainerStack): Promise<void> {
  await stack.mcp?.close().catch(() => {});
  stack.agent?.remove();
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

/** Login over the host's UNIX socket as the test uid; asserts success. */
export async function hostLogin(
  stack: ContainerStack,
  credId = "mock:site",
): Promise<LoginResult> {
  const res = await rawRpc(
    stack.daemon.socketPath,
    "login",
    loginParams(stack.fixture.url, credId),
  );
  stack.observe("rpc:login", res);
  if (res.error !== undefined)
    throw new Error(`login failed: ${JSON.stringify(res.error)}`);
  return res.result as LoginResult;
}

/** Logout over the host's UNIX socket; returns the raw reply. */
export async function hostLogout(
  stack: ContainerStack,
  sessionId: string,
): Promise<{ result?: unknown; error?: { code: number; message?: string } }> {
  const res = await rawRpc(stack.daemon.socketPath, "logout", {
    session_id: sessionId,
  });
  stack.observe("rpc:logout", res);
  return res;
}
