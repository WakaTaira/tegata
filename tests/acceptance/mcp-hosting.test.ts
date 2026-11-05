import { randomBytes } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { expect, test } from "vitest";
import { runApiProxyDaemonUntilExit } from "./support/api-proxy.js";
import { type CanarySet, defaultEntries, rawRpc } from "./support/harness.js";
import {
  connectRunner,
  fakeServerSpec,
  type HostedMcpStack,
  type OpenMcpServer,
  type RunnerSession,
  readServerLog,
  receivedRequests,
  renderMcpServers,
  type StreamExchange,
  settlesWithin,
  sha256Hex,
  startHostedMcpStack,
  stopHostedMcpStack,
  streamExchange,
} from "./support/mcp-hosting.js";
import { readAuditRecords, waitUntil } from "./support/phase3.js";
import { sleep } from "./support/phase4.js";

const TIMEOUT = { timeout: 120_000 };

function throwawayCanaries(): CanarySet {
  const random = () => randomBytes(12).toString("hex");
  return {
    username: `user_${random()}`,
    password: `pass_${random()}`,
    totpSeed: `seed_${random()}`,
    wrongPassword: `wrong_${random()}`,
  };
}

function startRunner(stack: HostedMcpStack): Promise<RunnerSession> {
  return connectRunner({
    socketPath: stack.daemon.socketPath,
    name: "fake",
    observe: stack.observe,
  });
}

/** Closes the runner and adds its stderr to the leak guard's observation surface. */
async function closeRunner(
  stack: HostedMcpStack,
  runner: RunnerSession | undefined,
): Promise<void> {
  if (runner === undefined) return;
  await runner.close().catch(() => {});
  stack.observe("runner:stderr", runner.stderr());
}

function processExists(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code !== "ESRCH";
  }
}

async function leaseCount(socketPath: string): Promise<unknown> {
  const status = await rawRpc(socketPath, "status", {});
  return (status.result as { leases?: unknown } | undefined)?.leases;
}

function mcpLine(id: string, method: string, params: unknown = {}): string {
  return `${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`;
}

function initializeLine(id: string): string {
  return mcpLine(id, "initialize", {
    protocolVersion: "2025-06-18",
    capabilities: {},
    clientInfo: { name: "acceptance-stream", version: "0.0.0" },
  });
}

function responseIds(exchange: StreamExchange): unknown[] {
  return exchange.lines.map((line) => {
    try {
      return (JSON.parse(line) as { id?: unknown }).id;
    } catch {
      return undefined;
    }
  });
}

test(
  "AC-135: Given [[mcp_server]] fake / When tegata-mcp-run fake is driven by an MCP stdio client and whoami is called / Then the result is the sha256 of the credential password",
  TIMEOUT,
  async () => {
    // Given: a fake server "fake" that puts the password of credential mock:site into TOKEN
    const stack = await startHostedMcpStack();
    let runner: RunnerSession | undefined;
    try {
      // When: start the runner as a regular stdio MCP server and call whoami
      runner = await startRunner(stack);
      const whoami = await runner.callTool("whoami");

      // Then: the result is the sha256 of the password, and the password itself does not appear
      expect(whoami.isError, whoami.text).toBe(false);
      expect(whoami.text).toBe(sha256Hex(stack.canaries.password));
      expect(whoami.text).not.toContain(stack.canaries.password);
    } finally {
      await closeRunner(stack, runner);
      await stopHostedMcpStack(stack);
    }
  },
);

test(
  "AC-136: Given an AC-135 runner session / When the leak tool is called / Then no response arrives, the runner exits, the audit log records mcp_action leak, and the password is on no observed surface",
  TIMEOUT,
  async () => {
    // Given: the same session as AC-135
    const stack = await startHostedMcpStack();
    let runner: RunnerSession | undefined;
    try {
      runner = await startRunner(stack);
      const whoami = await runner.callTool("whoami");
      expect(whoami.isError, whoami.text).toBe(false);

      // When: call a tool that outputs TOKEN verbatim
      let callError: unknown;
      try {
        const leaked = await runner.callTool("leak", {}, 10_000);
        stack.observe("runner:leak-result", leaked);
      } catch (error) {
        callError = error;
      }

      // Then: no response arrives, the client gets an error, and the runner exits
      expect(callError, "leak returned a response").toBeDefined();
      stack.observe("runner:leak-error", String(callError));
      expect(await settlesWithin(runner.exited, 10_000)).toBe(true);
      stack.observe("runner:stderr", runner.stderr());
      expect(String(callError)).not.toContain(stack.canaries.password);
      expect(runner.stderr()).not.toContain(stack.canaries.password);

      // Then: the audit log retains a leak event for mcp_server and does not contain the password
      await waitUntil("mcp_server leak audit record", () =>
        readAuditRecords(stack.daemon.auditLogPath).records.some(
          (record) =>
            record.method === "mcp_server" && record.mcp_action === "leak",
        ),
      );
      const { records } = readAuditRecords(stack.daemon.auditLogPath);
      const leakRecord = records.find(
        (record) =>
          record.method === "mcp_server" && record.mcp_action === "leak",
      );
      expect(leakRecord?.mcp_server).toBe("fake");
      expect(typeof leakRecord?.session_id).toBe("string");
      expect(JSON.stringify(records)).not.toContain(stack.canaries.password);

      // Then: the password appears 0 times on every surface the test can observe
      expect(await stack.guard.collectLeaks()).toEqual([]);
    } finally {
      await closeRunner(stack, runner);
      await stopHostedMcpStack(stack);
    }
  },
);

test(
  "AC-137: Given an AC-135 runner session and the server pid / When the runner's stdin is closed / Then within 5 seconds the server process is gone and status reports zero leases",
  TIMEOUT,
  async () => {
    // Given: the same session as AC-135, with the child process pid obtained from the pid tool
    const stack = await startHostedMcpStack();
    let runner: RunnerSession | undefined;
    try {
      runner = await startRunner(stack);
      const pidResult = await runner.callTool("pid");
      expect(pidResult.isError, pidResult.text).toBe(false);
      const serverPid = Number(pidResult.text);
      expect(Number.isInteger(serverPid) && serverPid > 0).toBe(true);
      expect(processExists(serverPid)).toBe(true);
      expect(await leaseCount(stack.daemon.socketPath)).toBe(1);

      // When: close the client and close the runner's stdin
      await closeRunner(stack, runner);
      runner = undefined;

      // Then: within 5 seconds the server process is gone and the lease count is 0
      await waitUntil(
        "hosted MCP server exit and lease release",
        async () =>
          !processExists(serverPid) &&
          (await leaseCount(stack.daemon.socketPath)) === 0,
        5_000,
      );
      expect(processExists(serverPid)).toBe(false);
      expect(await leaseCount(stack.daemon.socketPath)).toBe(0);
    } finally {
      await closeRunner(stack, runner);
      await stopHostedMcpStack(stack);
    }
  },
);

test(
  "AC-138: Given an unknown name or a relative command / When open_mcp_server runs or the daemon starts / Then NOT_FOUND is returned and startup is refused with a reason",
  TIMEOUT,
  async () => {
    // Given: a config that defines only "fake"
    const stack = await startHostedMcpStack();
    try {
      // When: open an undefined name
      const response = await rawRpc(
        stack.daemon.socketPath,
        "open_mcp_server",
        {
          name: "nope",
        },
      );
      stack.observe("rpc:open_mcp_server:unknown", response);

      // Then: NOT_FOUND, and the server is not started
      expect(response.error?.message).toBe("NOT_FOUND");
      expect(readServerLog(stack.serverLog)).toBeUndefined();
    } finally {
      await stopHostedMcpStack(stack);
    }

    // Given: a config with command = "node" (relative)
    const scratch = fs.mkdtempSync(
      path.join(os.tmpdir(), "tegata-mcp-reject-"),
    );
    try {
      const exit = await runApiProxyDaemonUntilExit({
        entries: defaultEntries(throwawayCanaries()),
        apiProxies: [],
        extraToml: renderMcpServers([
          fakeServerSpec(path.join(scratch, "received.jsonl"), {
            command: "node",
          }),
        ]),
      });

      // Then: startup is rejected, and stderr states the reason for the command
      expect(
        exit.code,
        `daemon kept running; stderr: ${exit.stderr}`,
      ).not.toBeNull();
      expect(exit.code).not.toBe(0);
      expect(exit.stderr).toMatch(/command/i);
      expect(exit.stderr).toMatch(/absolute|relative|"node"|`node`/i);
    } finally {
      fs.rmSync(scratch, { recursive: true, force: true });
    }
  },
);

test(
  "AC-139: Given an approve_cmd that records its environment and exits 1 / When open_mcp_server {name: fake} runs / Then APPROVAL_DENIED is returned, the record carries the method and mcp:fake, and the server never starts",
  TIMEOUT,
  async () => {
    // Given: an approve_cmd that writes its env to a file and exits 1
    const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "tegata-mcp-hitl-"));
    const envFile = path.join(scratch, "approve-env.txt");
    const stack = await startHostedMcpStack({
      top: { approveCmd: `env > ${envFile}; exit 1` },
    });
    try {
      // When: call open_mcp_server
      const response = await rawRpc(
        stack.daemon.socketPath,
        "open_mcp_server",
        {
          name: "fake",
        },
      );
      stack.observe("rpc:open_mcp_server:denied", response);

      // Then: APPROVAL_DENIED, and only the reference is passed to the approval command
      expect(response.error?.message).toBe("APPROVAL_DENIED");
      const env = fs.readFileSync(envFile, "utf8");
      stack.observe("mcp-hosting-approve-env", env);
      expect(env).toContain("TEGATA_METHOD=open_mcp_server");
      expect(env).toContain("TEGATA_TARGET_URL=mcp:fake");
      expect(env).not.toContain(stack.canaries.password);

      // Then: the fake server was not started (no startup record) and there is no lease
      await sleep(1_000);
      expect(readServerLog(stack.serverLog)).toBeUndefined();
      expect(await leaseCount(stack.daemon.socketPath)).toBe(0);
    } finally {
      await stopHostedMcpStack(stack);
      fs.rmSync(scratch, { recursive: true, force: true });
    }
  },
);

test(
  "AC-140: Given an open_mcp_server reply / When a connection with a wrong stream secret is followed by two with the right one / Then the first and third are closed, the second is relayed, and the server only receives the second's request",
  TIMEOUT,
  async () => {
    // Given: the open_mcp_server response (session_id, port, stream_secret)
    const stack = await startHostedMcpStack();
    let sessionId: string | undefined;
    const sockets: StreamExchange[] = [];
    try {
      const opened = await rawRpc(stack.daemon.socketPath, "open_mcp_server", {
        name: "fake",
      });
      stack.observe("rpc:open_mcp_server", opened);
      expect(opened.error, JSON.stringify(opened.error)).toBeUndefined();
      const session = opened.result as Partial<OpenMcpServer>;
      expect(typeof session.session_id).toBe("string");
      expect(Number.isInteger(session.port)).toBe(true);
      expect(session.stream_secret).toMatch(/^[A-Za-z0-9_-]{22,}$/);
      sessionId = session.session_id as string;
      const { port, stream_secret: secret } = session as OpenMcpServer;

      // When: the first connection sends a line with a wrong secret and a request
      let wrongSecret = randomBytes(16).toString("base64url");
      while (wrongSecret === secret)
        wrongSecret = randomBytes(16).toString("base64url");
      const first = await streamExchange(
        port,
        `${wrongSecret}\n${initializeLine("first")}`,
      );
      sockets.push(first);

      // When: the second connection sends a line with the correct secret and an initialize request
      const second = await streamExchange(
        port,
        `${secret}\n${initializeLine("second")}`,
        { waitFor: (lines) => lines.length > 0, timeoutMs: 10_000 },
      );
      sockets.push(second);

      // When: with the second connection still open, a third connects with the correct secret too
      const third = await streamExchange(
        port,
        `${secret}\n${initializeLine("third")}`,
      );
      sockets.push(third);

      // Then: the first and third are disconnected without a response, and only the second is
      // relayed
      expect(first.closed).toBe(true);
      expect(first.lines).toEqual([]);
      expect(third.closed).toBe(true);
      expect(third.lines).toEqual([]);
      expect(second.closed).toBe(false);
      expect(responseIds(second)).toEqual(["second"]);
      stack.observe("stream:second", second.lines);

      // Then: the only request the fake server received is the second connection's
      await sleep(500);
      const ids = receivedRequests(stack.serverLog)
        .filter((request) => request.id !== undefined)
        .map((request) => request.id);
      expect(ids).toEqual(["second"]);
    } finally {
      for (const exchange of sockets) exchange.socket.destroy();
      if (sessionId !== undefined)
        await rawRpc(stack.daemon.socketPath, "disconnect", {
          session_id: sessionId,
        }).catch(() => {});
      await stopHostedMcpStack(stack);
    }
  },
);
