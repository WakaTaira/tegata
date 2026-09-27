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

/** ランナーを閉じ、その stderr を leak guard の観測面へ加える。 */
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
    // Given: 資格 mock:site の password を TOKEN に入れる偽サーバー "fake"
    const stack = await startHostedMcpStack();
    let runner: RunnerSession | undefined;
    try {
      // When: ランナーを通常の stdio MCP サーバーとして起動し whoami を呼ぶ
      runner = await startRunner(stack);
      const whoami = await runner.callTool("whoami");

      // Then: 結果は password の sha256 で、password そのものは現れない
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
    // Given: AC-135 と同じセッション
    const stack = await startHostedMcpStack();
    let runner: RunnerSession | undefined;
    try {
      runner = await startRunner(stack);
      const whoami = await runner.callTool("whoami");
      expect(whoami.isError, whoami.text).toBe(false);

      // When: TOKEN をそのまま出力するツールを呼ぶ
      let callError: unknown;
      try {
        const leaked = await runner.callTool("leak", {}, 10_000);
        stack.observe("runner:leak-result", leaked);
      } catch (error) {
        callError = error;
      }

      // Then: 応答は届かずクライアントはエラーとなり、ランナーは終了する
      expect(callError, "leak returned a response").toBeDefined();
      stack.observe("runner:leak-error", String(callError));
      expect(await settlesWithin(runner.exited, 10_000)).toBe(true);
      stack.observe("runner:stderr", runner.stderr());
      expect(String(callError)).not.toContain(stack.canaries.password);
      expect(runner.stderr()).not.toContain(stack.canaries.password);

      // Then: 監査に mcp_server の leak イベントが残り、password は含まれない
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

      // Then: テストが観測できる全ての面で password が 0 件である
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
    // Given: AC-135 と同じセッションで、pid ツールから子プロセスの pid を得る
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

      // When: クライアントを閉じ、ランナーの stdin を閉じる
      await closeRunner(stack, runner);
      runner = undefined;

      // Then: 5 秒以内にサーバーのプロセスが消え、リースが 0 になる
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
    // Given: "fake" だけを定義した config
    const stack = await startHostedMcpStack();
    try {
      // When: 未定義の name を開く
      const response = await rawRpc(
        stack.daemon.socketPath,
        "open_mcp_server",
        {
          name: "nope",
        },
      );
      stack.observe("rpc:open_mcp_server:unknown", response);

      // Then: NOT_FOUND で、サーバーは起動されない
      expect(response.error?.message).toBe("NOT_FOUND");
      expect(readServerLog(stack.serverLog)).toBeUndefined();
    } finally {
      await stopHostedMcpStack(stack);
    }

    // Given: command = "node"（相対）の config
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

      // Then: 起動は拒否され、stderr に command の理由が出る
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
    // Given: env をファイルへ書いて exit 1 する approve_cmd
    const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "tegata-mcp-hitl-"));
    const envFile = path.join(scratch, "approve-env.txt");
    const stack = await startHostedMcpStack({
      top: { approveCmd: `env > ${envFile}; exit 1` },
    });
    try {
      // When: open_mcp_server を呼ぶ
      const response = await rawRpc(
        stack.daemon.socketPath,
        "open_mcp_server",
        {
          name: "fake",
        },
      );
      stack.observe("rpc:open_mcp_server:denied", response);

      // Then: APPROVAL_DENIED で、承認コマンドに参照だけが渡る
      expect(response.error?.message).toBe("APPROVAL_DENIED");
      const env = fs.readFileSync(envFile, "utf8");
      stack.observe("mcp-hosting-approve-env", env);
      expect(env).toContain("TEGATA_METHOD=open_mcp_server");
      expect(env).toContain("TEGATA_TARGET_URL=mcp:fake");
      expect(env).not.toContain(stack.canaries.password);

      // Then: 偽サーバーは起動されておらず（起動記録が無い）、リースも無い
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
    // Given: open_mcp_server の応答（session_id・port・stream_secret）
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

      // When: 1 本目は誤った secret の行と要求を送る
      let wrongSecret = randomBytes(16).toString("base64url");
      while (wrongSecret === secret)
        wrongSecret = randomBytes(16).toString("base64url");
      const first = await streamExchange(
        port,
        `${wrongSecret}\n${initializeLine("first")}`,
      );
      sockets.push(first);

      // When: 2 本目は正しい secret の行と initialize 要求を送る
      const second = await streamExchange(
        port,
        `${secret}\n${initializeLine("second")}`,
        { waitFor: (lines) => lines.length > 0, timeoutMs: 10_000 },
      );
      sockets.push(second);

      // When: 2 本目を開いたまま、3 本目も正しい secret で接続する
      const third = await streamExchange(
        port,
        `${secret}\n${initializeLine("third")}`,
      );
      sockets.push(third);

      // Then: 1 本目と 3 本目は応答なしで切断され、2 本目だけが中継される
      expect(first.closed).toBe(true);
      expect(first.lines).toEqual([]);
      expect(third.closed).toBe(true);
      expect(third.lines).toEqual([]);
      expect(second.closed).toBe(false);
      expect(responseIds(second)).toEqual(["second"]);
      stack.observe("stream:second", second.lines);

      // Then: 偽サーバーが受け取った要求は 2 本目のものだけである
      await sleep(500);
      const ids = receivedRequests(stack.serverLog)
        .filter((request) => request.id !== undefined)
        .map((request) => request.id);
      expect(ids).toEqual(["second"]);
    } finally {
      for (const exchange of sockets) exchange.socket.destroy();
      if (sessionId !== undefined)
        await rawRpc(stack.daemon.socketPath, "logout", {
          session_id: sessionId,
        }).catch(() => {});
      await stopHostedMcpStack(stack);
    }
  },
);
