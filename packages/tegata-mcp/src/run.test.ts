import { randomUUID } from "node:crypto";
import { createServer, createServer as createTcpServer } from "node:net";
import { join } from "node:path";
import { PassThrough, Writable } from "node:stream";
import { afterEach, describe, expect, test } from "vitest";
import { run } from "./run.js";

/** 書き込みを同期的に文字列へ蓄積する Writable。'data' イベントの非同期性を避けるために使う。 */
class CapturingWritable extends Writable {
  text = "";
  override _write(
    chunk: Buffer,
    _encoding: BufferEncoding,
    callback: (error?: Error | null) => void,
  ) {
    this.text += chunk.toString();
    callback();
  }
}

const originalSocket = process.env.TEGATA_SOCKET;
const originalBridge = process.env.TEGATA_BRIDGE;

afterEach(() => {
  if (originalSocket === undefined) delete process.env.TEGATA_SOCKET;
  else process.env.TEGATA_SOCKET = originalSocket;
  if (originalBridge === undefined) delete process.env.TEGATA_BRIDGE;
  else process.env.TEGATA_BRIDGE = originalBridge;
});

/** テスト用のストリーム三つ組。stdout / stderr は書き込まれたテキストを蓄積する。
 * stderr は run.ts から write() のみ呼ばれるため、Writable の非同期な仕組みを介さない
 * 最小限のモックにして、書き込みを即座に観測できるようにする。 */
function fakeStreams() {
  const stdin = new PassThrough();
  const stdout = new CapturingWritable();
  let stderrText = "";
  const stderr = {
    write: (chunk: string) => {
      stderrText += chunk;
      return true;
    },
  } as unknown as NodeJS.WritableStream;
  return {
    streams: { stdin, stdout, stderr },
    stdin,
    get stdoutText() {
      return stdout.text;
    },
    get stderrText() {
      return stderrText;
    },
  };
}

/** open_mcp_server（と、指定すれば logout / bridge_open_tunnel）に応答する偽デーモン。 */
async function startFakeDaemon(
  openResult: unknown,
  extra: (method: string, params: unknown) => unknown = () => ({ ok: true }),
) {
  const socketPath = join(process.cwd(), `.tegata-mcp-${randomUUID()}.sock`);
  const calls: { method: string; params: unknown }[] = [];
  const server = createServer((socket) => {
    let data = "";
    socket.on("data", (chunk) => {
      data += chunk.toString();
      const lineEnd = data.indexOf("\n");
      if (lineEnd === -1) return;
      const request = JSON.parse(data.slice(0, lineEnd)) as {
        id: number;
        method: string;
        params?: unknown;
      };
      calls.push({ method: request.method, params: request.params });
      const result =
        request.method === "open_mcp_server"
          ? openResult
          : extra(request.method, request.params);
      const response =
        result !== null && typeof result === "object" && "error" in result
          ? {
              jsonrpc: "2.0",
              id: request.id,
              error: (result as { error: unknown }).error,
            }
          : { jsonrpc: "2.0", id: request.id, result };
      socket.write(`${JSON.stringify(response)}\n`);
    });
  });
  await new Promise<void>((resolve) => server.listen(socketPath, resolve));
  process.env.TEGATA_SOCKET = socketPath;
  return {
    calls,
    async stop() {
      await new Promise<void>((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      );
    },
  };
}

describe("run", () => {
  test("fails with INTERNAL when no name is given", async () => {
    const fake = fakeStreams();
    const exitCode = await run(undefined, fake.streams);
    expect(exitCode).toBe(1);
    expect(fake.stderrText).toBe("INTERNAL\n");
  });

  test("fails with INTERNAL when TEGATA_SOCKET is unset", async () => {
    delete process.env.TEGATA_SOCKET;
    const fake = fakeStreams();
    const exitCode = await run("fake", fake.streams);
    expect(exitCode).toBe(1);
    expect(fake.stderrText).toBe("INTERNAL\n");
  });

  test("passes through the daemon's error classification code", async () => {
    const daemon = await startFakeDaemon({ error: { message: "NOT_FOUND" } });
    try {
      const fake = fakeStreams();
      const exitCode = await run("nope", fake.streams);
      expect(exitCode).toBe(1);
      expect(fake.stderrText).toBe("NOT_FOUND\n");
      expect(daemon.calls).toEqual([
        { method: "open_mcp_server", params: { name: "nope" } },
      ]);
    } finally {
      await daemon.stop();
    }
  });

  test("sends the stream secret first, then relays and logs out on stdin EOF", async () => {
    const secret = "sekret-line";
    const tcpServer = createTcpServer();
    let firstLine = "";
    const connected = new Promise<void>((resolve) => {
      tcpServer.on("connection", (socket) => {
        let data = "";
        socket.on("data", (chunk) => {
          data += chunk.toString();
          const lineEnd = data.indexOf("\n");
          if (lineEnd !== -1 && firstLine === "") {
            firstLine = data.slice(0, lineEnd);
            resolve();
          }
        });
      });
    });
    await new Promise<void>((resolve) =>
      tcpServer.listen(0, "127.0.0.1", resolve),
    );
    const address = tcpServer.address();
    if (address === null || typeof address === "string") {
      throw new Error("expected a TCP address");
    }

    const daemon = await startFakeDaemon({
      session_id: "s1",
      port: address.port,
      stream_secret: secret,
    });
    try {
      const { streams, stdin } = fakeStreams();
      const runPromise = run("fake", streams);
      await connected;
      expect(firstLine).toBe(secret);
      stdin.end();
      const exitCode = await runPromise;
      expect(exitCode).toBe(0);
      expect(daemon.calls).toEqual([
        { method: "open_mcp_server", params: { name: "fake" } },
        { method: "logout", params: { session_id: "s1" } },
      ]);
    } finally {
      await daemon.stop();
      await new Promise<void>((resolve) => tcpServer.close(() => resolve()));
    }
  });

  test("tunnels through the bridge when TEGATA_BRIDGE=1", async () => {
    const secret = "bridged-secret";
    const tcpServer = createTcpServer();
    let firstLine = "";
    const connected = new Promise<void>((resolve) => {
      tcpServer.on("connection", (socket) => {
        let data = "";
        socket.on("data", (chunk) => {
          data += chunk.toString();
          const lineEnd = data.indexOf("\n");
          if (lineEnd !== -1 && firstLine === "") {
            firstLine = data.slice(0, lineEnd);
            resolve();
          }
        });
      });
    });
    await new Promise<void>((resolve) =>
      tcpServer.listen(0, "127.0.0.1", resolve),
    );
    const address = tcpServer.address();
    if (address === null || typeof address === "string") {
      throw new Error("expected a TCP address");
    }

    const daemon = await startFakeDaemon(
      { session_id: "s2", port: 9999, stream_secret: secret },
      (method) =>
        method === "bridge_open_tunnel"
          ? { local_port: address.port }
          : { ok: true },
    );
    process.env.TEGATA_BRIDGE = "1";
    try {
      const { streams, stdin } = fakeStreams();
      const runPromise = run("fake", streams);
      await connected;
      expect(firstLine).toBe(secret);
      stdin.end();
      const exitCode = await runPromise;
      expect(exitCode).toBe(0);
      expect(daemon.calls).toEqual([
        { method: "open_mcp_server", params: { name: "fake" } },
        {
          method: "bridge_open_tunnel",
          params: { session_id: "s2", port: 9999 },
        },
        { method: "logout", params: { session_id: "s2" } },
      ]);
    } finally {
      await daemon.stop();
      await new Promise<void>((resolve) => tcpServer.close(() => resolve()));
    }
  });
});
