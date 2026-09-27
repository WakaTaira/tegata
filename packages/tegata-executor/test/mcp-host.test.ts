import { existsSync, readFileSync, statSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, test } from "vitest";
import {
  formatExecutorErrorLine,
  formatMcpServerEvent,
  parseRequest,
} from "../src/index.js";
import {
  createStreamSecret,
  LineInspector,
  MCP_MAX_LINE_BYTES,
  type McpServerEvent,
  McpServerStartError,
  startMcpServer,
} from "../src/mcp-host.js";

const FAKE_SERVER = fileURLToPath(
  new URL("./fixtures/fake-mcp-server.mjs", import.meta.url),
);
const TOKEN = "tok-3f9a1c7e-secret-value";

const cleanups: Array<() => Promise<void>> = [];

afterEach(async () => {
  while (cleanups.length > 0) await cleanups.pop()?.();
});

async function waitFor(
  predicate: () => boolean,
  timeoutMs = 5_000,
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() > deadline) throw new Error("condition was not met");
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
}

function processExists(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

type Started = {
  port: number;
  secret: string;
  events: McpServerEvent[];
  logPath: string;
  close: () => Promise<void>;
};

async function start(mode = "serve"): Promise<Started> {
  const logDir = await mkdtemp(path.join(os.tmpdir(), "tegata-mcp-test-"));
  const logPath = path.join(logDir, "received.log");
  const secret = createStreamSecret();
  const events: McpServerEvent[] = [];
  const host = await startMcpServer({
    command: process.execPath,
    args: [FAKE_SERVER, mode],
    env: { TOKEN, LOG: logPath },
    scan: [TOKEN],
    streamSecret: secret,
    onEvent: (event) => events.push(event),
  });
  cleanups.push(async () => {
    await host.close();
    await rm(logDir, { recursive: true, force: true });
  });
  return { port: host.port, secret, events, logPath, close: host.close };
}

type Client = {
  socket: net.Socket;
  received: () => string;
  closed: Promise<void>;
  isClosed: () => boolean;
  lines: () => string[];
};

async function connect(port: number, first?: string): Promise<Client> {
  const socket = net.connect(port, "127.0.0.1");
  socket.on("error", () => undefined);
  await new Promise<void>((resolve, reject) => {
    socket.once("connect", () => resolve());
    socket.once("error", reject);
  });
  let data = "";
  let closedFlag = false;
  socket.setEncoding("utf8");
  socket.on("data", (chunk: string) => {
    data += chunk;
  });
  const closed = new Promise<void>((resolve) =>
    socket.once("close", () => {
      closedFlag = true;
      resolve();
    }),
  );
  if (first !== undefined) socket.write(first);
  cleanups.push(async () => {
    socket.destroy();
  });
  return {
    socket,
    received: () => data,
    closed,
    isClosed: () => closedFlag,
    lines: () => data.split("\n").filter((line) => line !== ""),
  };
}

function readLog(logPath: string): string {
  return existsSync(logPath) ? readFileSync(logPath, "utf8") : "";
}

describe("mcp_server request parsing", () => {
  const base = {
    op: "mcp_server_start",
    id: 7,
    command: "/usr/bin/server",
    args: ["--stdio"],
    env: { API_KEY: "value" },
    scan: ["value"],
  };

  test("accepts a start request", () => {
    expect(parseRequest(JSON.stringify(base))).toEqual(base);
  });

  test("accepts a stop request", () => {
    expect(
      parseRequest(JSON.stringify({ op: "mcp_server_stop", id: 8 })),
    ).toEqual({ op: "mcp_server_stop", id: 8 });
  });

  test.each([
    ["a relative command", { command: "node" }],
    ["a missing command", { command: undefined }],
    ["non-string args", { args: [1] }],
    ["missing args", { args: undefined }],
    ["an env array", { env: ["x"] }],
    ["a non-string env value", { env: { A: 1 } }],
    ["an env name with '='", { env: { "A=B": "x" } }],
    ["an empty env name", { env: { "": "x" } }],
    ["an env value with NUL", { env: { A: "x\u0000y" } }],
    ["an argument with NUL", { args: ["x\u0000y"] }],
    ["missing scan", { scan: undefined }],
    ["non-string scan", { scan: [null] }],
  ])("rejects %s with the request id", (_label, override) => {
    expect(() =>
      parseRequest(JSON.stringify({ ...base, ...override })),
    ).toThrow(expect.objectContaining({ id: 7 }));
  });
});

describe("mcp_server events and diagnostics", () => {
  test("formats each event without secrets", () => {
    expect(formatMcpServerEvent({ action: "connected" })).toEqual({
      event: "mcp_server",
      action: "connected",
    });
    expect(formatMcpServerEvent({ action: "exit", exit_code: null })).toEqual({
      event: "mcp_server",
      action: "exit",
      exit_code: null,
    });
    expect(formatMcpServerEvent({ action: "leak" })).toEqual({
      event: "mcp_server",
      action: "leak",
    });
  });

  test("redacts env values, scan values, and the stream secret", () => {
    const request = {
      op: "mcp_server_start" as const,
      command: "/usr/bin/server",
      args: [],
      env: { API_KEY: "env-secret" },
      scan: ["scan-secret"],
    };
    const line = formatExecutorErrorLine(
      request,
      "mcp_server",
      "INTERNAL",
      new Error("env-secret scan-secret stream-secret"),
      ["stream-secret"],
    );
    expect(line).not.toContain("env-secret");
    expect(line).not.toContain("scan-secret");
    expect(line).not.toContain("stream-secret");
    expect(line).toContain('"op":"mcp_server_start"');
  });
});

describe("LineInspector", () => {
  test("returns complete lines and holds an incomplete line", () => {
    const inspector = new LineInspector(["secret"]);
    const first = inspector.push(Buffer.from('{"a":1}\n{"b"'));
    expect(first.leaked).toBe(false);
    expect(first.lines.map(String)).toEqual(['{"a":1}\n']);
    const second = inspector.push(Buffer.from(":2}\n"));
    expect(second.lines.map(String)).toEqual(['{"b":2}\n']);
  });

  test("detects a value split across chunks within one line", () => {
    const inspector = new LineInspector(["secret"]);
    expect(inspector.push(Buffer.from('{"v":"sec')).leaked).toBe(false);
    const result = inspector.push(Buffer.from('ret"}\n'));
    expect(result).toEqual({ lines: [], leaked: true });
  });

  test("drops safe lines of the same chunk once a leak is found", () => {
    const inspector = new LineInspector(["secret"]);
    const result = inspector.push(Buffer.from("safe\nsecret\nafter\n"));
    expect(result).toEqual({ lines: [], leaked: true });
    expect(inspector.push(Buffer.from("more\n"))).toEqual({
      lines: [],
      leaked: true,
    });
  });

  test("detects a value in its JSON-escaped form", () => {
    const value = 'pa"ss\\word';
    const inspector = new LineInspector([value]);
    const line = `${JSON.stringify({ result: value })}\n`;
    expect(line).not.toContain(value);
    expect(inspector.push(Buffer.from(line))).toEqual({
      lines: [],
      leaked: true,
    });
  });

  test("ignores empty scan values", () => {
    const inspector = new LineInspector(["", "secret"]);
    expect(inspector.push(Buffer.from("plain\n")).lines.map(String)).toEqual([
      "plain\n",
    ]);
  });

  test("accepts a line of exactly the limit and rejects a longer one", () => {
    const exact = new LineInspector(["secret"]);
    const line = Buffer.alloc(MCP_MAX_LINE_BYTES, 0x61);
    expect(exact.push(line).leaked).toBe(false);
    expect(exact.push(Buffer.from("\n")).lines[0].length).toBe(
      MCP_MAX_LINE_BYTES + 1,
    );

    const incomplete = new LineInspector(["secret"]);
    expect(incomplete.push(line).leaked).toBe(false);
    expect(incomplete.push(Buffer.from("a")).leaked).toBe(true);

    const complete = new LineInspector(["secret"]);
    expect(complete.push(Buffer.concat([line, Buffer.from("a\n")]))).toEqual({
      lines: [],
      leaked: true,
    });
  });
});

describe("startMcpServer", () => {
  test("rejects a server that exits during startup", async () => {
    await expect(
      startMcpServer({
        command: process.execPath,
        args: [FAKE_SERVER, "early-exit"],
        env: {},
        scan: [],
        streamSecret: createStreamSecret(),
        onEvent: () => undefined,
      }),
    ).rejects.toBeInstanceOf(McpServerStartError);
  });

  test("rejects a command that cannot be spawned without echoing env values", async () => {
    const error = await startMcpServer({
      command: path.join(os.tmpdir(), "tegata-missing-mcp-server"),
      args: [],
      env: { TOKEN },
      scan: [TOKEN],
      streamSecret: createStreamSecret(),
      onEvent: () => undefined,
    }).catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(McpServerStartError);
    expect(String((error as Error).message)).not.toContain(TOKEN);
  });

  test("relays an authenticated connection in an isolated environment", async () => {
    const server = await start();
    const client = await connect(server.port, `${server.secret}\n`);
    await waitFor(() => server.events.length === 1);
    expect(server.events).toEqual([{ action: "connected" }]);

    client.socket.write("echo hello\nenv\npid\n");
    await waitFor(() => client.lines().length === 3);
    const [echo, envLine, pidLine] = client.lines();
    expect(echo).toBe("echo hello");
    const env = JSON.parse(envLine) as {
      keys: string[];
      home: string;
      cwd: string;
      path: string | null;
    };
    expect(env.keys.filter((key) => key !== "PATH")).toEqual([
      "HOME",
      "LOG",
      "TOKEN",
    ]);
    expect(env.path).toBe(process.env.PATH ?? null);
    expect(env.cwd).toBe(env.home);
    expect(path.dirname(env.home)).toBe(os.tmpdir());
    if (process.platform !== "win32") {
      expect(statSync(env.home).mode & 0o777).toBe(0o700);
    }

    const pid = Number(pidLine);
    await server.close();
    expect(processExists(pid)).toBe(false);
    expect(existsSync(env.home)).toBe(false);
    await client.closed;
    expect(server.events).toEqual([{ action: "connected" }]);
  });

  test("forwards bytes sent in the same packet as the secret line", async () => {
    const server = await start();
    const client = await connect(server.port, `${server.secret}\necho same\n`);
    await waitFor(() => client.lines().length === 1);
    expect(client.lines()).toEqual(["echo same"]);
  });

  test("cuts a wrong secret and every connection after the first valid one", async () => {
    const server = await start();
    const wrong = await connect(server.port, "wrong-secret\necho wrong\n");
    await wrong.closed;

    const second = await connect(server.port, `${server.secret}\n`);
    await waitFor(() => server.events.length === 1);
    const third = await connect(server.port, `${server.secret}\necho third\n`);
    await third.closed;

    second.socket.write("echo second\n");
    await waitFor(() => second.lines().length === 1);
    expect(second.lines()).toEqual(["echo second"]);
    expect(wrong.received()).toBe("");
    expect(third.received()).toBe("");
    expect(readLog(server.logPath)).toBe("echo second\n");
    expect(server.events).toEqual([{ action: "connected" }]);
  });

  test("cuts an oversized secret line", async () => {
    const server = await start();
    const client = await connect(server.port, "x".repeat(300));
    await client.closed;
    expect(readLog(server.logPath)).toBe("");
    expect(server.events).toEqual([]);
  });

  test("cuts a connection that does not send the secret in time", async () => {
    const server = await start();
    const client = await connect(server.port);
    const startedAt = Date.now();
    await client.closed;
    expect(Date.now() - startedAt).toBeGreaterThanOrEqual(4_500);

    const valid = await connect(server.port, `${server.secret}\necho late\n`);
    await waitFor(() => valid.lines().length === 1);
    expect(valid.lines()).toEqual(["echo late"]);
  }, 15_000);

  test("blocks a leaking line, stops the server, and reports only leak", async () => {
    const server = await start();
    const client = await connect(server.port, `${server.secret}\npid\n`);
    await waitFor(() => client.lines().length === 1);
    const pid = Number(client.lines()[0]);

    client.socket.write("leak\n");
    await client.closed;
    await waitFor(() => server.events.length === 2);
    expect(server.events).toEqual([
      { action: "connected" },
      { action: "leak" },
    ]);
    expect(processExists(pid)).toBe(false);
    expect(client.received()).not.toContain(TOKEN);
    await new Promise((resolve) => setTimeout(resolve, 200));
    expect(server.events).toHaveLength(2);
  });

  test("detects a value written across separate chunks", async () => {
    const server = await start();
    const client = await connect(server.port, `${server.secret}\nsplit\n`);
    await client.closed;
    await waitFor(() => server.events.length === 2);
    expect(server.events[1]).toEqual({ action: "leak" });
    expect(client.received()).toBe("");
  });

  test("treats a line over the limit as a leak", async () => {
    const server = await start();
    const client = await connect(server.port, `${server.secret}\nbig\n`);
    await client.closed;
    await waitFor(() => server.events.length === 2);
    expect(server.events[1]).toEqual({ action: "leak" });
    expect(client.received()).toBe("");
  });

  test("reports the exit code when the server exits by itself", async () => {
    const server = await start();
    const client = await connect(
      server.port,
      `${server.secret}\necho before\nexit 3\n`,
    );
    await client.closed;
    await waitFor(() => server.events.length === 2);
    expect(server.events).toEqual([
      { action: "connected" },
      { action: "exit", exit_code: 3 },
    ]);
    expect(client.lines()).toEqual(["echo before"]);
    await expect(connect(server.port)).rejects.toThrow();
  });

  test("discards an incomplete line when the server exits", async () => {
    const server = await start();
    const client = await connect(
      server.port,
      `${server.secret}\npartial-exit\n`,
    );
    await client.closed;
    await waitFor(() => server.events.length === 2);
    expect(server.events[1]).toEqual({ action: "exit", exit_code: 0 });
    expect(client.received()).toBe("");
  });

  test("closes the server stdin when the connection ends", async () => {
    const server = await start();
    const client = await connect(server.port, `${server.secret}\n`);
    await waitFor(() => server.events.length === 1);
    client.socket.end();
    await waitFor(() => server.events.length === 2);
    expect(server.events[1]).toEqual({ action: "exit", exit_code: 0 });
  });

  test("reports an exit that happens before any connection", async () => {
    const server = await start("exit-later");
    await waitFor(() => server.events.length === 1);
    expect(server.events).toEqual([{ action: "exit", exit_code: 4 }]);
  });

  test("escalates to SIGKILL for a server that ignores SIGTERM", async () => {
    const server = await start("stubborn");
    const client = await connect(server.port, `${server.secret}\npid\n`);
    await waitFor(() => client.lines().length === 1);
    const pid = Number(client.lines()[0]);

    const startedAt = Date.now();
    await server.close();
    if (process.platform !== "win32") {
      expect(Date.now() - startedAt).toBeGreaterThanOrEqual(1_900);
    }
    expect(processExists(pid)).toBe(false);
    await client.closed;
    expect(server.events).toEqual([{ action: "connected" }]);
  }, 10_000);
});
