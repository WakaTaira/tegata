import { randomUUID } from "node:crypto";
import { createServer } from "node:net";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "vitest";
import { loginHandler } from "./index.js";

const endpoint = "ws://127.0.0.1:9001/devtools/browser/abc";
const originalSocket = process.env.TEGATA_SOCKET;
const originalBridge = process.env.TEGATA_BRIDGE;

afterEach(() => {
  if (originalSocket === undefined) delete process.env.TEGATA_SOCKET;
  else process.env.TEGATA_SOCKET = originalSocket;
  if (originalBridge === undefined) delete process.env.TEGATA_BRIDGE;
  else process.env.TEGATA_BRIDGE = originalBridge;
});

async function startFakeServer(bridgeError = false) {
  const socketPath = join(process.cwd(), `.tegata-mcp-${randomUUID()}.sock`);
  let loginCompleted = false;
  const server = createServer((socket) => {
    let data = "";
    socket.on("data", (chunk) => {
      data += chunk.toString();
      const lineEnd = data.indexOf("\n");
      if (lineEnd === -1) return;
      const request = JSON.parse(data.slice(0, lineEnd)) as {
        method: string;
        params?: unknown;
      };
      if (!loginCompleted) {
        expect(request.method).toBe("login");
        loginCompleted = true;
      } else {
        expect(request.method).toBe("bridge_open_tunnel");
        expect(request.params).toEqual({ session_id: "s1", port: 9001 });
      }
      const response =
        request.method === "login"
          ? {
              jsonrpc: "2.0",
              id: 1,
              result: { session_id: "s1", channel: { kind: "cdp", endpoint } },
            }
          : bridgeError
            ? {
                jsonrpc: "2.0",
                id: 1,
                error: { code: -32000, message: "FORBIDDEN" },
              }
            : { jsonrpc: "2.0", id: 1, result: { local_port: 4242 } };
      socket.write(`${JSON.stringify(response)}\n`);
    });
  });
  await new Promise<void>((resolve) => server.listen(socketPath, resolve));
  process.env.TEGATA_SOCKET = socketPath;
  return { server, socketPath };
}

async function stopFakeServer(server: ReturnType<typeof createServer>) {
  await new Promise<void>((resolve, reject) =>
    server.close((error) => (error ? reject(error) : resolve())),
  );
}

describe.sequential("login bridge", () => {
  test("rewrites the endpoint through the bridge", async () => {
    const fake = await startFakeServer();
    process.env.TEGATA_BRIDGE = "1";
    try {
      const result = await loginHandler({});
      expect(result).toEqual({
        content: [
          {
            type: "text",
            text: JSON.stringify({
              session_id: "s1",
              channel: {
                kind: "cdp",
                endpoint: "ws://127.0.0.1:4242/devtools/browser/abc",
              },
            }),
          },
        ],
      });
    } finally {
      await stopFakeServer(fake.server);
    }
  });

  test("returns the bridge error code through existing error handling", async () => {
    const fake = await startFakeServer(true);
    process.env.TEGATA_BRIDGE = "1";
    try {
      const result = await loginHandler({});
      expect(result).toEqual({
        isError: true,
        content: [{ type: "text", text: "INTERNAL" }],
      });
    } finally {
      await stopFakeServer(fake.server);
    }
  });

  test("preserves the endpoint when bridge mode is disabled", async () => {
    const fake = await startFakeServer();
    delete process.env.TEGATA_BRIDGE;
    try {
      const result = await loginHandler({});
      expect(result).toEqual({
        content: [
          {
            type: "text",
            text: JSON.stringify({
              session_id: "s1",
              channel: { kind: "cdp", endpoint },
            }),
          },
        ],
      });
    } finally {
      await stopFakeServer(fake.server);
    }
  });
});
