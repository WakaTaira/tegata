// AC-116 — a worker target must not bring down the executor guard.

import { expect, test } from "vitest";
import { fixtureSteps, rawRpc } from "./support/harness.js";
import { type LoginResult, sleep } from "./support/phase4.js";
import { type Stack, startStack, stopStack } from "./support/stack.js";

class CdpClient {
  private readonly ws: WebSocket;
  private nextId = 1;
  private readonly pending = new Map<
    number,
    (message: {
      result?: Record<string, unknown>;
      error?: { message?: string };
    }) => void
  >();

  private constructor(ws: WebSocket) {
    this.ws = ws;
    this.ws.onmessage = (event) => {
      const message = JSON.parse(event.data as string) as {
        id?: number;
        result?: Record<string, unknown>;
        error?: { message?: string };
      };
      if (message.id === undefined) return;
      this.pending.get(message.id)?.(message);
      this.pending.delete(message.id);
    };
  }

  static async connect(endpoint: string): Promise<CdpClient> {
    const ws = new WebSocket(endpoint);
    await new Promise<void>((resolve, reject) => {
      ws.onopen = () => resolve();
      ws.onerror = () => reject(new Error("CDP websocket failed to open"));
    });
    return new CdpClient(ws);
  }

  send(
    method: string,
    params: Record<string, unknown> = {},
    sessionId?: string,
  ): Promise<Record<string, unknown>> {
    return new Promise((resolve, reject) => {
      const id = this.nextId++;
      this.pending.set(id, (message) => {
        if (message.error !== undefined) {
          reject(new Error(`${method}: ${message.error.message ?? "failed"}`));
        } else {
          resolve(message.result ?? {});
        }
      });
      this.ws.send(JSON.stringify({ id, method, params, sessionId }));
    });
  }

  close(): void {
    this.ws.close();
  }
}

async function login(stack: Stack): Promise<LoginResult> {
  const response = await stack.mcp.callTool("login", {
    cred_id: "mock:site",
    target_url: `${stack.fixture.url}/with-worker/`,
    ...fixtureSteps(),
  });
  expect(response.isError, `login failed: ${response.text}`).toBe(false);
  return response.json as LoginResult;
}

async function expectExecutorAlive(stack: Stack, label: string): Promise<void> {
  const status = await rawRpc(stack.daemon.socketPath, "status", {});
  stack.guard.observe(label, status);
  expect(status.result).toEqual({ ok: true, browsers: 1, leases: 1 });
}

async function waitForWorker(
  client: CdpClient,
  sessionId: string,
): Promise<void> {
  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline) {
    const evaluated = await client.send(
      "Runtime.evaluate",
      {
        expression: "document.body?.dataset.workerReady === 'true'",
        returnByValue: true,
      },
      sessionId,
    );
    if ((evaluated.result as { value?: unknown }).value === true) return;
    await sleep(100);
  }
  throw new Error("the dedicated worker did not start");
}

test("AC-116: a worker page keeps the logged-in executor alive", async () => {
  // Given: a login on a page that starts a dedicated worker and registers a
  // service worker while the executor guard is attached
  const stack = await startStack();
  let client: CdpClient | undefined;
  try {
    const result = await login(stack);
    await sleep(2_000);
    await expectExecutorAlive(stack, "rpc:status:after-login");

    // When: the agent navigates the logged-in tab to a worker page again
    client = await CdpClient.connect(result.channel.endpoint);
    const { targetInfos } = await client.send("Target.getTargets");
    const pageTarget = (
      targetInfos as Array<{ targetId: string; type: string; url: string }>
    ).find(
      (target) =>
        target.type === "page" && target.url.startsWith(stack.fixture.url),
    );
    if (pageTarget === undefined)
      throw new Error("logged-in page target not found");
    const { sessionId } = await client.send("Target.attachToTarget", {
      targetId: pageTarget.targetId,
      flatten: true,
    });
    await client.send(
      "Page.navigate",
      { url: `${stack.fixture.url}/with-worker/` },
      sessionId as string,
    );
    await waitForWorker(client, sessionId as string);
    await sleep(3_000);

    // Then: the executor and its browser survive, and the session still
    // serves the logged-in page
    await expectExecutorAlive(stack, "rpc:status:after-worker");
    const evaluated = await client.send(
      "Runtime.evaluate",
      {
        expression: "document.querySelector('#welcome') !== null",
        returnByValue: true,
      },
      sessionId as string,
    );
    expect((evaluated.result as { value?: unknown }).value).toBe(true);
  } finally {
    client?.close();
    await stopStack(stack);
  }
});
