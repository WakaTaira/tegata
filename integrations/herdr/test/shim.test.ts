import { type ChildProcess, spawn } from "node:child_process";
import { createServer, type Server } from "node:http";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  type Browser,
  type BrowserContext,
  chromium,
  type Page,
} from "playwright-core";
import { afterEach, beforeEach, describe, expect, test } from "vitest";

type CdpMessage = {
  id?: number;
  method?: string;
  params?: Record<string, unknown>;
  sessionId?: string;
  result?: Record<string, unknown>;
  error?: Record<string, unknown>;
};

type CdpSocket = {
  readyState: number;
  send(data: string): void;
  close(): void;
  addEventListener(
    type: string,
    listener: (event: { data?: unknown }) => void,
  ): void;
};

const HERDR_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SHIM_PATH = join(HERDR_ROOT, "src", "shim.ts");

class CdpClient {
  private socket: CdpSocket | null = null;
  private nextId = 1;
  private readonly pending = new Map<number, (message: CdpMessage) => void>();
  private readonly history: CdpMessage[] = [];
  private readonly listeners = new Set<(message: CdpMessage) => void>();

  async connect(endpoint: string): Promise<void> {
    await new Promise<void>((resolve, reject) => {
      let opened = false;
      const socket = new globalThis.WebSocket(endpoint) as unknown as CdpSocket;
      this.socket = socket;
      socket.addEventListener("open", () => {
        opened = true;
        resolve();
      });
      socket.addEventListener("message", (event) => {
        const message = JSON.parse(String(event.data)) as CdpMessage;
        this.history.push(message);
        if (typeof message.id === "number") {
          const resolvePending = this.pending.get(message.id);
          if (resolvePending) {
            this.pending.delete(message.id);
            resolvePending(message);
          }
        }
        for (const listener of this.listeners) {
          listener(message);
        }
      });
      socket.addEventListener("error", () => {
        if (!opened) {
          reject(new Error("CDP WebSocket connection failed"));
        }
      });
      socket.addEventListener("close", () => {
        if (!opened) {
          reject(new Error("CDP WebSocket closed during connection"));
        }
      });
    });
  }

  send(
    method: string,
    params: Record<string, unknown> = {},
    sessionId?: string,
  ): Promise<CdpMessage> {
    const socket = this.socket;
    if (socket?.readyState !== 1) {
      throw new Error("CDP WebSocket is not open");
    }
    const id = this.nextId;
    this.nextId += 1;
    const message = { id, method, params, ...(sessionId ? { sessionId } : {}) };
    const response = new Promise<CdpMessage>((resolve) =>
      this.pending.set(id, resolve),
    );
    socket.send(JSON.stringify(message));
    return response;
  }

  onMessage(listener: (message: CdpMessage) => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  async waitForEvent(
    predicate: (message: CdpMessage) => boolean,
    timeoutMs = 5_000,
  ): Promise<CdpMessage> {
    const old = this.history.find(predicate);
    if (old) {
      return old;
    }
    return await new Promise((resolve, reject) => {
      let timer: ReturnType<typeof setTimeout>;
      const listener = (message: CdpMessage) => {
        if (!predicate(message)) {
          return;
        }
        clearTimeout(timer);
        this.listeners.delete(listener);
        resolve(message);
      };
      timer = setTimeout(() => {
        this.listeners.delete(listener);
        reject(new Error("timed out waiting for CDP event"));
      }, timeoutMs);
      this.listeners.add(listener);
    });
  }

  close(): void {
    this.socket?.close();
  }
}

type Fixture = {
  server: Server;
  origin: string;
  browser: Browser;
  context: BrowserContext;
  loginPage: Page;
  loginTargetId: string;
  contextId: string;
  endpoint: string;
};

describe("tegata Herdr shim", () => {
  let fixture: Fixture | null = null;
  let shim: ChildProcess | null = null;
  let plugin: CdpClient | null = null;
  let upstream: CdpClient | null = null;

  beforeEach(async () => {
    fixture = await startFixture();
  });

  afterEach(async () => {
    plugin?.close();
    upstream?.close();
    await stopChild(shim);
    if (fixture) {
      await fixture.browser.close().catch(() => {});
      await closeServer(fixture.server);
    }
    fixture = null;
    shim = null;
    plugin = null;
    upstream = null;
  });

  test("serves the browser discovery endpoint and isolates targets by context", async () => {
    const current = requireFixture(fixture);
    const shimPort = await freePort();
    shim = spawnShim(current.endpoint, current.loginTargetId, shimPort);
    const version = await waitForJson(
      `http://127.0.0.1:${shimPort}/json/version`,
      shim,
    );
    expect(version.webSocketDebuggerUrl).toBe(
      `ws://127.0.0.1:${shimPort}/devtools/browser/tegata-shim`,
    );
    await expect(
      fetch(`http://127.0.0.1:${shimPort}/json/list`).then((response) =>
        response.json(),
      ),
    ).resolves.toEqual([]);

    plugin = new CdpClient();
    await plugin.connect(version.webSocketDebuggerUrl as string);
    upstream = new CdpClient();
    await upstream.connect(current.endpoint);
    await plugin.send("Target.setDiscoverTargets", { discover: true });
    const targetEvents = pluginMessages(plugin, "Target.targetCreated");

    const created = await plugin.send("Target.createTarget", {
      url: `${current.origin}/page`,
    });
    const createdTargetId = stringField(created.result?.targetId);
    expect(createdTargetId).toBeTruthy();
    const shimInfo = await plugin.send("Target.getTargetInfo", {
      targetId: createdTargetId,
    });
    expect(shimInfo.result?.targetInfo).toMatchObject({
      browserContextId: current.contextId,
    });
    const upstreamInfo = await upstream.send("Target.getTargetInfo", {
      targetId: createdTargetId,
    });
    expect(upstreamInfo.result?.targetInfo).toMatchObject({
      browserContextId: current.contextId,
    });

    const attached = await plugin.send("Target.attachToTarget", {
      targetId: createdTargetId,
      flatten: true,
    });
    const sessionId = stringField(attached.result?.sessionId);
    expect(sessionId).toBeTruthy();
    await plugin.send("Page.enable", {}, sessionId);
    await plugin.send("Runtime.enable", {}, sessionId);
    await plugin.send(
      "Page.navigate",
      { url: `${current.origin}/page` },
      sessionId,
    );
    await plugin.waitForEvent(
      (message) =>
        message.method === "Page.loadEventFired" &&
        message.sessionId === sessionId,
    );
    const cookie = await plugin.send(
      "Runtime.evaluate",
      { expression: "document.cookie" },
      sessionId,
    );
    expect(cookie.result?.result).toMatchObject({
      value: "tegata_session=logged-in",
    });

    await plugin.send(
      "Page.navigate",
      { url: `${current.origin}/large` },
      sessionId,
    );
    await plugin.waitForEvent(
      (message) =>
        message.method === "Page.loadEventFired" &&
        message.sessionId === sessionId,
    );
    const screenshot = await plugin.send(
      "Page.captureScreenshot",
      { format: "png" },
      sessionId,
    );
    const screenshotData = stringField(screenshot.result?.data);
    expect(screenshotData).toBeTruthy();
    expect(screenshotData?.length).toBeGreaterThan(65_535);

    const loginClose = await plugin.send("Target.closeTarget", {
      targetId: current.loginTargetId,
    });
    expect(loginClose.error).toMatchObject({
      code: -32601,
      message: "blocked by tegata-herdr shim",
    });
    const browserClose = await plugin.send("Browser.close");
    expect(browserClose.error).toMatchObject({
      code: -32601,
      message: "blocked by tegata-herdr shim",
    });
    const contextDispose = await plugin.send("Target.disposeBrowserContext", {
      browserContextId: current.contextId,
    });
    expect(contextDispose.error).toMatchObject({
      code: -32601,
      message: "blocked by tegata-herdr shim",
    });
    await expect(current.loginPage.title()).resolves.toBe("tegata-login");

    const defaultPage = await current.browser.newPage();
    await defaultPage.goto(`${current.origin}/page`);
    const defaultInfo = await defaultPage
      .context()
      .newCDPSession(defaultPage)
      .then((session) => session.send("Target.getTargetInfo"));
    await new Promise((resolve) => setTimeout(resolve, 150));
    expect(
      targetEvents.some(
        (message) =>
          stringField(message.params?.targetInfo?.targetId) ===
          defaultInfo.targetInfo.targetId,
      ),
    ).toBe(false);

    const createdClose = await plugin.send("Target.closeTarget", {
      targetId: createdTargetId,
    });
    expect(createdClose.result).toMatchObject({ success: true });
    await waitUntil(async () => {
      const response = await upstream?.send("Target.getTargetInfo", {
        targetId: createdTargetId,
      });
      return Boolean(response?.error);
    });
  });

  test("keeps the session alive after SIGTERM and exits when the upstream closes", async () => {
    const current = requireFixture(fixture);
    const firstPort = await freePort();
    shim = spawnShim(current.endpoint, current.loginTargetId, firstPort);
    await waitForJson(`http://127.0.0.1:${firstPort}/json/version`, shim);
    const startedAt = Date.now();
    shim.kill("SIGTERM");
    await waitForChildExit(shim, 1_500);
    expect(Date.now() - startedAt).toBeLessThanOrEqual(1_500);
    await expect(current.loginPage.title()).resolves.toBe("tegata-login");

    const secondPort = await freePort();
    shim = spawnShim(current.endpoint, current.loginTargetId, secondPort);
    await waitForJson(`http://127.0.0.1:${secondPort}/json/version`, shim);
    await current.browser.close();
    await waitForChildExit(shim, 1_500);
  });
});

async function startFixture(): Promise<Fixture> {
  const server = createServer((request, response) => {
    const url = new URL(request.url ?? "/", "http://127.0.0.1");
    response.setHeader("content-type", "text/html; charset=utf-8");
    if (url.pathname === "/large") {
      response.end(largePage());
      return;
    }
    response.end(
      "<html><head><title>tegata-login</title></head><body>login</body></html>",
    );
  });
  const fixturePort = await listenServer(server);
  const origin = `http://127.0.0.1:${fixturePort}`;
  const upstreamPort = await freePort();
  const browser = await chromium.launch({
    headless: true,
    args: [`--remote-debugging-port=${upstreamPort}`],
  });
  const context = await browser.newContext();
  const loginPage = await context.newPage();
  await loginPage.goto(`${origin}/page`);
  await context.addCookies([
    { name: "tegata_session", value: "logged-in", url: origin },
  ]);
  await loginPage.reload();
  const targetInfo = await loginPage
    .context()
    .newCDPSession(loginPage)
    .then((session) => session.send("Target.getTargetInfo"));
  const endpoint = await waitForBrowserEndpoint(upstreamPort);
  const loginTargetId = stringField(targetInfo.targetInfo?.targetId);
  const contextId = stringField(targetInfo.targetInfo?.browserContextId);
  if (!loginTargetId || !contextId) {
    await browser.close();
    await closeServer(server);
    throw new Error(
      "Playwright did not return a non-default browser context target",
    );
  }
  return {
    server,
    origin,
    browser,
    context,
    loginPage,
    loginTargetId,
    contextId,
    endpoint,
  };
}

function spawnShim(
  endpoint: string,
  targetId: string,
  port: number,
): ChildProcess {
  return spawn(
    process.execPath,
    [SHIM_PATH, `--remote-debugging-port=${port}`],
    {
      env: {
        ...process.env,
        TEGATA_HERDR_ENDPOINT: endpoint,
        TEGATA_HERDR_TARGET_ID: targetId,
      },
      stdio: ["ignore", "ignore", "pipe"],
    },
  );
}

async function waitForBrowserEndpoint(port: number): Promise<string> {
  const version = await waitForJson(`http://127.0.0.1:${port}/json/version`);
  const endpoint = stringField(version.webSocketDebuggerUrl);
  if (!endpoint) {
    throw new Error("Chromium did not expose a CDP endpoint");
  }
  return endpoint;
}

async function waitForJson(
  url: string,
  child?: ChildProcess,
): Promise<Record<string, unknown>> {
  const started = Date.now();
  while (Date.now() - started < 10_000) {
    if (child?.exitCode !== null && child?.exitCode !== undefined) {
      throw new Error(`shim exited early with code ${child.exitCode}`);
    }
    try {
      const response = await fetch(url);
      if (response.ok) {
        return (await response.json()) as Record<string, unknown>;
      }
    } catch {
      // ローカル endpoint の起動を待ちます。
    }
    await sleep(50);
  }
  throw new Error(`timed out waiting for ${url}`);
}

async function waitForChildExit(
  child: ChildProcess | null,
  timeoutMs: number,
): Promise<void> {
  if (!child) {
    return;
  }
  if (child.exitCode !== null || child.signalCode !== null) {
    return;
  }
  await new Promise<void>((resolve, reject) => {
    let timer: ReturnType<typeof setTimeout>;
    const onExit = () => {
      clearTimeout(timer);
      resolve();
    };
    timer = setTimeout(() => {
      child.off("exit", onExit);
      reject(new Error(`child did not exit within ${timeoutMs} ms`));
    }, timeoutMs);
    child.once("exit", onExit);
  });
}

async function stopChild(child: ChildProcess | null): Promise<void> {
  if (!child || child.exitCode !== null || child.signalCode !== null) {
    return;
  }
  child.kill("SIGTERM");
  await waitForChildExit(child, 1_500).catch(() => child.kill("SIGKILL"));
}

function pluginMessages(client: CdpClient, method: string): CdpMessage[] {
  const messages: CdpMessage[] = [];
  client.onMessage((message) => {
    if (message.method === method) {
      messages.push(message);
    }
  });
  return messages;
}

async function waitUntil(
  predicate: () => Promise<boolean>,
  timeoutMs = 5_000,
): Promise<void> {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    if (await predicate()) {
      return;
    }
    await sleep(50);
  }
  throw new Error("condition did not become true");
}

function requireFixture(value: Fixture | null): Fixture {
  if (!value) {
    throw new Error("fixture was not initialized");
  }
  return value;
}

async function freePort(): Promise<number> {
  const server = createServer();
  const port = await listenServer(server, 0);
  await closeServer(server);
  return port;
}

function listenServer(server: Server, port = 0): Promise<number> {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", () => {
      const address = server.address();
      if (!address || typeof address === "string") {
        reject(new Error("server did not receive a TCP address"));
        return;
      }
      resolve(address.port);
    });
  });
}

function closeServer(server: Server): Promise<void> {
  return new Promise((resolve) => server.close(() => resolve()));
}

function largePage(): string {
  return `<!doctype html>
<html><body><canvas id="canvas" width="1200" height="800"></canvas>
<script>
const canvas = document.getElementById("canvas");
const context = canvas.getContext("2d");
const image = context.createImageData(canvas.width, canvas.height);
let value = 17;
for (let index = 0; index < image.data.length; index += 4) {
  value = (value * 1664525 + 1013904223) >>> 0;
  image.data[index] = value & 255;
  image.data[index + 1] = (value >>> 8) & 255;
  image.data[index + 2] = (value >>> 16) & 255;
  image.data[index + 3] = 255;
}
context.putImageData(image, 0, 0);
</script></body></html>`;
}

function stringField(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
