import {
  createServer,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from "node:http";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

import {
  type ServerWebSocket,
  SOCKET_CLOSE_GRACE_MS,
  WebSocketServer,
} from "./ws.ts";

type JsonObject = Record<string, unknown>;

export type CdpMessage = {
  id?: string | number;
  method?: string;
  params?: JsonObject;
  sessionId?: string;
  result?: unknown;
  error?: JsonObject;
  [key: string]: unknown;
};

type PendingProxyRequest = {
  clientId: string | number;
  method: string;
  sessionId?: string;
};

export type TargetInfo = JsonObject & {
  targetId?: string;
  browserContextId?: string;
};

type UpstreamSocket = {
  readyState: number;
  send(data: string): void;
  close(): void;
  addEventListener(
    type: string,
    listener: (event: { data?: unknown }) => void,
  ): void;
};

const BROWSER_METHODS = new Set([
  "Target.setDiscoverTargets",
  "Target.createTarget",
  "Target.attachToTarget",
  "Target.closeTarget",
  "Target.getTargetInfo",
]);

const SESSION_METHODS = new Set([
  "Page.enable",
  "Runtime.enable",
  "Log.enable",
  "Page.bringToFront",
  "Emulation.setDeviceMetricsOverride",
  "Emulation.setPageScaleFactor",
  "Page.startScreencast",
  "Page.screencastFrameAck",
  "Page.stopScreencast",
  "Input.dispatchMouseEvent",
  "Input.dispatchKeyEvent",
  "Input.insertText",
  "Page.navigate",
  "Page.reload",
  "Page.stopLoading",
  "Page.getNavigationHistory",
  "Page.navigateToHistoryEntry",
  "Runtime.evaluate",
  "Page.captureScreenshot",
]);

const TARGET_EVENT_METHODS = new Set([
  "Target.targetCreated",
  "Target.targetInfoChanged",
  "Target.targetDestroyed",
  "Target.targetCrashed",
  "Target.attachedToTarget",
  "Target.detachedFromTarget",
]);

const STARTUP_TIMEOUT_MS = 10_000;

export function shouldForwardUpstreamResponse(
  message: CdpMessage,
  pending: ReadonlyMap<number, unknown>,
): boolean {
  if (message.id === undefined) {
    return true;
  }
  return typeof message.id === "number" && pending.has(message.id);
}

export function shouldForwardTargetEvent(
  message: CdpMessage,
  contextId: string,
  loginTargetId: string,
  shimTargets: ReadonlySet<string>,
  targetInfos: ReadonlyMap<string, TargetInfo>,
  attachedSessions: ReadonlySet<string>,
): boolean {
  const method = message.method;
  if (!method || !TARGET_EVENT_METHODS.has(method)) {
    return false;
  }
  const params = isRecord(message.params) ? message.params : {};
  if (method === "Target.targetCrashed") {
    const targetId = stringField(params.targetId);
    return (
      targetId === loginTargetId ||
      (targetId !== null && shimTargets.has(targetId))
    );
  }
  if (
    method === "Target.attachedToTarget" ||
    method === "Target.detachedFromTarget"
  ) {
    const sessionId = stringField(params.sessionId);
    return sessionId !== null && attachedSessions.has(sessionId);
  }
  if (method === "Target.targetDestroyed") {
    const targetId = stringField(params.targetId);
    if (!targetId) {
      return false;
    }
    return (
      targetId === loginTargetId ||
      shimTargets.has(targetId) ||
      targetInfos.get(targetId)?.browserContextId === contextId
    );
  }

  const targetInfo = isRecord(params.targetInfo)
    ? (params.targetInfo as TargetInfo)
    : null;
  const targetId = targetInfo ? stringField(targetInfo.targetId) : null;
  const previous = targetId ? targetInfos.get(targetId) : undefined;
  const eventContextId =
    stringField(targetInfo?.browserContextId) ?? previous?.browserContextId;
  return Boolean(targetId && eventContextId === contextId);
}

class UpstreamConnection {
  private readonly endpoint: string;
  private socket: UpstreamSocket | null = null;
  private nextId = 1;
  private readonly pending = new Map<
    number,
    { resolve: (message: CdpMessage) => void; reject: (error: Error) => void }
  >();
  private messageHandler: ((message: CdpMessage) => void) | null = null;
  private closeHandler: (() => void) | null = null;
  private closeNotified = false;
  private forceCloseTimer: ReturnType<typeof setTimeout> | null = null;

  constructor(endpoint: string) {
    this.endpoint = endpoint;
  }

  onMessage(handler: (message: CdpMessage) => void): void {
    this.messageHandler = handler;
  }

  onClose(handler: () => void): void {
    this.closeHandler = handler;
  }

  async connect(): Promise<void> {
    await new Promise<void>((resolve, reject) => {
      let opened = false;
      let settled = false;
      let socket: UpstreamSocket;
      try {
        socket = new globalThis.WebSocket(
          this.endpoint,
        ) as unknown as UpstreamSocket;
      } catch (error) {
        reject(error instanceof Error ? error : new Error(String(error)));
        return;
      }
      this.socket = socket;

      const failBeforeOpen = (error: Error) => {
        if (!settled) {
          settled = true;
          reject(error);
        }
      };

      socket.addEventListener("open", () => {
        opened = true;
        if (!settled) {
          settled = true;
          resolve();
        }
      });
      socket.addEventListener("message", (event) => this.receive(event.data));
      socket.addEventListener("error", () => {
        if (!opened) {
          failBeforeOpen(
            new Error("failed to connect to the tegata CDP endpoint"),
          );
        }
      });
      socket.addEventListener("close", () => {
        this.handleClose();
        if (!opened) {
          failBeforeOpen(
            new Error("the tegata CDP endpoint closed during startup"),
          );
        }
      });
    });
  }

  allocateId(): number {
    const id = this.nextId;
    this.nextId += 1;
    return id;
  }

  send(message: CdpMessage): void {
    if (this.socket?.readyState !== 1) {
      throw new Error("the tegata CDP endpoint is not connected");
    }
    this.socket.send(JSON.stringify(message));
  }

  request(method: string, params: JsonObject): Promise<CdpMessage> {
    const id = this.allocateId();
    const promise = new Promise<CdpMessage>((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
    });
    try {
      this.send({ id, method, params });
    } catch (error) {
      this.pending.delete(id);
      throw error;
    }
    return promise;
  }

  close(): void {
    if (!this.socket || this.socket.readyState >= 2) {
      this.handleClose();
      return;
    }
    this.socket.close();
  }

  forceClose(): void {
    if (!this.socket || this.socket.readyState >= 2) {
      this.handleClose();
      return;
    }
    try {
      this.socket.close();
    } catch {
      this.handleClose();
      return;
    }
    this.forceCloseTimer = setTimeout(() => {
      this.forceCloseTimer = null;
      try {
        this.socket?.close();
      } catch {
        // 上流 socket が既に破棄されている場合は処理を継続します。
      }
      this.handleClose();
    }, SOCKET_CLOSE_GRACE_MS);
  }

  private receive(data: unknown): void {
    let message: CdpMessage;
    try {
      const parsed = JSON.parse(messageText(data)) as unknown;
      if (!isRecord(parsed)) {
        throw new Error("CDP message is not an object");
      }
      message = parsed as CdpMessage;
    } catch (error) {
      this.messageHandler?.({
        method: "__tegata_shim_protocol_error",
        params: {
          message: error instanceof Error ? error.message : String(error),
        },
      });
      return;
    }

    if (typeof message.id === "number") {
      const pending = this.pending.get(message.id);
      if (pending) {
        this.pending.delete(message.id);
        pending.resolve(message);
        return;
      }
    }
    this.messageHandler?.(message);
  }

  private handleClose(): void {
    if (this.closeNotified) {
      return;
    }
    if (this.forceCloseTimer) {
      clearTimeout(this.forceCloseTimer);
      this.forceCloseTimer = null;
    }
    this.closeNotified = true;
    const error = new Error("the tegata CDP endpoint closed");
    for (const pending of this.pending.values()) {
      pending.reject(error);
    }
    this.pending.clear();
    this.closeHandler?.();
  }
}

class ShimRuntime {
  private readonly upstream: UpstreamConnection;
  private readonly port: number;
  private readonly endpoint: string;
  private readonly contextId: string;
  private readonly loginTargetId: string;
  private readonly webSockets = new WebSocketServer((connection) =>
    this.acceptPlugin(connection),
  );
  private readonly targetInfos = new Map<string, TargetInfo>();
  private readonly shimTargets = new Set<string>();
  private readonly attachedSessions = new Set<string>();
  private readonly pending = new Map<number, PendingProxyRequest>();
  private httpServer: Server | null = null;
  private pluginConnection: ServerWebSocket | null = null;
  private stopping = false;
  private stopped = false;
  private shutdownCode = 0;
  private readonly stoppedPromise: Promise<number>;
  private resolveStopped!: (code: number) => void;

  constructor(
    upstream: UpstreamConnection,
    port: number,
    endpoint: string,
    contextId: string,
    loginTargetId: string,
  ) {
    this.upstream = upstream;
    this.port = port;
    this.endpoint = endpoint;
    this.contextId = contextId;
    this.loginTargetId = loginTargetId;
    this.targetInfos.set(loginTargetId, {
      targetId: loginTargetId,
      browserContextId: contextId,
    });
    this.stoppedPromise = new Promise<number>((resolve) => {
      this.resolveStopped = resolve;
    });
    upstream.onMessage((message) => this.handleUpstreamMessage(message));
    upstream.onClose(() => void this.shutdown("session ended"));
  }

  async start(): Promise<void> {
    const server = createServer((request, response) => {
      void this.handleHttpRequest(request, response);
    });
    server.on("upgrade", (request, socket, head) => {
      try {
        this.webSockets.handleUpgrade(request, socket, head);
      } catch {
        socket.destroy();
      }
    });
    this.httpServer = server;

    await new Promise<void>((resolve, reject) => {
      const onError = (error: Error) => {
        server.off("error", onError);
        reject(error);
      };
      server.once("error", onError);
      server.listen(this.port, "127.0.0.1", () => {
        server.off("error", onError);
        resolve();
      });
    });
  }

  waitForExit(): Promise<number> {
    return this.stoppedPromise;
  }

  shutdown(reason = "shim shutting down", code = 0): void {
    if (this.stopping) {
      return;
    }
    this.stopping = true;
    this.shutdownCode = code;
    this.pending.clear();
    this.attachedSessions.clear();
    this.webSockets.close(1000, reason);
    this.upstream.forceClose();

    const server = this.httpServer;
    if (!server) {
      this.finishShutdown();
      return;
    }
    server.close(() => this.finishShutdown());
  }

  private acceptPlugin(connection: ServerWebSocket): void {
    if (this.pluginConnection) {
      connection.close(1008, "only one plugin connection is allowed");
      return;
    }
    this.pluginConnection = connection;
    connection.onMessage((text) => this.handlePluginMessage(connection, text));
    connection.onClose(() => {
      if (this.pluginConnection === connection) {
        this.pluginConnection = null;
        this.pending.clear();
        this.attachedSessions.clear();
      }
    });
  }

  private async handleHttpRequest(
    request: IncomingMessage,
    response: ServerResponse,
  ): Promise<void> {
    const requestUrl = new URL(
      request.url ?? "/",
      `http://127.0.0.1:${this.port}`,
    );
    if (request.method !== "GET") {
      response.statusCode = 404;
      response.end();
      return;
    }

    if (requestUrl.pathname === "/json/version") {
      const version = await this.readUpstreamVersion();
      writeJson(response, {
        ...version,
        webSocketDebuggerUrl: this.webSocketUrl(),
      });
      return;
    }
    if (
      requestUrl.pathname === "/json" ||
      requestUrl.pathname === "/json/list"
    ) {
      writeJson(response, []);
      return;
    }
    response.statusCode = 404;
    response.end();
  }

  private async readUpstreamVersion(): Promise<JsonObject> {
    try {
      const response = await fetch(
        `${upstreamHttpBase(this.endpoint)}/json/version`,
      );
      if (response.ok) {
        const body = (await response.json()) as unknown;
        if (isRecord(body)) {
          return body;
        }
      }
    } catch {
      // 上流の HTTP endpoint が利用できない場合は shim の固定値を返します。
    }
    return { Browser: "tegata-shim", "Protocol-Version": "1.3" };
  }

  private handlePluginMessage(connection: ServerWebSocket, text: string): void {
    if (connection !== this.pluginConnection || this.stopping) {
      return;
    }

    let message: CdpMessage;
    try {
      const parsed = JSON.parse(text) as unknown;
      if (!isRecord(parsed)) {
        throw new Error("CDP message is not an object");
      }
      message = parsed as CdpMessage;
    } catch {
      this.sendBlocked(connection, {}, "invalid CDP message");
      return;
    }

    const method = message.method;
    if (
      typeof method !== "string" ||
      (typeof message.id !== "number" && typeof message.id !== "string")
    ) {
      this.sendBlocked(connection, message, "invalid CDP request");
      return;
    }

    const hasSession = typeof message.sessionId === "string";
    if (
      hasSession ? !SESSION_METHODS.has(method) : SESSION_METHODS.has(method)
    ) {
      this.sendBlocked(connection, message, "invalid CDP session");
      return;
    }
    if (!BROWSER_METHODS.has(method) && !SESSION_METHODS.has(method)) {
      this.sendBlocked(connection, message, "method is not allowed");
      return;
    }
    if (hasSession && !this.attachedSessions.has(message.sessionId as string)) {
      this.sendBlocked(connection, message, "session is not attached");
      return;
    }

    const params = isRecord(message.params) ? message.params : {};
    if (method === "Target.createTarget") {
      message.params = { ...params, browserContextId: this.contextId };
    } else if (method === "Target.closeTarget") {
      const targetId = stringField(params.targetId);
      if (!targetId || !this.shimTargets.has(targetId)) {
        this.sendBlocked(
          connection,
          message,
          "target is not owned by the shim",
        );
        return;
      }
    } else if (
      method === "Target.attachToTarget" ||
      method === "Target.getTargetInfo"
    ) {
      const targetId = stringField(params.targetId);
      if (!targetId || !this.isAllowedTarget(targetId)) {
        this.sendBlocked(
          connection,
          message,
          "target is outside the tegata context",
        );
        return;
      }
    }

    const upstreamId = this.upstream.allocateId();
    this.pending.set(upstreamId, {
      clientId: message.id,
      method,
      ...(hasSession ? { sessionId: message.sessionId } : {}),
    });
    try {
      this.upstream.send({ ...message, id: upstreamId });
    } catch {
      this.pending.delete(upstreamId);
      this.sendBlocked(
        connection,
        message,
        "upstream CDP endpoint is unavailable",
      );
    }
  }

  private handleUpstreamMessage(message: CdpMessage): void {
    if (this.stopping) {
      return;
    }

    if (message.id !== undefined) {
      if (!shouldForwardUpstreamResponse(message, this.pending)) {
        return;
      }
      const pending = this.pending.get(message.id as number);
      if (!pending) {
        return;
      }
      this.pending.delete(message.id as number);
      this.recordResponse(pending, message);
      this.sendToPlugin({ ...message, id: pending.clientId });
      return;
    }

    if (message.sessionId && !this.attachedSessions.has(message.sessionId)) {
      return;
    }
    if (!message.sessionId) {
      if (
        typeof message.method !== "string" ||
        !TARGET_EVENT_METHODS.has(message.method) ||
        !this.allowTargetEvent(message)
      ) {
        return;
      }
    }
    this.sendToPlugin(message);
  }

  private recordResponse(
    pending: PendingProxyRequest,
    message: CdpMessage,
  ): void {
    if (message.error || !isRecord(message.result)) {
      return;
    }
    if (pending.method === "Target.createTarget") {
      const targetId = stringField(message.result.targetId);
      if (targetId) {
        this.shimTargets.add(targetId);
        this.targetInfos.set(targetId, {
          targetId,
          browserContextId: this.contextId,
        });
      }
    } else if (pending.method === "Target.attachToTarget") {
      const sessionId = stringField(message.result.sessionId);
      if (sessionId) {
        this.attachedSessions.add(sessionId);
      }
    } else if (pending.method === "Target.getTargetInfo") {
      const targetInfo = isRecord(message.result.targetInfo)
        ? (message.result.targetInfo as TargetInfo)
        : null;
      const targetId = targetInfo ? stringField(targetInfo.targetId) : null;
      if (
        targetId &&
        stringField(targetInfo?.browserContextId) === this.contextId
      ) {
        this.targetInfos.set(targetId, targetInfo);
      }
    }
  }

  private allowTargetEvent(message: CdpMessage): boolean {
    if (
      !shouldForwardTargetEvent(
        message,
        this.contextId,
        this.loginTargetId,
        this.shimTargets,
        this.targetInfos,
        this.attachedSessions,
      )
    ) {
      return false;
    }

    const params = isRecord(message.params) ? message.params : {};
    if (message.method === "Target.targetDestroyed") {
      const targetId = stringField(params.targetId);
      if (targetId) {
        this.targetInfos.delete(targetId);
        this.shimTargets.delete(targetId);
      }
    } else if (
      message.method === "Target.targetCreated" ||
      message.method === "Target.targetInfoChanged"
    ) {
      const targetInfo = isRecord(params.targetInfo)
        ? (params.targetInfo as TargetInfo)
        : null;
      const targetId = targetInfo ? stringField(targetInfo.targetId) : null;
      const previous = targetId ? this.targetInfos.get(targetId) : undefined;
      const eventContextId =
        stringField(targetInfo?.browserContextId) ?? previous?.browserContextId;
      if (targetId && eventContextId) {
        this.targetInfos.set(targetId, {
          ...previous,
          ...targetInfo,
          targetId,
          browserContextId: eventContextId,
        });
      }
    } else if (message.method === "Target.detachedFromTarget") {
      const sessionId = stringField(params.sessionId);
      if (sessionId) {
        this.attachedSessions.delete(sessionId);
      }
    }
    return true;
  }

  private isAllowedTarget(targetId: string): boolean {
    if (targetId === this.loginTargetId || this.shimTargets.has(targetId)) {
      return true;
    }
    return this.targetInfos.get(targetId)?.browserContextId === this.contextId;
  }

  private sendBlocked(
    connection: ServerWebSocket,
    message: CdpMessage,
    reason: string,
  ): void {
    console.error(
      `tegata-herdr shim: blocked ${message.method ?? "unknown method"} (${reason})`,
    );
    const response: CdpMessage = {
      id: message.id,
      error: { code: -32601, message: "blocked by tegata-herdr shim" },
    };
    if (message.sessionId) {
      response.sessionId = message.sessionId;
    }
    connection.sendText(JSON.stringify(response));
  }

  private sendToPlugin(message: CdpMessage): void {
    if (this.pluginConnection?.readyState === "open") {
      this.pluginConnection.sendText(JSON.stringify(message));
    }
  }

  private webSocketUrl(): string {
    return `ws://127.0.0.1:${this.port}/devtools/browser/tegata-shim`;
  }

  private finishShutdown(): void {
    if (this.stopped) {
      return;
    }
    this.stopped = true;
    this.resolveStopped(this.shutdownCode);
  }
}

async function main(): Promise<number> {
  const initialParentPid = process.ppid;
  const endpoint = process.env.TEGATA_HERDR_ENDPOINT?.trim();
  const targetId = process.env.TEGATA_HERDR_TARGET_ID?.trim();
  let upstream: UpstreamConnection | null = null;
  let runtime: ShimRuntime | null = null;
  const parentWatch = setInterval(() => {
    if (process.ppid === 1 || process.ppid !== initialParentPid) {
      if (runtime) {
        runtime.shutdown("parent process exited");
      } else {
        upstream?.forceClose();
        process.exit(0);
      }
    }
  }, 1_000);
  parentWatch.unref();

  const shutdownOnSignal = () => {
    if (runtime) {
      runtime.shutdown();
    } else {
      upstream?.forceClose();
      process.exit(0);
    }
  };
  process.once("SIGTERM", shutdownOnSignal);
  process.once("SIGINT", shutdownOnSignal);

  try {
    let valid = true;
    if (!endpoint) {
      console.error("TEGATA_HERDR_ENDPOINT is required");
      valid = false;
    }
    if (!targetId) {
      console.error("TEGATA_HERDR_TARGET_ID is required");
      valid = false;
    }
    if (!valid) {
      return 1;
    }

    const port = parseRemoteDebuggingPort(process.argv.slice(2));
    if (port === null) {
      console.error("--remote-debugging-port must be a valid TCP port");
      return 1;
    }
    if (!isWebSocketEndpoint(endpoint)) {
      console.error("TEGATA_HERDR_ENDPOINT must be a ws:// or wss:// URL");
      return 1;
    }

    const connection = new UpstreamConnection(endpoint);
    upstream = connection;
    const response = await withTimeout(
      (async () => {
        await connection.connect();
        return await connection.request("Target.getTargetInfo", {
          targetId,
        });
      })(),
      STARTUP_TIMEOUT_MS,
      "timed out starting the tegata Herdr shim",
    );
    const result = isRecord(response.result) ? response.result : null;
    const targetInfo =
      result && isRecord(result.targetInfo)
        ? (result.targetInfo as TargetInfo)
        : null;
    const contextId = targetInfo
      ? stringField(targetInfo.browserContextId)
      : null;
    if (response.error || !contextId) {
      throw new Error("Target.getTargetInfo did not return a browser context");
    }

    const candidate = new ShimRuntime(
      upstream,
      port,
      endpoint,
      contextId,
      targetId,
    );
    await candidate.start();
    runtime = candidate;
    return await runtime.waitForExit();
  } catch (error) {
    upstream?.forceClose();
    console.error(
      `tegata-herdr shim: startup failed: ${error instanceof Error ? error.message : String(error)}`,
    );
    return 1;
  } finally {
    clearInterval(parentWatch);
    process.removeListener("SIGTERM", shutdownOnSignal);
    process.removeListener("SIGINT", shutdownOnSignal);
  }
}

function withTimeout<T>(
  promise: Promise<T>,
  timeoutMs: number,
  message: string,
): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(message)), timeoutMs);
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (error: unknown) => {
        clearTimeout(timer);
        reject(error);
      },
    );
  });
}

function parseRemoteDebuggingPort(args: string[]): number | null {
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    const value = arg.startsWith("--remote-debugging-port=")
      ? arg.slice("--remote-debugging-port=".length)
      : arg === "--remote-debugging-port"
        ? args[index + 1]
        : null;
    if (value !== null && value !== undefined) {
      const port = Number(value);
      return Number.isInteger(port) && port >= 1 && port <= 65_535
        ? port
        : null;
    }
  }
  return null;
}

function isWebSocketEndpoint(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === "ws:" || url.protocol === "wss:";
  } catch {
    return false;
  }
}

function upstreamHttpBase(endpoint: string): string {
  const url = new URL(endpoint);
  return `http://${url.host}`;
}

function messageText(data: unknown): string {
  if (typeof data === "string") {
    return data;
  }
  if (data instanceof ArrayBuffer) {
    return Buffer.from(data).toString("utf8");
  }
  return String(data);
}

function isRecord(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function stringField(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

function writeJson(response: ServerResponse, body: unknown): void {
  const text = JSON.stringify(body);
  response.statusCode = 200;
  response.setHeader("content-type", "application/json");
  response.setHeader("content-length", String(Buffer.byteLength(text)));
  response.end(text);
}

const isMainModule =
  process.argv[1] !== undefined &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href;

if (isMainModule) {
  void main()
    .then((code) => process.exit(code))
    .catch((error: unknown) => {
      console.error(
        `tegata-herdr shim: ${error instanceof Error ? error.message : String(error)}`,
      );
      process.exit(1);
    });
}
