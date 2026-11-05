import { type ChildProcess, spawn } from "node:child_process";
import { timingSafeEqual } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { closeServer, listenLoopback } from "./loopback.js";

/** A server that exits within this time right after launch is treated as a startup failure. */
export const MCP_STARTUP_GRACE_MS = 1_000;
/** Upper bound on waiting for the first line of a connection (the stream secret). */
export const MCP_HANDSHAKE_TIMEOUT_MS = 5_000;
/** Upper bound on the stream secret line (including the newline). */
export const MCP_HANDSHAKE_MAX_BYTES = 256;
/**
 * Upper bound on one line of server output (excluding the newline). Exceeding it is treated the
 * same as a leak.
 */
export const MCP_MAX_LINE_BYTES = 16 * 1024 * 1024;
/** Grace period from SIGTERM to SIGKILL. */
export const MCP_KILL_GRACE_MS = 2_000;

const NEWLINE = 0x0a;

export type McpServerEvent =
  | { action: "connected" }
  | { action: "exit"; exit_code: number | null }
  | { action: "leak" };

export type McpServerOptions = {
  command: string;
  args: string[];
  env: Record<string, string>;
  scan: string[];
  streamSecret: string;
  onEvent: (event: McpServerEvent) => void;
};

export type McpServerHost = {
  port: number;
  /**
   * Call after the startup response has been written. Events that occurred until then are held and
   * emitted here in order of occurrence.
   * If an event line appeared before the response, the daemon could not treat it as an event for a
   * lease not yet established.
   */
  releaseEvents: () => void;
  close: () => Promise<void>;
};

/**
 * Represents a startup failure. The message includes none of the env values, arguments, or spawn
 * exception text.
 * Node's argument validation exceptions quote the values, so passing them straight to a diagnostic
 * line could leak secrets.
 */
export class McpServerStartError extends Error {
  override name = "McpServerStartError";
}

export type LineInspection = { lines: Buffer[]; leaked: boolean };

/**
 * Returns the value and its form escaped as a JSON string (only when it differs from the original
 * value).
 * MCP output is JSON, so a value containing `"` or `\` can appear in escaped form.
 */
function withJsonEscaped(value: string): string[] {
  const escaped = JSON.stringify(value).slice(1, -1);
  return escaped === value ? [value] : [value, escaped];
}

/**
 * Splits server output on newlines and returns only complete lines after scanning them.
 * If a line containing a scanned value or a line exceeding the limit is detected, nothing is
 * returned, including other lines in the same chunk.
 * An incomplete line is kept internally and is not emitted before scanning.
 */
export class LineInspector {
  private readonly needles: Buffer[];
  private pending: Buffer[] = [];
  private pendingBytes = 0;
  private failed = false;

  constructor(
    scan: readonly string[],
    private readonly maxLineBytes: number = MCP_MAX_LINE_BYTES,
  ) {
    // An empty string matches every line, so it is excluded from the scan targets.
    const values = scan.filter((value) => value !== "");
    this.needles = [...new Set(values.flatMap(withJsonEscaped))].map((value) =>
      Buffer.from(value, "utf8"),
    );
  }

  push(chunk: Buffer): LineInspection {
    if (this.failed) return { lines: [], leaked: true };
    const lines: Buffer[] = [];
    let start = 0;
    for (;;) {
      const newline = chunk.indexOf(NEWLINE, start);
      if (newline < 0) break;
      if (this.pendingBytes + (newline - start) > this.maxLineBytes) {
        return this.fail();
      }
      const line = Buffer.concat([
        ...this.pending,
        chunk.subarray(start, newline + 1),
      ]);
      this.pending = [];
      this.pendingBytes = 0;
      if (this.containsSecret(line)) return this.fail();
      lines.push(line);
      start = newline + 1;
    }
    if (start < chunk.length) {
      this.pending.push(chunk.subarray(start));
      this.pendingBytes += chunk.length - start;
      if (this.pendingBytes > this.maxLineBytes) return this.fail();
    }
    return { lines, leaked: false };
  }

  private containsSecret(line: Buffer): boolean {
    return this.needles.some((needle) => line.includes(needle));
  }

  private fail(): LineInspection {
    this.failed = true;
    this.pending = [];
    this.pendingBytes = 0;
    return { lines: [], leaked: true };
  }
}

function bytesEqual(candidate: Buffer, expected: Buffer): boolean {
  // The secret length is public, so a length mismatch may be rejected immediately.
  if (candidate.length !== expected.length) return false;
  return timingSafeEqual(candidate, expected);
}

function hasExited(child: ChildProcess): boolean {
  return child.exitCode !== null || child.signalCode !== null;
}

function ignoreError(): void {}

/** Rejects if spawn fails or the process exits before the grace period after launch has passed. */
function waitForStartup(child: ChildProcess): Promise<void> {
  return new Promise((resolve, reject) => {
    const cleanup = () => {
      clearTimeout(timer);
      child.off("error", onError);
      child.off("exit", onExit);
    };
    const onError = (error: NodeJS.ErrnoException) => {
      cleanup();
      reject(
        new McpServerStartError(
          `MCP server could not be spawned (${error.code ?? "unknown"})`,
        ),
      );
    };
    const onExit = (code: number | null, signal: NodeJS.Signals | null) => {
      cleanup();
      reject(
        new McpServerStartError(
          `MCP server exited during startup (exit code ${code ?? "null"}, signal ${signal ?? "null"})`,
        ),
      );
    };
    const timer = setTimeout(() => {
      cleanup();
      resolve();
    }, MCP_STARTUP_GRACE_MS);
    child.once("error", onError);
    child.once("exit", onExit);
  });
}

/**
 * Sends SIGTERM, and sends SIGKILL if the process is still alive after the grace period.
 * On Windows, `kill()` force-terminates for either signal, so no branching is needed.
 */
function terminateChild(child: ChildProcess): Promise<void> {
  if (child.pid === undefined || hasExited(child)) return Promise.resolve();
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      if (!hasExited(child)) child.kill("SIGKILL");
    }, MCP_KILL_GRACE_MS);
    child.once("exit", () => {
      clearTimeout(timer);
      resolve();
    });
    child.kill("SIGTERM");
  });
}

/**
 * Variables inherited only on Windows. Runtimes such as Node fail to start or communicate without
 * SYSTEMROOT.
 */
const WINDOWS_INHERITED_ENV = ["SYSTEMROOT", "WINDIR"] as const;

/**
 * Builds the environment variables passed to the server. The executor's environment variables are
 * inherited only for PATH and,
 * on Windows, SYSTEMROOT and WINDIR (only if present); HOME is the session directory.
 */
export function serverEnvironment(
  env: Record<string, string>,
  home: string,
  platform: NodeJS.Platform = process.platform,
  inherited: NodeJS.ProcessEnv = process.env,
): NodeJS.ProcessEnv {
  const result: NodeJS.ProcessEnv = {
    ...env,
    PATH: inherited.PATH,
    HOME: home,
  };
  if (platform === "win32") {
    for (const name of WINDOWS_INHERITED_ENV) {
      const value = inherited[name];
      if (value !== undefined) result[name] = value;
    }
  }
  return result;
}

function spawnServer(options: McpServerOptions, dir: string): ChildProcess {
  try {
    return spawn(options.command, options.args, {
      env: serverEnvironment(options.env, dir),
      cwd: dir,
      stdio: ["pipe", "pipe", "ignore"],
      windowsHide: true,
    });
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code ?? "unknown";
    throw new McpServerStartError(`MCP server could not be spawned (${code})`);
  }
}

/**
 * Holds the state of the relay that connects the launched server process to the loopback listener.
 * Only one connection is established per session, and it is not re-established after disconnection.
 */
class McpRelay {
  private connection: net.Socket | undefined;
  private claimed = false;
  private finished = false;
  private reading = false;
  private waitingDrain = false;
  private readonly handshakes = new Set<net.Socket>();
  private readonly inspector: LineInspector;
  private readonly secret: Buffer;
  private termination: Promise<void> | undefined;
  private closing: Promise<void> | undefined;
  private heldEvents: McpServerEvent[] | undefined = [];
  readonly server: net.Server;

  constructor(
    private readonly child: ChildProcess,
    private readonly dir: string,
    private readonly options: McpServerOptions,
  ) {
    this.inspector = new LineInspector(options.scan);
    this.secret = Buffer.from(options.streamSecret, "utf8");
    this.server = net.createServer((socket) => this.accept(socket));
    child.on("error", ignoreError);
    child.stdin?.on("error", ignoreError);
    child.stdout?.on("error", ignoreError);
    // Even when the process exits with no connection, stdout is read to the end so that close
    // fires.
    child.once("exit", () => this.startReading());
    child.once("close", (code: number | null) => this.handleExit(code));
  }

  private accept(socket: net.Socket): void {
    socket.on("error", ignoreError);
    if (this.claimed || this.finished || hasExited(this.child)) {
      socket.destroy();
      return;
    }
    this.handshakes.add(socket);
    let buffered = Buffer.alloc(0);
    const timer = setTimeout(() => socket.destroy(), MCP_HANDSHAKE_TIMEOUT_MS);
    const onData = (chunk: Buffer) => {
      buffered = Buffer.concat([buffered, chunk]);
      const newline = buffered.indexOf(NEWLINE);
      const lineBytes = newline < 0 ? buffered.length : newline + 1;
      if (lineBytes > MCP_HANDSHAKE_MAX_BYTES) {
        socket.destroy();
        return;
      }
      if (newline < 0) return;
      clearTimeout(timer);
      socket.off("data", onData);
      socket.pause();
      this.handshakes.delete(socket);
      const candidate = buffered.subarray(0, newline);
      if (
        this.claimed ||
        this.finished ||
        hasExited(this.child) ||
        !bytesEqual(candidate, this.secret)
      ) {
        socket.destroy();
        return;
      }
      this.establish(socket, buffered.subarray(newline + 1));
    };
    socket.on("data", onData);
    socket.once("close", () => {
      clearTimeout(timer);
      this.handshakes.delete(socket);
    });
  }

  /** Events are held before the startup response, and emitted immediately after releaseEvents. */
  private emit(event: McpServerEvent): void {
    if (this.heldEvents !== undefined) {
      this.heldEvents.push(event);
      return;
    }
    this.options.onEvent(event);
  }

  releaseEvents(): void {
    const held = this.heldEvents;
    if (held === undefined) return;
    this.heldEvents = undefined;
    for (const event of held) this.options.onEvent(event);
  }

  private establish(socket: net.Socket, rest: Buffer): void {
    this.claimed = true;
    this.connection = socket;
    for (const other of this.handshakes) other.destroy();
    this.handshakes.clear();
    const stdin = this.child.stdin;
    if (stdin !== null) {
      if (rest.length > 0) stdin.write(rest);
      socket.pipe(stdin);
    }
    socket.once("close", () => {
      this.connection = undefined;
      if (stdin !== null && !stdin.writableEnded) stdin.end();
      // Output after disconnection is discarded, so reading paused by backpressure is resumed.
      this.child.stdout?.resume();
      // The connection is not re-established, so even a server that ignores EOF is made to exit.
      // The exit is notified as an exit event.
      void this.terminate();
    });
    this.startReading();
    this.emit({ action: "connected" });
  }

  private startReading(): void {
    if (this.reading) return;
    this.reading = true;
    this.child.stdout?.on("data", (chunk: Buffer) => this.handleOutput(chunk));
  }

  private handleOutput(chunk: Buffer): void {
    if (this.finished) return;
    const { lines, leaked } = this.inspector.push(chunk);
    if (leaked) {
      void this.handleLeak();
      return;
    }
    const connection = this.connection;
    if (connection === undefined) return;
    let writable = true;
    for (const line of lines) writable = connection.write(line) && writable;
    if (!writable && !this.waitingDrain) {
      this.waitingDrain = true;
      this.child.stdout?.pause();
      connection.once("drain", () => {
        this.waitingDrain = false;
        this.child.stdout?.resume();
      });
    }
  }

  private async handleLeak(): Promise<void> {
    this.finished = true;
    this.child.stdout?.destroy();
    this.dropConnections();
    await this.terminate();
    this.emit({ action: "leak" });
  }

  private handleExit(code: number | null): void {
    if (this.finished) return;
    this.finished = true;
    // Complete lines have already been written and are flushed by end before closing. An incomplete
    // line is discarded.
    this.connection?.end();
    for (const socket of this.handshakes) socket.destroy();
    this.handshakes.clear();
    void closeServer(this.server);
    this.emit({ action: "exit", exit_code: code });
  }

  private dropConnections(): void {
    this.connection?.destroy();
    for (const socket of this.handshakes) socket.destroy();
    this.handshakes.clear();
    void closeServer(this.server);
  }

  private terminate(): Promise<void> {
    this.termination ??= terminateChild(this.child);
    return this.termination;
  }

  close(): Promise<void> {
    this.closing ??= (async () => {
      this.finished = true;
      this.dropConnections();
      await closeServer(this.server);
      await this.terminate();
      this.child.stdin?.destroy();
      this.child.stdout?.destroy();
      await rm(this.dir, { recursive: true, force: true }).catch(
        () => undefined,
      );
    })();
    return this.closing;
  }
}

/**
 * Launches a stdio MCP server permitted by config and relays it over loopback TCP protected by the
 * stream secret.
 * The env values, the scan, and the stream secret are never emitted anywhere, including exception
 * messages.
 */
export async function startMcpServer(
  options: McpServerOptions,
): Promise<McpServerHost> {
  // mkdtemp creates the directory with 0700.
  const dir = await mkdtemp(path.join(os.tmpdir(), "tegata-mcp-"));
  let child: ChildProcess | undefined;
  try {
    child = spawnServer(options, dir);
    await waitForStartup(child);
    const relay = new McpRelay(child, dir, options);
    try {
      const port = await listenLoopback(relay.server);
      return {
        port,
        releaseEvents: () => relay.releaseEvents(),
        close: () => relay.close(),
      };
    } catch (error) {
      await relay.close();
      throw new McpServerStartError(
        `MCP relay listener could not be opened (${(error as NodeJS.ErrnoException).code ?? "unknown"})`,
      );
    }
  } catch (error) {
    if (child !== undefined) {
      child.on("error", ignoreError);
      await terminateChild(child);
      child.stdin?.destroy();
      child.stdout?.destroy();
    }
    await rm(dir, { recursive: true, force: true }).catch(() => undefined);
    throw error;
  }
}
