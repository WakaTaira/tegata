import { type ChildProcess, spawn } from "node:child_process";
import { timingSafeEqual } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { closeServer, listenLoopback } from "./loopback.js";

/** 起動直後にこの時間内で終了したサーバーは起動失敗とみなす。 */
export const MCP_STARTUP_GRACE_MS = 1_000;
/** 接続の最初の行（stream secret）を待つ上限。 */
export const MCP_HANDSHAKE_TIMEOUT_MS = 5_000;
/** stream secret 行の上限（改行を含む）。 */
export const MCP_HANDSHAKE_MAX_BYTES = 256;
/** サーバー出力 1 行の上限（改行を除く）。超過は漏洩と同じ扱いとする。 */
export const MCP_MAX_LINE_BYTES = 16 * 1024 * 1024;
/** SIGTERM から SIGKILL までの猶予。 */
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
   * 起動応答を書き終えた後に呼ぶ。それまでに生じたイベントは保留されており、ここで発生順に出す。
   * 応答より先にイベント行が出ると、デーモンが未確立のリースへのイベントとして扱えないためである。
   */
  releaseEvents: () => void;
  close: () => Promise<void>;
};

/**
 * 起動失敗を表す。メッセージには env の値・引数・spawn の例外文言を含めない。
 * Node の引数検査の例外は値を引用するため、そのまま診断行へ流すと秘密が漏れうるからである。
 */
export class McpServerStartError extends Error {
  override name = "McpServerStartError";
}

export type LineInspection = { lines: Buffer[]; leaked: boolean };

/**
 * 値と、JSON 文字列として escape した形（元の値と異なる場合のみ）を返す。
 * MCP の出力は JSON であるため、`"` や `\` を含む値は escape された形で現れうる。
 */
function withJsonEscaped(value: string): string[] {
  const escaped = JSON.stringify(value).slice(1, -1);
  return escaped === value ? [value] : [value, escaped];
}

/**
 * サーバー出力を改行で区切り、完結した行だけを検査して返す。
 * 検査対象の値を含む行、または上限を超える行を検出した場合は、同じ chunk の行も含めて何も返さない。
 * 未完行は内部に保持し、検査前に外へ出さない。
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
    // 空文字はあらゆる行に一致するため、検査対象から除く。
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
  // secret の長さは公開情報であるため、長さの不一致は即座に拒否してよい。
  if (candidate.length !== expected.length) return false;
  return timingSafeEqual(candidate, expected);
}

function hasExited(child: ChildProcess): boolean {
  return child.exitCode !== null || child.signalCode !== null;
}

function ignoreError(): void {}

/** 起動から猶予時間が過ぎるまでに spawn が失敗するか終了した場合は reject する。 */
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
 * SIGTERM を送り、猶予後も残っていれば SIGKILL を送る。
 * Windows では `kill()` がどちらのシグナルでも強制終了となるため、分岐を要しない。
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

/** Windows でのみ引き継ぐ変数。Node などのランタイムは SYSTEMROOT が無いと起動・通信に失敗する。 */
const WINDOWS_INHERITED_ENV = ["SYSTEMROOT", "WINDIR"] as const;

/**
 * サーバーへ渡す環境変数を組み立てる。executor の環境変数は PATH と、Windows の場合の
 * SYSTEMROOT・WINDIR（存在する場合のみ）以外引き継がず、HOME はセッション用ディレクトリとする。
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
 * 起動済みのサーバープロセスと loopback リスナーを結ぶ中継の状態を持つ。
 * 1 セッションにつき成立させる接続は 1 本のみであり、切断後も再成立させない。
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
    // 接続が無いまま終了した場合も stdout を読み切り、close を発火させる。
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

  /** 起動応答の前はイベントを保留し、releaseEvents 以後は即座に出す。 */
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
      // 切断後の出力は捨てるため、backpressure で止めた読み取りを再開する。
      this.child.stdout?.resume();
      // 接続は再成立しないため、EOF を無視するサーバーも残さず終了させる。終了は exit イベントとして通知される。
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
    // 完結した行はすでに書き込み済みであり、end により送り切ってから閉じる。未完行は破棄される。
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
 * config で許可された stdio MCP サーバーを起動し、stream secret で守った loopback TCP で中継する。
 * env の値・scan・stream secret は例外メッセージを含めどこにも出力しない。
 */
export async function startMcpServer(
  options: McpServerOptions,
): Promise<McpServerHost> {
  // mkdtemp は 0700 で作成する。
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
