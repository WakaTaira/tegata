import { connect as connectTcp } from "node:net";
import { pathToFileURL } from "node:url";
import { callDaemon, openBridgeTunnel, type RpcResponse } from "./index.js";

/** open_mcp_server の応答から取り出した、中継に必要な値。 */
type OpenMcpServerResult = {
  sessionId: string;
  port: number;
  streamSecret: string;
};

/** ランナーが読み書きするストリーム。テストから差し替え可能にするため引数として受け取る。 */
export type RunStreams = {
  stdin: NodeJS.ReadableStream;
  stdout: NodeJS.WritableStream;
  stderr: NodeJS.WritableStream;
};

/** 終了シグナルの購読元。テストから差し替え可能にするため引数として受け取る。 */
export type SignalSource = {
  on(signal: NodeJS.Signals, listener: () => void): unknown;
  off(signal: NodeJS.Signals, listener: () => void): unknown;
};

/** 受けた場合に logout してから終了するシグナルと、その際の終了コード（128 + シグナル番号）。 */
const TERMINATION_SIGNALS = [
  ["SIGTERM", 143],
  ["SIGINT", 130],
] as const;

/** 終了シグナルの受信を記録し、中継中であれば登録済みのハンドラへ即座に伝える。 */
type SignalWatch = {
  received: () => number | undefined;
  onSignal: (handler: (exitCode: number) => void) => void;
  dispose: () => void;
};

function watchSignals(source: SignalSource): SignalWatch {
  let received: number | undefined;
  let handler: ((exitCode: number) => void) | undefined;
  const listeners = TERMINATION_SIGNALS.map(([signal, exitCode]) => {
    const listener = () => {
      if (received !== undefined) return;
      received = exitCode;
      handler?.(exitCode);
    };
    source.on(signal, listener);
    return [signal, listener] as const;
  });
  return {
    received: () => received,
    onSignal: (next) => {
      handler = next;
    },
    dispose: () => {
      for (const [signal, listener] of listeners) source.off(signal, listener);
    },
  };
}

/** 分類コードのみを stderr へ 1 行出し、失敗の終了コードを返す。 */
function fail(streams: RunStreams, code: string): number {
  streams.stderr.write(`${code}\n`);
  return 1;
}

/** 応答に session_id があれば取り出す。形の不正な応答でも開いたセッションを閉じるために使う。 */
function sessionIdOf(result: unknown): string | undefined {
  if (typeof result !== "object" || result === null) return undefined;
  const sessionId = (result as { session_id?: unknown }).session_id;
  return typeof sessionId === "string" ? sessionId : undefined;
}

/** open_mcp_server の応答を検証して取り出す。形が合わなければ INTERNAL 扱いにする。 */
function parseOpenMcpServerResult(result: unknown): OpenMcpServerResult {
  const sessionId = sessionIdOf(result);
  if (sessionId === undefined) {
    throw new Error("invalid open_mcp_server result");
  }
  const parsed = result as { port?: unknown; stream_secret?: unknown };
  if (
    typeof parsed.port !== "number" ||
    !Number.isInteger(parsed.port) ||
    typeof parsed.stream_secret !== "string"
  ) {
    throw new Error("invalid open_mcp_server result");
  }
  return {
    sessionId,
    port: parsed.port,
    streamSecret: parsed.stream_secret,
  };
}

/** セッションを閉じる。stream secret やサーバーの出力を一切含まない best-effort な後始末。 */
async function logout(sessionId: string): Promise<void> {
  try {
    await callDaemon("logout", { session_id: sessionId });
  } catch {
    // デーモンが既に失効させている等、ここでの失敗は中継の終了自体を妨げない。
  }
}

/**
 * ポートへ接続し、先頭に stream secret を送ったうえで stdin / stdout をそのまま中継する。
 * stdin の EOF・接続断・終了シグナルのいずれかで logout を送って終了する。
 */
async function connectAndRelay(
  port: number,
  streamSecret: string,
  sessionId: string,
  streams: RunStreams,
  signals: SignalWatch,
): Promise<number> {
  return new Promise<number>((resolve) => {
    const socket = connectTcp({ host: "127.0.0.1", port });
    let finished = false;

    const finish = (exitCode: number) => {
      if (finished) return;
      finished = true;
      socket.destroy();
      void logout(sessionId).finally(() => resolve(exitCode));
    };

    socket.once("error", () => finish(1));
    socket.once("close", () => finish(0));
    socket.once("connect", () => {
      socket.write(`${streamSecret}\n`);
      streams.stdin.pipe(socket);
      socket.pipe(streams.stdout);
    });
    streams.stdin.once("end", () => finish(0));
    signals.onSignal(finish);
  });
}

/** 開いたセッションについて、必要なら bridge のトンネルを開いてから中継する。 */
async function relaySession(
  opened: OpenMcpServerResult,
  streams: RunStreams,
  signals: SignalWatch,
): Promise<number> {
  let localPort = opened.port;
  if (process.env.TEGATA_BRIDGE === "1") {
    const tunnel = await openBridgeTunnel(opened.sessionId, opened.port);
    if ("failure" in tunnel) {
      await logout(opened.sessionId);
      return fail(streams, tunnel.failure.content[0]?.text ?? "INTERNAL");
    }
    localPort = tunnel.localPort;
  }
  const signalled = signals.received();
  if (signalled !== undefined) {
    await logout(opened.sessionId);
    return signalled;
  }
  return connectAndRelay(
    localPort,
    opened.streamSecret,
    opened.sessionId,
    streams,
    signals,
  );
}

/** open_mcp_server でセッションを開いて中継する。開いたセッションはどの経路でも logout する。 */
async function openAndRelay(
  name: string,
  streams: RunStreams,
  signals: SignalWatch,
): Promise<number> {
  let response: RpcResponse;
  try {
    response = await callDaemon("open_mcp_server", { name });
  } catch {
    return fail(streams, "INTERNAL");
  }
  if (response.error !== undefined) {
    const code =
      typeof response.error.message === "string"
        ? response.error.message
        : "INTERNAL";
    return fail(streams, code);
  }

  let opened: OpenMcpServerResult;
  try {
    opened = parseOpenMcpServerResult(response.result);
  } catch {
    const sessionId = sessionIdOf(response.result);
    if (sessionId !== undefined) await logout(sessionId);
    return fail(streams, "INTERNAL");
  }

  try {
    return await relaySession(opened, streams, signals);
  } catch {
    await logout(opened.sessionId);
    return fail(streams, "INTERNAL");
  }
}

/**
 * `tegata-mcp-run <name>` の本体。呼び出しごとに分類コードのみを stderr へ出す。
 * 終了シグナルは open_mcp_server の応答を待ってから扱い、開いたセッションを logout してから終了する。
 */
export async function run(
  name: string | undefined,
  streams: RunStreams,
  signals: SignalSource = process,
): Promise<number> {
  if (name === undefined || name === "") return fail(streams, "INTERNAL");
  const watch = watchSignals(signals);
  try {
    return await openAndRelay(name, streams, watch);
  } finally {
    watch.dispose();
  }
}

if (
  process.argv[1] !== undefined &&
  pathToFileURL(process.argv[1]).href === import.meta.url
) {
  // 終了シグナルや接続断で終えた場合も stdin の読み取りが残るため、破棄して自然終了させる。
  // process.exit を使わないのは、stdout へ書き込み途中の応答を切り捨てないためである。
  run(process.argv[2], {
    stdin: process.stdin,
    stdout: process.stdout,
    stderr: process.stderr,
  })
    .then((exitCode) => {
      process.exitCode = exitCode;
    })
    .catch(() => {
      process.exitCode = 1;
    })
    .finally(() => {
      process.stdin.destroy();
    });
}
