#!/usr/bin/env node
import { connect as connectTcp } from "node:net";
import { pathToFileURL } from "node:url";
import { callDaemon, openBridgeTunnel } from "./index.js";

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

/** open_mcp_server の応答を検証して取り出す。形が合わなければ INTERNAL 扱いにする。 */
function parseOpenMcpServerResult(result: unknown): OpenMcpServerResult {
  if (typeof result !== "object" || result === null) {
    throw new Error("invalid open_mcp_server result");
  }
  const parsed = result as {
    session_id?: unknown;
    port?: unknown;
    stream_secret?: unknown;
  };
  if (
    typeof parsed.session_id !== "string" ||
    typeof parsed.port !== "number" ||
    !Number.isInteger(parsed.port) ||
    typeof parsed.stream_secret !== "string"
  ) {
    throw new Error("invalid open_mcp_server result");
  }
  return {
    sessionId: parsed.session_id,
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
 * stdin の EOF か接続断のいずれかで logout を送って終了する。
 */
async function connectAndRelay(
  port: number,
  streamSecret: string,
  sessionId: string,
  streams: RunStreams,
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
  });
}

/** `tegata-mcp-run <name>` の本体。呼び出しごとに分類コードのみを stderr へ出す。 */
export async function run(
  name: string | undefined,
  streams: RunStreams,
): Promise<number> {
  if (name === undefined || name === "") {
    streams.stderr.write("INTERNAL\n");
    return 1;
  }

  let opened: Awaited<ReturnType<typeof callDaemon>>;
  try {
    opened = await callDaemon("open_mcp_server", { name });
  } catch {
    streams.stderr.write("INTERNAL\n");
    return 1;
  }
  if (opened.error !== undefined) {
    const code =
      typeof opened.error.message === "string"
        ? opened.error.message
        : "INTERNAL";
    streams.stderr.write(`${code}\n`);
    return 1;
  }

  let parsed: OpenMcpServerResult;
  try {
    parsed = parseOpenMcpServerResult(opened.result);
  } catch {
    streams.stderr.write("INTERNAL\n");
    return 1;
  }

  let localPort = parsed.port;
  if (process.env.TEGATA_BRIDGE === "1") {
    const tunnel = await openBridgeTunnel(parsed.sessionId, parsed.port);
    if ("failure" in tunnel) {
      const code = tunnel.failure.content[0]?.text ?? "INTERNAL";
      await logout(parsed.sessionId);
      streams.stderr.write(`${code}\n`);
      return 1;
    }
    localPort = tunnel.localPort;
  }

  return connectAndRelay(
    localPort,
    parsed.streamSecret,
    parsed.sessionId,
    streams,
  );
}

if (
  process.argv[1] !== undefined &&
  pathToFileURL(process.argv[1]).href === import.meta.url
) {
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
    });
}
