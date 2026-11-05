import { connect as connectTcp } from "node:net";
import { pathToFileURL } from "node:url";
import { callDaemon, openBridgeTunnel, type RpcResponse } from "./index.js";

/** Values extracted from the open_mcp_server response that are needed for relay. */
type OpenMcpServerResult = {
  sessionId: string;
  port: number;
  streamSecret: string;
};

/** The streams the runner reads and writes. Taken as an argument so that tests can replace them. */
export type RunStreams = {
  stdin: NodeJS.ReadableStream;
  stdout: NodeJS.WritableStream;
  stderr: NodeJS.WritableStream;
};

/**
 * The source of termination-signal subscriptions. Taken as an argument so that tests can replace
 * it.
 */
export type SignalSource = {
  on(signal: NodeJS.Signals, listener: () => void): unknown;
  off(signal: NodeJS.Signals, listener: () => void): unknown;
};

/**
 * The signals that, when received, trigger logout and exit, and the exit code in that case (128 +
 * signal number).
 */
const TERMINATION_SIGNALS = [
  ["SIGTERM", 143],
  ["SIGINT", 130],
] as const;

/**
 * Records receipt of a termination signal and, if relaying, immediately notifies the registered
 * handler.
 */
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

/** Writes only the classification code to stderr as one line and returns the failure exit code. */
function fail(streams: RunStreams, code: string): number {
  streams.stderr.write(`${code}\n`);
  return 1;
}

/**
 * Extracts session_id from the response if present. Used to close an opened session even for a
 * malformed response.
 */
function sessionIdOf(result: unknown): string | undefined {
  if (typeof result !== "object" || result === null) return undefined;
  const sessionId = (result as { session_id?: unknown }).session_id;
  return typeof sessionId === "string" ? sessionId : undefined;
}

/** Validates and extracts the open_mcp_server response. Treats a mismatched shape as INTERNAL. */
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

/**
 * Closes the session. A best-effort cleanup that contains neither the stream secret nor any server
 * output.
 */
async function logout(sessionId: string): Promise<void> {
  try {
    // Call logout until the alias is retired, so that the session is reliably closed even with an
    // older daemon.
    await callDaemon("logout", { session_id: sessionId });
  } catch {
    // A failure here, such as the daemon having already revoked the session, does not prevent the
    // relay itself from ending.
  }
}

/**
 * Connects to the port, sends the stream secret first, and then relays stdin / stdout as is.
 * Sends logout and exits on any of stdin EOF, connection loss, or a termination signal.
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

/** For the opened session, opens a bridge tunnel if needed and then relays. */
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

/**
 * Opens a session with open_mcp_server and relays. The opened session is logged out on every path.
 */
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
 * The body of `tegata-mcp-run <name>`. Emits only the classification code to stderr on each
 * invocation.
 * A termination signal is handled after waiting for the open_mcp_server response, and the opened
 * session is logged out before exiting.
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
  // Reading stdin remains even after finishing via a termination signal or connection loss, so
  // destroy it to let the process exit naturally.
  // process.exit is not used so that a response being written to stdout is not truncated.
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
