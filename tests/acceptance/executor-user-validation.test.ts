// AC-55a, AC-55b, AC-55c, AC-55d — startup validation of the `executor_socket`
// config key and the executor's `hello` / EOF handling: the daemon must
// refuse to start when the socket-activated executor would run as the
// daemon's own user, and when the configured socket is not connectable; the
// executor itself must answer `hello` with its real uid/pid and exit cleanly
// on stdin EOF.
// Traceability: docs/secret/briefs/tegata-v042-browser-worker.md acceptance
// condition AC-55a, AC-55b, AC-55c, AC-55d.

import { type ChildProcess, spawn } from "node:child_process";
import { once } from "node:events";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import readline from "node:readline";
import { expect, test } from "vitest";
import { bins, REPO_ROOT, renderDaemonConfig } from "./support/harness.js";

interface ForegroundResult {
  code: number | null;
  signal: NodeJS.Signals | null;
  stderr: string;
}

/**
 * デーモンをフォアグラウンドで起動し、終了（成功・失敗いずれか）まで待つ。
 * `startDaemon`（harness.ts）はソケット出現までの成功前提のため、起動失敗を
 * 検証したいここでは使えない。10 秒以内に終了しなければタイムアウト失敗と
 * みなして kill する。
 */
async function runForeground(configPath: string): Promise<ForegroundResult> {
  const child: ChildProcess = spawn(bins().tegatad, ["--config", configPath], {
    stdio: ["ignore", "ignore", "pipe"],
  });
  let stderr = "";
  child.stderr?.on("data", (chunk) => {
    stderr += chunk.toString("utf8");
  });
  const timer = setTimeout(() => child.kill("SIGKILL"), 10_000);
  try {
    const [code, signal] = (await once(child, "exit")) as [
      number | null,
      NodeJS.Signals | null,
    ];
    return { code, signal, stderr };
  } finally {
    clearTimeout(timer);
  }
}

/** `executor_socket` を足した config.toml を書き、そのパスを返す。 */
function writeConfigWithExecutorSocket(executorSocket: string): {
  daemonDir: string;
  configPath: string;
} {
  const daemonDir = fs.mkdtempSync(
    path.join(os.tmpdir(), "tegatad-executor-socket-"),
  );
  const stateDir = path.join(daemonDir, "state");
  fs.mkdirSync(stateDir);
  const base = renderDaemonConfig({
    socketPath: path.join(daemonDir, "tegatad.sock"),
    stateDir,
    auditLogPath: path.join(stateDir, "audit.log"),
    allowedUids: [os.userInfo().uid],
    entries: [],
  });
  const configPath = path.join(daemonDir, "config.toml");
  fs.writeFileSync(
    configPath,
    `executor_socket = ${JSON.stringify(executorSocket)}\n${base}`,
    { mode: 0o600 },
  );
  return { daemonDir, configPath };
}

/**
 * `{"op":"hello"}` に対して、指定した uid で応答するダミー executor サーバー
 * を UDS 上に立てる。1 行読み、1 行返して接続を閉じる。
 */
function startHelloServer(uid: number): {
  socketPath: string;
  dir: string;
  close(): Promise<void>;
} {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tegata-hello-srv-"));
  const socketPath = path.join(dir, "executor.sock");
  const server = net.createServer((socket) => {
    const rl = readline.createInterface({ input: socket });
    rl.once("line", (line) => {
      const req = JSON.parse(line) as { op?: string };
      if (req.op === "hello") {
        socket.write(
          `${JSON.stringify({ ok: true, uid, pid: process.pid })}\n`,
        );
      }
      socket.end();
    });
  });
  server.listen(socketPath);
  return {
    socketPath,
    dir,
    close: () =>
      new Promise((resolve) => {
        server.close(() => resolve());
      }),
  };
}

/** executor entry の解決。`bins()` と同じ流儀（env 優先、無ければ既定パス）。 */
function executorEntry(): string {
  return (
    process.env.TEGATA_EXECUTOR_ENTRY ??
    path.join(REPO_ROOT, "packages/tegata-executor/dist/index.js")
  );
}

test("AC-55a: executor_socket whose hello reports the daemon's own uid is refused at startup", async () => {
  // Given: hello にテスト実行 uid で応答する UDS サーバーがあり、config の
  // executor_socket がそれを指す
  const hello = startHelloServer(os.userInfo().uid);
  const { daemonDir, configPath } = writeConfigWithExecutorSocket(
    hello.socketPath,
  );
  try {
    // When: デーモンを起動する
    const result = await runForeground(configPath);

    // Then: 非ゼロで終了し、stderr に該当文言を含む
    expect(
      result.code,
      `expected a non-zero exit; stderr: ${result.stderr}`,
    ).not.toBe(0);
    expect(result.stderr).toContain(
      "executor must not run as the daemon's own user",
    );
  } finally {
    await hello.close();
    fs.rmSync(daemonDir, { recursive: true, force: true });
    fs.rmSync(hello.dir, { recursive: true, force: true });
  }
});

test("AC-55b: executor_socket pointing at a nonexistent path is refused at startup", async () => {
  // Given: executor_socket に存在しないパスを書いた config
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tegata-no-socket-"));
  const noSuchSocket = path.join(dir, "no-such.sock");
  const { daemonDir, configPath } = writeConfigWithExecutorSocket(noSuchSocket);
  try {
    // When: デーモンを起動する
    const result = await runForeground(configPath);

    // Then: 非ゼロで終了し、stderr に該当文言を含む
    expect(
      result.code,
      `expected a non-zero exit; stderr: ${result.stderr}`,
    ).not.toBe(0);
    expect(result.stderr).toContain("is not connectable");
  } finally {
    fs.rmSync(daemonDir, { recursive: true, force: true });
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("AC-55c: the executor answers hello with its own uid and pid", async () => {
  // Given: 実 executor entry を stdio パイプで起動した
  const child = spawn(process.execPath, [executorEntry()], {
    stdio: ["pipe", "pipe", "inherit"],
  });
  try {
    const rl = readline.createInterface({ input: child.stdout });
    const responseLine = new Promise<string>((resolve, reject) => {
      rl.once("line", resolve);
      child.once("exit", (code) =>
        reject(new Error(`executor exited early (code ${code})`)),
      );
    });

    // When: {"op":"hello"} を 1 行送る
    child.stdin.write(`${JSON.stringify({ op: "hello" })}\n`);

    // Then: 1 行の応答が ok: true、uid はテスト実行 uid、pid は子プロセスの pid
    const line = await responseLine;
    const response = JSON.parse(line) as {
      ok: boolean;
      uid: number;
      pid: number;
    };
    expect(response.ok).toBe(true);
    expect(response.uid).toBe(os.userInfo().uid);
    expect(response.pid).toBe(child.pid);
  } finally {
    child.kill("SIGKILL");
  }
});

test("AC-55d: the executor exits cleanly on stdin EOF", async () => {
  // Given: 実 executor entry を stdio パイプで起動した
  const child = spawn(process.execPath, [executorEntry()], {
    stdio: ["pipe", "ignore", "inherit"],
  });
  const timer = setTimeout(() => child.kill("SIGKILL"), 2_000);
  try {
    // When: stdin を閉じる
    child.stdin.end();

    // Then: 2 秒以内に終了コード 0 で終了する
    const [code] = (await once(child, "exit")) as [number | null];
    expect(code).toBe(0);
  } finally {
    clearTimeout(timer);
  }
});
