import { type ChildProcess, spawn } from "node:child_process";
import { once } from "node:events";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { bins, rawRpc } from "./harness.js";

export type FakeBwMode =
  | "always-fail"
  | "invalid-json"
  | "success"
  | "sync-fail"
  | "sync-hang"
  | `fail-until:${number}`;

export interface ColdStartCanaries {
  email: string;
  masterPassword: string;
  sessionKey: string;
  itemId: string;
  itemName: string;
}

export interface ColdStartDaemon {
  socketPath: string;
  namespace: string;
  canaries: ColdStartCanaries;
  setBwMode(mode: FakeBwMode): void;
  setBwItemName(name: string): void;
  callLog(): string[];
  loginCalls(): string[];
  syncCalls(): string[];
  listItemsCalls(): string[];
  stderr(): string;
  stop(): Promise<void>;
}

const FAKE_BW = `#!/bin/sh
set -u

call_log="\${FAKE_BW_CALL_LOG:?}"
state_file="\${FAKE_BW_STATE_FILE:?}"
list_count_file="\${FAKE_BW_LIST_COUNT_FILE:?}"
remote_items_file="\${FAKE_BW_REMOTE_ITEMS_FILE:?}"
cached_items_file="\${FAKE_BW_CACHED_ITEMS_FILE:?}"

printf '%s\\n' "$*" >> "$call_log"

if [ "\${1:-}" = "--version" ]; then
  printf '%s\\n' '2026.09.acceptance'
  exit 0
fi

if [ "\${1:-}" = "config" ] && [ "\${2:-}" = "server" ]; then
  if [ "\${3:-}" = "" ]; then
    printf '%s\\n' "$FAKE_BW_SERVER_URL"
  fi
  exit 0
fi

if [ "\${1:-}" = "login" ] && [ "\${2:-}" = "--check" ]; then
  printf 'You are not logged in as %s.\\n' "$FAKE_BW_EMAIL" >&2
  exit 1
fi

if [ "\${1:-}" = "login" ] || [ "\${1:-}" = "unlock" ]; then
  # 診断行のマスク経路を通すため、email・master password・払い出す session key を stderr に混ぜる。
  printf 'debug: %s %s %s\\n' "$FAKE_BW_EMAIL" "\${BW_PASSWORD:-}" "$FAKE_BW_SESSION" >&2
  printf '%s\\n' "$FAKE_BW_SESSION"
  exit 0
fi

if [ "\${1:-}" = "status" ]; then
  printf 'debug: session %s\\n' "\${BW_SESSION:-}" >&2
  printf '%s\\n' '{"status":"unlocked"}'
  exit 0
fi

if [ "\${1:-}" = "sync" ]; then
  mode=success
  if [ -f "$state_file" ]; then
    mode=$(sed -n '1p' "$state_file")
  fi
  case "$mode" in
    sync-fail)
      exit 1
      ;;
    sync-hang)
      sleep 30
      exit 0
      ;;
  esac
  if [ -f "$remote_items_file" ]; then
    cp "$remote_items_file" "$cached_items_file"
  fi
  exit 0
fi

if [ "\${1:-}" = "logout" ] || [ "\${1:-}" = "lock" ]; then
  exit 0
fi

if [ "\${1:-}" = "list" ] && [ "\${2:-}" = "items" ]; then
  count=0
  if [ -f "$list_count_file" ]; then
    count=$(sed -n '1p' "$list_count_file")
  fi
  case "$count" in
    ''|*[!0-9]*) count=0 ;;
  esac
  count=$((count + 1))
  printf '%s\\n' "$count" > "$list_count_file"

  mode=success
  if [ -f "$state_file" ]; then
    mode=$(sed -n '1p' "$state_file")
  fi
  printf 'debug: %s session %s\\n' "$FAKE_BW_EMAIL" "\${BW_SESSION:-}" >&2
  case "$mode" in
    always-fail)
      exit 1
      ;;
    invalid-json)
      printf '%s\\n' 'not-json'
      exit 0
      ;;
    fail-until:*)
      limit=\${mode#fail-until:}
      if [ "$count" -le "$limit" ]; then
        exit 1
      fi
      ;;
  esac
  items_json="$FAKE_BW_ITEMS_JSON"
  if [ -f "$cached_items_file" ]; then
    items_json=$(cat "$cached_items_file")
  fi
  printf '%s\\n' "$items_json"
  exit 0
fi

if [ "\${1:-}" = "get" ] && [ "\${2:-}" = "item" ]; then
  item_json="$FAKE_BW_ITEM_JSON"
  if [ -f "$cached_items_file" ]; then
    item_json=$(cat "$cached_items_file")
    item_json=$(printf '%s' "$item_json" | sed 's/^\\[//; s/\\]$//')
  fi
  printf '%s\\n' "$item_json"
  exit 0
fi

exit 0
`;

function tomlString(value: string): string {
  return JSON.stringify(value);
}

function readLines(filePath: string): string[] {
  if (!fs.existsSync(filePath)) return [];
  return fs
    .readFileSync(filePath, "utf8")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line !== "");
}

async function stopChild(child: ChildProcess): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return;
  const closed = once(child, "close").catch(() => {});
  child.kill("SIGTERM");
  const timer = setTimeout(() => child.kill("SIGKILL"), 3_000);
  await closed;
  clearTimeout(timer);
}

async function waitForDaemon(
  child: ChildProcess,
  socketPath: string,
  getStderr: () => string,
): Promise<void> {
  let spawnError: Error | undefined;
  child.once("error", (error) => {
    spawnError = error;
  });
  const deadline = Date.now() + 15_000;
  while (Date.now() < deadline) {
    if (spawnError !== undefined) throw spawnError;
    if (child.exitCode !== null) {
      throw new Error(
        `tegatad exited before becoming ready (code ${child.exitCode}); stderr: ${getStderr()}`,
      );
    }
    if (fs.existsSync(socketPath)) {
      try {
        const response = await rawRpc(socketPath, "status", {});
        if (response.result !== undefined) return;
      } catch {
        // 起動途中のソケット接続失敗は、次の試行で確認します。
      }
    }
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error(`timed out waiting for tegatad; stderr: ${getStderr()}`);
}

export async function startColdStartDaemon(opts: {
  mode: FakeBwMode;
  namespace: string;
  serverUrl: string;
  canaries: ColdStartCanaries;
  env?: Record<string, string>;
}): Promise<ColdStartDaemon> {
  const daemonDir = fs.mkdtempSync(
    path.join(os.tmpdir(), "tegatad-cold-start-"),
  );
  const fakeBinDir = path.join(daemonDir, "fake-bin");
  const stateDir = path.join(daemonDir, "state");
  fs.mkdirSync(fakeBinDir, { mode: 0o700 });
  fs.mkdirSync(stateDir, { mode: 0o700 });
  fs.chmodSync(fakeBinDir, 0o700);
  fs.chmodSync(stateDir, 0o700);

  const bwPath = path.join(fakeBinDir, "bw");
  const statePath = path.join(daemonDir, "bw-state");
  const callLogPath = path.join(daemonDir, "bw-calls.log");
  const listCountPath = path.join(daemonDir, "bw-list-count");
  const remoteItemsPath = path.join(daemonDir, "bw-remote-items.json");
  const cachedItemsPath = path.join(daemonDir, "bw-cached-items.json");
  const socketPath = path.join(daemonDir, "tegatad.sock");
  const configPath = path.join(daemonDir, "config.toml");
  fs.writeFileSync(bwPath, FAKE_BW, { mode: 0o700 });
  fs.writeFileSync(statePath, `${opts.mode}\n`, { mode: 0o600 });
  fs.writeFileSync(callLogPath, "", { mode: 0o600 });

  const item = {
    id: opts.canaries.itemId,
    name: opts.canaries.itemName,
    login: { uris: [{ uri: "https://cold-start.invalid/login" }] },
  };
  fs.writeFileSync(remoteItemsPath, JSON.stringify([item]), { mode: 0o600 });
  fs.writeFileSync(cachedItemsPath, JSON.stringify([item]), { mode: 0o600 });
  const config = [
    `socket_path = ${tomlString(socketPath)}`,
    `state_dir = ${tomlString(stateDir)}`,
    `audit_log_path = ${tomlString(path.join(stateDir, "audit.log"))}`,
    `allowed_uids = [${os.userInfo().uid}]`,
    "",
    "[[providers]]",
    `namespace = ${tomlString(opts.namespace)}`,
    'type = "bitwarden-cli"',
    `server_url = ${tomlString(opts.serverUrl)}`,
    `email = ${tomlString(opts.canaries.email)}`,
    `askpass_cmd = ${tomlString(`echo '${opts.canaries.masterPassword}'`)}`,
    "session_ttl_secs = 300",
    "",
  ].join("\n");
  fs.writeFileSync(configPath, config, { mode: 0o600 });

  let stderr = "";
  const inheritedPath = process.env.PATH ?? "/usr/bin:/bin";
  const child = spawn(bins().tegatad, ["--config", configPath], {
    cwd: daemonDir,
    env: {
      ...process.env,
      ...opts.env,
      PATH: `${fakeBinDir}${path.delimiter}${inheritedPath}`,
      FAKE_BW_CALL_LOG: callLogPath,
      FAKE_BW_STATE_FILE: statePath,
      FAKE_BW_LIST_COUNT_FILE: listCountPath,
      FAKE_BW_REMOTE_ITEMS_FILE: remoteItemsPath,
      FAKE_BW_CACHED_ITEMS_FILE: cachedItemsPath,
      FAKE_BW_SERVER_URL: opts.serverUrl,
      FAKE_BW_SESSION: opts.canaries.sessionKey,
      FAKE_BW_EMAIL: opts.canaries.email,
      FAKE_BW_ITEMS_JSON: JSON.stringify([item]),
      FAKE_BW_ITEM_JSON: JSON.stringify(item),
    },
    stdio: ["ignore", "ignore", "pipe"],
  });
  child.stderr?.setEncoding("utf8");
  child.stderr?.on("data", (chunk: string) => {
    stderr += chunk;
  });

  try {
    await waitForDaemon(child, socketPath, () => stderr);
  } catch (error) {
    await stopChild(child);
    fs.rmSync(daemonDir, { recursive: true, force: true });
    throw error;
  }

  return {
    socketPath,
    namespace: opts.namespace,
    canaries: opts.canaries,
    setBwMode(mode) {
      fs.writeFileSync(statePath, `${mode}\n`, { mode: 0o600 });
    },
    setBwItemName(name) {
      fs.writeFileSync(remoteItemsPath, JSON.stringify([{ ...item, name }]), {
        mode: 0o600,
      });
    },
    callLog: () => readLines(callLogPath),
    loginCalls: () =>
      readLines(callLogPath).filter((line) => {
        const args = line.split(/\s+/);
        return args[0] === "login" && args[1] !== "--check";
      }),
    syncCalls: () =>
      readLines(callLogPath).filter((line) => line.split(/\s+/)[0] === "sync"),
    listItemsCalls: () =>
      readLines(callLogPath).filter((line) => {
        const args = line.split(/\s+/);
        return args[0] === "list" && args[1] === "items";
      }),
    stderr: () => stderr,
    stop: async () => {
      await stopChild(child);
      fs.rmSync(daemonDir, { recursive: true, force: true });
    },
  };
}
