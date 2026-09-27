import type { ChildProcess } from "node:child_process";
import { execFileSync, spawn } from "node:child_process";
import { chmod, mkdir } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

type Placement = "split" | "tab" | "zoomed" | "overlay";
type Direction = "right" | "down";
const TARGET_ID_PATTERN = /^[A-Za-z0-9_-]{1,128}$/;

type OpenOptions = {
  endpoint: string;
  targetId: string;
  url?: string;
  placement: Placement;
  direction?: Direction;
};

type CdpMessage = {
  id?: number;
  result?: { targetInfo?: { url?: unknown } };
  error?: { message?: string };
};

async function main(): Promise<number> {
  try {
    const options = parseArgs(process.argv.slice(2));
    const herdr = findHerdr();
    const url =
      options.url ?? (await targetUrl(options.endpoint, options.targetId));
    const stateFile = await createStateFile(options.targetId);
    const chromeShim = resolve(
      dirname(fileURLToPath(import.meta.url)),
      "../bin/tegata-herdr-chrome",
    );
    const args = [
      "plugin",
      "pane",
      "open",
      "--plugin",
      "official.browser",
      "--entrypoint",
      "browser",
      "--placement",
      options.placement,
    ];
    if (options.direction) {
      args.push("--direction", options.direction);
    }
    args.push(
      "--env",
      `HERDR_BROWSER_CHROME=${chromeShim}`,
      "--env",
      `HERDR_BROWSER_DAEMON_STATE=${stateFile}`,
      "--env",
      `HERDR_BROWSER_INITIAL_URL=${url}`,
      "--env",
      `TEGATA_HERDR_ENDPOINT=${options.endpoint}`,
      "--env",
      `TEGATA_HERDR_TARGET_ID=${options.targetId}`,
      "--env",
      `TEGATA_HERDR_NODE=${process.execPath}`,
      "--focus",
    );

    return await runHerdr(herdr, args, {
      ...process.env,
      HERDR_BROWSER_CHROME: chromeShim,
      HERDR_BROWSER_DAEMON_STATE: stateFile,
      HERDR_BROWSER_INITIAL_URL: url,
      TEGATA_HERDR_ENDPOINT: options.endpoint,
      TEGATA_HERDR_TARGET_ID: options.targetId,
      TEGATA_HERDR_NODE: process.execPath,
    });
  } catch (error) {
    console.error(
      `tegata-herdr-open: ${error instanceof Error ? error.message : String(error)}`,
    );
    return 1;
  }
}

export function parseArgs(args: string[]): OpenOptions {
  let endpoint: string | undefined;
  let targetId: string | undefined;
  let url: string | undefined;
  let placement: Placement = "split";
  let direction: Direction | undefined;

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    const [name, inlineValue] = splitOption(arg);
    if (
      ![
        "--endpoint",
        "--target-id",
        "--url",
        "--placement",
        "--direction",
      ].includes(name)
    ) {
      throw new Error(`unknown option: ${name}`);
    }
    const value = inlineValue ?? args[++index];
    if (!value || value.startsWith("--")) {
      throw new Error(`${name} requires a value`);
    }
    if (name === "--endpoint") {
      endpoint = value;
    } else if (name === "--target-id") {
      targetId = value;
    } else if (name === "--url") {
      url = value;
    } else if (name === "--placement") {
      if (!isPlacement(value)) {
        throw new Error("--placement must be split, tab, zoomed, or overlay");
      }
      placement = value;
    } else if (name === "--direction") {
      if (!isDirection(value)) {
        throw new Error("--direction must be right or down");
      }
      direction = value;
    }
  }

  if (!endpoint) {
    throw new Error("--endpoint is required");
  }
  if (!targetId) {
    throw new Error("--target-id is required");
  }
  if (!isValidTargetId(targetId)) {
    throw new Error(
      "--target-id must contain 1-128 ASCII letters, digits, underscores, or hyphens",
    );
  }
  if (!isWebSocketEndpoint(endpoint)) {
    throw new Error("--endpoint must be a ws:// or wss:// URL");
  }
  return { endpoint, targetId, url, placement, direction };
}

function splitOption(arg: string): [string, string | undefined] {
  const separator = arg.indexOf("=");
  return separator < 0
    ? [arg, undefined]
    : [arg.slice(0, separator), arg.slice(separator + 1)];
}

async function createStateFile(targetId: string): Promise<string> {
  const runtimeDir = process.env.XDG_RUNTIME_DIR?.trim() || "/tmp";
  const stateDir = join(runtimeDir, "tegata-herdr");
  await mkdir(stateDir, { recursive: true, mode: 0o700 });
  await chmod(stateDir, 0o700);
  return join(stateDir, `${targetId}.json`);
}

function findHerdr(): string {
  try {
    const path = execFileSync("which", ["herdr"], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
    if (path) {
      return path;
    }
  } catch {
    // PATH 上の herdr が見つからない場合は下で理由を示します。
  }
  throw new Error("herdr was not found on PATH");
}

async function targetUrl(endpoint: string, targetId: string): Promise<string> {
  const socket = await connectWebSocket(endpoint);
  try {
    const response = await request(socket, "Target.getTargetInfo", {
      targetId,
    });
    const url = response.result?.targetInfo?.url;
    if (response.error || typeof url !== "string") {
      throw new Error("Target.getTargetInfo did not return a target URL");
    }
    return url;
  } finally {
    socket.close();
  }
}

type LauncherWebSocket = {
  readyState: number;
  send(data: string): void;
  close(): void;
  addEventListener(
    type: string,
    listener: (event: { data?: unknown }) => void,
  ): void;
};

async function connectWebSocket(endpoint: string): Promise<LauncherWebSocket> {
  return await new Promise((resolve, reject) => {
    let socket: LauncherWebSocket;
    try {
      socket = new globalThis.WebSocket(
        endpoint,
      ) as unknown as LauncherWebSocket;
    } catch (error) {
      reject(error instanceof Error ? error : new Error(String(error)));
      return;
    }
    socket.addEventListener("open", () => resolve(socket));
    socket.addEventListener("error", () =>
      reject(new Error("failed to connect to the tegata CDP endpoint")),
    );
    socket.addEventListener("close", () =>
      reject(new Error("the tegata CDP endpoint closed")),
    );
  });
}

async function request(
  socket: LauncherWebSocket,
  method: string,
  params: Record<string, unknown>,
): Promise<CdpMessage> {
  return await new Promise((resolve, reject) => {
    const timeout = setTimeout(
      () => reject(new Error("timed out waiting for Target.getTargetInfo")),
      10_000,
    );
    socket.addEventListener("message", (event) => {
      try {
        const message = JSON.parse(String(event.data)) as CdpMessage;
        if (message.id === 1) {
          clearTimeout(timeout);
          resolve(message);
        }
      } catch {
        clearTimeout(timeout);
        reject(new Error("received an invalid CDP response"));
      }
    });
    socket.send(JSON.stringify({ id: 1, method, params }));
  });
}

function runHerdr(
  command: string,
  args: string[],
  env: NodeJS.ProcessEnv,
): Promise<number> {
  return new Promise((resolve, reject) => {
    const child: ChildProcess = spawn(command, args, {
      env,
      stdio: "inherit",
    });
    child.once("error", (error) =>
      reject(new Error(`failed to start herdr: ${error.message}`)),
    );
    child.once("exit", (code) => resolve(code ?? 1));
  });
}

function isPlacement(value: string): value is Placement {
  return (
    value === "split" ||
    value === "tab" ||
    value === "zoomed" ||
    value === "overlay"
  );
}

function isDirection(value: string): value is Direction {
  return value === "right" || value === "down";
}

function isWebSocketEndpoint(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === "ws:" || url.protocol === "wss:";
  } catch {
    return false;
  }
}

export function isValidTargetId(value: string): boolean {
  return TARGET_ID_PATTERN.test(value);
}

const isMainModule =
  process.argv[1] !== undefined &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href;

if (isMainModule) {
  void main()
    .then((code) => {
      process.exitCode = code;
    })
    .catch((error: unknown) => {
      console.error(
        `tegata-herdr-open: ${error instanceof Error ? error.message : String(error)}`,
      );
      process.exitCode = 1;
    });
}
