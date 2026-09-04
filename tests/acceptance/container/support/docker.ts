/**
 * Docker plumbing for the Phase 4b container suite. Owned by the acceptance
 * suite (gauntlet); do not modify during implementation.
 *
 * Everything in this file is a pinned test-rig contract:
 *   - env TEGATA_DOCKER (default "docker"; whitespace-separated, so
 *     "sudo docker" works) is the docker CLI. When `${TEGATA_DOCKER} info`
 *     fails the whole suite is skipped.
 *   - the suite creates its own user-defined bridge network (subnet
 *     TEGATA_TEST_SUBNET, default 172.30.255.0/24; bridge interface
 *     TEGATA_TEST_BRIDGE, default tegata-test0) and the host daemon binds the
 *     network's gateway address. Containers reach the host only through that
 *     address.
 *   - containers are a plain image (TEGATA_TEST_IMAGE, default
 *     debian:bookworm-slim) with the Nix store closure of the tools they run
 *     (node, tegata-bridge, leakscan) bind-mounted read-only. Nothing else of
 *     the host is mounted: no docker socket, no --privileged, no state_dir.
 *   - everything the suite creates carries the label ACCEPTANCE_LABEL so a
 *     later run can remove what an aborted run left behind.
 */
import { spawn, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import fs from "node:fs";

export const ACCEPTANCE_LABEL = "tegata.acceptance=phase4b";

/** The docker CLI as argv (`sudo docker` splits into two words). */
export function dockerCommand(): string[] {
  const raw = process.env.TEGATA_DOCKER?.trim();
  return raw !== undefined && raw !== "" ? raw.split(/\s+/) : ["docker"];
}

let cachedAvailability: boolean | undefined;

/** True when `${TEGATA_DOCKER} info` succeeds (checked once per process). */
export function dockerAvailable(): boolean {
  if (cachedAvailability === undefined) {
    const [command, ...prefix] = dockerCommand();
    const res = spawnSync(command, [...prefix, "info"], {
      stdio: "ignore",
      timeout: 30_000,
    });
    cachedAvailability = res.status === 0;
  }
  return cachedAvailability;
}

export interface DockerOptions {
  input?: string;
  allowFailure?: boolean;
  timeoutMs?: number;
}

export interface DockerResult {
  status: number | null;
  stdout: string;
  stderr: string;
}

/** Run one docker CLI command to completion; throws on failure by default. */
export function docker(args: string[], opts: DockerOptions = {}): DockerResult {
  const [command, ...prefix] = dockerCommand();
  const res = spawnSync(command, [...prefix, ...args], {
    encoding: "utf8",
    input: opts.input ?? "",
    timeout: opts.timeoutMs ?? 180_000,
    maxBuffer: 64 * 1024 * 1024,
  });
  if (res.error) throw res.error;
  if (res.status !== 0 && opts.allowFailure !== true) {
    throw new Error(
      `docker ${args.slice(0, 2).join(" ")} failed (status ${res.status}): ${res.stderr.trim()}`,
    );
  }
  return { status: res.status, stdout: res.stdout, stderr: res.stderr };
}

/**
 * Run one docker CLI command to completion without blocking the event loop.
 * Used for everything that may take long (probes, scans, `docker exec` of
 * container-side tools): a blocked loop stalls vitest's worker RPC and
 * surfaces as an unhandled "Timeout calling onTaskUpdate".
 */
export function dockerAsync(
  args: string[],
  opts: DockerOptions = {},
): Promise<DockerResult> {
  const [command, ...prefix] = dockerCommand();
  return new Promise((resolve, reject) => {
    const child = spawn(command, [...prefix, ...args], {
      stdio: ["pipe", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => {
      stdout += chunk;
    });
    child.stderr.setEncoding("utf8");
    child.stderr.on("data", (chunk: string) => {
      stderr += chunk;
    });
    const timer = setTimeout(
      () => child.kill("SIGKILL"),
      opts.timeoutMs ?? 180_000,
    );
    child.once("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.once("close", (status) => {
      clearTimeout(timer);
      if (status !== 0 && opts.allowFailure !== true) {
        reject(
          new Error(
            `docker ${args.slice(0, 2).join(" ")} failed (status ${status}): ${stderr.trim()}`,
          ),
        );
        return;
      }
      resolve({ status, stdout, stderr });
    });
    child.stdin.end(opts.input ?? "");
  });
}

const STORE_PATH = /\/nix\/store\/[a-z0-9]{32}-[A-Za-z0-9._+-]+/g;

/**
 * Top-level Nix store paths a binary needs at run time: its own package when
 * it lives in the store, otherwise every store path embedded in the file
 * (ELF interpreter, RUNPATH entries, and anything else it references).
 */
export function storeReferences(file: string): string[] {
  if (file.startsWith("/nix/store/"))
    return [file.split("/").slice(0, 4).join("/")];
  const text = fs.readFileSync(file).toString("latin1");
  const refs = new Set<string>();
  for (const match of text.matchAll(STORE_PATH)) refs.add(match[0]);
  return [...refs].filter((p) => fs.existsSync(p));
}

/** Runtime closure of the given store paths (`nix-store -qR`). */
export function storeClosure(roots: string[]): string[] {
  if (roots.length === 0) return [];
  const res = spawnSync("nix-store", ["-qR", ...roots], { encoding: "utf8" });
  if (res.error) throw res.error;
  if (res.status !== 0)
    throw new Error(`nix-store -qR failed: ${res.stderr.trim()}`);
  return [...new Set(res.stdout.split("\n").filter((line) => line !== ""))];
}

export interface Mount {
  host: string;
  container: string;
  /** Mounts are read-only unless this is explicitly false. */
  readOnly?: boolean;
}

/** Read-only bind mounts of the runtime closure of `binaries`. */
export function closureMounts(binaries: string[]): Mount[] {
  const roots = new Set<string>();
  for (const binary of binaries)
    for (const ref of storeReferences(binary)) roots.add(ref);
  return storeClosure([...roots]).map((p) => ({ host: p, container: p }));
}

export interface TestNetwork {
  name: string;
  subnet: string;
  /** The host-side address of the bridge; the daemon binds here. */
  gateway: string;
  /** Host interface name of the bridge (firewall rules key on it). */
  bridge: string;
  remove(): void;
}

function gatewayOf(subnet: string): string {
  const match = /^(\d+)\.(\d+)\.(\d+)\.\d+\/24$/.exec(subnet);
  if (match === null)
    throw new Error(`TEGATA_TEST_SUBNET must be an IPv4 /24 (got ${subnet})`);
  return `${match[1]}.${match[2]}.${match[3]}.1`;
}

/** Remove containers and networks an earlier, aborted run left behind. */
export function removeStaleResources(): void {
  const containers = docker([
    "ps",
    "-aq",
    "--filter",
    `label=${ACCEPTANCE_LABEL}`,
  ])
    .stdout.split("\n")
    .filter((id) => id !== "");
  if (containers.length > 0)
    docker(["rm", "-f", ...containers], { allowFailure: true });
  const networks = docker([
    "network",
    "ls",
    "-q",
    "--filter",
    `label=${ACCEPTANCE_LABEL}`,
  ])
    .stdout.split("\n")
    .filter((id) => id !== "");
  for (const id of networks)
    docker(["network", "rm", id], { allowFailure: true });
}

/** Create the suite's private bridge network. */
export function createTestNetwork(): TestNetwork {
  removeStaleResources();
  const subnet = process.env.TEGATA_TEST_SUBNET ?? "172.30.255.0/24";
  const gateway = gatewayOf(subnet);
  const bridge = process.env.TEGATA_TEST_BRIDGE ?? "tegata-test0";
  const name = `tegata-acc-${randomBytes(4).toString("hex")}`;
  docker([
    "network",
    "create",
    "--driver",
    "bridge",
    "--subnet",
    subnet,
    "--gateway",
    gateway,
    "--opt",
    `com.docker.network.bridge.name=${bridge}`,
    "--label",
    ACCEPTANCE_LABEL,
    name,
  ]);
  return {
    name,
    subnet,
    gateway,
    bridge,
    remove: () => {
      docker(["network", "rm", name], { allowFailure: true });
    },
  };
}

export interface ExecOptions {
  input?: string;
  env?: Record<string, string>;
  allowFailure?: boolean;
  timeoutMs?: number;
}

export interface Container {
  name: string;
  /** Run a command inside the container to completion (event loop stays free). */
  exec(args: string[], opts?: ExecOptions): Promise<DockerResult>;
  /** Start a long-running command inside the container (`docker exec -d`). */
  execDetached(args: string[], env?: Record<string, string>): void;
  /** Host command line that runs `args` inside the container, stdin attached. */
  execCommandLine(
    args: string[],
    env?: Record<string, string>,
  ): { command: string; args: string[] };
  remove(): void;
}

function envFlags(env: Record<string, string> | undefined): string[] {
  return Object.entries(env ?? {}).flatMap(([key, value]) => [
    "-e",
    `${key}=${value}`,
  ]);
}

/** Start an idle container on `network` with the given read-only mounts. */
export function runContainer(opts: {
  network: string;
  mounts: Mount[];
  image?: string;
}): Container {
  const image =
    opts.image ?? process.env.TEGATA_TEST_IMAGE ?? "debian:bookworm-slim";
  const name = `tegata-acc-${randomBytes(4).toString("hex")}`;
  const volumeFlags = opts.mounts.flatMap((m) => [
    "-v",
    `${m.host}:${m.container}${m.readOnly === false ? "" : ":ro"}`,
  ]);
  docker([
    "run",
    "-d",
    "--name",
    name,
    "--label",
    ACCEPTANCE_LABEL,
    "--network",
    opts.network,
    ...volumeFlags,
    image,
    "sleep",
    "infinity",
  ]);
  const [command, ...prefix] = dockerCommand();
  return {
    name,
    exec: (args, execOpts = {}) =>
      dockerAsync(["exec", "-i", ...envFlags(execOpts.env), name, ...args], {
        input: execOpts.input,
        allowFailure: execOpts.allowFailure,
        timeoutMs: execOpts.timeoutMs,
      }),
    execDetached: (args, env) => {
      docker(["exec", "-d", ...envFlags(env), name, ...args]);
    },
    execCommandLine: (args, env) => ({
      command,
      args: [...prefix, "exec", "-i", ...envFlags(env), name, ...args],
    }),
    remove: () => {
      docker(["rm", "-f", name], { allowFailure: true });
    },
  };
}
