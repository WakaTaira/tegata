import { execFile } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

export interface LeakGuardOptions {
  leakscanBin: string;
  agentVisibleRoots: string[];
  psSampleIntervalMs?: number;
  psSampleCommands?: string[][];
}

export interface LeakHit {
  surface: "observed" | "fs" | "ps";
  label: string;
  canaryLabel: string;
  encoding: string;
}

export interface LeakGuard {
  readonly runId: string;
  canary(label: string): string;
  observe(label: string, value: unknown): void;
  collectLeaks(): Promise<LeakHit[]>;
  assertNoLeaks(): Promise<void>;
  dispose(): Promise<void>;
}

interface FileSnapshot {
  size: number;
  mtimeMs: number;
}

interface ObservedValue {
  label: string;
  jsonString: string;
}

interface ScanHit {
  path: string;
  canary_index: number;
  encoding: string;
  byte_offset: number;
}

interface ScanReport {
  hits: ScanHit[];
}

interface ScanTarget {
  surface: "observed" | "fs" | "ps";
  label: string;
  path: string;
}

interface PsSample {
  command: string;
  stdout: string;
}

function formatPsSamplerError(command: string, error: unknown): string {
  const errorObject =
    typeof error === "object" && error !== null
      ? (error as { code?: unknown; signal?: unknown })
      : undefined;
  if (typeof errorObject?.signal === "string") {
    return `${command}: killed by signal ${errorObject.signal}`;
  }
  if (typeof errorObject?.code === "number") {
    return `${command}: exited with code ${errorObject.code}`;
  }
  if (typeof errorObject?.code === "string") {
    return `${command}: failed to start: ${errorObject.code}`;
  }
  return `${command}: failed to start`;
}

function snapshotFiles(
  roots: string[],
  observationErrors: string[] = [],
): Map<string, FileSnapshot> {
  const snapshot = new Map<string, FileSnapshot>();

  for (const root of roots) {
    addFilesToSnapshot(path.resolve(root), snapshot, observationErrors, true);
  }

  return snapshot;
}

function isIgnorableFsError(error: unknown): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    (error.code === "EACCES" || error.code === "ENOENT")
  );
}

function isIgnorableEnvironError(error: unknown): boolean {
  return (
    isIgnorableFsError(error) ||
    (typeof error === "object" &&
      error !== null &&
      "code" in error &&
      error.code === "ESRCH")
  );
}

function addFilesToSnapshot(
  directory: string,
  snapshot: Map<string, FileSnapshot>,
  observationErrors: string[] = [],
  isWatchedRoot = false,
): void {
  try {
    if (!fs.lstatSync(directory).isDirectory()) {
      return;
    }
  } catch (error) {
    if (isWatchedRoot || !isIgnorableFsError(error)) {
      observationErrors.push(`lstat ${directory}: ${String(error)}`);
    }
    return;
  }

  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(directory, { withFileTypes: true });
  } catch (error) {
    if (isWatchedRoot || !isIgnorableFsError(error)) {
      observationErrors.push(`readdir ${directory}: ${String(error)}`);
    }
    return;
  }

  for (const entry of entries) {
    const entryPath = path.join(directory, entry.name);
    if (entry.isSymbolicLink()) {
      continue;
    }

    if (entry.isDirectory()) {
      addFilesToSnapshot(entryPath, snapshot, observationErrors);
      continue;
    }

    if (!entry.isFile()) {
      continue;
    }

    try {
      const stats = fs.lstatSync(entryPath);
      snapshot.set(entryPath, { size: stats.size, mtimeMs: stats.mtimeMs });
    } catch (error) {
      if (!isIgnorableFsError(error)) {
        observationErrors.push(`lstat ${entryPath}: ${String(error)}`);
      }
    }
  }
}

function changedFiles(
  roots: string[],
  initialSnapshot: Map<string, FileSnapshot>,
  observationErrors: string[],
): string[] {
  const currentSnapshot = snapshotFiles(roots, observationErrors);
  const changed: string[] = [];

  for (const [filePath, current] of currentSnapshot) {
    const initial = initialSnapshot.get(filePath);
    if (
      initial === undefined ||
      initial.size !== current.size ||
      initial.mtimeMs !== current.mtimeMs
    ) {
      changed.push(filePath);
    }
  }

  return changed;
}

function runLeakscan(
  leakscanBin: string,
  canariesPath: string,
  targets: string[],
): Promise<ScanReport> {
  return new Promise((resolve, reject) => {
    execFile(
      leakscanBin,
      ["--canaries", canariesPath, "--json", ...targets],
      { encoding: "utf8" },
      (error, stdout, stderr) => {
        const exitCode =
          typeof error?.code === "number" ? error.code : undefined;
        if (error !== null && exitCode !== 1) {
          const details = stderr.trim();
          reject(
            new Error(
              `leakscan failed${exitCode === 2 ? " with exit code 2" : ""}: ${details || error.message}`,
            ),
          );
          return;
        }

        try {
          resolve(JSON.parse(stdout) as ScanReport);
        } catch (parseError) {
          reject(
            new Error(
              `leakscan returned invalid JSON: ${parseError instanceof Error ? parseError.message : String(parseError)}`,
            ),
          );
        }
      },
    );
  });
}

export async function createLeakGuard(
  opts: LeakGuardOptions,
): Promise<LeakGuard> {
  const runId = crypto.randomBytes(8).toString("hex");
  const canaries = new Map<string, string>();
  const observed: ObservedValue[] = [];
  const psSamples: PsSample[] = [];
  const observationErrors: string[] = [];
  const initialSnapshot = snapshotFiles(
    opts.agentVisibleRoots,
    observationErrors,
  );
  const workDir = await fs.promises.mkdtemp(
    path.join(os.tmpdir(), "tegata-leak-"),
  );
  const observedDir = path.join(workDir, "observed");
  const fsDir = path.join(workDir, "fs");
  const psDir = path.join(workDir, "ps");
  const environDir = path.join(workDir, "environ");
  await Promise.all([
    fs.promises.mkdir(observedDir),
    fs.promises.mkdir(fsDir),
    fs.promises.mkdir(psDir),
    fs.promises.mkdir(environDir),
  ]);

  const pendingSamples = new Set<Promise<void>>();
  let samplingStopped = false;
  let interval: NodeJS.Timeout | undefined = setInterval(() => {
    const sample = new Promise<void>((resolve) => {
      const commands = opts.psSampleCommands ?? [["ps", "-eo", "args"]];
      Promise.all(
        commands.map(
          (argv) =>
            new Promise<void>((resolveCommand) => {
              const [command, ...args] = argv;
              if (command === undefined) {
                observationErrors.push("ps: sampler command is empty");
                resolveCommand();
                return;
              }
              try {
                execFile(
                  command,
                  args,
                  { encoding: "utf8" },
                  (error, stdout) => {
                    if (stdout !== "") {
                      psSamples.push({ command, stdout });
                    }
                    if (error !== null) {
                      observationErrors.push(
                        formatPsSamplerError(command, error),
                      );
                    }
                    resolveCommand();
                  },
                );
              } catch (error) {
                observationErrors.push(formatPsSamplerError(command, error));
                resolveCommand();
              }
            }),
        ),
      ).then(() => resolve());
    });
    pendingSamples.add(sample);
    void sample.then(
      () => pendingSamples.delete(sample),
      () => pendingSamples.delete(sample),
    );
  }, opts.psSampleIntervalMs ?? 200);
  interval.unref();

  const stopSampling = async (): Promise<void> => {
    if (samplingStopped) {
      return;
    }
    samplingStopped = true;
    if (interval !== undefined) {
      clearInterval(interval);
      interval = undefined;
    }
    await Promise.all([...pendingSamples]);
  };

  const writeCanaries = async (): Promise<string> => {
    const canariesPath = path.join(workDir, "canaries.json");
    await fs.promises.writeFile(
      canariesPath,
      JSON.stringify({ canaries: [...canaries.values()] }),
    );
    return canariesPath;
  };

  const writeObserved = async (): Promise<ScanTarget[]> => {
    const targets: ScanTarget[] = [];
    await Promise.all(
      observed.map(async (value, index) => {
        const targetPath = path.join(observedDir, `${index}.json`);
        await fs.promises.writeFile(targetPath, value.jsonString);
        targets.push({
          surface: "observed",
          label: value.label,
          path: targetPath,
        });
      }),
    );
    return targets;
  };

  const writePsSamples = async (): Promise<ScanTarget[]> => {
    const targets: ScanTarget[] = [];
    await Promise.all(
      psSamples.map(async (sample, index) => {
        const targetPath = path.join(psDir, `${index}.txt`);
        await fs.promises.writeFile(targetPath, sample.stdout);
        targets.push({
          surface: "ps",
          label: `ps-sample-${index}-${path.basename(sample.command)}`,
          path: targetPath,
        });
      }),
    );
    return targets;
  };

  const writeEnvironSamples = async (): Promise<ScanTarget[]> => {
    const targets: ScanTarget[] = [];
    let entries: string[];
    try {
      entries = await fs.promises.readdir("/proc");
    } catch (error) {
      observationErrors.push(`readdir /proc: ${String(error)}`);
      return targets;
    }

    for (const entry of entries) {
      if (!/^\d+$/.test(entry)) {
        continue;
      }
      const environPath = path.join("/proc", entry, "environ");
      let contents: Buffer;
      try {
        contents = await fs.promises.readFile(environPath);
      } catch (error) {
        if (!isIgnorableEnvironError(error)) {
          observationErrors.push(`read ${environPath}: ${String(error)}`);
        }
        continue;
      }
      const targetPath = path.join(environDir, `${entry}.bin`);
      await fs.promises.writeFile(targetPath, contents);
      targets.push({
        surface: "ps",
        label: `environ-${entry}`,
        path: targetPath,
      });
    }
    return targets;
  };

  const throwObservationErrors = (): void => {
    if (observationErrors.length > 0) {
      throw new Error(
        `Leak observation failed: ${observationErrors.join("; ")}`,
      );
    }
  };

  const collectLeaks = async (): Promise<LeakHit[]> => {
    await Promise.all([...pendingSamples]);
    const canaryEntries = [...canaries.entries()];
    const environTargets = await writeEnvironSamples();
    throwObservationErrors();
    if (canaryEntries.length === 0) {
      return [];
    }

    const [canariesPath, observedTargets, psTargets] = await Promise.all([
      writeCanaries(),
      writeObserved(),
      writePsSamples(),
    ]);
    const fsTargets: ScanTarget[] = [];
    await Promise.all(
      changedFiles(
        opts.agentVisibleRoots,
        initialSnapshot,
        observationErrors,
      ).map(async (filePath, index) => {
        const targetPath = path.join(fsDir, `${index}`);
        try {
          await fs.promises.copyFile(filePath, targetPath);
        } catch (error) {
          const errorCode =
            typeof error === "object" && error !== null && "code" in error
              ? error.code
              : undefined;
          if (errorCode === "ENOENT") {
            return;
          }
          observationErrors.push(
            `copy fs target: ${typeof errorCode === "string" ? errorCode : "unknown error"}`,
          );
          return;
        }
        fsTargets.push({
          surface: "fs",
          label: filePath,
          path: targetPath,
        });
      }),
    );
    throwObservationErrors();
    const scanTargets = [
      ...observedTargets,
      ...fsTargets,
      ...psTargets,
      ...environTargets,
    ];
    if (scanTargets.length === 0) {
      return [];
    }

    const report = await runLeakscan(
      opts.leakscanBin,
      canariesPath,
      scanTargets.map((target) => target.path),
    );
    const targetByPath = new Map(
      scanTargets.map((target) => [target.path, target]),
    );
    const labelByCanaryIndex = canaryEntries.map(([label]) => label);

    return report.hits.map((hit) => {
      const target = targetByPath.get(hit.path);
      if (target === undefined) {
        throw new Error(
          `leakscan returned an unknown target path: ${hit.path}`,
        );
      }
      const canaryLabel = labelByCanaryIndex[hit.canary_index];
      if (canaryLabel === undefined) {
        throw new Error(
          `leakscan returned an unknown canary index: ${hit.canary_index}`,
        );
      }
      return {
        surface: target.surface,
        label: target.label,
        canaryLabel,
        encoding: hit.encoding,
      };
    });
  };

  let disposePromise: Promise<void> | undefined;
  return {
    runId,
    canary(label: string): string {
      const existing = canaries.get(label);
      if (existing !== undefined) {
        return existing;
      }
      const value = `LEAK_CANARY_${runId}_${label}_${crypto.randomBytes(16).toString("hex")}`;
      canaries.set(label, value);
      return value;
    },
    observe(label: string, value: unknown): void {
      let jsonString: string | undefined;
      try {
        jsonString = JSON.stringify(value);
      } catch {
        jsonString = undefined;
      }
      observed.push({ label, jsonString: jsonString ?? "[unserializable]" });
    },
    collectLeaks,
    async assertNoLeaks(): Promise<void> {
      await stopSampling();
      const hits = await collectLeaks();
      if (hits.length > 0) {
        const summary = hits.map(({ surface, label, encoding }) => ({
          surface,
          label,
          encoding,
        }));
        throw new Error(`Canary leak detected: ${JSON.stringify(summary)}`);
      }
    },
    dispose(): Promise<void> {
      if (disposePromise === undefined) {
        disposePromise = (async () => {
          await stopSampling();
          await fs.promises.rm(workDir, { recursive: true, force: true });
        })();
      }
      return disposePromise;
    },
  };
}
