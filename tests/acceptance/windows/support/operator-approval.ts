import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import readline from "node:readline";
import { sha256Hex } from "./phase4.js";
import { psRun, rigEnv, winAgentTempWsl } from "./winrig.js";

export interface ApprovalDaemon {
  pipeName: string;
  stateDirWsl: string;
  stderr(): string;
  stop(): Promise<void>;
}

export async function startApprovalDaemon(opts: {
  allowedSids: string[];
  approveTimeoutSecs: number;
  credId: string;
  targetUrl: string;
}): Promise<ApprovalDaemon> {
  const tempWsl = await winAgentTempWsl();
  const tempWin = (await psRun("$env:TEMP")).stdout.trim();
  const id = Math.random().toString(16).slice(2, 10);
  const dirWsl = path.join(tempWsl, `tegata-approval-${id}`);
  const stateDirWsl = path.join(dirWsl, "state");
  fs.mkdirSync(stateDirWsl, { recursive: true });
  const dirWin = `${tempWin}\\tegata-approval-${id}`;
  const pipeName = `tegata-approval-${id}`;
  fs.writeFileSync(
    path.join(stateDirWsl, "token_hash"),
    `${sha256Hex("acceptance-token")}\n`,
  );
  fs.writeFileSync(
    path.join(dirWsl, "config.toml"),
    [
      `pipe_name = ${JSON.stringify(pipeName)}`,
      "tcp_port = 0",
      `state_dir = ${JSON.stringify(`${dirWin}\\state`)}`,
      `audit_log_path = ${JSON.stringify(`${dirWin}\\state\\audit.log`)}`,
      `token_hash_path = ${JSON.stringify(`${dirWin}\\state\\token_hash`)}`,
      `allowed_sids = [${opts.allowedSids.map((sid) => JSON.stringify(sid)).join(", ")}]`,
      "approve_operator = true",
      `approve_timeout_secs = ${opts.approveTimeoutSecs}`,
      "[[providers]]",
      'namespace = "mock"',
      'type = "mock"',
      "[[providers.entries]]",
      `id = ${JSON.stringify(opts.credId)}`,
      'name = "Acceptance Test Site"',
      `uri = ${JSON.stringify(opts.targetUrl)}`,
      'kind = "login"',
      'username = "acceptance"',
      'password = "acceptance"',
    ].join("\n") + "\n",
  );
  const child = spawn(
    rigEnv().tegatadExe,
    ["--config", `${dirWin}\\config.toml`, "--foreground"],
    { stdio: ["ignore", "pipe", "pipe"] },
  );
  let stderr = "";
  child.stderr?.setEncoding("utf8");
  child.stderr?.on("data", (data: string) => {
    stderr += data;
  });
  const rl = readline.createInterface({ input: child.stdout });
  await new Promise<void>((resolve, reject) => {
    rl.on("line", (line) => {
      try {
        if (JSON.parse(line).ready === true) resolve();
      } catch {}
    });
    child.once("exit", (code) =>
      reject(new Error(`foreground daemon exited (${code})`)),
    );
  });
  return {
    pipeName,
    stateDirWsl,
    stderr: () => stderr,
    stop: async () => {
      if (child.exitCode === null) {
        child.kill("SIGTERM");
        await new Promise<void>((resolve) =>
          child.once("exit", () => resolve()),
        );
      }
      fs.rmSync(dirWsl, { recursive: true, force: true });
    },
  };
}
