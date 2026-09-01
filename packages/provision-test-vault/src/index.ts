#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import {
  createCipheriv,
  createHmac,
  generateKeyPairSync,
  pbkdf2Sync,
  randomBytes,
} from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const KDF_ITERATIONS = 600_000;
const ENC_TYPE = "2";

type ProvisionItem = {
  name: string;
  uri: string;
  username: string;
  password: string;
  totp_seed?: string;
};

type Arguments = {
  server: string;
  email: string;
  password: string;
};

function parseArguments(argv: string[]): Arguments {
  const values = new Map<string, string>();
  for (let index = 0; index < argv.length; index += 1) {
    const key = argv[index];
    if (
      key?.startsWith("--") &&
      argv[index + 1] &&
      !argv[index + 1].startsWith("--")
    ) {
      values.set(key.slice(2), argv[index + 1]);
      index += 1;
    }
  }
  const server = values.get("server");
  const email = values.get("email");
  const password = values.get("password");
  if (!server || !email || !password) {
    throw new Error("--server, --email, and --password are required");
  }
  return { server, email, password };
}

function hkdfExpand(prk: Buffer, info: string, length: number): Buffer {
  const infoBytes = Buffer.from(info, "utf8");
  const output: Buffer[] = [];
  let previous = Buffer.alloc(0);
  for (let counter = 1; Buffer.concat(output).length < length; counter += 1) {
    previous = createHmac("sha256", prk)
      .update(Buffer.concat([previous, infoBytes, Buffer.from([counter])]))
      .digest();
    output.push(previous);
  }
  return Buffer.concat(output).subarray(0, length);
}

function encrypt(value: Buffer, key: Buffer): string {
  const iv = randomBytes(16);
  const cipher = createCipheriv("aes-256-cbc", key.subarray(0, 32), iv);
  const data = Buffer.concat([cipher.update(value), cipher.final()]);
  const mac = createHmac("sha256", key.subarray(32))
    .update(Buffer.concat([iv, data]))
    .digest();
  return [
    `${ENC_TYPE}.${iv.toString("base64")}`,
    data.toString("base64"),
    mac.toString("base64"),
  ].join("|");
}

function deriveKeys(
  email: string,
  password: string,
): {
  masterPasswordHash: string;
  key: string;
  privateKey: string;
  publicKey: string;
} {
  const masterKey = pbkdf2Sync(
    password,
    email.toLowerCase(),
    KDF_ITERATIONS,
    32,
    "sha256",
  );
  const masterPasswordHash = pbkdf2Sync(
    masterKey,
    password,
    1,
    32,
    "sha256",
  ).toString("base64");
  const stretchedKey = Buffer.concat([
    hkdfExpand(masterKey, "enc", 32),
    hkdfExpand(masterKey, "mac", 32),
  ]);
  const symmetricKey = randomBytes(64);
  const { publicKey, privateKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicExponent: 0x10001,
  });
  const publicKeyBytes = publicKey.export({ type: "spki", format: "der" });
  const privateKeyBytes = privateKey.export({ type: "pkcs8", format: "der" });
  return {
    masterPasswordHash,
    key: encrypt(symmetricKey, stretchedKey),
    publicKey: Buffer.from(publicKeyBytes).toString("base64"),
    privateKey: encrypt(Buffer.from(privateKeyBytes), symmetricKey),
  };
}

function childEnvironment(
  appDataDir: string,
  extra: Record<string, string> = {},
): NodeJS.ProcessEnv {
  return {
    ...process.env,
    BW_SESSION: undefined,
    BW_APPDATA_DIR: appDataDir,
    BITWARDENCLI_APPDATA_DIR: appDataDir,
    ...extra,
  };
}

const EXCERPT_LIMIT = 2000;

function excerpt(value: string): string {
  const trimmed = value.trim();
  if (trimmed === "") return "<empty>";
  return trimmed.length > EXCERPT_LIMIT
    ? `${trimmed.slice(0, EXCERPT_LIMIT)}…`
    : trimmed;
}

type BwOutput = { stdout: string; stderr: string };

function runBw(
  args: string[],
  appDataDir: string,
  input?: string,
  extra: Record<string, string> = {},
): BwOutput {
  const result = spawnSync("bw", args, {
    env: childEnvironment(appDataDir, extra),
    input,
    encoding: "utf8",
    stdio: ["pipe", "pipe", "pipe"],
  });
  if (result.error) {
    throw new Error(
      `bw ${args[0] ?? "command"} could not run: ${result.error.message}`,
    );
  }
  if (result.status !== 0) {
    const exit =
      result.status === null ? `signal ${result.signal}` : `${result.status}`;
    throw new Error(
      `bw ${args[0] ?? "command"} exited with ${exit}; stderr: ${excerpt(result.stderr)}`,
    );
  }
  return { stdout: result.stdout, stderr: result.stderr };
}

async function registerAccount(
  server: string,
  email: string,
  password: string,
): Promise<void> {
  const keys = deriveKeys(email, password);
  const body = {
    email,
    masterPasswordHash: keys.masterPasswordHash,
    masterPasswordHint: null,
    name: "Tegata Test Vault",
    receiveMarketingEmails: false,
    kdf: 0,
    kdfIterations: KDF_ITERATIONS,
    key: keys.key,
    keys: {
      publicKey: keys.publicKey,
      encryptedPrivateKey: keys.privateKey,
    },
  };
  const request = async (path: string): Promise<Response> =>
    fetch(`${server.replace(/\/$/, "")}${path}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
  let response = await request("/identity/accounts/register");
  if (response.status === 404) {
    response = await request("/api/accounts/register");
  }
  if (response.status === 400) {
    return;
  }
  if (!response.ok) {
    throw new Error(
      `account registration failed with status ${response.status}`,
    );
  }
}

/**
 * Parses bw output that must be JSON, reporting the raw output on failure —
 * bw is known to exit 0 with empty stdout when it loses its session-key
 * persistence race, and the raw capture is what a diagnosis needs.
 */
function parseBwJson(command: string, output: BwOutput): unknown {
  try {
    return JSON.parse(output.stdout);
  } catch {
    throw new Error(
      `${command} returned unparseable JSON; stdout: ${excerpt(output.stdout)}; stderr: ${excerpt(output.stderr)}`,
    );
  }
}

function buildItem(template: unknown, item: ProvisionItem): string {
  const value = template as Record<string, unknown>;
  const login = (value.login ?? {}) as Record<string, unknown>;
  value.type = 1;
  value.name = item.name;
  value.login = {
    ...login,
    uris: [{ match: null, uri: item.uri }],
    username: item.username,
    password: item.password,
    totp: item.totp_seed ?? null,
  };
  return JSON.stringify(value);
}

async function main(): Promise<void> {
  const { server, email, password } = parseArguments(process.argv.slice(2));
  const appDataDir = mkdtempSync(join(tmpdir(), "tegata-provision-"));
  try {
    await registerAccount(server, email, password);
    runBw(["config", "server", server], appDataDir);
    const passwordFile = join(appDataDir, "master-password");
    writeFileSync(passwordFile, password, { encoding: "utf8", mode: 0o600 });
    let session: string;
    try {
      session = runBw(
        ["login", email, "--raw", "--passwordfile", passwordFile],
        appDataDir,
      ).stdout.split(/\r?\n/, 1)[0];
    } finally {
      rmSync(passwordFile, { force: true });
    }
    if (!session) {
      throw new Error("bw login returned no session");
    }
    const input = await new Promise<string>((resolve, reject) => {
      let value = "";
      process.stdin.setEncoding("utf8");
      process.stdin.on("data", (chunk: string) => {
        value += chunk;
      });
      process.stdin.on("end", () => resolve(value));
      process.stdin.on("error", reject);
    });
    const items = JSON.parse(input) as ProvisionItem[];
    let created = 0;
    for (const item of items) {
      const template = parseBwJson(
        "bw get template",
        runBw(["get", "template", "item"], appDataDir, undefined, {
          BW_SESSION: session,
        }),
      );
      const encoded = runBw(["encode"], appDataDir, buildItem(template, item), {
        BW_SESSION: session,
      }).stdout.trim();
      runBw(["create", "item", encoded], appDataDir, undefined, {
        BW_SESSION: session,
      });
      created += 1;
    }
    process.stdout.write(`${JSON.stringify({ ok: true, created })}\n`);
  } finally {
    rmSync(appDataDir, { recursive: true, force: true });
  }
}

main().catch((error: unknown) => {
  const message =
    error instanceof Error ? error.message : "provisioning failed";
  process.stderr.write(`provision-test-vault: ${message}\n`);
  process.exitCode = 1;
});
