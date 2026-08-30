#!/usr/bin/env node

import { createHmac, randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";
import {
  createServer,
  type IncomingMessage,
  type ServerResponse,
} from "node:http";

interface Credentials {
  username: string;
  password: string;
  totp_seed?: string;
}

const sessions = new Map<string, true>();

function usageError(message: string): never {
  throw new Error(message);
}

function parseArguments(): { port: number; credsFile?: string } {
  let port: number | undefined;
  let credsFile: string | undefined;

  for (let index = 2; index < process.argv.length; index += 1) {
    const argument = process.argv[index];
    if (argument === "--port") {
      const value = process.argv[index + 1];
      if (value === undefined) usageError("--port requires a value");
      port = Number(value);
      if (!Number.isInteger(port) || port < 0 || port > 65535) {
        usageError("--port must be an integer from 0 to 65535");
      }
      index += 1;
    } else if (argument === "--creds-file") {
      const value = process.argv[index + 1];
      if (value === undefined) usageError("--creds-file requires a path");
      credsFile = value;
      index += 1;
    } else {
      usageError(`unknown argument: ${argument}`);
    }
  }

  if (port === undefined) usageError("--port is required");
  return { port, credsFile };
}

function parseCredentials(input: string): Credentials {
  const value: unknown = JSON.parse(input);
  const record = value as Record<string, unknown>;
  if (
    typeof value !== "object" ||
    value === null ||
    typeof record.username !== "string" ||
    typeof record.password !== "string" ||
    ("totp_seed" in record && typeof record.totp_seed !== "string")
  ) {
    throw new Error("credentials must contain username and password strings");
  }
  return value as Credentials;
}

function decodeBase32(input: string, padded: boolean): Buffer | undefined {
  if (padded && input.length % 8 !== 0) return undefined;
  if (!padded && input.includes("=")) return undefined;

  const paddingIndex = input.indexOf("=");
  const content = paddingIndex === -1 ? input : input.slice(0, paddingIndex);
  const padding = paddingIndex === -1 ? "" : input.slice(paddingIndex);
  if (padding.length > 6 || (padding.length > 0 && !/^=+$/.test(padding))) {
    return undefined;
  }
  if (paddingIndex !== -1 && !padded) return undefined;
  if (
    content.length % 8 === 1 ||
    content.length % 8 === 3 ||
    content.length % 8 === 6
  ) {
    return undefined;
  }
  if (padded && padding.length !== (8 - (content.length % 8)) % 8) {
    return undefined;
  }

  let buffer = 0;
  let bits = 0;
  const output: number[] = [];
  for (const character of content) {
    const code = character.charCodeAt(0);
    const value =
      code >= 65 && code <= 90
        ? code - 65
        : code >= 50 && code <= 55
          ? code - 24
          : -1;
    if (value < 0) return undefined;
    buffer = (buffer << 5) | value;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      output.push((buffer >> bits) & 0xff);
    }
  }
  if (bits > 0 && (buffer & ((1 << bits) - 1)) !== 0) return undefined;
  return Buffer.from(output);
}

function totpKey(seed: string): Buffer {
  return (
    decodeBase32(seed, true) ??
    decodeBase32(seed, false) ??
    decodeBase32(seed.toUpperCase(), true) ??
    decodeBase32(seed.toUpperCase(), false) ??
    Buffer.from(seed, "utf8")
  );
}

function totpCode(seed: string, unixTimeSecs: number): string {
  const counter = Math.floor(unixTimeSecs / 30);
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(BigInt(counter));
  const digest = createHmac("sha1", totpKey(seed)).update(message).digest();
  const offset = digest[19] & 0x0f;
  const binary =
    ((digest[offset] & 0x7f) << 24) |
    (digest[offset + 1] << 16) |
    (digest[offset + 2] << 8) |
    digest[offset + 3];
  return String(binary % 1_000_000).padStart(6, "0");
}

function validTotp(seed: string, submitted: string | null): boolean {
  if (submitted === null) return false;
  const now = Math.floor(Date.now() / 1000);
  return [now - 30, now, now + 30].some(
    (time) => time >= 0 && totpCode(seed, time) === submitted,
  );
}

async function readCredentials(
  credsFile: string | undefined,
): Promise<Credentials> {
  if (credsFile !== undefined) {
    return parseCredentials(await readFile(credsFile, "utf8"));
  }
  if (process.stdin.isTTY) {
    throw new Error(
      "credentials must be supplied through stdin or --creds-file",
    );
  }

  let input = "";
  for await (const chunk of process.stdin) input += chunk;
  return parseCredentials(input);
}

function writePage(
  response: ServerResponse,
  body: string,
  headers?: Record<string, string>,
): void {
  response.writeHead(200, {
    "Content-Type": "text/html; charset=utf-8",
    ...headers,
  });
  response.end(body);
}

function loginForm(error = false, totpEnabled = false): string {
  const errorMessage = error
    ? '<div id="login-error">invalid credentials</div>'
    : "";
  const totpInput = totpEnabled ? '<input id="totp" name="totp">' : "";
  return `<!doctype html>
<html lang="en">
<body>
${errorMessage}
<form method="POST" action="/login">
<input id="username" name="username">
<input id="password" name="password" type="password">
${totpInput}
<button id="submit" type="submit">Log in</button>
</form>
</body>
</html>`;
}

function loggedInPage(): string {
  return '<!doctype html><html lang="en"><body><div id="welcome">login-ok</div></body></html>';
}

function sessionFrom(request: IncomingMessage): string | undefined {
  const cookieHeader = request.headers.cookie;
  if (cookieHeader === undefined) return undefined;
  for (const cookie of cookieHeader.split(";")) {
    const [name, ...valueParts] = cookie.trim().split("=");
    if (name === "session") return valueParts.join("=");
  }
  return undefined;
}

function handleRequest(
  request: IncomingMessage,
  response: ServerResponse,
  credentials: Credentials,
): void {
  if (request.method === "GET" && request.url === "/") {
    const session = sessionFrom(request);
    writePage(
      response,
      session !== undefined && sessions.has(session)
        ? loggedInPage()
        : loginForm(false, credentials.totp_seed !== undefined),
    );
    return;
  }

  if (request.method === "POST" && request.url === "/login") {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk: string) => {
      body += chunk;
    });
    request.on("end", () => {
      const form = new URLSearchParams(body);
      if (
        form.get("username") === credentials.username &&
        form.get("password") === credentials.password &&
        (credentials.totp_seed === undefined ||
          validTotp(credentials.totp_seed, form.get("totp")))
      ) {
        const session = randomBytes(32).toString("hex");
        sessions.set(session, true);
        writePage(response, loggedInPage(), {
          "Set-Cookie": `session=${session}; HttpOnly; Path=/; SameSite=Lax`,
        });
      } else {
        writePage(
          response,
          loginForm(true, credentials.totp_seed !== undefined),
        );
      }
    });
    return;
  }

  response.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
  response.end("not found");
}

async function main(): Promise<void> {
  const { port, credsFile } = parseArguments();
  const credentials = await readCredentials(credsFile);
  const server = createServer((request, response) =>
    handleRequest(request, response, credentials),
  );
  server.on("error", () => {
    console.error("target fixture server error");
    process.exitCode = 1;
  });
  server.listen(port, "127.0.0.1", () => {
    const address = server.address();
    if (address === null || typeof address === "string") {
      console.error("target fixture did not receive a network address");
      process.exitCode = 1;
      return;
    }
    console.log(JSON.stringify({ port: address.port }));
  });
}

main().catch(() => {
  console.error("target fixture failed to start");
  process.exitCode = 1;
});
