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

interface OAuthDeviceCode {
  userCode: string;
  expiresAt: number;
  consumed: boolean;
}

const sessions = new Map<string, true>();
const deviceCodes = new Map<string, boolean>();
const oauthDeviceCodes = new Map<string, OAuthDeviceCode>();
// 現在有効な token。access token は失効時刻、refresh token は対応する access token を値とする。
const activeAccessTokens = new Map<string, number>();
const activeRefreshTokens = new Map<string, string>();
// 失効・期限切れにかかわらず発行したすべての token の履歴（/oauth/state で公開する）。
const issuedAccessTokens: string[] = [];
const issuedRefreshTokens: string[] = [];
const oauthRevokedTokens = new Set<string>();
const oauthGrantCounts = { device_code: 0, refresh_token: 0 };
let oauthIssued = 0;
let oauthExpiresIn = 3600;
let oauthDeny = false;
let observedSecChUa: string | null = null;
let receivedUsername: string | null = null;
let mutatingFillState: {
  nickname: string;
  passwordLength: number;
} | null = null;

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

function writeJson(
  response: ServerResponse,
  status: number,
  body: Record<string, unknown>,
): void {
  response.writeHead(status, { "Content-Type": "application/json" });
  response.end(JSON.stringify(body));
}

function requestOrigin(request: IncomingMessage): string {
  return `http://${request.headers.host ?? "127.0.0.1"}`;
}

function newOAuthToken(): string {
  return randomBytes(32).toString("hex");
}

function issueOAuthTokens(): {
  access_token: string;
  refresh_token: string;
} {
  const accessToken = newOAuthToken();
  const refreshToken = newOAuthToken();
  activeAccessTokens.set(accessToken, Date.now() + oauthExpiresIn * 1000);
  activeRefreshTokens.set(refreshToken, accessToken);
  issuedAccessTokens.push(accessToken);
  issuedRefreshTokens.push(refreshToken);
  oauthIssued += 1;
  return { access_token: accessToken, refresh_token: refreshToken };
}

function markOAuthTokenRevoked(token: string): void {
  oauthRevokedTokens.add(token);
}

function revokeOAuthAccessToken(token: string): void {
  if (activeAccessTokens.delete(token)) markOAuthTokenRevoked(token);
}

function revokeOAuthRefreshToken(token: string): void {
  const accessToken = activeRefreshTokens.get(token);
  if (accessToken === undefined) return;
  activeRefreshTokens.delete(token);
  markOAuthTokenRevoked(token);
  revokeOAuthAccessToken(accessToken);
}

function validOAuthAccessToken(token: string): boolean {
  const expiresAt = activeAccessTokens.get(token);
  if (expiresAt === undefined) return false;
  if (expiresAt <= Date.now()) {
    activeAccessTokens.delete(token);
    return false;
  }
  return true;
}

function readRequestBody(
  request: IncomingMessage,
  callback: (body: string) => void,
): void {
  let body = "";
  request.setEncoding("utf8");
  request.on("data", (chunk: string) => {
    body += chunk;
  });
  request.on("end", () => callback(body));
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

function focusThiefForm(passwordType: "password" | "text"): string {
  const focusListener =
    passwordType === "password"
      ? `<script>
const password = document.getElementById("password");
password?.addEventListener("focus", () => {
  document.getElementById("username")?.focus();
});
</script>`
      : "";
  return `<!doctype html>
<html lang="en">
<body>
<form method="POST" action="/login">
<input id="username" name="username" type="text">
<input id="password" name="password" type="${passwordType}">
<button id="submit" type="submit">Log in</button>
</form>
${focusListener}
</body>
</html>`;
}

function mutatingFillForm(): string {
  return `<!doctype html>
<html lang="en">
<body>
<form method="POST" action="/login">
<input id="username" name="username" type="text">
<input id="password" name="password" type="password">
<input id="nickname" name="nickname" type="text">
<button id="submit" type="submit">Log in</button>
</form>
<script>
const password = document.getElementById("password");
const nickname = document.getElementById("nickname");
// 同期要求で報告する。FILL_MISMATCH 後のブラウザ破棄で最後の報告が失われないよう、
// executor の検査が戻る前に fixture へ状態を届けるためである。
const reportState = () => {
  const request = new XMLHttpRequest();
  request.open("POST", "/mutating-fill-state", false);
  request.setRequestHeader("Content-Type", "application/json");
  request.send(JSON.stringify({
    nickname: nickname?.value ?? "",
    passwordLength: password?.value.length ?? 0
  }));
};
password?.addEventListener("input", () => {
  if (nickname !== null) nickname.value = "tampered";
  reportState();
});
nickname?.addEventListener("input", reportState);
</script>
</body>
</html>`;
}

function delayedStepForm(): string {
  return `<!doctype html>
<html lang="en">
<body>
<form method="POST" action="/login" id="login-form">
<input id="username" name="username" type="text">
<button id="next" type="button">Next</button>
</form>
<script>
document.getElementById("next")?.addEventListener("click", () => {
  setTimeout(() => {
    const form = document.getElementById("login-form");
    if (form === null || document.getElementById("password") !== null) return;
    form.insertAdjacentHTML(
      "beforeend",
      '<input id="password" name="password" type="password"><button id="submit" type="submit">Log in</button>',
    );
  }, 2000);
});
</script>
</body>
</html>`;
}

function withWorkers(page: string): string {
  return page.replace(
    "</body>",
    `<script>
const worker = new Worker("/worker.js");
worker.addEventListener("message", () => {
  document.body.dataset.workerReady = "true";
});
if ("serviceWorker" in navigator) {
  navigator.serviceWorker.register("/service-worker.js").catch(() => {});
}
</script>
</body>`,
  );
}

function loggedInPage(): string {
  return '<!doctype html><html lang="en"><body><div id="welcome">login-ok</div></body></html>';
}

function withBusyPoll(page: string): string {
  return page.replace(
    "</body>",
    `<script>
const poll = () => fetch("/busy/poll").finally(poll);
poll();
</script>
</body>`,
  );
}

function busyLoginForm(error = false, totpEnabled = false): string {
  return withBusyPoll(
    loginForm(error, totpEnabled).replace(
      'action="/login"',
      'action="/busy/login"',
    ),
  );
}

function busyLoggedInPage(): string {
  return withBusyPoll(
    loggedInPage().replace(
      '<div id="welcome">login-ok</div>',
      '<div id="welcome">login-ok</div><input type="password" hidden>',
    ),
  );
}

function devicePage(): string {
  return `<!doctype html>
<html lang="en">
<body>
<form method="post" action="/device">
<input name="user_code" type="text">
<button type="submit">Continue</button>
</form>
</body>
</html>`;
}

function deviceAuthorizationPage(userCode: string): string {
  return `<!doctype html>
<html lang="en">
<body>
<form method="post" action="/device/approve">
<input type="hidden" name="user_code" value="${userCode}">
<button type="submit">Authorize</button>
</form>
</body>
</html>`;
}

function deviceErrorPage(): string {
  return '<!doctype html><html lang="en"><body><p id="device-error">unknown device code</p></body></html>';
}

function deviceApprovedPage(): string {
  return '<!doctype html><html lang="en"><body><p id="device-ok">device approved</p></body></html>';
}

function newDeviceCode(): string {
  const value = randomBytes(4).toString("hex").toUpperCase();
  return `${value.slice(0, 4)}-${value.slice(4)}`;
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

function handleOAuthDeviceAuthorization(
  request: IncomingMessage,
  response: ServerResponse,
): void {
  readRequestBody(request, (body) => {
    const form = new URLSearchParams(body);
    if (form.get("client_id") === null || form.get("client_id") === "") {
      writeJson(response, 400, { error: "invalid_request" });
      return;
    }
    const userCode = newDeviceCode();
    const deviceCode = newOAuthToken();
    deviceCodes.set(userCode, false);
    oauthDeviceCodes.set(deviceCode, {
      userCode,
      expiresAt: Date.now() + 300_000,
      consumed: false,
    });
    writeJson(response, 200, {
      device_code: deviceCode,
      user_code: userCode,
      verification_uri: `${requestOrigin(request)}/device`,
      expires_in: 300,
      interval: 1,
    });
  });
}

function handleDeviceCodeGrant(
  form: URLSearchParams,
  response: ServerResponse,
): void {
  const deviceCode = form.get("device_code");
  const grant =
    deviceCode === null ? undefined : oauthDeviceCodes.get(deviceCode);
  if (grant === undefined) {
    writeJson(response, 400, { error: "invalid_grant" });
    return;
  }
  if (grant.expiresAt <= Date.now()) {
    writeJson(response, 400, { error: "expired_token" });
    return;
  }
  if (oauthDeny) {
    writeJson(response, 400, { error: "access_denied" });
    return;
  }
  if (grant.consumed) {
    writeJson(response, 400, { error: "invalid_grant" });
    return;
  }
  if (deviceCodes.get(grant.userCode) !== true) {
    writeJson(response, 400, { error: "authorization_pending" });
    return;
  }
  grant.consumed = true;
  oauthGrantCounts.device_code += 1;
  writeJson(response, 200, {
    ...issueOAuthTokens(),
    token_type: "Bearer",
    expires_in: oauthExpiresIn,
  });
}

function handleRefreshTokenGrant(
  form: URLSearchParams,
  response: ServerResponse,
): void {
  const refreshToken = form.get("refresh_token");
  const oldAccessToken =
    refreshToken === null ? undefined : activeRefreshTokens.get(refreshToken);
  if (refreshToken === null || oldAccessToken === undefined) {
    writeJson(response, 400, { error: "invalid_grant" });
    return;
  }
  revokeOAuthRefreshToken(refreshToken);
  oauthGrantCounts.refresh_token += 1;
  writeJson(response, 200, {
    ...issueOAuthTokens(),
    token_type: "Bearer",
    expires_in: oauthExpiresIn,
  });
}

function handleOAuthToken(
  request: IncomingMessage,
  response: ServerResponse,
): void {
  readRequestBody(request, (body) => {
    const form = new URLSearchParams(body);
    const grantType = form.get("grant_type");
    if (grantType === "urn:ietf:params:oauth:grant-type:device_code") {
      handleDeviceCodeGrant(form, response);
    } else if (grantType === "refresh_token") {
      handleRefreshTokenGrant(form, response);
    } else {
      writeJson(response, 400, { error: "unsupported_grant_type" });
    }
  });
}

function handleOAuthRevoke(
  request: IncomingMessage,
  response: ServerResponse,
): void {
  readRequestBody(request, (body) => {
    const token = new URLSearchParams(body).get("token");
    if (token === null || token === "") {
      writeJson(response, 400, { error: "invalid_request" });
      return;
    }
    if (activeAccessTokens.has(token)) revokeOAuthAccessToken(token);
    else revokeOAuthRefreshToken(token);
    writeJson(response, 200, {});
  });
}

function handleOAuthState(response: ServerResponse): void {
  writeJson(response, 200, {
    grants: oauthGrantCounts,
    issued: oauthIssued,
    revoked: oauthRevokedTokens.size,
    access_tokens: issuedAccessTokens,
    refresh_tokens: issuedRefreshTokens,
  });
}

function handleOAuthConfig(
  request: IncomingMessage,
  response: ServerResponse,
): void {
  readRequestBody(request, (body) => {
    let value: unknown;
    try {
      value = JSON.parse(body);
    } catch {
      writeJson(response, 400, { error: "invalid_request" });
      return;
    }
    if (typeof value !== "object" || value === null) {
      writeJson(response, 400, { error: "invalid_request" });
      return;
    }
    const config = value as Record<string, unknown>;
    if ("expires_in" in config) {
      if (
        typeof config.expires_in !== "number" ||
        !Number.isInteger(config.expires_in) ||
        config.expires_in <= 0
      ) {
        writeJson(response, 400, { error: "invalid_request" });
        return;
      }
      oauthExpiresIn = config.expires_in;
    }
    if ("deny" in config) {
      if (typeof config.deny !== "boolean") {
        writeJson(response, 400, { error: "invalid_request" });
        return;
      }
      oauthDeny = config.deny;
    }
    writeJson(response, 200, {});
  });
}

function handleApiMe(request: IncomingMessage, response: ServerResponse): void {
  const authorization = request.headers.authorization;
  const token =
    authorization?.startsWith("Bearer ") === true
      ? authorization.slice("Bearer ".length)
      : undefined;
  if (token !== undefined && validOAuthAccessToken(token)) {
    writeJson(response, 200, { user: "fixture" });
  } else {
    writeJson(response, 401, { error: "unauthorized" });
  }
}

/** OAuth 認可サーバーと保護 API の経路を処理する。該当しない要求には false を返す。 */
function handleOAuthRequest(
  request: IncomingMessage,
  response: ServerResponse,
): boolean {
  const route = `${request.method} ${request.url}`;
  if (route === "POST /oauth/device_authorization") {
    handleOAuthDeviceAuthorization(request, response);
  } else if (route === "POST /oauth/token") {
    handleOAuthToken(request, response);
  } else if (route === "POST /oauth/revoke") {
    handleOAuthRevoke(request, response);
  } else if (route === "GET /oauth/state") {
    handleOAuthState(response);
  } else if (route === "POST /oauth/config") {
    handleOAuthConfig(request, response);
  } else if (route === "GET /api/me") {
    handleApiMe(request, response);
  } else {
    return false;
  }
  return true;
}

function handleRequest(
  request: IncomingMessage,
  response: ServerResponse,
  credentials: Credentials,
): void {
  if (request.method === "GET" && request.url === "/busy/poll") {
    const timer = setTimeout(() => {
      if (response.destroyed) return;
      response.writeHead(204);
      response.end();
    }, 25_000);
    timer.unref();
    response.on("close", () => clearTimeout(timer));
    return;
  }

  if (request.method === "GET" && request.url === "/busy/") {
    const session = sessionFrom(request);
    writePage(
      response,
      session !== undefined && sessions.has(session)
        ? busyLoggedInPage()
        : busyLoginForm(false, credentials.totp_seed !== undefined),
    );
    return;
  }

  if (request.method === "GET" && request.url === "/focus-thief/") {
    receivedUsername = null;
    writePage(response, focusThiefForm("password"));
    return;
  }

  if (request.method === "GET" && request.url === "/password-as-text/") {
    receivedUsername = null;
    writePage(response, focusThiefForm("text"));
    return;
  }

  if (request.method === "GET" && request.url === "/mutating-fill/") {
    receivedUsername = null;
    mutatingFillState = null;
    writePage(response, mutatingFillForm());
    return;
  }

  if (request.method === "GET" && request.url === "/delayed-step/") {
    receivedUsername = null;
    writePage(response, delayedStepForm());
    return;
  }

  if (request.method === "GET" && request.url === "/received-submission") {
    writeJson(response, 200, { username: receivedUsername });
    return;
  }

  if (request.method === "GET" && request.url === "/mutating-fill-state") {
    writeJson(response, 200, {
      nickname: mutatingFillState?.nickname ?? null,
      password_length: mutatingFillState?.passwordLength ?? null,
    });
    return;
  }

  if (
    request.method === "GET" &&
    (request.url === "/" ||
      request.url === "/ua-gated/" ||
      request.url === "/with-worker/")
  ) {
    if (request.url === "/ua-gated/") {
      const secChUa = request.headers["sec-ch-ua"];
      observedSecChUa = Array.isArray(secChUa)
        ? secChUa.join(", ")
        : (secChUa ?? null);
    }
    if (
      request.url === "/ua-gated/" &&
      (request.headers["user-agent"]?.includes("HeadlessChrome") === true ||
        observedSecChUa?.includes("HeadlessChrome") === true)
    ) {
      response.writeHead(403, { "Content-Type": "text/plain; charset=utf-8" });
      response.end("headless user agent or client hint is forbidden");
      return;
    }
    const session = sessionFrom(request);
    const page =
      session !== undefined && sessions.has(session)
        ? loggedInPage()
        : loginForm(false, credentials.totp_seed !== undefined);
    writePage(
      response,
      request.url === "/with-worker/" ? withWorkers(page) : page,
    );
    return;
  }

  if (request.method === "GET" && request.url === "/observed-headers") {
    response.writeHead(200, { "Content-Type": "application/json" });
    response.end(JSON.stringify({ sec_ch_ua: observedSecChUa }));
    return;
  }

  if (request.method === "GET" && request.url === "/worker.js") {
    response.writeHead(200, { "Content-Type": "application/javascript" });
    response.end('self.postMessage("worker-ready");');
    return;
  }

  if (request.method === "GET" && request.url === "/service-worker.js") {
    response.writeHead(200, { "Content-Type": "application/javascript" });
    response.end(
      'self.addEventListener("install", () => self.skipWaiting()); self.addEventListener("activate", () => self.clients.claim());',
    );
    return;
  }

  if (
    request.method === "POST" &&
    (request.url === "/login" || request.url === "/busy/login")
  ) {
    const busy = request.url === "/busy/login";
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk: string) => {
      body += chunk;
    });
    request.on("end", () => {
      const form = new URLSearchParams(body);
      receivedUsername = form.get("username");
      if (
        form.get("username") === credentials.username &&
        form.get("password") === credentials.password &&
        (credentials.totp_seed === undefined ||
          validTotp(credentials.totp_seed, form.get("totp")))
      ) {
        const session = randomBytes(32).toString("hex");
        sessions.set(session, true);
        writePage(response, busy ? busyLoggedInPage() : loggedInPage(), {
          "Set-Cookie": `session=${session}; HttpOnly; Path=/; SameSite=Lax`,
        });
      } else {
        writePage(
          response,
          busy
            ? busyLoginForm(true, credentials.totp_seed !== undefined)
            : loginForm(true, credentials.totp_seed !== undefined),
        );
      }
    });
    return;
  }

  if (request.method === "POST" && request.url === "/mutating-fill-state") {
    readRequestBody(request, (body) => {
      try {
        const value = JSON.parse(body) as Record<string, unknown>;
        if (
          typeof value.nickname !== "string" ||
          typeof value.passwordLength !== "number"
        ) {
          writeJson(response, 400, { error: "invalid_state" });
          return;
        }
        mutatingFillState = {
          nickname: value.nickname,
          passwordLength: value.passwordLength,
        };
        writeJson(response, 200, { ok: true });
      } catch {
        writeJson(response, 400, { error: "invalid_state" });
      }
    });
    return;
  }

  if (handleOAuthRequest(request, response)) return;

  if (request.method === "POST" && request.url === "/device/issue") {
    const userCode = newDeviceCode();
    deviceCodes.set(userCode, false);
    response.writeHead(200, { "Content-Type": "application/json" });
    response.end(JSON.stringify({ user_code: userCode }));
    return;
  }

  if (request.method === "GET" && request.url?.startsWith("/device/status?")) {
    const userCode = new URL(request.url, "http://127.0.0.1").searchParams.get(
      "user_code",
    );
    response.writeHead(200, { "Content-Type": "application/json" });
    response.end(
      JSON.stringify({
        approved: userCode !== null && deviceCodes.get(userCode) === true,
      }),
    );
    return;
  }

  if (request.method === "GET" && request.url === "/device") {
    writePage(response, devicePage());
    return;
  }

  if (request.method === "POST" && request.url === "/device") {
    const session = sessionFrom(request);
    if (session === undefined || !sessions.has(session)) {
      response.writeHead(302, { Location: "/" });
      response.end();
      return;
    }
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk: string) => {
      body += chunk;
    });
    request.on("end", () => {
      const userCode = new URLSearchParams(body).get("user_code");
      writePage(
        response,
        userCode !== null && deviceCodes.has(userCode)
          ? deviceAuthorizationPage(userCode)
          : deviceErrorPage(),
      );
    });
    return;
  }

  if (request.method === "POST" && request.url === "/device/approve") {
    const session = sessionFrom(request);
    if (session === undefined || !sessions.has(session)) {
      response.writeHead(302, { Location: "/" });
      response.end();
      return;
    }
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk: string) => {
      body += chunk;
    });
    request.on("end", () => {
      const userCode = new URLSearchParams(body).get("user_code");
      if (userCode !== null && deviceCodes.has(userCode)) {
        deviceCodes.set(userCode, true);
        writePage(response, deviceApprovedPage());
      } else {
        writePage(response, deviceErrorPage());
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
