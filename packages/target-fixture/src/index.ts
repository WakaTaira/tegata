#!/usr/bin/env node

import { createHash, createHmac, randomBytes } from "node:crypto";
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

// State of the /persistent-cookies/ login site (Issue #45). A valid `device`
// cookie skips the login form; every request's cookie names are recorded.
interface RecordedRequest {
  method: string;
  path: string;
  cookies: string[];
}
const validDeviceCookies = new Set<string>();
const issuedDeviceCookies: string[] = [];
const issuedSidCookies: string[] = [];
const persistentCookieRequests: RecordedRequest[] = [];
let persistentCookieLoginPosts = 0;

// State of the /stepwise/ login sites (Issue #46). Every recorded field value
// is masked by `maskStepwiseValue`, so the state never carries a credential.
interface StepwiseFlow {
  passwordOk: boolean;
}
interface StepwisePost {
  path: string;
  kind: string | null;
  fields: Record<string, string>;
}
interface StepwiseInput {
  path: string;
  field: string;
  value: string;
}
interface StepwiseStickyReport {
  when: string;
  target: string;
  password_length: number;
}
const stepwiseFlows = new Map<string, StepwiseFlow>();
const stepwiseSessions = new Set<string>();
const stepwiseRequests: Array<{ method: string; path: string }> = [];
const stepwisePosts: StepwisePost[] = [];
const stepwiseInputs: StepwiseInput[] = [];
const stepwiseTotp: Array<{ code: string; valid: boolean }> = [];
const stepwiseStickyReports: StepwiseStickyReport[] = [];

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

function cookiesFrom(request: IncomingMessage): Map<string, string> {
  const cookies = new Map<string, string>();
  const cookieHeader = request.headers.cookie;
  if (cookieHeader === undefined) return cookies;
  for (const cookie of cookieHeader.split(";")) {
    const [name, ...valueParts] = cookie.trim().split("=");
    if (name !== "") cookies.set(name, valueParts.join("="));
  }
  return cookies;
}

function recordPersistentCookieRequest(request: IncomingMessage): void {
  persistentCookieRequests.push({
    method: request.method ?? "",
    path: request.url ?? "",
    cookies: [...cookiesFrom(request).keys()],
  });
}

function persistentCookieLoginForm(error: boolean): string {
  return loginForm(error, false).replace(
    'action="/login"',
    'action="/persistent-cookies/login"',
  );
}

function hasValidDeviceCookie(request: IncomingMessage): boolean {
  const device = cookiesFrom(request).get("device");
  return device !== undefined && validDeviceCookies.has(device);
}

function handlePersistentCookieLogin(
  request: IncomingMessage,
  response: ServerResponse,
  credentials: Credentials,
): void {
  persistentCookieLoginPosts += 1;
  readRequestBody(request, (body) => {
    const form = new URLSearchParams(body);
    if (
      form.get("username") !== credentials.username ||
      form.get("password") !== credentials.password
    ) {
      writePage(response, persistentCookieLoginForm(true));
      return;
    }
    const device = `device-canary-${randomBytes(16).toString("hex")}`;
    const sid = `sid-canary-${randomBytes(16).toString("hex")}`;
    validDeviceCookies.add(device);
    issuedDeviceCookies.push(device);
    issuedSidCookies.push(sid);
    response.writeHead(200, {
      "Content-Type": "text/html; charset=utf-8",
      "Set-Cookie": [
        `device=${device}; Max-Age=86400; Path=/; SameSite=Lax`,
        `sid=${sid}; HttpOnly; Path=/; SameSite=Lax`,
      ],
    });
    response.end(loggedInPage());
  });
}

/**
 * Login site that issues a one-day persistent `device` cookie and a session
 * `sid` cookie, and serves the logged-in page straight away to a request
 * carrying a valid `device`. Returns false for requests it does not handle.
 */
function handlePersistentCookieRequest(
  request: IncomingMessage,
  response: ServerResponse,
  credentials: Credentials,
): boolean {
  const route = `${request.method} ${request.url}`;
  if (route === "GET /persistent-cookies/state") {
    writeJson(response, 200, {
      login_posts: persistentCookieLoginPosts,
      requests: persistentCookieRequests,
      device_values: issuedDeviceCookies,
      sid_values: issuedSidCookies,
    });
  } else if (route === "POST /persistent-cookies/invalidate") {
    validDeviceCookies.clear();
    writeJson(response, 200, { ok: true });
  } else if (route === "GET /persistent-cookies/") {
    recordPersistentCookieRequest(request);
    writePage(
      response,
      hasValidDeviceCookie(request)
        ? loggedInPage()
        : persistentCookieLoginForm(false),
    );
  } else if (route === "POST /persistent-cookies/login") {
    recordPersistentCookieRequest(request);
    handlePersistentCookieLogin(request, response, credentials);
  } else {
    return false;
  }
  return true;
}

/** Value attribute of a visible checkbox on the stepwise username page. */
const STEPWISE_VALUE_MARKER = "stepwise-value-attribute-marker";
const STEPWISE_ECHO_KINDS = ["text", "attr", "query"] as const;

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

/**
 * Mask a submitted value for the recorded state: credential values become
 * markers and anything else becomes its sha256, so `/stepwise/state` never
 * carries a secret.
 */
function maskStepwiseValue(value: string, credentials: Credentials): string {
  if (value === "") return "<empty>";
  if (value === credentials.username) return "<username>";
  if (value === credentials.password) return "<password>";
  if (
    credentials.totp_seed !== undefined &&
    validTotp(credentials.totp_seed, value)
  )
    return "<totp>";
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

// input イベントを同期要求で報告する。executor の fill が戻る前に、欄へ入った値を fixture に
// 届けるためである。値は fixture 側で伏せて記録する。
const STEPWISE_INPUT_REPORTER = `<script>
document.addEventListener("input", (event) => {
  const target = event.target;
  if (!(target instanceof HTMLInputElement)) return;
  const request = new XMLHttpRequest();
  request.open("POST", "/stepwise/input", false);
  request.setRequestHeader("Content-Type", "application/json");
  request.send(JSON.stringify({
    path: location.pathname,
    field: target.name || target.id,
    value: target.value
  }));
}, true);
</script>`;

function stepwisePage(title: string, body: string): string {
  return `<!doctype html>
<html lang="en">
<head><title>${title}</title></head>
<body>
${body}
${STEPWISE_INPUT_REPORTER}
</body>
</html>`;
}

function stepwiseError(message: string | undefined): string {
  return message === undefined ? "" : `<div id="login-error">${message}</div>`;
}

function stepwiseUsernamePage(error?: string): string {
  return stepwisePage(
    "Sign in",
    `<h1>Sign in</h1>
${stepwiseError(error)}
<form method="POST" action="/stepwise/username">
<label for="username">Username or email address</label>
<input id="username" name="username" type="text" autocomplete="username">
<label><input id="remember" name="remember" type="checkbox" value="${STEPWISE_VALUE_MARKER}"> Remember me</label>
<button id="next" type="submit">Next</button>
</form>`,
  );
}

function stepwisePasswordPage(error?: string): string {
  return stepwisePage(
    "Enter your password",
    `<h1>Enter your password</h1>
${stepwiseError(error)}
<form method="POST" action="/stepwise/password">
<label for="password">Password</label>
<input id="password" name="password" type="password" autocomplete="current-password">
<button id="sign-in" type="submit">Sign in</button>
</form>`,
  );
}

function stepwisePushPage(): string {
  return stepwisePage(
    "Two-factor authentication",
    `<h1>Two-factor authentication</h1>
<p>Waiting for approval on your mobile device.</p>
<button type="button">More options</button>
<div id="other-methods" hidden>
<a href="/stepwise/2fa/app">Use your authenticator app</a>
</div>
<script>
document.querySelector("button")?.addEventListener("click", () => {
  const methods = document.getElementById("other-methods");
  if (methods !== null) methods.hidden = false;
});
</script>`,
  );
}

function stepwiseAppPage(error?: string): string {
  return stepwisePage(
    "Authenticator app",
    `<h1>Authenticator app</h1>
${stepwiseError(error)}
<form method="POST" action="/stepwise/2fa/app">
<label for="otp">Authentication code</label>
<input id="otp" name="otp" type="text" inputmode="numeric" autocomplete="one-time-code">
<button id="verify" type="submit">Verify</button>
</form>`,
  );
}

function stepwiseHomePage(username: string): string {
  return stepwisePage(
    "Home",
    `<h1>Home</h1>
<div id="signed-in">Signed in as ${escapeHtml(username)}</div>
<a href="/stepwise/home">Dashboard</a>`,
  );
}

function stepwiseEchoForm(kind: string): string {
  return stepwisePage(
    "Sign in",
    `<h1>Sign in</h1>
<form method="POST" action="/stepwise/echo/login?kind=${kind}">
<input id="username" name="username" type="text" autocomplete="username">
<input id="password" name="password" type="password" autocomplete="current-password">
<button id="submit" type="submit">Sign in</button>
</form>`,
  );
}

function stepwiseStickyPage(): string {
  return stepwisePage(
    "Sign in",
    `<h1>Sign in</h1>
<form id="sticky-form">
<input id="username" name="username" type="text" autocomplete="username">
<input id="password" name="password" type="password" autocomplete="current-password">
<button id="submit" type="submit">Sign in</button>
</form>
<button id="help" type="button">Help</button>
<div id="status"></div>
<script>
const stickyPassword = document.getElementById("password");
// 同期要求で報告する。クリックの処理が進む前に、その時点の password 欄の値の長さを
// fixture に届けるためである。
const reportSticky = (when, target) => {
  const request = new XMLHttpRequest();
  request.open("POST", "/stepwise/sticky/report", false);
  request.setRequestHeader("Content-Type", "application/json");
  request.send(JSON.stringify({
    when,
    target,
    password_length: stickyPassword?.value.length ?? 0
  }));
};
document.addEventListener("click", (event) => {
  const target = event.target;
  reportSticky("click", target instanceof Element ? target.id || target.tagName : "");
}, true);
document.getElementById("sticky-form")?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const body = new URLSearchParams(new FormData(event.currentTarget));
  const response = await fetch("/stepwise/sticky/login", { method: "POST", body });
  const result = await response.json();
  const status = document.getElementById("status");
  if (status === null) return;
  if (result.ok === true) {
    status.innerHTML = '<div id="welcome">Signed in</div>';
    return;
  }
  // 誤った password の欄の値はそのまま残し、エラー表示だけを描き直す。
  status.innerHTML = '<div id="login-error">Incorrect password</div>';
  reportSticky("rerender", "status");
});
</script>`,
  );
}

function recordStepwisePost(
  path: string,
  kind: string | null,
  form: URLSearchParams,
  credentials: Credentials,
): void {
  const fields: Record<string, string> = {};
  for (const [name, value] of form) {
    fields[name] = maskStepwiseValue(value, credentials);
  }
  stepwisePosts.push({ path, kind, fields });
}

function stepwiseFlowFrom(request: IncomingMessage): StepwiseFlow | undefined {
  const id = cookiesFrom(request).get("stepwise_flow");
  return id === undefined ? undefined : stepwiseFlows.get(id);
}

function hasStepwiseSession(request: IncomingMessage): boolean {
  const session = cookiesFrom(request).get("stepwise_session");
  return session !== undefined && stepwiseSessions.has(session);
}

function redirect(response: ServerResponse, location: string): void {
  response.writeHead(303, { Location: location });
  response.end();
}

function handleStepwiseUsername(
  request: IncomingMessage,
  response: ServerResponse,
  credentials: Credentials,
): void {
  readRequestBody(request, (body) => {
    const form = new URLSearchParams(body);
    recordStepwisePost("/stepwise/username", null, form, credentials);
    if (form.get("username") !== credentials.username) {
      writePage(response, stepwiseUsernamePage("Unknown user"));
      return;
    }
    const flow = randomBytes(16).toString("hex");
    stepwiseFlows.set(flow, { passwordOk: false });
    writePage(response, stepwisePasswordPage(), {
      "Set-Cookie": `stepwise_flow=${flow}; HttpOnly; Path=/stepwise; SameSite=Lax`,
    });
  });
}

function handleStepwisePassword(
  request: IncomingMessage,
  response: ServerResponse,
  credentials: Credentials,
): void {
  const flow = stepwiseFlowFrom(request);
  readRequestBody(request, (body) => {
    const form = new URLSearchParams(body);
    recordStepwisePost("/stepwise/password", null, form, credentials);
    if (flow === undefined) {
      redirect(response, "/stepwise/");
      return;
    }
    if (form.get("password") !== credentials.password) {
      writePage(response, stepwisePasswordPage("Incorrect password"));
      return;
    }
    flow.passwordOk = true;
    writePage(response, stepwisePushPage());
  });
}

function handleStepwiseTotp(
  request: IncomingMessage,
  response: ServerResponse,
  credentials: Credentials,
): void {
  const flow = stepwiseFlowFrom(request);
  readRequestBody(request, (body) => {
    const form = new URLSearchParams(body);
    recordStepwisePost("/stepwise/2fa/app", null, form, credentials);
    if (flow?.passwordOk !== true) {
      redirect(response, "/stepwise/");
      return;
    }
    const code = form.get("otp") ?? "";
    const valid =
      credentials.totp_seed !== undefined &&
      validTotp(credentials.totp_seed, code);
    stepwiseTotp.push({ code, valid });
    if (!valid) {
      writePage(response, stepwiseAppPage("Invalid code"));
      return;
    }
    const session = randomBytes(32).toString("hex");
    stepwiseSessions.add(session);
    response.writeHead(303, {
      Location: "/stepwise/home",
      "Set-Cookie": `stepwise_session=${session}; Max-Age=86400; HttpOnly; Path=/stepwise; SameSite=Lax`,
    });
    response.end();
  });
}

function handleStepwiseEcho(
  request: IncomingMessage,
  response: ServerResponse,
  credentials: Credentials,
  kind: string,
): void {
  readRequestBody(request, (body) => {
    const form = new URLSearchParams(body);
    recordStepwisePost("/stepwise/echo/login", kind, form, credentials);
    const password = form.get("password") ?? "";
    if (kind === "text") {
      writePage(
        response,
        stepwisePage(
          "Welcome",
          `<p id="echo">You entered: ${escapeHtml(password)}</p>`,
        ),
      );
    } else if (kind === "attr") {
      writePage(
        response,
        stepwisePage(
          "Welcome",
          `<button id="echo" type="button" aria-label="${escapeHtml(password)}">Continue</button>`,
        ),
      );
    } else {
      redirect(
        response,
        `/stepwise/echo/result?kind=query&password=${encodeURIComponent(password)}`,
      );
    }
  });
}

function handleStepwiseSticky(
  request: IncomingMessage,
  response: ServerResponse,
  credentials: Credentials,
): void {
  readRequestBody(request, (body) => {
    const form = new URLSearchParams(body);
    recordStepwisePost("/stepwise/sticky/login", null, form, credentials);
    writeJson(response, 200, {
      ok:
        form.get("username") === credentials.username &&
        form.get("password") === credentials.password,
    });
  });
}

function recordStepwiseJson(
  request: IncomingMessage,
  response: ServerResponse,
  record: (value: Record<string, unknown>) => boolean,
): void {
  readRequestBody(request, (body) => {
    try {
      const value = JSON.parse(body) as Record<string, unknown>;
      if (typeof value !== "object" || value === null || !record(value)) {
        writeJson(response, 400, { error: "invalid_report" });
        return;
      }
      writeJson(response, 200, { ok: true });
    } catch {
      writeJson(response, 400, { error: "invalid_report" });
    }
  });
}

function stepwiseStateBody(): Record<string, unknown> {
  return {
    requests: stepwiseRequests,
    posts: stepwisePosts,
    inputs: stepwiseInputs,
    totp: stepwiseTotp,
    sticky_reports: stepwiseStickyReports,
  };
}

/** Test-only endpoints of the stepwise sites (state and in-page reports). */
function handleStepwiseControl(
  route: string,
  request: IncomingMessage,
  response: ServerResponse,
  credentials: Credentials,
): boolean {
  if (route === "GET /stepwise/state") {
    writeJson(response, 200, stepwiseStateBody());
  } else if (route === "POST /stepwise/input") {
    recordStepwiseJson(request, response, (value) => {
      if (
        typeof value.path !== "string" ||
        typeof value.field !== "string" ||
        typeof value.value !== "string"
      )
        return false;
      stepwiseInputs.push({
        path: value.path,
        field: value.field,
        value: maskStepwiseValue(value.value, credentials),
      });
      return true;
    });
  } else if (route === "POST /stepwise/sticky/report") {
    recordStepwiseJson(request, response, (value) => {
      if (
        typeof value.when !== "string" ||
        typeof value.target !== "string" ||
        typeof value.password_length !== "number"
      )
        return false;
      stepwiseStickyReports.push({
        when: value.when,
        target: value.target,
        password_length: value.password_length,
      });
      return true;
    });
  } else {
    return false;
  }
  return true;
}

/**
 * Stepwise login sites (Issue #46): (1) username -> password -> 2FA push
 * page with "More options" -> authenticator app -> signed-in page, (2) echo
 * pages that reflect the submitted password into text, an attribute, or the
 * URL query (`?kind=`), (3) a page that keeps a wrong password in its field
 * and reports the field on every click. Returns false for other requests.
 */
function handleStepwiseRequest(
  request: IncomingMessage,
  response: ServerResponse,
  credentials: Credentials,
): boolean {
  const url = new URL(request.url ?? "/", "http://127.0.0.1");
  if (!url.pathname.startsWith("/stepwise/")) return false;
  const route = `${request.method} ${url.pathname}`;
  if (handleStepwiseControl(route, request, response, credentials)) return true;
  stepwiseRequests.push({ method: request.method ?? "", path: url.pathname });
  const kind = url.searchParams.get("kind") ?? "";
  const echoKind = (STEPWISE_ECHO_KINDS as readonly string[]).includes(kind);
  if (route === "GET /stepwise/") {
    writePage(
      response,
      hasStepwiseSession(request)
        ? stepwiseHomePage(credentials.username)
        : stepwiseUsernamePage(),
    );
  } else if (route === "POST /stepwise/username") {
    handleStepwiseUsername(request, response, credentials);
  } else if (route === "POST /stepwise/password") {
    handleStepwisePassword(request, response, credentials);
  } else if (route === "GET /stepwise/2fa/app") {
    if (stepwiseFlowFrom(request)?.passwordOk === true)
      writePage(response, stepwiseAppPage());
    else redirect(response, "/stepwise/");
  } else if (route === "POST /stepwise/2fa/app") {
    handleStepwiseTotp(request, response, credentials);
  } else if (route === "GET /stepwise/home") {
    if (hasStepwiseSession(request))
      writePage(response, stepwiseHomePage(credentials.username));
    else redirect(response, "/stepwise/");
  } else if (route === "GET /stepwise/echo/" && echoKind) {
    writePage(response, stepwiseEchoForm(kind));
  } else if (route === "POST /stepwise/echo/login" && echoKind) {
    handleStepwiseEcho(request, response, credentials, kind);
  } else if (route === "GET /stepwise/echo/result") {
    writePage(response, stepwisePage("Done", '<p id="echo">Thanks</p>'));
  } else if (route === "GET /stepwise/sticky/") {
    writePage(response, stepwiseStickyPage());
  } else if (route === "POST /stepwise/sticky/login") {
    handleStepwiseSticky(request, response, credentials);
  } else {
    response.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
    response.end("not found");
  }
  return true;
}

// State of the /trap/ pages (Issue #57). Every recorded field value is masked
// by `maskStepwiseValue`, so the state never carries a credential.
interface TrapPost {
  path: string;
  fields: Record<string, string>;
}
interface TrapInput {
  path: string;
  origin: string;
  field: string;
  value: string;
}
const trapRequests: Array<{ method: string; host: string; path: string }> = [];
const trapPosts: TrapPost[] = [];
const trapInputs: TrapInput[] = [];

/** Default values planted on /trap/values/; none of them may reach a snapshot. */
const TRAP_VALUE_CANARIES = {
  defaultValue: "trapval-default-value-4c1e9a",
  csrfToken: "trapval-hidden-csrf-token-8d2f71",
  dataAttribute: "trapval-data-attribute-5b7e03",
  scriptVariable: "trapval-inline-script-variable-a9c4d6",
  textarea: "trapval-textarea-default-31f8b2",
  explicitRole: "trapval-explicit-role-note-e60d5c",
  labeledText: "trapval-labeled-placeholder-text-7a3c19",
  labeledPassword: "trapval-labeled-placeholder-password-0f92e4",
} as const;

/** Number of archive links that push the /trap/huge/ pages past 64 KiB. */
const TRAP_HUGE_ARTICLES = 1200;

// input イベントを同期要求で報告する。iframe の中（別 origin・srcdoc を含む）にも同じ処理を置き、
// どの文書のどの欄に値が入ったかを fixture へ届ける。値は fixture 側で伏せて記録する。
const TRAP_INPUT_REPORTER_SOURCE = `document.addEventListener("input", (event) => {
  const target = event.target;
  if (!(target instanceof HTMLInputElement) && !(target instanceof HTMLTextAreaElement)) return;
  const request = new XMLHttpRequest();
  request.open("POST", "/trap/input", false);
  request.setRequestHeader("Content-Type", "application/json");
  request.send(JSON.stringify({
    path: location.pathname,
    origin: location.origin,
    field: target.name || target.id,
    value: target.value
  }));
}, true);`;

function trapPage(title: string, body: string): string {
  return `<!doctype html>
<html lang="en">
<head><title>${title}</title></head>
<body>
${body}
<script>${TRAP_INPUT_REPORTER_SOURCE}</script>
</body>
</html>`;
}

function trapSignedInPage(username: string): string {
  return trapPage(
    "Welcome",
    `<h1>Welcome</h1>
<div id="signed-in">Signed in as ${escapeHtml(username)}</div>`,
  );
}

function trapErrorPage(): string {
  return trapPage(
    "Sign in failed",
    '<div id="login-error">Incorrect username or password</div>',
  );
}

function trapNamesUsernamePage(error?: string): string {
  return trapPage(
    "Sign in to Trap",
    `<h1>Sign in to Trap</h1>
${stepwiseError(error)}
<form method="POST" action="/trap/names/username">
<span id="identifier-label">Phone, email, or username</span>
<input id="identifier" name="username" type="text" aria-labelledby="identifier-label" autocomplete="username">
<button id="next-step" type="submit"><svg width="20" height="20" viewBox="0 0 20 20"><title>Next step</title><path d="M4 10h12M12 6l4 4-4 4"></path></svg></button>
<input id="log-in" type="submit" value="Log in">
<button id="forgot" type="button"><img alt="Forgot password" width="16" height="16" src="data:image/gif;base64,R0lGODlhAQABAAAAACH5BAEKAAEALAAAAAABAAEAAAICTAEAOw=="></button>
</form>`,
  );
}

function trapNamesPasswordPage(error?: string): string {
  return trapPage(
    "Enter your password",
    `<h1>Enter your password</h1>
${stepwiseError(error)}
<form method="POST" action="/trap/names/password">
<label for="password">Password</label>
<input id="password" name="password" type="password" autocomplete="current-password">
<button id="sign-in" type="submit">Sign in</button>
</form>`,
  );
}

function trapOneScreenPage(): string {
  return trapPage(
    "Sign in",
    `<div style="display:none">
<form method="POST" action="/trap/one-screen/hidden">
<label for="hidden-user">Hidden username</label>
<input id="hidden-user" name="username" type="text">
<label for="hidden-pass">Hidden password</label>
<input id="hidden-pass" name="password" type="password">
<button type="submit">Hidden duplicate sign in</button>
</form>
</div>
<h1>Sign in</h1>
<form method="POST" action="/trap/one-screen/login">
<label for="user">Username</label>
<input id="user" name="username" type="text" autocomplete="username">
<label for="pass">Password</label>
<input id="pass" name="password" type="password" autocomplete="current-password">
<button id="sign-in" type="submit">Sign in</button>
</form>`,
  );
}

function trapRememberedPage(username: string): string {
  return trapPage(
    "Welcome back",
    `<h1>Welcome back</h1>
<p>Continue as <strong>${escapeHtml(username)}</strong></p>
<form method="POST" action="/trap/remembered/login">
<label for="pass">Password</label>
<input id="pass" name="password" type="password" autocomplete="current-password">
<button id="continue" type="submit">Continue</button>
</form>`,
  );
}

function trapFramesPage(port: string): string {
  const embedded = `<label for="embedded-pass">Embedded password</label>
<input id="embedded-pass" name="password" type="password">
<script>${TRAP_INPUT_REPORTER_SOURCE}</script>`;
  return trapPage(
    "Partner sign in",
    `<h1>Partner sign in</h1>
<iframe id="same-frame" title="Sign in frame" src="/trap/frames/same" width="420" height="200"></iframe>
<iframe id="cross-frame" title="Partner frame" src="http://localhost:${port}/trap/frames/cross" width="420" height="120"></iframe>
<iframe id="srcdoc-frame" title="Embedded frame" srcdoc="${escapeHtml(embedded)}" width="420" height="120"></iframe>
<iframe id="spoof-frame" title="Spoofed frame" src="http://localhost:${port}/trap/frames/spoof" width="420" height="120"></iframe>
<iframe id="widget-frame" title="Widget frame" src="/trap/frames/widget" width="420" height="80"></iframe>
<button id="remove-widget" type="button">Remove widget frame</button>
<script>
document.getElementById("remove-widget")?.addEventListener("click", () => {
  document.getElementById("widget-frame")?.remove();
});
</script>`,
  );
}

function trapFramesSamePage(): string {
  return trapPage(
    "Sign in frame",
    `<form method="POST" action="/trap/frames/same/login" target="_top">
<label for="frame-user">Frame username</label>
<input id="frame-user" name="username" type="text">
<label for="frame-pass">Frame password</label>
<input id="frame-pass" name="password" type="password">
<button id="frame-sign-in" type="submit">Frame sign in</button>
</form>`,
  );
}

function trapFramesCrossPage(): string {
  return trapPage(
    "Partner frame",
    `<label for="partner-pass">Partner password</label>
<input id="partner-pass" name="password" type="password">
<button type="button">Partner continue</button>`,
  );
}

// ownerDocument を差し替え、page の JS から見える文書の origin を main frame の origin と偽る。
function trapFramesSpoofPage(port: string): string {
  const claimed = JSON.stringify(`http://127.0.0.1:${port}`);
  return trapPage(
    "Spoofed frame",
    `<script>
(() => {
  const claimedOrigin = ${claimed};
  const claimedLocation = { origin: claimedOrigin, href: claimedOrigin + "/trap/frames/" };
  const descriptor = Object.getOwnPropertyDescriptor(Node.prototype, "ownerDocument");
  const realGetter = descriptor.get;
  Object.defineProperty(Node.prototype, "ownerDocument", {
    configurable: true,
    get() {
      const doc = realGetter.call(this);
      if (doc === null) return doc;
      return new Proxy(doc, {
        get(target, property) {
          if (property === "location") return claimedLocation;
          const value = Reflect.get(target, property, target);
          return typeof value === "function" ? value.bind(target) : value;
        }
      });
    }
  });
})();
</script>
<label for="spoof-pass">Spoofed password</label>
<input id="spoof-pass" name="password" type="password">`,
  );
}

function trapFramesWidgetPage(): string {
  return trapPage(
    "Widget frame",
    '<button id="widget-action" type="button">Widget action</button>',
  );
}

function trapValuesPage(): string {
  const c = TRAP_VALUE_CANARIES;
  return trapPage(
    "Sign in",
    `<h1>Sign in</h1>
<script>window.trapSessionToken = ${JSON.stringify(c.scriptVariable)};</script>
<form method="POST" action="/trap/values/login">
<input type="hidden" name="csrf" value="${c.csrfToken}">
<label for="username">Username</label>
<input id="username" name="username" type="text" placeholder="you@example.com" autocomplete="username">
<label for="password">Password</label>
<input id="password" name="password" type="password" placeholder="Your password" value="${c.labeledPassword}">
<label for="display-name">Display name</label>
<input id="display-name" name="display_name" type="text" value="${c.defaultValue}">
<label for="referral">Referral code</label>
<input id="referral" name="referral" type="text" placeholder="Optional code" value="${c.labeledText}">
<label for="notes">Notes</label>
<textarea id="notes" name="notes">${c.textarea}</textarea>
<input id="account-note" name="account_note" type="text" role="note" aria-label="Account note" value="${c.explicitRole}">
<p data-token="${c.dataAttribute}">Promotional terms apply.</p>
<button id="sign-in" type="submit">Sign in</button>
</form>`,
  );
}

function trapArchiveList(): string {
  const items: string[] = [];
  for (let index = 1; index <= TRAP_HUGE_ARTICLES; index += 1) {
    items.push(
      `<li><a href="/trap/huge/article/${index}.html">Archive article number ${index}</a></li>`,
    );
  }
  return `<ul id="archive">\n${items.join("\n")}\n</ul>`;
}

function trapHugePage(): string {
  return trapPage(
    "Archive",
    `<h1>Archive</h1>
<button id="collapse" type="button">Collapse archive</button>
<button id="expand" type="button">Expand archive</button>
${trapArchiveList()}
<form method="POST" action="/trap/huge/login">
<label for="user">Username</label>
<input id="user" name="username" type="text" autocomplete="username">
<label for="pass">Password</label>
<input id="pass" name="password" type="password" autocomplete="current-password">
<button id="sign-in" type="submit">Sign in</button>
</form>
<script>
const archive = document.getElementById("archive");
document.getElementById("collapse")?.addEventListener("click", () => {
  if (archive !== null) archive.hidden = true;
});
document.getElementById("expand")?.addEventListener("click", () => {
  if (archive !== null) archive.hidden = false;
});
</script>`,
  );
}

function trapLoginForm(action: string): string {
  return `<form method="POST" action="${action}">
<label for="user">Username</label>
<input id="user" name="username" type="text" autocomplete="username">
<label for="pass">Password</label>
<input id="pass" name="password" type="password" autocomplete="current-password">
<button id="sign-in" type="submit">Sign in</button>
</form>`;
}

function trapHugeEchoResultPage(password: string): string {
  return trapPage(
    "Archive",
    `<h1>Archive</h1>
${trapArchiveList()}
<p id="echo">Your password is ${escapeHtml(password)}</p>`,
  );
}

function trapEchoResultPage(password: string): string {
  const shown = escapeHtml(password);
  return trapPage(
    "Welcome",
    `<h1>Welcome ${shown}</h1>
<p>Your password is ${shown}</p>
<button id="echo-name" type="button">${shown}</button>
<button id="echo-label" type="button" aria-label="${shown}">Continue</button>
<label for="recovery">Recovery value</label>
<input id="recovery" name="recovery" type="text" value="${shown}">`,
  );
}

function recordTrapPost(
  path: string,
  form: URLSearchParams,
  credentials: Credentials,
): void {
  const fields: Record<string, string> = {};
  for (const [name, value] of form) {
    fields[name] = maskStepwiseValue(value, credentials);
  }
  trapPosts.push({ path, fields });
}

function validTrapLogin(form: URLSearchParams, credentials: Credentials) {
  return (
    form.get("username") === credentials.username &&
    form.get("password") === credentials.password
  );
}

/** Read and record a form POST, then answer with the page `render` builds. */
function handleTrapPost(
  path: string,
  request: IncomingMessage,
  response: ServerResponse,
  credentials: Credentials,
  render: (form: URLSearchParams) => string,
): void {
  readRequestBody(request, (body) => {
    const form = new URLSearchParams(body);
    recordTrapPost(path, form, credentials);
    writePage(response, render(form));
  });
}

/** Test-only endpoints of the trap pages (state and in-page reports). */
function handleTrapControl(
  route: string,
  request: IncomingMessage,
  response: ServerResponse,
  credentials: Credentials,
): boolean {
  if (route === "GET /trap/state") {
    writeJson(response, 200, {
      requests: trapRequests,
      posts: trapPosts,
      inputs: trapInputs,
    });
  } else if (route === "POST /trap/input") {
    recordStepwiseJson(request, response, (value) => {
      if (
        typeof value.path !== "string" ||
        typeof value.origin !== "string" ||
        typeof value.field !== "string" ||
        typeof value.value !== "string"
      )
        return false;
      trapInputs.push({
        path: value.path,
        origin: value.origin,
        field: value.field,
        value: maskStepwiseValue(value.value, credentials),
      });
      return true;
    });
  } else {
    return false;
  }
  return true;
}

/** Form POST routes of the trap pages and the page each one answers with. */
function trapPostRoutes(
  credentials: Credentials,
): Record<string, (form: URLSearchParams) => string> {
  const signedIn = (form: URLSearchParams) =>
    validTrapLogin(form, credentials)
      ? trapSignedInPage(credentials.username)
      : trapErrorPage();
  return {
    "/trap/names/username": (form) =>
      form.get("username") === credentials.username
        ? trapNamesPasswordPage()
        : trapNamesUsernamePage("Unknown user"),
    "/trap/names/password": (form) =>
      form.get("password") === credentials.password
        ? trapSignedInPage(credentials.username)
        : trapNamesPasswordPage("Incorrect password"),
    "/trap/one-screen/login": signedIn,
    "/trap/one-screen/hidden": () => trapErrorPage(),
    "/trap/remembered/login": (form) =>
      form.get("password") === credentials.password
        ? trapSignedInPage(credentials.username)
        : trapErrorPage(),
    "/trap/frames/same/login": signedIn,
    "/trap/values/login": signedIn,
    "/trap/huge/login": signedIn,
    "/trap/huge/echo/login": (form) =>
      trapHugeEchoResultPage(form.get("password") ?? ""),
    "/trap/echo/login": (form) =>
      trapEchoResultPage(form.get("password") ?? ""),
  };
}

/** GET routes of the trap pages. `port` is the fixture's port. */
function trapGetPage(
  path: string,
  port: string,
  credentials: Credentials,
): string | undefined {
  switch (path) {
    case "/trap/names/":
      return trapNamesUsernamePage();
    case "/trap/one-screen/":
      return trapOneScreenPage();
    case "/trap/remembered/":
      return trapRememberedPage(credentials.username);
    case "/trap/frames/":
      return trapFramesPage(port);
    case "/trap/frames/same":
      return trapFramesSamePage();
    case "/trap/frames/cross":
      return trapFramesCrossPage();
    case "/trap/frames/spoof":
      return trapFramesSpoofPage(port);
    case "/trap/frames/widget":
      return trapFramesWidgetPage();
    case "/trap/values/":
      return trapValuesPage();
    case "/trap/huge/":
      return trapHugePage();
    case "/trap/huge/echo/":
      return trapPage("Sign in", trapLoginForm("/trap/huge/echo/login"));
    case "/trap/echo/":
      return trapPage("Sign in", trapLoginForm("/trap/echo/login"));
    default:
      return undefined;
  }
}

/**
 * Trap pages for the aria snapshot (Issue #57): `names` (elements named only
 * through aria-labelledby, an SVG title, an image alt or a submit value),
 * `one-screen` (a hidden duplicate form before the real one), `remembered`
 * (the username shown as text), `frames` (same-origin, cross-origin, srcdoc,
 * ownerDocument-spoofing and removable iframes; the cross-origin ones live on
 * `localhost`), `values` (planted default values), `huge` (past 64 KiB, with
 * a form near the end, and `huge/echo/` echoing the password at the end) and
 * `echo` (the password shown in a heading, a button name, an aria-label, an
 * input value and a paragraph). Returns false for other requests.
 */
function handleTrapRequest(
  request: IncomingMessage,
  response: ServerResponse,
  credentials: Credentials,
): boolean {
  const url = new URL(request.url ?? "/", requestOrigin(request));
  if (!url.pathname.startsWith("/trap/")) return false;
  const route = `${request.method} ${url.pathname}`;
  if (handleTrapControl(route, request, response, credentials)) return true;
  trapRequests.push({
    method: request.method ?? "",
    host: url.host,
    path: url.pathname,
  });
  if (request.method === "POST") {
    const render = trapPostRoutes(credentials)[url.pathname];
    if (render !== undefined) {
      handleTrapPost(url.pathname, request, response, credentials, render);
      return true;
    }
  } else if (request.method === "GET") {
    const page = trapGetPage(url.pathname, url.port, credentials);
    if (page !== undefined) {
      writePage(response, page);
      return true;
    }
  }
  response.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
  response.end("not found");
  return true;
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

// State of the /device-cookies/ device approval pages (Issue #49). They accept
// the `device` cookie and the `sid` session issued by the /persistent-cookies/
// login site and send every other request to the login page, even a GET.
const deviceCookieRequests: RecordedRequest[] = [];
const voidedSidCookies = new Set<string>();
let deviceCookieApprovals = 0;

function recordDeviceCookieRequest(request: IncomingMessage): void {
  deviceCookieRequests.push({
    method: request.method ?? "",
    path: request.url ?? "",
    cookies: [...cookiesFrom(request).keys()],
  });
}

function hasDeviceCookieSession(request: IncomingMessage): boolean {
  if (hasValidDeviceCookie(request)) return true;
  const sid = cookiesFrom(request).get("sid");
  return (
    sid !== undefined &&
    issuedSidCookies.includes(sid) &&
    !voidedSidCookies.has(sid)
  );
}

function redirectToDeviceCookieLogin(response: ServerResponse): void {
  response.writeHead(302, { Location: "/device-cookies/login" });
  response.end();
}

function deviceCookieEntryPage(): string {
  return devicePage().replace(
    'action="/device"',
    'action="/device-cookies/device"',
  );
}

function deviceCookieAuthorizationPage(userCode: string): string {
  return deviceAuthorizationPage(userCode).replace(
    'action="/device/approve"',
    'action="/device-cookies/approve"',
  );
}

function handleDeviceCookieEntry(
  request: IncomingMessage,
  response: ServerResponse,
): void {
  readRequestBody(request, (body) => {
    const userCode = new URLSearchParams(body).get("user_code");
    writePage(
      response,
      userCode !== null && deviceCodes.has(userCode)
        ? deviceCookieAuthorizationPage(userCode)
        : deviceErrorPage(),
    );
  });
}

function handleDeviceCookieApprove(
  request: IncomingMessage,
  response: ServerResponse,
): void {
  readRequestBody(request, (body) => {
    const userCode = new URLSearchParams(body).get("user_code");
    if (userCode !== null && deviceCodes.has(userCode)) {
      deviceCodes.set(userCode, true);
      deviceCookieApprovals += 1;
      writePage(response, deviceApprovedPage());
    } else {
      writePage(response, deviceErrorPage());
    }
  });
}

/** Device authorization whose `verification_uri` is the gated approval page. */
function handleDeviceCookieOAuthAuthorization(
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
      verification_uri: `${requestOrigin(request)}/device-cookies/device`,
      expires_in: 300,
      interval: 1,
    });
  });
}

/**
 * Device approval pages behind the persistent-cookie login: `GET /device` and
 * the `POST` steps require a valid `device` cookie or `sid` session, while
 * `GET /open` shows the empty form to anyone (its submission still requires
 * the session). `GET /state` reports `{login_posts, approvals, requests}`,
 * `POST /invalidate` voids every `device` cookie and `sid` session. Returns
 * false for requests it does not handle.
 */
function handleDeviceCookieRequest(
  request: IncomingMessage,
  response: ServerResponse,
): boolean {
  const route = `${request.method} ${request.url}`;
  if (route === "GET /device-cookies/state") {
    writeJson(response, 200, {
      login_posts: persistentCookieLoginPosts,
      approvals: deviceCookieApprovals,
      requests: deviceCookieRequests,
    });
    return true;
  }
  if (route === "POST /device-cookies/invalidate") {
    validDeviceCookies.clear();
    for (const sid of issuedSidCookies) voidedSidCookies.add(sid);
    writeJson(response, 200, { ok: true });
    return true;
  }
  if (request.url?.startsWith("/device-cookies/") !== true) return false;
  recordDeviceCookieRequest(request);
  const authenticated = hasDeviceCookieSession(request);
  if (route === "GET /device-cookies/login") {
    writePage(response, persistentCookieLoginForm(false));
  } else if (route === "GET /device-cookies/open") {
    writePage(response, deviceCookieEntryPage());
  } else if (route === "POST /device-cookies/oauth/device_authorization") {
    handleDeviceCookieOAuthAuthorization(request, response);
  } else if (
    route !== "GET /device-cookies/device" &&
    route !== "POST /device-cookies/device" &&
    route !== "POST /device-cookies/approve"
  ) {
    response.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
    response.end("not found");
  } else if (!authenticated) {
    redirectToDeviceCookieLogin(response);
  } else if (route === "GET /device-cookies/device") {
    writePage(response, deviceCookieEntryPage());
  } else if (route === "POST /device-cookies/device") {
    handleDeviceCookieEntry(request, response);
  } else {
    handleDeviceCookieApprove(request, response);
  }
  return true;
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

  if (handlePersistentCookieRequest(request, response, credentials)) return;

  if (handleDeviceCookieRequest(request, response)) return;

  if (handleStepwiseRequest(request, response, credentials)) return;

  if (handleTrapRequest(request, response, credentials)) return;

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
