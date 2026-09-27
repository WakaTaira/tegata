#!/usr/bin/env node

import { mkdtemp, rm } from "node:fs/promises";
import { createServer } from "node:net";
import os from "node:os";
import path from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { type Browser, chromium, type Page } from "playwright-core";
import {
  type ApiProxy,
  type ApiProxyRequestRecord,
  startApiProxy,
} from "./api-proxy.js";
import {
  abortableSleep,
  type DeviceAuthorization,
  isRecord,
  OAUTH_REQUEST_TIMEOUT_MS,
  OAuthGrantError,
  OAuthProxySession,
  type OAuthTokenAction,
  pollForToken,
  postForm,
  renderValueTemplate,
  requestDeviceAuthorization,
  revokeTokens,
  type TokenSet,
  tokenPollDeadline,
} from "./oauth.js";

type FillStep = {
  action: "fill";
  selector: string;
  value: "{{username}}" | "{{password}}" | "{{totp}}";
};

type DeviceFillStep = {
  action: "fill";
  selector: string;
  value: FillStep["value"] | "{{user_code}}";
};

type ClickStep = {
  action: "click";
  selector: string;
};

type LoginStep = FillStep | ClickStep;
type DeviceStep = DeviceFillStep | ClickStep;

type RequestId = number;

type LoginRequest = {
  op: "login";
  id?: RequestId;
  target_url: string;
  steps: LoginStep[] | null;
  success_selector: string | null;
  failure_selector: string | null;
  secret: {
    username: string;
    password: string;
    totp: string | null;
  };
};

type AuthorizeDeviceRequest = {
  op: "authorize_device";
  id?: RequestId;
  login_url: string;
  verification_url: string;
  user_code: string;
  steps: DeviceStep[] | null;
  success_selector: string;
  failure_selector: string | null;
  secret: LoginRequest["secret"];
};

type LeaseRequest = { op: "lease"; id?: RequestId };

type ReleaseRequest = { op: "release"; id?: RequestId; target_id: string };

type StaticApiProxyStartRequest = {
  op: "api_proxy_start";
  id?: RequestId;
  upstream: string;
  header: string;
  header_value: string;
};

type OAuthRequestConfig = {
  client_id: string;
  device_authorization_url: string;
  token_url: string;
  revocation_url: string | null;
  scope: string | null;
  login_url: string;
  steps: DeviceStep[] | null;
  success_selector: string;
  failure_selector: string | null;
  secret: LoginRequest["secret"];
};

type OAuthApiProxyStartRequest = {
  op: "api_proxy_start";
  id?: RequestId;
  upstream: string;
  header: string;
  value_template: string;
  oauth: OAuthRequestConfig;
};

type ApiProxyStartRequest =
  | StaticApiProxyStartRequest
  | OAuthApiProxyStartRequest;

type ApiProxyStopRequest = { op: "api_proxy_stop"; id?: RequestId };

type Request =
  | LoginRequest
  | AuthorizeDeviceRequest
  | LeaseRequest
  | ReleaseRequest
  | ApiProxyStartRequest
  | ApiProxyStopRequest
  | { op: "hello"; id?: RequestId }
  | { op: "shutdown"; id?: RequestId };

type ErrorCode =
  | "INVALID_CREDENTIAL"
  | "MFA_REQUIRED"
  | "SELECTOR_NOT_FOUND"
  | "VAULT_LOCKED"
  | "RATE_LIMITED"
  | "TOTP_NOT_EXPOSABLE"
  | "DEVICE_CODE_REJECTED"
  | "LOGIN_RESULT_TIMEOUT"
  | "OAUTH_GRANT_FAILED"
  | "INTERNAL";

export class SelectorNotFoundError extends Error {
  constructor(readonly stepIndex?: number) {
    super();
  }
}

export class InvalidCredentialError extends Error {}

export class MfaRequiredError extends Error {}

export class DeviceCodeRejectedError extends Error {}

export class LoginResultTimeoutError extends Error {}

type ExecutionStage = "login" | "device" | "oauth";

type DiagnosticRequest =
  | LoginRequest
  | AuthorizeDeviceRequest
  | ApiProxyStartRequest;

/** 診断行から置換する秘密の候補。未設定の値（null・undefined・空文字）は無視される。 */
type SecretCandidates = Array<string | null | undefined>;

function truncateUtf8(value: string, maxBytes: number): string {
  let bytes = 0;
  let end = 0;
  for (const character of value) {
    const characterBytes = Buffer.byteLength(character, "utf8");
    if (bytes + characterBytes > maxBytes) break;
    bytes += characterBytes;
    end += character.length;
  }
  return value.slice(0, end);
}

function redactExecutorErrorMessage(
  message: string,
  secrets: SecretCandidates,
): string {
  const nonEmptySecrets = secrets.filter(
    (secret): secret is string =>
      secret !== undefined && secret !== null && secret !== "",
  );
  return [...new Set(nonEmptySecrets)]
    .sort((left, right) => right.length - left.length)
    .reduce(
      (redacted, secret) => redacted.replaceAll(secret, "[REDACTED]"),
      message,
    );
}

function removeUrlQueryAndFragment(value: string): string {
  return value.replace(/\b[a-z][a-z\d+.-]*:\/\/[^\s"'()]*/giu, (url) => {
    const detailStart = url.search(/[?#]/u);
    return detailStart === -1 ? url : url.slice(0, detailStart);
  });
}

function requestSecrets(request: DiagnosticRequest): SecretCandidates {
  if (request.op === "api_proxy_start") {
    return "oauth" in request
      ? [
          request.oauth.secret.username,
          request.oauth.secret.password,
          request.oauth.secret.totp,
        ]
      : [request.header_value];
  }
  const loginSecrets = [
    request.secret.username,
    request.secret.password,
    request.secret.totp,
  ];
  return request.op === "login"
    ? loginSecrets
    : [...loginSecrets, request.user_code];
}

/**
 * 診断行を組み立てる。`runtimeSecrets` には要求に含まれず実行中に得た秘密
 * （device code・user code・token 等）を渡し、要求由来の秘密と同じく置換する。
 */
export function formatExecutorErrorLine(
  request: DiagnosticRequest,
  stage: ExecutionStage,
  code: ErrorCode,
  error: unknown,
  runtimeSecrets: SecretCandidates = [],
): string {
  const secrets = [...requestSecrets(request), ...runtimeSecrets];
  const rawMessage = error instanceof Error ? error.message : "";
  const message = truncateUtf8(
    removeUrlQueryAndFragment(
      redactExecutorErrorMessage(rawMessage, secrets),
    ).split(/\r\n|[\r\n]/u, 1)[0],
    300,
  );
  const name = truncateUtf8(
    redactExecutorErrorMessage(
      error instanceof Error ? error.name : typeof error,
      secrets,
    ),
    64,
  );
  return `tegata-executor: error ${JSON.stringify({
    op: request.op,
    stage,
    code,
    name,
    message,
  })}\n`;
}

export function classifyError(
  error: unknown,
  stage: ExecutionStage,
): ErrorCode {
  if (stage === "oauth") {
    return error instanceof OAuthGrantError ? "OAUTH_GRANT_FAILED" : "INTERNAL";
  }
  if (stage === "device") {
    return error instanceof DeviceCodeRejectedError
      ? "DEVICE_CODE_REJECTED"
      : "INTERNAL";
  }
  return error instanceof SelectorNotFoundError
    ? "SELECTOR_NOT_FOUND"
    : error instanceof InvalidCredentialError
      ? "INVALID_CREDENTIAL"
      : error instanceof MfaRequiredError
        ? "MFA_REQUIRED"
        : error instanceof LoginResultTimeoutError
          ? "LOGIN_RESULT_TIMEOUT"
          : "INTERNAL";
}

type ClassifiedExecutionError = {
  code: ErrorCode;
  step?: number;
};

function classifyExecutionError(
  error: unknown,
  stage: ExecutionStage,
): ClassifiedExecutionError {
  const code = classifyError(error, stage);
  return code === "SELECTOR_NOT_FOUND" &&
    error instanceof SelectorNotFoundError &&
    error.stepIndex !== undefined
    ? { code, step: error.stepIndex }
    : { code };
}

function formatErrorResponse(error: ClassifiedExecutionError) {
  return {
    ok: false as const,
    error: error.code,
    ...(error.step === undefined ? {} : { step: error.step }),
  };
}

function writeExecutorErrorLine(
  request: DiagnosticRequest,
  stage: ExecutionStage,
  error: ClassifiedExecutionError,
  cause: unknown,
  runtimeSecrets: SecretCandidates = [],
): void {
  if (
    error.code !== "INTERNAL" &&
    error.code !== "LOGIN_RESULT_TIMEOUT" &&
    error.code !== "OAUTH_GRANT_FAILED"
  ) {
    return;
  }
  process.stderr.write(
    formatExecutorErrorLine(request, stage, error.code, cause, runtimeSecrets),
  );
}

let activeBrowser: Browser | undefined;
let activeGuard: CdpGuard | undefined;
let activeTempDir: string | undefined;
let activeBrowserContextId: string | undefined;
let activeApiProxy: { close: () => Promise<void> } | undefined;
let activeOAuthStart:
  | { controller: AbortController; done: Promise<void> }
  | undefined;
let shuttingDown = false;

type CdpMessage = {
  id?: number;
  method?: string;
  params?: Record<string, unknown>;
  sessionId?: string;
  result?: Record<string, unknown>;
  error?: { message?: string };
};

type CdpGuard = {
  close: () => void;
  failure: Promise<never>;
  browserPid: number | undefined;
  assertOpen: () => void;
  registerUserAgentOverride: (override: UserAgentOverride) => Promise<void>;
  waitForTargetReady: (targetId: string) => Promise<void>;
  send: (
    method: string,
    params: Record<string, unknown>,
  ) => Promise<Record<string, unknown> | undefined>;
};

type PendingCdpCommand = {
  resolve: (result: Record<string, unknown> | undefined) => void;
  reject: (error: unknown) => void;
  timeout: ReturnType<typeof setTimeout>;
};

type TargetReadiness = {
  promise: Promise<void>;
  resolve: () => void;
  reject: (error: unknown) => void;
};

const autoAttachParams = {
  autoAttach: true,
  waitForDebuggerOnStart: true,
  flatten: true,
};

export type UserAgentBrand = {
  brand: string;
  version: string;
};

export type UserAgentMetadata = {
  brands: UserAgentBrand[];
  fullVersionList: UserAgentBrand[];
  platform: string;
  platformVersion: string;
  architecture: string;
  bitness: string;
  model: string;
  mobile: boolean;
};

export type UserAgentOverride = {
  userAgent: string;
  userAgentMetadata: UserAgentMetadata;
};

export function headfulUserAgent(ua: string): string {
  return ua.replaceAll("HeadlessChrome", "Chrome");
}

export function withoutHeadlessBrands(
  brands: UserAgentBrand[],
): UserAgentBrand[] {
  return brands.filter(({ brand }) => !brand.includes("Headless"));
}

export function headfulUserAgentMetadata(
  metadata: UserAgentMetadata,
): UserAgentMetadata {
  return {
    ...metadata,
    brands: withoutHeadlessBrands(metadata.brands),
    fullVersionList: withoutHeadlessBrands(metadata.fullVersionList),
  };
}

// 新規タブの初回ナビゲーションでは client hints がガードの接続前に確定しており、
// Emulation.setUserAgentOverride が反映されません。そのため文書リクエストを捕捉し、
// Headless ブランドを除いた client hints に書き換えてから継続します。
const guardFetchPatterns = [
  { urlPattern: "file://*", requestStage: "Request" },
  { urlPattern: "*", resourceType: "Document", requestStage: "Request" },
];

const brandClientHintHeaders = new Set([
  "sec-ch-ua",
  "sec-ch-ua-full-version-list",
]);

function mustBlockPausedRequest(url: string): boolean {
  try {
    return new URL(url).protocol === "file:";
  } catch {
    return true;
  }
}

function withoutHeadlessClientHintBrands(value: string): string {
  return value
    .split(",")
    .map((item) => item.trim())
    .filter((item) => !/^"[^"]*Headless[^"]*"/.test(item))
    .join(", ");
}

function headfulClientHintHeaders(
  headers: unknown,
): Array<{ name: string; value: string }> | undefined {
  if (!isRecord(headers)) return undefined;
  let rewritten = false;
  const entries = Object.entries(headers).flatMap(([name, value]) => {
    if (typeof value !== "string") return [];
    if (!brandClientHintHeaders.has(name.toLowerCase())) {
      return [{ name, value }];
    }
    const headful = withoutHeadlessClientHintBrands(value);
    if (headful !== value) rewritten = true;
    return [{ name, value: headful }];
  });
  return rewritten ? entries : undefined;
}

function isPageOrIframeTarget(targetType: string): boolean {
  return targetType === "page" || targetType === "iframe";
}

export function guardTargetCommands(
  targetType: string,
  userAgentOverrideRegistered = true,
): string[] {
  const commands: string[] = [];
  const fileGuardTarget = isPageOrIframeTarget(targetType);
  if (fileGuardTarget) {
    commands.push("Fetch.enable");
    if (targetType === "page") commands.push("Target.setAutoAttach");
    if (userAgentOverrideRegistered) {
      commands.push("Emulation.setUserAgentOverride");
    }
  }
  commands.push("Runtime.runIfWaitingForDebugger");
  return commands;
}

function isUserAgentBrand(value: unknown): value is UserAgentBrand {
  return (
    isRecord(value) &&
    typeof value.brand === "string" &&
    typeof value.version === "string"
  );
}

function isUserAgentMetadata(value: unknown): value is UserAgentMetadata {
  return (
    isRecord(value) &&
    Array.isArray(value.brands) &&
    value.brands.every(isUserAgentBrand) &&
    Array.isArray(value.fullVersionList) &&
    value.fullVersionList.every(isUserAgentBrand) &&
    typeof value.platform === "string" &&
    typeof value.platformVersion === "string" &&
    typeof value.architecture === "string" &&
    typeof value.bitness === "string" &&
    typeof value.model === "string" &&
    typeof value.mobile === "boolean"
  );
}

async function readNavigatorUserAgentData(
  page: Page,
): Promise<{ userAgent: string; metadata: UserAgentMetadata } | undefined> {
  try {
    const value = await page.evaluate(async () => {
      const userAgentData = (
        navigator as Navigator & {
          userAgentData?: {
            brands: UserAgentBrand[];
            mobile: boolean;
            getHighEntropyValues: (hints: string[]) => Promise<{
              fullVersionList: UserAgentBrand[];
              platform: string;
              platformVersion: string;
              architecture: string;
              bitness: string;
              model: string;
            }>;
          };
        }
      ).userAgentData;
      if (userAgentData === undefined) return undefined;
      const highEntropyValues = await userAgentData.getHighEntropyValues([
        "fullVersionList",
        "platformVersion",
        "architecture",
        "bitness",
        "model",
      ]);
      return {
        userAgent: navigator.userAgent,
        metadata: {
          brands: userAgentData.brands,
          fullVersionList: highEntropyValues.fullVersionList,
          platform: highEntropyValues.platform,
          platformVersion: highEntropyValues.platformVersion,
          architecture: highEntropyValues.architecture,
          bitness: highEntropyValues.bitness,
          model: highEntropyValues.model,
          mobile: userAgentData.mobile,
        },
      };
    });
    if (
      !isRecord(value) ||
      typeof value.userAgent !== "string" ||
      !isUserAgentMetadata(value.metadata)
    ) {
      return undefined;
    }
    return { userAgent: value.userAgent, metadata: value.metadata };
  } catch {
    return undefined;
  }
}

function fallbackPlatform(): string {
  if (process.platform === "linux") return "Linux";
  if (process.platform === "win32") return "Windows";
  if (process.platform === "darwin") return "macOS";
  throw new Error(`unsupported browser platform: ${process.platform}`);
}

function fallbackUserAgentMetadata(product: string): UserAgentMetadata {
  const version = product.match(/\/(\d+(?:\.\d+)*)/)?.[1];
  if (version === undefined) {
    throw new Error("browser product version was not returned");
  }
  return {
    brands: [{ brand: "Chromium", version: version.split(".")[0] }],
    fullVersionList: [{ brand: "Chromium", version }],
    platform: fallbackPlatform(),
    platformVersion: "",
    architecture: "",
    bitness: "",
    model: "",
    mobile: false,
  };
}

function isNullableString(value: unknown): value is string | null {
  return value === null || typeof value === "string";
}

function isSecretPlaceholder(value: unknown): value is FillStep["value"] {
  return (
    value === "{{username}}" || value === "{{password}}" || value === "{{totp}}"
  );
}

function isDevicePlaceholder(value: unknown): value is DeviceFillStep["value"] {
  return isSecretPlaceholder(value) || value === "{{user_code}}";
}

class InvalidRequestError extends Error {
  constructor(readonly id?: RequestId) {
    super("invalid request");
  }
}

function isAbsent(value: unknown): value is null | undefined {
  return value === undefined || value === null;
}

function isOptionalNullableString(
  value: unknown,
): value is string | null | undefined {
  return value === undefined || isNullableString(value);
}

function isRequestSecret(value: unknown): value is {
  username: string;
  password: string;
  totp?: string | null;
} {
  return (
    isRecord(value) &&
    typeof value.username === "string" &&
    typeof value.password === "string" &&
    isOptionalNullableString(value.totp)
  );
}

function parseDeviceSteps(value: unknown, id?: RequestId): DeviceStep[] | null {
  if (isAbsent(value)) return null;
  if (!Array.isArray(value)) throw new InvalidRequestError(id);
  return value.map((step): DeviceStep => {
    if (!isRecord(step) || typeof step.selector !== "string") {
      throw new InvalidRequestError(id);
    }
    if (step.action === "click") {
      return { action: "click", selector: step.selector };
    }
    if (step.action === "fill" && isDevicePlaceholder(step.value)) {
      return { action: "fill", selector: step.selector, value: step.value };
    }
    throw new InvalidRequestError(id);
  });
}

function parseOAuthConfig(value: unknown, id?: RequestId): OAuthRequestConfig {
  if (
    !isRecord(value) ||
    typeof value.client_id !== "string" ||
    typeof value.device_authorization_url !== "string" ||
    typeof value.token_url !== "string" ||
    !isOptionalNullableString(value.revocation_url) ||
    !isOptionalNullableString(value.scope) ||
    typeof value.login_url !== "string" ||
    typeof value.success_selector !== "string" ||
    !isOptionalNullableString(value.failure_selector) ||
    !isRequestSecret(value.secret)
  ) {
    throw new InvalidRequestError(id);
  }
  return {
    client_id: value.client_id,
    device_authorization_url: value.device_authorization_url,
    token_url: value.token_url,
    revocation_url: value.revocation_url ?? null,
    scope: value.scope ?? null,
    login_url: value.login_url,
    steps: parseDeviceSteps(value.steps, id),
    success_selector: value.success_selector,
    failure_selector: value.failure_selector ?? null,
    secret: {
      username: value.secret.username,
      password: value.secret.password,
      totp: value.secret.totp ?? null,
    },
  };
}

/** 静的トークン（`header_value`）と OAuth（`value_template` + `oauth`）のどちらか一方のみを受け付ける。 */
function parseApiProxyStart(
  value: Record<string, unknown>,
  id?: RequestId,
): ApiProxyStartRequest {
  if (typeof value.upstream !== "string" || typeof value.header !== "string") {
    throw new InvalidRequestError(id);
  }
  const base = {
    op: "api_proxy_start" as const,
    id,
    upstream: value.upstream,
    header: value.header,
  };
  if (isAbsent(value.oauth)) {
    if (
      typeof value.header_value !== "string" ||
      !isAbsent(value.value_template)
    ) {
      throw new InvalidRequestError(id);
    }
    return { ...base, header_value: value.header_value };
  }
  if (
    !isAbsent(value.header_value) ||
    typeof value.value_template !== "string"
  ) {
    throw new InvalidRequestError(id);
  }
  return {
    ...base,
    value_template: value.value_template,
    oauth: parseOAuthConfig(value.oauth, id),
  };
}

export function parseRequest(line: string): Request {
  let value: unknown;
  try {
    value = JSON.parse(line);
  } catch {
    throw new InvalidRequestError();
  }
  const id =
    isRecord(value) && typeof value.id === "number" ? value.id : undefined;
  if (!isRecord(value) || typeof value.op !== "string") {
    throw new InvalidRequestError(id);
  }
  if (value.op === "hello") return { op: "hello", id };
  if (value.op === "shutdown") return { op: "shutdown", id };
  if (value.op === "lease") return { op: "lease", id };
  if (value.op === "api_proxy_stop") return { op: "api_proxy_stop", id };
  if (value.op === "api_proxy_start") return parseApiProxyStart(value, id);
  if (value.op === "release") {
    if (typeof value.target_id !== "string") {
      throw new InvalidRequestError(id);
    }
    return { op: "release", id, target_id: value.target_id };
  }
  if (value.op === "authorize_device") {
    const secret = value.secret;
    if (
      typeof value.login_url !== "string" ||
      typeof value.verification_url !== "string" ||
      typeof value.user_code !== "string" ||
      typeof value.success_selector !== "string" ||
      (value.failure_selector !== undefined &&
        !isNullableString(value.failure_selector)) ||
      !isRecord(secret) ||
      typeof secret.username !== "string" ||
      typeof secret.password !== "string" ||
      (secret.totp !== undefined && !isNullableString(secret.totp))
    ) {
      throw new InvalidRequestError(id);
    }

    return {
      op: "authorize_device",
      id,
      login_url: value.login_url,
      verification_url: value.verification_url,
      user_code: value.user_code,
      steps: parseDeviceSteps(value.steps, id),
      success_selector: value.success_selector,
      failure_selector: value.failure_selector ?? null,
      secret: {
        username: secret.username,
        password: secret.password,
        totp: secret.totp ?? null,
      },
    };
  }
  if (value.op !== "login") throw new InvalidRequestError(id);

  const secret = value.secret;
  if (
    typeof value.target_url !== "string" ||
    (value.success_selector !== undefined &&
      !isNullableString(value.success_selector)) ||
    (value.failure_selector !== undefined &&
      !isNullableString(value.failure_selector)) ||
    !isRecord(secret) ||
    typeof secret.username !== "string" ||
    typeof secret.password !== "string" ||
    (secret.totp !== undefined && !isNullableString(secret.totp))
  ) {
    throw new InvalidRequestError(id);
  }

  let steps: LoginStep[] | null = null;
  if (value.steps !== null) {
    if (!Array.isArray(value.steps)) throw new InvalidRequestError(id);
    steps = value.steps.map((step): LoginStep => {
      if (!isRecord(step) || typeof step.selector !== "string") {
        throw new InvalidRequestError(id);
      }
      if (step.action === "click") {
        return { action: "click", selector: step.selector };
      }
      if (step.action === "fill" && isSecretPlaceholder(step.value)) {
        return {
          action: "fill",
          selector: step.selector,
          value: step.value,
        };
      }
      throw new InvalidRequestError(id);
    });
  }

  return {
    op: "login",
    id,
    target_url: value.target_url,
    steps,
    success_selector: value.success_selector ?? null,
    failure_selector: value.failure_selector ?? null,
    secret: {
      username: secret.username,
      password: secret.password,
      totp: secret.totp ?? null,
    },
  };
}

async function reservePort(): Promise<number> {
  const server = createServer();
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });
  const address = server.address();
  if (address === null || typeof address === "string") {
    server.close();
    throw new Error("could not reserve a port");
  }
  const port = address.port;
  await new Promise<void>((resolve, reject) => {
    server.close((error) => (error === undefined ? resolve() : reject(error)));
  });
  return port;
}

async function waitForEndpoint(port: number): Promise<string> {
  const response = await fetch(`http://127.0.0.1:${port}/json/version`);
  if (!response.ok) throw new Error("could not read CDP endpoint");
  const value: unknown = await response.json();
  if (!isRecord(value) || typeof value.webSocketDebuggerUrl !== "string") {
    throw new Error("CDP endpoint was not returned");
  }
  return value.webSocketDebuggerUrl;
}

async function openGuard(endpoint: string): Promise<CdpGuard> {
  const ws = new WebSocket(endpoint);
  let nextId = 1;
  let rejectOpen: (error: unknown) => void = () => undefined;
  let rejectFailure: (error: unknown) => void = () => undefined;
  let failureError: Error | undefined;
  let intentionallyClosed = false;
  let browserPid: number | undefined;
  const pending = new Map<number, PendingCdpCommand>();
  const targetReadiness = new Map<string, TargetReadiness>();
  const attachedTargets = new Map<
    string,
    { targetType: string; sessionId: string }
  >();
  let userAgentOverride: UserAgentOverride | undefined;
  const failure = new Promise<never>((_resolve, reject) => {
    rejectFailure = reject;
  });

  const getTargetReadiness = (targetId: string): TargetReadiness => {
    const existing = targetReadiness.get(targetId);
    if (existing !== undefined) return existing;
    let resolveReadiness: () => void = () => undefined;
    let rejectReadiness: (error: unknown) => void = () => undefined;
    const promise = new Promise<void>((resolve, reject) => {
      resolveReadiness = resolve;
      rejectReadiness = reject;
    });
    promise.catch(() => undefined);
    const readiness = {
      promise,
      resolve: resolveReadiness,
      reject: rejectReadiness,
    };
    targetReadiness.set(targetId, readiness);
    return readiness;
  };

  const fail = (error: unknown): void => {
    if (failureError !== undefined) return;
    failureError =
      error instanceof Error ? error : new Error("CDP guard failed");
    rejectOpen(failureError);
    rejectFailure(failureError);
    for (const { reject, timeout } of pending.values()) {
      clearTimeout(timeout);
      reject(failureError);
    }
    pending.clear();
  };

  const send = (
    method: string,
    params: Record<string, unknown>,
    sessionId?: string,
    failOnTimeout = true,
  ): Promise<Record<string, unknown> | undefined> =>
    new Promise((resolve, reject) => {
      if (ws.readyState !== WebSocket.OPEN) {
        reject(new Error("CDP guard websocket is not open"));
        return;
      }
      const id = nextId++;
      const timeout = setTimeout(() => {
        pending.delete(id);
        const error = new Error("CDP guard command timed out");
        reject(error);
        if (failOnTimeout) fail(error);
      }, 10_000);
      pending.set(id, { resolve, reject, timeout });
      try {
        ws.send(JSON.stringify({ id, method, params, sessionId }));
      } catch (error) {
        pending.delete(id);
        clearTimeout(timeout);
        reject(error);
      }
    });

  const registerUserAgentOverride = async (
    override: UserAgentOverride,
  ): Promise<void> => {
    userAgentOverride = override;
    try {
      await Promise.all(
        [...attachedTargets.values()]
          .filter(({ targetType }) => isPageOrIframeTarget(targetType))
          .map(({ sessionId }) =>
            send("Emulation.setUserAgentOverride", override, sessionId),
          ),
      );
    } catch (error) {
      fail(error);
      throw error;
    }
  };

  const handleEvent = (message: CdpMessage): void => {
    if (message.method === "Target.attachedToTarget") {
      const params = message.params;
      const targetInfo = params?.targetInfo;
      const sessionId = params?.sessionId;
      if (
        !isRecord(targetInfo) ||
        typeof targetInfo.type !== "string" ||
        typeof targetInfo.targetId !== "string" ||
        typeof sessionId !== "string"
      ) {
        fail(new Error("invalid Target.attachedToTarget event"));
        return;
      }
      attachedTargets.set(targetInfo.targetId, {
        targetType: targetInfo.type,
        sessionId,
      });
      const readiness = getTargetReadiness(targetInfo.targetId);
      const fileGuardTarget = isPageOrIframeTarget(targetInfo.type);
      void (async () => {
        if (fileGuardTarget) {
          await send(
            "Fetch.enable",
            { patterns: guardFetchPatterns },
            sessionId,
          );
          if (targetInfo.type === "page") {
            await send("Target.setAutoAttach", autoAttachParams, sessionId);
          }
        }
        // デバッガ待ちで停止中の target では、Emulation.setUserAgentOverride の応答が
        // 再開まで返りません。そのため上書きの応答を待たずに再開命令を続けて送り、
        // 両方の応答を待ちます。コマンドは送信順に処理されるため、User-Agent は
        // 再開後の最初のリクエストから上書きされます（client hints は guardFetchPatterns を参照）。
        const commands: Array<Promise<unknown>> = [];
        if (fileGuardTarget && userAgentOverride !== undefined) {
          commands.push(
            send(
              "Emulation.setUserAgentOverride",
              userAgentOverride,
              sessionId,
            ),
          );
        }
        commands.push(
          send(
            "Runtime.runIfWaitingForDebugger",
            {},
            sessionId,
            fileGuardTarget,
          ),
        );
        await Promise.all(commands);
      })()
        .then(() => readiness.resolve())
        .catch((error) => {
          if (fileGuardTarget) {
            readiness.reject(error);
            fail(error);
          } else {
            readiness.resolve();
          }
        });
      return;
    }

    if (message.method === "Target.detachedFromTarget") {
      const targetId = message.params?.targetId;
      if (typeof targetId === "string") attachedTargets.delete(targetId);
      return;
    }

    if (message.method === "Fetch.requestPaused") {
      const params = message.params;
      const request = params?.request;
      if (
        typeof message.sessionId !== "string" ||
        typeof params?.requestId !== "string" ||
        !isRecord(request) ||
        typeof request.url !== "string"
      ) {
        fail(new Error("invalid Fetch.requestPaused event"));
        return;
      }
      if (mustBlockPausedRequest(request.url)) {
        void send(
          "Fetch.failRequest",
          { requestId: params.requestId, errorReason: "AccessDenied" },
          message.sessionId,
        ).catch(fail);
        return;
      }
      const headers = headfulClientHintHeaders(request.headers);
      // 継続の失敗は中断済みのナビゲーションで正常に起こりうるうえ、
      // file:// 遮断にも影響しないため、ガード失敗として扱いません。
      void send(
        "Fetch.continueRequest",
        headers === undefined
          ? { requestId: params.requestId }
          : { requestId: params.requestId, headers },
        message.sessionId,
        false,
      ).catch(() => undefined);
    }
  };

  ws.onmessage = (event) => {
    let message: CdpMessage;
    try {
      message = JSON.parse(event.data as string) as CdpMessage;
    } catch (error) {
      fail(error);
      return;
    }
    if (typeof message.id === "number") {
      const command = pending.get(message.id);
      if (command === undefined) return;
      pending.delete(message.id);
      clearTimeout(command.timeout);
      if (message.error !== undefined) {
        command.reject(
          new Error(message.error.message ?? "CDP command failed"),
        );
      } else {
        command.resolve(message.result);
      }
      return;
    }
    handleEvent(message);
  };
  ws.onerror = () => fail(new Error("CDP guard websocket failed"));
  ws.onclose = () => {
    if (!intentionallyClosed) fail(new Error("CDP guard websocket closed"));
  };

  const opened = new Promise<void>((resolve, reject) => {
    rejectOpen = reject;
    ws.onopen = () => {
      void send("Target.setAutoAttach", autoAttachParams)
        .then(() => resolve())
        .catch(fail);
    };
  });

  try {
    await Promise.race([opened, failure]);
  } catch (error) {
    intentionallyClosed = true;
    ws.close();
    throw error;
  }

  try {
    const result = await send(
      "SystemInfo.getProcessInfo",
      {},
      undefined,
      false,
    );
    const processInfo = result?.processInfo;
    if (Array.isArray(processInfo)) {
      const browserProcess = processInfo.find(
        (value) => isRecord(value) && value.type === "browser",
      );
      if (isRecord(browserProcess) && typeof browserProcess.id === "number") {
        browserPid = browserProcess.id;
      }
    }
  } catch {
    browserPid = undefined;
  }

  return {
    close: () => {
      intentionallyClosed = true;
      ws.close();
      for (const { timeout } of pending.values()) clearTimeout(timeout);
      pending.clear();
    },
    failure,
    browserPid,
    registerUserAgentOverride,
    assertOpen: () => {
      if (failureError !== undefined) throw failureError;
    },
    waitForTargetReady: (targetId) => {
      const readiness = getTargetReadiness(targetId);
      return readiness.promise.finally(() => {
        if (targetReadiness.get(targetId) === readiness) {
          targetReadiness.delete(targetId);
        }
      });
    },
    send: (method, params) => send(method, params),
  };
}

async function withGuard<T>(
  guard: CdpGuard,
  operation: () => Promise<T>,
): Promise<T> {
  return Promise.race([operation(), guard.failure]);
}

async function waitForTargetReady(
  guard: CdpGuard,
  targetId: string,
): Promise<void> {
  let timeout: ReturnType<typeof setTimeout> | undefined;
  try {
    await withGuard(guard, () =>
      Promise.race([
        guard.waitForTargetReady(targetId),
        new Promise<never>((_resolve, reject) => {
          timeout = setTimeout(() => {
            reject(new Error("CDP target readiness timed out"));
          }, 5_000);
        }),
      ]),
    );
  } finally {
    if (timeout !== undefined) clearTimeout(timeout);
  }
}

function isTimeoutError(error: unknown): boolean {
  return error instanceof Error && error.name === "TimeoutError";
}

async function fill(
  page: Page,
  selector: string,
  value: string,
  stepIndex?: number,
): Promise<void> {
  try {
    await page.fill(selector, value, { timeout: 10_000 });
  } catch (error) {
    if (isTimeoutError(error)) throw new SelectorNotFoundError(stepIndex);
    throw error;
  }
}

async function click(
  page: Page,
  selector: string,
  stepIndex?: number,
): Promise<void> {
  try {
    await page.click(selector, { timeout: 10_000 });
  } catch (error) {
    if (isTimeoutError(error)) throw new SelectorNotFoundError(stepIndex);
    throw error;
  }
}

export function substituteSecrets(
  value: string,
  secret: LoginRequest["secret"],
  userCode?: string,
): string {
  const substitutions = {
    username: secret.username,
    password: secret.password,
    totp: secret.totp,
    user_code: userCode,
  };
  return value.replace(
    /\{\{(username|password|totp|user_code)\}\}/g,
    (_placeholder, key: keyof typeof substitutions) => {
      const substitution = substitutions[key];
      if (substitution === null) throw new MfaRequiredError();
      if (substitution === undefined) {
        throw new Error("user code is unavailable");
      }
      return substitution;
    },
  );
}

export interface RunStepsOptions {
  userCode?: string;
  automaticTotp?: boolean;
  failureSelector?: string | null;
}

export async function runSteps(
  page: Page,
  steps: LoginStep[] | DeviceStep[] | null,
  secret: LoginRequest["secret"],
  options: RunStepsOptions = {},
): Promise<void> {
  const { userCode, automaticTotp = false, failureSelector = null } = options;
  if (steps !== null) {
    if (
      secret.totp === null &&
      steps.some((step) => step.action === "fill" && step.value === "{{totp}}")
    ) {
      throw new MfaRequiredError();
    }
    for (const [stepIndex, step] of steps.entries()) {
      await withRejectionCheck(page, failureSelector, () =>
        step.action === "fill"
          ? fill(
              page,
              step.selector,
              substituteSecrets(step.value, secret, userCode),
              stepIndex,
            )
          : click(page, step.selector, stepIndex),
      );
      await throwIfRejected(page, failureSelector);
    }
    return;
  }

  const password = page.locator('input[type="password"]').first();
  const usernameIndex = await password.evaluate((element) => {
    const inputs = Array.from(
      document.querySelectorAll<HTMLInputElement>("input"),
    );
    return inputs.findIndex(
      (candidate) =>
        (candidate.type === "text" || candidate.type === "email") &&
        (candidate.compareDocumentPosition(element) &
          Node.DOCUMENT_POSITION_FOLLOWING) !==
          0,
    );
  });
  if (usernameIndex >= 0) {
    try {
      await page
        .locator("input")
        .nth(usernameIndex)
        .fill(secret.username, { timeout: 10_000 });
    } catch (error) {
      if (isTimeoutError(error)) throw new SelectorNotFoundError();
      throw error;
    }
  }
  await fill(page, 'input[type="password"]', secret.password);

  if (automaticTotp) {
    const totpSelectors = [
      'input[autocomplete="one-time-code"]',
      'input[name="totp"]',
      "input#totp",
    ];
    if (await selectorExists(page, totpSelectors[0])) {
      if (secret.totp === null) throw new MfaRequiredError();
      await fillFirstMatching(page, totpSelectors, secret.totp);
    } else if (await selectorExists(page, totpSelectors[1])) {
      if (secret.totp === null) throw new MfaRequiredError();
      await fillFirstMatching(page, totpSelectors, secret.totp);
    } else if (await selectorExists(page, totpSelectors[2])) {
      if (secret.totp === null) throw new MfaRequiredError();
      await fillFirstMatching(page, totpSelectors, secret.totp);
    }
  }

  const submit = page.locator('button[type="submit"], input[type="submit"]');
  if ((await submit.count()) > 0) {
    try {
      await submit.first().click({ timeout: 10_000 });
    } catch (error) {
      if (isTimeoutError(error)) throw new SelectorNotFoundError();
      throw error;
    }
  } else {
    try {
      await password.press("Enter", { timeout: 10_000 });
    } catch (error) {
      if (isTimeoutError(error)) throw new SelectorNotFoundError();
      throw error;
    }
  }
}

type WaitResult = "success" | "failure" | undefined;

const DEFAULT_RESULT_SETTLE_MS = 10_000;

export function raceDecisive<T>(
  waits: Array<Promise<T | undefined>>,
  timeout: Promise<undefined>,
): Promise<T | undefined> {
  return Promise.race([
    ...waits.map((wait) =>
      wait.then((result) =>
        result === undefined ? new Promise<never>(() => {}) : result,
      ),
    ),
    timeout,
  ]);
}

async function waitForSelector(page: Page, selector: string): Promise<boolean> {
  try {
    await page.waitForSelector(selector, {
      state: "attached",
      timeout: 15_000,
    });
    return true;
  } catch (error) {
    if (isTimeoutError(error)) return false;
    throw error;
  }
}

async function waitForResult(
  page: Page,
  successSelector: string | null,
  failureSelector: string | null,
  waitForDefaultResult?: () => Promise<WaitResult>,
): Promise<WaitResult> {
  const waits: Array<Promise<WaitResult>> = [];
  if (successSelector !== null) {
    waits.push(
      waitForSelector(page, successSelector).then((matched) =>
        matched ? "success" : undefined,
      ),
    );
  }
  if (failureSelector !== null) {
    waits.push(
      waitForSelector(page, failureSelector).then((matched) =>
        matched ? "failure" : undefined,
      ),
    );
  }
  if (
    waitForDefaultResult !== undefined &&
    (successSelector === null || failureSelector === null)
  ) {
    waits.push(waitForDefaultResult());
  }
  return raceDecisive(
    waits,
    new Promise<undefined>((resolve) => setTimeout(resolve, 15_000)),
  );
}

async function waitForLoginResult(
  page: Page,
  successSelector: string | null,
  failureSelector: string | null,
): Promise<void> {
  const waitForDefaultResult = async (): Promise<
    "success" | "failure" | undefined
  > => {
    const networkIdleSettled = await page
      .waitForLoadState("networkidle", { timeout: DEFAULT_RESULT_SETTLE_MS })
      .then(() => true)
      .catch(() => false);
    const { hasPasswordInput } = await page.evaluate((loadStateSettled) => {
      const inputs = Array.from(
        document.querySelectorAll<HTMLInputElement>("input"),
      );
      const hasPasswordInput = inputs.some((input) => {
        const style = getComputedStyle(input);
        return (
          input.type === "password" &&
          !input.hidden &&
          style.display !== "none" &&
          style.visibility !== "hidden" &&
          input.offsetWidth !== 0 &&
          input.offsetHeight !== 0
        );
      });
      return { hasPasswordInput, loadStateSettled };
    }, networkIdleSettled);
    if (!hasPasswordInput && successSelector === null) return "success";
    if (hasPasswordInput && failureSelector === null) return "failure";
    return undefined;
  };

  const result = await waitForResult(
    page,
    successSelector,
    failureSelector,
    waitForDefaultResult,
  );
  if (result === "failure") throw new InvalidCredentialError();
  if (result !== "success") throw new LoginResultTimeoutError();
}

export function classifyDeviceResult(
  result: "success" | "failure" | undefined,
): "ok" | "DEVICE_CODE_REJECTED" | "INTERNAL" {
  if (result === "success") return "ok";
  if (result === "failure") return "DEVICE_CODE_REJECTED";
  return "INTERNAL";
}

async function selectorExists(page: Page, selector: string): Promise<boolean> {
  return (await page.locator(selector).count()) > 0;
}

async function throwIfRejected(
  page: Page,
  failureSelector: string | null,
): Promise<void> {
  if (
    failureSelector !== null &&
    (await selectorExists(page, failureSelector))
  ) {
    throw new DeviceCodeRejectedError();
  }
}

// SPA 型サイトでは拒否表示が遅れて描画され、次の操作のセレクタ待ちが先に timeout しうる。
// そのためセレクタ不在で失敗した時点で failure_selector を再確認し、拒否として分類する。
async function withRejectionCheck(
  page: Page,
  failureSelector: string | null,
  action: () => Promise<void>,
): Promise<void> {
  try {
    await action();
  } catch (error) {
    if (error instanceof SelectorNotFoundError) {
      await throwIfRejected(page, failureSelector);
    }
    throw error;
  }
}

async function fillFirstMatching(
  page: Page,
  selectors: string[],
  value: string,
): Promise<void> {
  for (const selector of selectors) {
    const locator = page.locator(selector);
    if ((await locator.count()) === 0) continue;
    try {
      await locator.first().fill(value, { timeout: 10_000 });
    } catch (error) {
      if (isTimeoutError(error)) throw new SelectorNotFoundError();
      throw error;
    }
    return;
  }
  throw new SelectorNotFoundError();
}

async function clickFirstMatching(
  page: Page,
  selectors: string[],
): Promise<void> {
  for (const selector of selectors) {
    const locator = page.locator(selector);
    if ((await locator.count()) === 0) continue;
    try {
      await locator.first().click({ timeout: 10_000 });
    } catch (error) {
      if (isTimeoutError(error)) throw new SelectorNotFoundError();
      throw error;
    }
    return;
  }
  throw new SelectorNotFoundError();
}

async function waitForDeviceResult(
  page: Page,
  successSelector: string,
  failureSelector: string | null,
): Promise<void> {
  const result = await waitForResult(page, successSelector, failureSelector);
  const classification = classifyDeviceResult(result);
  if (classification === "DEVICE_CODE_REJECTED") {
    throw new DeviceCodeRejectedError();
  }
  if (classification === "INTERNAL") {
    throw new Error("device authorization result timed out");
  }
}

async function executeDeviceFlow(
  page: Page,
  request: AuthorizeDeviceRequest,
): Promise<void> {
  const failureSelector = request.failure_selector;
  await throwIfRejected(page, failureSelector);
  if (request.steps === null) {
    await withRejectionCheck(page, failureSelector, () =>
      fillFirstMatching(
        page,
        [
          'input[name="user_code"]',
          'input[autocomplete="one-time-code"]',
          'input[type="text"]',
        ],
        request.user_code,
      ),
    );
    await withRejectionCheck(page, failureSelector, () =>
      clickFirstMatching(page, ['button[type="submit"]']),
    );
    await throwIfRejected(page, failureSelector);
    await withRejectionCheck(page, failureSelector, () =>
      clickFirstMatching(page, [
        'button:has-text("Authorize")',
        'button:has-text("Continue")',
        'button:has-text("Approve")',
      ]),
    );
  } else {
    await runSteps(page, request.steps, request.secret, {
      userCode: request.user_code,
      failureSelector,
    });
  }
  await waitForDeviceResult(
    page,
    request.success_selector,
    request.failure_selector,
  );
}

async function openBrowserPage() {
  const port = await reservePort();
  const dir = await mkdtemp(path.join(os.tmpdir(), "tegata-browser-"));
  activeTempDir = dir;
  // ブラウザが参照する設定・キャッシュを executor の作業領域から隔離します。
  const browser = await chromium.launch({
    headless: true,
    args: [`--remote-debugging-port=${port}`],
    env: {
      ...process.env,
      HOME: dir,
      XDG_CONFIG_HOME: dir,
      XDG_CACHE_HOME: dir,
    },
  });
  activeBrowser = browser;
  // ページ操作より先に CDP エンドポイントを取得し、全 target にガードを張ります。
  const endpoint = await waitForEndpoint(port);
  const guard = await openGuard(endpoint);
  activeGuard = guard;
  const browserSession = await withGuard(guard, () =>
    browser.newBrowserCDPSession(),
  );
  try {
    const page = await withGuard(guard, () => browser.newPage());
    const pageSession = await withGuard(guard, () =>
      page.context().newCDPSession(page),
    );
    const targetInfoResult = await withGuard(guard, () =>
      pageSession.send("Target.getTargetInfo"),
    );
    const targetInfo = targetInfoResult.targetInfo;
    if (
      !isRecord(targetInfo) ||
      typeof targetInfo.targetId !== "string" ||
      typeof targetInfo.browserContextId !== "string"
    ) {
      throw new Error("CDP target information was not returned");
    }
    await waitForTargetReady(guard, targetInfo.targetId);

    const pageUserAgent = await withGuard(guard, () =>
      readNavigatorUserAgentData(page),
    );
    const version = await withGuard(guard, () =>
      browserSession.send("Browser.getVersion"),
    );
    const userAgent = headfulUserAgent(
      pageUserAgent?.userAgent ??
        (typeof version.userAgent === "string"
          ? version.userAgent
          : (() => {
              throw new Error("browser user agent was not returned");
            })()),
    );
    const userAgentMetadata = headfulUserAgentMetadata(
      pageUserAgent?.metadata ??
        (typeof version.product === "string"
          ? fallbackUserAgentMetadata(version.product)
          : (() => {
              throw new Error("browser product was not returned");
            })()),
    );
    await withGuard(guard, () =>
      guard.registerUserAgentOverride({ userAgent, userAgentMetadata }),
    );

    return {
      endpoint,
      page,
      pageSession,
      targetId: targetInfo.targetId,
      browserContextId: targetInfo.browserContextId,
    };
  } finally {
    await browserSession.detach().catch(() => undefined);
  }
}

async function executeLogin(
  request: LoginRequest,
): Promise<{ endpoint: string; targetId: string }> {
  const { endpoint, page, pageSession, targetId, browserContextId } =
    await openBrowserPage();
  const guard = activeGuard;
  if (guard === undefined) throw new Error("CDP guard is not available");
  await withGuard(guard, () => page.goto(request.target_url));
  await withGuard(guard, () => runSteps(page, request.steps, request.secret));
  await withGuard(guard, () =>
    waitForLoginResult(
      page,
      request.success_selector,
      request.failure_selector,
    ),
  );
  await pageSession.detach().catch(() => undefined);
  activeBrowserContextId = browserContextId;
  monitorGuardFailure(guard);
  guard.assertOpen();
  return { endpoint, targetId };
}

type ExecutionErrorWriter = (
  stage: ExecutionStage,
  classified: ClassifiedExecutionError,
  cause: unknown,
) => void;

function throwIfDeviceAuthorizationAborted(signal?: AbortSignal): void {
  if (signal?.aborted) throw new Error("device authorization was aborted");
}

/**
 * device 承認をブラウザで行う。`signal` が中断された場合は、ブラウザ起動の後および各段の前で打ち切る。
 * ブラウザの後始末は呼び出し側が行う。
 */
async function executeAuthorizeDevice(
  request: AuthorizeDeviceRequest,
  writeError: ExecutionErrorWriter = (stage, classified, cause) =>
    writeExecutorErrorLine(request, stage, classified, cause),
  signal?: AbortSignal,
): Promise<ClassifiedExecutionError | undefined> {
  let stage: ExecutionStage = "login";
  try {
    throwIfDeviceAuthorizationAborted(signal);
    const { page, pageSession } = await openBrowserPage();
    const guard = activeGuard;
    if (guard === undefined) throw new Error("CDP guard is not available");
    const runStage = <T>(action: () => Promise<T>): Promise<T> => {
      throwIfDeviceAuthorizationAborted(signal);
      return withGuard(guard, action);
    };
    try {
      await runStage(() => page.goto(request.login_url));
      await runStage(() =>
        runSteps(page, null, request.secret, { automaticTotp: true }),
      );
      await runStage(() => waitForLoginResult(page, null, null));
      stage = "device";
      await runStage(() => page.goto(request.verification_url));
      await runStage(() => executeDeviceFlow(page, request));
    } finally {
      await pageSession.detach().catch(() => undefined);
    }
    return undefined;
  } catch (error) {
    const classified = classifyExecutionError(error, stage);
    writeError(stage, classified, error);
    return classified;
  }
}

export function formatResponse(value: unknown, id?: RequestId): unknown {
  return id === undefined || !isRecord(value) ? value : { ...value, id };
}

function writeResponse(value: unknown, id?: RequestId): void {
  const response = formatResponse(value, id);
  process.stdout.write(`${JSON.stringify(response)}\n`);
}

export function formatApiProxyEvent(record: ApiProxyRequestRecord): unknown {
  return {
    event: "api_proxy_request",
    http_method: record.http_method,
    path: record.path,
    status: record.status,
  };
}

function writeApiProxyEvent(record: ApiProxyRequestRecord): void {
  // 応答行と同じく 1 回の write で 1 行を出力し、行単位の JSON を保つ。
  process.stdout.write(`${JSON.stringify(formatApiProxyEvent(record))}\n`);
}

export function formatOAuthTokenEvent(action: OAuthTokenAction): unknown {
  return { event: "oauth_token", action };
}

function writeOAuthTokenEvent(action: OAuthTokenAction): void {
  process.stdout.write(`${JSON.stringify(formatOAuthTokenEvent(action))}\n`);
}

function monitorGuardFailure(guard: CdpGuard): void {
  void guard.failure.then(undefined, async () => {
    if (shuttingDown) return;
    shuttingDown = true;
    await closeApiProxy();
    await cleanupResources();
    process.exit(1);
  });
}

function killBrowserProcess(browserPid: number | undefined): void {
  if (browserPid === undefined) {
    process.stderr.write(
      "ブラウザプロセスの PID を取得できないため、強制終了を実行できません。\n",
    );
    return;
  }
  try {
    process.kill(browserPid, "SIGKILL");
  } catch {
    return;
  }
}

async function cleanupResources(): Promise<void> {
  const guard = activeGuard;
  const browserPid = guard?.browserPid;
  activeGuard = undefined;
  if (guard !== undefined) {
    guard.close();
  }
  const browser = activeBrowser;
  activeBrowser = undefined;
  if (browser !== undefined) {
    let closeTimedOut = false;
    let timeout: ReturnType<typeof setTimeout> | undefined;
    await Promise.race([
      browser.close().catch(() => undefined),
      new Promise<void>((resolve) => {
        timeout = setTimeout(() => {
          closeTimedOut = true;
          resolve();
        }, 5_000);
      }),
    ]);
    if (timeout !== undefined) clearTimeout(timeout);
    if (closeTimedOut) killBrowserProcess(browserPid);
  }
  const dir = activeTempDir;
  activeTempDir = undefined;
  activeBrowserContextId = undefined;
  if (dir !== undefined) {
    await rm(dir, { recursive: true, force: true }).catch(() => undefined);
  }
}

async function handleLease(request: LeaseRequest): Promise<void> {
  const guard = activeGuard;
  const browserContextId = activeBrowserContextId;
  if (
    activeBrowser === undefined ||
    guard === undefined ||
    browserContextId === undefined
  ) {
    writeResponse(
      { ok: false, error: "INTERNAL" satisfies ErrorCode },
      request.id,
    );
    return;
  }

  let targetId: string | undefined;
  try {
    const result = await withGuard(guard, () =>
      guard.send("Target.createTarget", {
        url: "about:blank",
        browserContextId,
      }),
    );
    const createdTargetId = result?.targetId;
    if (typeof createdTargetId !== "string") {
      throw new Error("CDP target was not created");
    }
    targetId = createdTargetId;
    await waitForTargetReady(guard, targetId);
    writeResponse({ ok: true, target_id: targetId }, request.id);
  } catch {
    if (targetId !== undefined) {
      await guard
        .send("Target.closeTarget", { targetId })
        .catch(() => undefined);
    }
    writeResponse(
      { ok: false, error: "INTERNAL" satisfies ErrorCode },
      request.id,
    );
  }
}

async function handleRelease(request: ReleaseRequest): Promise<void> {
  const guard = activeGuard;
  if (activeBrowser === undefined || guard === undefined) {
    writeResponse(
      { ok: false, error: "INTERNAL" satisfies ErrorCode },
      request.id,
    );
    return;
  }

  try {
    await withGuard(guard, () =>
      guard.send("Target.closeTarget", { targetId: request.target_id }),
    );
    writeResponse({ ok: true }, request.id);
  } catch {
    try {
      guard.assertOpen();
    } catch {
      writeResponse(
        { ok: false, error: "INTERNAL" satisfies ErrorCode },
        request.id,
      );
      return;
    }
    writeResponse({ ok: true }, request.id);
  }
}

async function handleLogin(request: LoginRequest): Promise<void> {
  if (activeBrowser !== undefined) {
    const error = new Error("browser is already active");
    const classified = classifyExecutionError(error, "login");
    writeExecutorErrorLine(request, "login", classified, error);
    writeResponse(formatErrorResponse(classified), request.id);
    return;
  }

  try {
    const { endpoint, targetId } = await executeLogin(request);
    writeResponse({ ok: true, endpoint, target_id: targetId }, request.id);
  } catch (error) {
    const classified = classifyExecutionError(error, "login");
    writeExecutorErrorLine(request, "login", classified, error);
    await cleanupResources();
    writeResponse(formatErrorResponse(classified), request.id);
  }
}

async function handleAuthorizeDevice(
  request: AuthorizeDeviceRequest,
): Promise<void> {
  if (activeBrowser !== undefined) {
    const error = new Error("browser is already active");
    const classified = classifyExecutionError(error, "login");
    writeExecutorErrorLine(request, "login", classified, error);
    writeResponse(formatErrorResponse(classified), request.id);
    return;
  }

  const classified = await executeAuthorizeDevice(request);
  await cleanupResources();
  writeResponse(
    classified === undefined ? { ok: true } : formatErrorResponse(classified),
    request.id,
  );
}

async function closeApiProxy(): Promise<void> {
  const proxy = activeApiProxy;
  activeApiProxy = undefined;
  if (proxy !== undefined) await proxy.close();
}

async function handleApiProxyStart(
  request: ApiProxyStartRequest,
): Promise<void> {
  if (activeApiProxy !== undefined) {
    writeResponse(
      { ok: false, error: "INTERNAL" satisfies ErrorCode },
      request.id,
    );
    return;
  }
  if ("oauth" in request) {
    await handleOAuthApiProxyStart(request);
    return;
  }

  try {
    const proxy = await startApiProxy({
      upstream: request.upstream,
      header: request.header,
      headerValue: request.header_value,
      onRequest: writeApiProxyEvent,
    });
    activeApiProxy = proxy;
    writeResponse(
      { ok: true, port: proxy.port, secret: proxy.secret },
      request.id,
    );
  } catch {
    writeResponse(
      { ok: false, error: "INTERNAL" satisfies ErrorCode },
      request.id,
    );
  }
}

// 応答は最初の要求から 80 秒以内（デーモンの初回要求の上限 90 秒の内側）に返す。grant の各段はこの期限で
// 打ち切り、残りを後始末（打ち切った承認処理の完了待ち 5 秒・ブラウザの終了 5 秒、または token の失効 5 秒）と
// 応答に充てる。
const OAUTH_GRANT_BUDGET_MS = 65_000;
// 期限超過・中断で見切った承認処理が、起動し終えたブラウザを残さず終わるまで待つ上限。
const ORPHAN_AUTHORIZATION_WAIT_MS = 5_000;

function toAuthorizeDeviceRequest(
  request: OAuthApiProxyStartRequest,
  device: DeviceAuthorization,
): AuthorizeDeviceRequest {
  const { oauth } = request;
  return {
    op: "authorize_device",
    login_url: oauth.login_url,
    verification_url: device.verificationUrl,
    user_code: device.userCode,
    steps: oauth.steps,
    success_selector: oauth.success_selector,
    failure_selector: oauth.failure_selector,
    secret: oauth.secret,
  };
}

/** `promise` の完了を最大 `ms` ミリ秒待つ。結果・失敗は問わない。 */
async function waitAtMost(
  promise: Promise<unknown>,
  ms: number,
): Promise<void> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  await Promise.race([
    promise.catch(() => undefined),
    new Promise<void>((resolve) => {
      timer = setTimeout(resolve, ms);
    }),
  ]);
  if (timer !== undefined) clearTimeout(timer);
}

/**
 * device 承認をブラウザで行い、成否にかかわらずブラウザを閉じる。
 * 期限超過または中断の場合は承認処理を打ち切って OAuthGrantError とし、以後に届く遅れた診断行は出力しない。
 * 打ち切った承認処理がブラウザの起動を終える前に後始末すると、ブラウザが残るため、その完了を短く待ってから閉じる。
 */
async function authorizeDeviceInBrowser(
  request: OAuthApiProxyStartRequest,
  device: DeviceAuthorization,
  deadline: number,
  signal: AbortSignal,
  runtimeSecrets: string[],
): Promise<ClassifiedExecutionError | undefined> {
  const cancel = new AbortController();
  const onAbort = (): void => cancel.abort();
  signal.addEventListener("abort", onAbort, { once: true });
  if (signal.aborted) cancel.abort();
  const timer = setTimeout(onAbort, Math.max(0, deadline - Date.now()));
  const expired = new Promise<"expired">((resolve) => {
    cancel.signal.addEventListener("abort", () => resolve("expired"), {
      once: true,
    });
    if (cancel.signal.aborted) resolve("expired");
  });
  const authorization = executeAuthorizeDevice(
    toAuthorizeDeviceRequest(request, device),
    (stage, classified, cause) => {
      // 打ち切った後の失敗は、打ち切りの理由として別に報告するため出力しない。
      if (!cancel.signal.aborted) {
        writeExecutorErrorLine(
          request,
          stage,
          classified,
          cause,
          runtimeSecrets,
        );
      }
    },
    cancel.signal,
  );
  try {
    const result = await Promise.race([authorization, expired]);
    if (result === "expired") {
      throw new OAuthGrantError(
        "device authorization in the browser did not finish in time",
      );
    }
    return result;
  } finally {
    clearTimeout(timer);
    signal.removeEventListener("abort", onAbort);
    cancel.abort();
    await waitAtMost(authorization, ORPHAN_AUTHORIZATION_WAIT_MS);
    await cleanupResources();
  }
}

/** device-code grant で access token を得る。ブラウザ段の失敗は分類済みの結果として返す。 */
async function acquireOAuthTokens(
  request: OAuthApiProxyStartRequest,
  deadline: number,
  signal: AbortSignal,
  runtimeSecrets: string[],
): Promise<{ tokens: TokenSet; issuedAt: number } | ClassifiedExecutionError> {
  const { oauth } = request;
  const device = await requestDeviceAuthorization(
    oauth,
    postForm,
    Math.min(OAUTH_REQUEST_TIMEOUT_MS, deadline - Date.now()),
    signal,
  );
  const receivedAt = Date.now();
  runtimeSecrets.push(device.deviceCode, device.userCode);
  const browserError = await authorizeDeviceInBrowser(
    request,
    device,
    deadline,
    signal,
    runtimeSecrets,
  );
  if (browserError !== undefined) return browserError;
  const tokens = await pollForToken(
    oauth,
    device,
    {
      receivedAt,
      deadline: tokenPollDeadline({
        receivedAt,
        expiresIn: device.expiresIn,
        pollStartedAt: Date.now(),
        budgetDeadline: deadline,
      }),
    },
    { post: postForm, now: Date.now, sleep: abortableSleep, signal },
  );
  runtimeSecrets.push(tokens.accessToken);
  if (tokens.refreshToken !== null) runtimeSecrets.push(tokens.refreshToken);
  return { tokens, issuedAt: Date.now() };
}

/** 取得した token でプロキシを起動する。起動できない場合は token を失効させてから例外を返す。 */
async function startOAuthProxySession(
  request: OAuthApiProxyStartRequest,
  tokens: TokenSet,
  issuedAt: number,
) {
  let proxy: ApiProxy;
  try {
    proxy = await startApiProxy({
      upstream: request.upstream,
      header: request.header,
      headerValue: renderValueTemplate(
        request.value_template,
        tokens.accessToken,
      ),
      onRequest: writeApiProxyEvent,
    });
  } catch (error) {
    // 応答より前にイベント行を出すとデーモンが応答として読むため、ここでは失効のみ行う。
    await revokeTokens(request.oauth, tokens, postForm);
    throw error;
  }
  const session = new OAuthProxySession({
    endpoints: request.oauth,
    proxy,
    valueTemplate: request.value_template,
    tokens,
    issuedAt,
    onEvent: writeOAuthTokenEvent,
  });
  return { port: proxy.port, secret: proxy.secret, session };
}

async function runOAuthApiProxyStart(
  request: OAuthApiProxyStartRequest,
  signal: AbortSignal,
): Promise<void> {
  if (activeBrowser !== undefined) {
    const error = new Error("browser is already active");
    const classified = classifyExecutionError(error, "oauth");
    writeExecutorErrorLine(request, "oauth", classified, error);
    writeResponse(formatErrorResponse(classified), request.id);
    return;
  }
  const deadline = Date.now() + OAUTH_GRANT_BUDGET_MS;
  const runtimeSecrets: string[] = [];
  try {
    const acquired = await acquireOAuthTokens(
      request,
      deadline,
      signal,
      runtimeSecrets,
    );
    if (!("tokens" in acquired)) {
      writeResponse(formatErrorResponse(acquired), request.id);
      return;
    }
    const { port, secret, session } = await startOAuthProxySession(
      request,
      acquired.tokens,
      acquired.issuedAt,
    );
    activeApiProxy = session;
    writeResponse({ ok: true, port, secret }, request.id);
    // デーモンは初回要求の応答を最初の 1 行として読むため、イベント行は応答の後に出力する。
    writeOAuthTokenEvent("issued");
  } catch (error) {
    const classified = classifyExecutionError(error, "oauth");
    // shutdown による中断は grant の失敗ではないため、診断行を出さない。
    if (!signal.aborted) {
      writeExecutorErrorLine(
        request,
        "oauth",
        classified,
        error,
        runtimeSecrets,
      );
    }
    writeResponse(formatErrorResponse(classified), request.id);
  }
}

/** 実行中の grant を記録し、shutdown が中断と完了待ちを行えるようにする。 */
async function handleOAuthApiProxyStart(
  request: OAuthApiProxyStartRequest,
): Promise<void> {
  const controller = new AbortController();
  const done = runOAuthApiProxyStart(request, controller.signal);
  activeOAuthStart = { controller, done };
  try {
    await done;
  } finally {
    activeOAuthStart = undefined;
  }
}

async function handleApiProxyStop(request: ApiProxyStopRequest): Promise<void> {
  await closeApiProxy();
  writeResponse({ ok: true }, request.id);
}

async function shutdown(request?: { id?: RequestId }): Promise<void> {
  if (shuttingDown) return;
  shuttingDown = true;
  const oauthStart = activeOAuthStart;
  if (oauthStart !== undefined) {
    oauthStart.controller.abort();
    await oauthStart.done;
  }
  await closeApiProxy();
  await cleanupResources();
  if (request !== undefined) writeResponse({ ok: true }, request.id);
  process.exit(0);
}

let stdinEofHandled = false;

function handleStdinEof(): void {
  if (stdinEofHandled || shuttingDown) return;
  stdinEofHandled = true;
  void shutdown();
}

async function main(): Promise<void> {
  const input = createInterface({ input: process.stdin });
  for await (const line of input) {
    if (shuttingDown || line.trim() === "") continue;
    try {
      const request = parseRequest(line);
      if (request.op === "hello") {
        writeResponse(
          {
            ok: true,
            uid: process.getuid?.() ?? null,
            pid: process.pid,
          },
          request.id,
        );
        continue;
      }
      if (request.op === "shutdown") {
        await shutdown(request);
        return;
      }
      if (request.op === "lease") {
        await handleLease(request);
        continue;
      }
      if (request.op === "release") {
        await handleRelease(request);
        continue;
      }
      if (request.op === "authorize_device") {
        await handleAuthorizeDevice(request);
        continue;
      }
      if (request.op === "api_proxy_start") {
        await handleApiProxyStart(request);
        continue;
      }
      if (request.op === "api_proxy_stop") {
        await handleApiProxyStop(request);
        continue;
      }
      await handleLogin(request);
    } catch (error) {
      writeResponse(
        { ok: false, error: "INTERNAL" satisfies ErrorCode },
        error instanceof InvalidRequestError ? error.id : undefined,
      );
    }
  }
  await shutdown();
}

if (
  process.argv[1] !== undefined &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  process.stdin.once("end", handleStdinEof);
  process.stdin.once("close", handleStdinEof);

  process.once("SIGTERM", () => {
    void shutdown();
  });

  void main();
}
