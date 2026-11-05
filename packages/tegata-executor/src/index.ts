#!/usr/bin/env node

import fs from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { createRequire } from "node:module";
import { createServer } from "node:net";
import os from "node:os";
import path from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import {
  type Browser,
  type BrowserContext,
  type CDPSession,
  chromium,
  type ElementHandle,
  type Frame,
  type Locator,
  type Page,
} from "playwright-core";
import {
  type ApiProxy,
  type ApiProxyRequestRecord,
  startApiProxy,
} from "./api-proxy.js";
import { createLoopbackSecret } from "./loopback.js";
import {
  type McpServerEvent,
  type McpServerHost,
  startMcpServer,
} from "./mcp-host.js";
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
import {
  finalizeSnapshot,
  MAX_REF_LENGTH,
  REF_PATTERN,
  type Snapshot,
  SnapshotRejectedError,
} from "./snapshot.js";
import {
  captureAriaSnapshot,
  clearFilledFields,
  disposeHandles,
  settlePage,
  trackNavigation,
} from "./stepwise.js";

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

type WaitForStep = {
  action: "wait_for";
  selector: string;
};

type LoginStep = FillStep | ClickStep | WaitForStep;
type DeviceStep = DeviceFillStep | ClickStep | WaitForStep;

type RequestId = number;

/**
 * The cookie shape exchanged with the daemon. Of Playwright's Cookie type, only the fields listed
 * here are handled.
 */
export type Cookie = {
  name: string;
  value: string;
  domain: string;
  path: string;
  expires: number;
  httpOnly: boolean;
  secure: boolean;
  sameSite: "Strict" | "Lax" | "None";
};

type LoginRequest = {
  op: "login";
  id?: RequestId;
  target_url: string;
  steps: LoginStep[] | null;
  success_selector: string | null;
  failure_selector: string | null;
  // Omission is treated the same as null, and no cookies are restored.
  cookies?: Cookie[] | null;
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
  // Omission is treated the same as null, and no cookies are restored.
  cookies?: Cookie[] | null;
  secret: LoginRequest["secret"];
};

type LeaseRequest = { op: "lease"; id?: RequestId };

type ReleaseRequest = { op: "release"; id?: RequestId; target_id: string };

type ExportCookiesRequest = { op: "export_cookies"; id?: RequestId };

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
  // Omission is treated the same as null, and no cookies are restored.
  cookies?: Cookie[] | null;
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

type McpServerStartRequest = {
  op: "mcp_server_start";
  id?: RequestId;
  command: string;
  args: string[];
  env: Record<string, string>;
  scan: string[];
};

type McpServerStopRequest = { op: "mcp_server_stop"; id?: RequestId };

type LoginBeginRequest = {
  op: "login_begin";
  id?: RequestId;
  target_url: string;
  success_selector: string;
  failure_selector: string | null;
  cookies: Cookie[] | null;
  secret: { username: string; password: string };
};

/**
 * The form that points at an element in stepwise login. ref is the ref on a heading line of the
 * previous snapshot.
 */
type ElementTarget = { ref: string } | { selector: string };

type StepwiseFill = ElementTarget & { value: FillStep["value"] };

type StepwiseSubmit = { click: ElementTarget } | { press_enter: ElementTarget };

type StepwiseAction =
  | ({ action: "click" | "wait_for" } & ElementTarget)
  | ({ action: "fill"; value: "{{username}}" } & ElementTarget)
  | { action: "fill_submit"; fills: StepwiseFill[]; submit: StepwiseSubmit }
  | { action: "snapshot" }
  | { action: "abort" };

type LoginStepRequest = {
  op: "login_step";
  id?: RequestId;
  action: StepwiseAction;
  // The daemon passes the current code only when fill_submit contains {{totp}}.
  totp: string | null;
};

type Request =
  | LoginRequest
  | AuthorizeDeviceRequest
  | LeaseRequest
  | ReleaseRequest
  | ExportCookiesRequest
  | ApiProxyStartRequest
  | ApiProxyStopRequest
  | McpServerStartRequest
  | McpServerStopRequest
  | LoginBeginRequest
  | LoginStepRequest
  | { op: "hello"; id?: RequestId }
  | { op: "shutdown"; id?: RequestId };

type ErrorCode =
  | "INVALID_CREDENTIAL"
  | "MFA_REQUIRED"
  | "SELECTOR_NOT_FOUND"
  | "FILL_MISMATCH"
  | "VAULT_LOCKED"
  | "RATE_LIMITED"
  | "TOTP_NOT_EXPOSABLE"
  | "DEVICE_CODE_REJECTED"
  | "LOGIN_RESULT_TIMEOUT"
  | "OAUTH_GRANT_FAILED"
  | "SNAPSHOT_REJECTED"
  | "FILL_TARGET_REFUSED"
  | "INTERNAL";

export class SelectorNotFoundError extends Error {
  constructor(readonly stepIndex?: number) {
    super();
  }
}

export class FillMismatchError extends Error {
  constructor(readonly stepIndex?: number) {
    super();
  }
}

/**
 * Indicates that the origin of the frame of the element to fill does not match the origin of the
 * main frame.
 */
export class FillTargetRefusedError extends Error {}

export class InvalidCredentialError extends Error {}

export class MfaRequiredError extends Error {}

export class DeviceCodeRejectedError extends Error {}

export class LoginResultTimeoutError extends Error {}

type ExecutionStage = "login" | "device" | "oauth" | "mcp_server";

type DiagnosticRequest =
  | LoginRequest
  | AuthorizeDeviceRequest
  | ApiProxyStartRequest
  | McpServerStartRequest
  | LoginBeginRequest
  | LoginStepRequest;

/**
 * Secret candidates to replace in diagnostic lines. Unset values (null, undefined, empty string)
 * are ignored.
 */
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

function cookieValues(cookies: Cookie[] | null | undefined): string[] {
  return (cookies ?? []).map((cookie) => cookie.value);
}

function requestSecrets(request: DiagnosticRequest): SecretCandidates {
  // env also contains literals, but the executor does not distinguish them from secrets and
  // replaces all of them.
  if (request.op === "mcp_server_start") {
    return [...Object.values(request.env), ...request.scan];
  }
  if (request.op === "api_proxy_start") {
    return "oauth" in request
      ? [
          request.oauth.secret.username,
          request.oauth.secret.password,
          request.oauth.secret.totp,
          ...cookieValues(request.oauth.cookies),
        ]
      : [request.header_value];
  }
  // The only secret in a login_step request is the TOTP code; the credentials of a stepwise login
  // are passed by the caller as runtime secrets.
  if (request.op === "login_step") return [request.totp];
  if (request.op === "login_begin") {
    return [
      request.secret.username,
      request.secret.password,
      ...(request.cookies ?? []).map((cookie) => cookie.value),
    ];
  }
  const loginSecrets = [
    request.secret.username,
    request.secret.password,
    request.secret.totp,
  ];
  // Restored cookie values can also leak into in-page exception text on failure, so they are
  // included in the secrets to hide.
  if (request.op !== "login") {
    return [
      ...loginSecrets,
      request.user_code,
      ...cookieValues(request.cookies),
    ];
  }
  return [...loginSecrets, ...cookieValues(request.cookies)];
}

/**
 * Builds a diagnostic line. `runtimeSecrets` takes secrets obtained at runtime that are not part of
 * the request
 * (device code, user code, token, etc.), and they are replaced the same way as secrets derived from
 * the request.
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
  if (stage === "mcp_server") return "INTERNAL";
  if (stage === "device") {
    return error instanceof DeviceCodeRejectedError
      ? "DEVICE_CODE_REJECTED"
      : "INTERNAL";
  }
  return error instanceof SelectorNotFoundError
    ? "SELECTOR_NOT_FOUND"
    : error instanceof FillMismatchError
      ? "FILL_MISMATCH"
      : error instanceof InvalidCredentialError
        ? "INVALID_CREDENTIAL"
        : error instanceof MfaRequiredError
          ? "MFA_REQUIRED"
          : error instanceof LoginResultTimeoutError
            ? "LOGIN_RESULT_TIMEOUT"
            : error instanceof SnapshotRejectedError
              ? "SNAPSHOT_REJECTED"
              : error instanceof FillTargetRefusedError
                ? "FILL_TARGET_REFUSED"
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
  const stepIndex =
    error instanceof SelectorNotFoundError || error instanceof FillMismatchError
      ? error.stepIndex
      : undefined;
  return (code === "SELECTOR_NOT_FOUND" || code === "FILL_MISMATCH") &&
    stepIndex !== undefined
    ? { code, step: stepIndex }
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
let activeLoginContext: BrowserContext | undefined;
let activeApiProxy: { close: () => Promise<void> } | undefined;
let activeMcpServer: McpServerHost | undefined;
let activeMcpStart: Promise<void> | undefined;
let activeOAuthStart:
  | { controller: AbortController; done: Promise<void> }
  | undefined;
// The stepwise login before handoff. Reset to undefined on handoff, termination, and cleanup.
let activeStepwise: StepwiseSession | undefined;
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

// On the first navigation of a new tab, the client hints are fixed before the guard connects,
// so Emulation.setUserAgentOverride does not take effect. The document request is therefore
// intercepted,
// rewritten to client hints without the Headless brand, and then continued.
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

// The GREASE brand that a real Chromium always includes in brands. Keeping it even in the fallback
// avoids a combination that no real browser has, where brands holds only Chromium.
const greaseBrand = "Not)A;Brand";
const greaseMajorVersion = "24";
const greaseFullVersion = `${greaseMajorVersion}.0.0.0`;

export function fallbackUserAgentMetadata(product: string): UserAgentMetadata {
  const version = product.match(/\/(\d+(?:\.\d+)*)/)?.[1];
  if (version === undefined) {
    throw new Error("browser product version was not returned");
  }
  return {
    brands: [
      { brand: "Chromium", version: version.split(".")[0] },
      { brand: greaseBrand, version: greaseMajorVersion },
    ],
    fullVersionList: [
      { brand: "Chromium", version },
      { brand: greaseBrand, version: greaseFullVersion },
    ],
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
    if (step.action === "click" || step.action === "wait_for") {
      return { action: step.action, selector: step.selector };
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
    cookies: parseCookies(value.cookies, id),
    secret: {
      username: value.secret.username,
      password: value.secret.password,
      totp: value.secret.totp ?? null,
    },
  };
}

/**
 * Accepts exactly one of a static token (`header_value`) and OAuth (`value_template` + `oauth`).
 */
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

function isStringArray(value: unknown): value is string[] {
  return (
    Array.isArray(value) && value.every((item) => typeof item === "string")
  );
}

function hasNul(value: string): boolean {
  return value.includes("\0");
}

/**
 * Rejects names that spawn does not accept as environment variable names (empty, or containing `=`
 * or NUL).
 */
function isEnvRecord(value: unknown): value is Record<string, string> {
  return (
    isRecord(value) &&
    !Array.isArray(value) &&
    Object.entries(value).every(
      ([name, item]) =>
        name !== "" &&
        !name.includes("=") &&
        !hasNul(name) &&
        typeof item === "string" &&
        !hasNul(item),
    )
  );
}

/**
 * The argument validation exceptions that spawn throws synchronously quote the values, so a value
 * containing NUL is rejected here
 * to keep secrets off the exception path.
 */
function parseMcpServerStart(
  value: Record<string, unknown>,
  id?: RequestId,
): McpServerStartRequest {
  if (
    typeof value.command !== "string" ||
    hasNul(value.command) ||
    !path.isAbsolute(value.command) ||
    !isStringArray(value.args) ||
    value.args.some(hasNul) ||
    !isEnvRecord(value.env) ||
    !isStringArray(value.scan)
  ) {
    throw new InvalidRequestError(id);
  }
  return {
    op: "mcp_server_start",
    id,
    command: value.command,
    args: [...value.args],
    env: Object.fromEntries(Object.entries(value.env)),
    scan: [...value.scan],
  };
}

const cookieSameSiteValues: ReadonlySet<unknown> = new Set([
  "Strict",
  "Lax",
  "None",
]);

// The upper limit of the expiry that Playwright accepts (9999-12-31T23:59:59Z).
const MAX_COOKIE_EXPIRES_SECONDS = 253_402_300_799;

function isCookieExpires(value: unknown): value is number {
  return (
    typeof value === "number" &&
    Number.isFinite(value) &&
    (value === -1 || (value > 0 && value <= MAX_COOKIE_EXPIRES_SECONDS))
  );
}

/** Returns a cookie copying only the known fields, if and only if the shape is valid. */
function toCookie(value: unknown): Cookie | undefined {
  if (
    !isRecord(value) ||
    typeof value.name !== "string" ||
    typeof value.value !== "string" ||
    typeof value.domain !== "string" ||
    value.domain === "" ||
    typeof value.path !== "string" ||
    value.path === "" ||
    !isCookieExpires(value.expires) ||
    typeof value.httpOnly !== "boolean" ||
    typeof value.secure !== "boolean" ||
    !cookieSameSiteValues.has(value.sameSite)
  ) {
    return undefined;
  }
  return {
    name: value.name,
    value: value.value,
    domain: value.domain,
    path: value.path,
    expires: value.expires,
    httpOnly: value.httpOnly,
    secure: value.secure,
    sameSite: value.sameSite as Cookie["sameSite"],
  };
}

/**
 * The cookie contents are what the executor itself returned earlier, and are treated as input from
 * outside the trust boundary.
 * Malformed elements are dropped, and the request as a whole is not rejected.
 */
function parseCookies(value: unknown, id?: RequestId): Cookie[] | null {
  if (isAbsent(value)) return null;
  if (!Array.isArray(value)) throw new InvalidRequestError(id);
  return value.flatMap((item) => {
    const cookie = toCookie(item);
    return cookie === undefined ? [] : [cookie];
  });
}

// Upper bound on the number of fields one fill_submit can fill.
const MAX_STEPWISE_FILLS = 3;

function parseLoginBegin(
  value: Record<string, unknown>,
  id?: RequestId,
): LoginBeginRequest {
  const secret = value.secret;
  if (
    typeof value.target_url !== "string" ||
    typeof value.success_selector !== "string" ||
    !isOptionalNullableString(value.failure_selector) ||
    !isRecord(secret) ||
    typeof secret.username !== "string" ||
    typeof secret.password !== "string"
  ) {
    throw new InvalidRequestError(id);
  }
  return {
    op: "login_begin",
    id,
    target_url: value.target_url,
    success_selector: value.success_selector,
    failure_selector: value.failure_selector ?? null,
    cookies: parseCookies(value.cookies, id),
    secret: { username: secret.username, password: secret.password },
  };
}

function parseStepwiseFills(value: unknown, id?: RequestId): StepwiseFill[] {
  if (
    !Array.isArray(value) ||
    value.length < 1 ||
    value.length > MAX_STEPWISE_FILLS
  ) {
    throw new InvalidRequestError(id);
  }
  return value.map((fill): StepwiseFill => {
    if (!isRecord(fill) || !isSecretPlaceholder(fill.value)) {
      throw new InvalidRequestError(id);
    }
    return { ...parseElementTarget(fill, id), value: fill.value };
  });
}

function isRef(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length <= MAX_REF_LENGTH &&
    REF_PATTERN.test(value)
  );
}

/** Accepts exactly one of ref and selector. null is not treated as unspecified but as invalid. */
function parseElementTarget(
  value: Record<string, unknown>,
  id?: RequestId,
): ElementTarget {
  const hasRef = value.ref !== undefined;
  const hasSelector = value.selector !== undefined;
  if (hasRef && !hasSelector && isRef(value.ref)) return { ref: value.ref };
  if (hasSelector && !hasRef && typeof value.selector === "string") {
    return { selector: value.selector };
  }
  throw new InvalidRequestError(id);
}

/**
 * The submit element is an object with a ref or selector, or a string in the short selector form.
 */
function parseSubmitTarget(value: unknown, id?: RequestId): ElementTarget {
  if (typeof value === "string") return { selector: value };
  if (isRecord(value)) return parseElementTarget(value, id);
  throw new InvalidRequestError(id);
}

/** Accepts exactly one of click and press_enter. */
function parseStepwiseSubmit(value: unknown, id?: RequestId): StepwiseSubmit {
  if (!isRecord(value)) throw new InvalidRequestError(id);
  const hasClick = value.click !== undefined;
  const hasPressEnter = value.press_enter !== undefined;
  if (hasClick && !hasPressEnter) {
    return { click: parseSubmitTarget(value.click, id) };
  }
  if (hasPressEnter && !hasClick) {
    return { press_enter: parseSubmitTarget(value.press_enter, id) };
  }
  throw new InvalidRequestError(id);
}

/**
 * Validates a stepwise login action. A standalone fill accepts only {{username}}, and {{password}}
 * and {{totp}} are accepted
 * only inside fill_submit (the same double defense as the MCP schema and the daemon's validation).
 */
function parseStepwiseAction(
  value: Record<string, unknown>,
  id?: RequestId,
): StepwiseAction {
  const action = value.action;
  if (action === "snapshot" || action === "abort") return { action };
  if (action === "fill_submit") {
    return {
      action,
      fills: parseStepwiseFills(value.fills, id),
      submit: parseStepwiseSubmit(value.submit, id),
    };
  }
  if (action === "click" || action === "wait_for") {
    return { action, ...parseElementTarget(value, id) };
  }
  if (action === "fill" && value.value === "{{username}}") {
    return { action, ...parseElementTarget(value, id), value: value.value };
  }
  throw new InvalidRequestError(id);
}

function parseLoginStep(
  value: Record<string, unknown>,
  id?: RequestId,
): LoginStepRequest {
  if (!isOptionalNullableString(value.totp)) throw new InvalidRequestError(id);
  return {
    op: "login_step",
    id,
    action: parseStepwiseAction(value, id),
    totp: value.totp ?? null,
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
  if (value.op === "export_cookies") return { op: "export_cookies", id };
  if (value.op === "api_proxy_stop") return { op: "api_proxy_stop", id };
  if (value.op === "api_proxy_start") return parseApiProxyStart(value, id);
  if (value.op === "mcp_server_stop") return { op: "mcp_server_stop", id };
  if (value.op === "mcp_server_start") return parseMcpServerStart(value, id);
  if (value.op === "login_begin") return parseLoginBegin(value, id);
  if (value.op === "login_step") return parseLoginStep(value, id);
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
      cookies: parseCookies(value.cookies, id),
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
      if (step.action === "click" || step.action === "wait_for") {
        return { action: step.action, selector: step.selector };
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
    cookies: parseCookies(value.cookies, id),
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
        // On a target paused waiting for the debugger, the response to
        // Emulation.setUserAgentOverride
        // does not return until it resumes. The resume command is therefore sent right after,
        // without waiting for the override response, and both responses are awaited. Commands are
        // processed in send order,
        // so the User-Agent is overridden from the first request after resuming (see
        // guardFetchPatterns for client hints).
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
      // A continuation failure can legitimately occur for an already aborted navigation,
      // and it does not affect the file:// blocking, so it is not treated as a guard failure.
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

/**
 * The result of filling. The comparison is done inside the page and only the kind of result is
 * returned, so that other fields' values are not carried out of the page.
 */
type FillStatus = "ok" | "not_password" | "not_fillable" | "mismatch";

type FillArguments = { value: string; passwordOnly: boolean };

/**
 * The fill routine run inside the page. Playwright's fill proceeds focus, select all, insert
 * characters,
 * so on a site that moves focus while typing, the secret ends up in a different field. This routine
 * therefore
 * sets the value directly with the element's native value setter, independent of focus, and
 * verifies that no other field in the same document changed.
 * It is serialized into the page, so it must not reference external identifiers.
 *
 * Getters and setters on the page side may throw, and the exception text can contain the field's
 * value.
 * Propagating an exception out of the page would let that text reach stderr and would also skip
 * clearing the remaining secret,
 * so every exception is caught and converted into a result kind, and if the value was already set
 * it is cleared before returning.
 */
async function setValueInPage(
  element: Element,
  { value, passwordOnly }: FillArguments,
): Promise<FillStatus> {
  type Field = HTMLInputElement | HTMLTextAreaElement;
  const resolveView = () => {
    try {
      return element.ownerDocument.defaultView;
    } catch {
      return undefined;
    }
  };
  const view = resolveView();
  if (view === undefined) return "mismatch";
  if (view === null) return "not_fillable";
  // An element inside a frame can be identified only with the constructors of that frame's window.
  const isInput = (target: Element): target is HTMLInputElement =>
    target instanceof view.HTMLInputElement;
  const isTextArea = (target: Element): target is HTMLTextAreaElement =>
    target instanceof view.HTMLTextAreaElement;
  const resolveTarget = (): Field | FillStatus => {
    try {
      if (passwordOnly && !(isInput(element) && element.type === "password")) {
        return "not_password";
      }
      if (isInput(element) || isTextArea(element)) return element;
      return "not_fillable";
    } catch {
      return "mismatch";
    }
  };
  const resolved = resolveTarget();
  if (typeof resolved === "string") return resolved;
  const target: Field = resolved;
  const setNativeValue = (field: Field, next: string): void => {
    const prototype = isInput(field)
      ? view.HTMLInputElement.prototype
      : view.HTMLTextAreaElement.prototype;
    Object.getOwnPropertyDescriptor(prototype, "value")?.set?.call(field, next);
    field.dispatchEvent(new view.Event("input", { bubbles: true }));
    field.dispatchEvent(new view.Event("change", { bubbles: true }));
  };
  // A closed shadow root cannot be traversed from the page side, so fields inside it are not
  // verified.
  const collectFields = (
    root: Document | ShadowRoot,
    into: Field[],
  ): Field[] => {
    for (const node of Array.from(root.querySelectorAll("*"))) {
      if (isInput(node) || isTextArea(node)) into.push(node);
      if (node.shadowRoot !== null) collectFields(node.shadowRoot, into);
    }
    return into;
  };
  const otherFields = (): Field[] =>
    collectFields(target.ownerDocument, []).filter((field) => field !== target);
  // A field that did not exist before filling is expected to be empty.
  let expected: Map<Field, string>;
  try {
    expected = new Map<Field, string>();
    for (const field of otherFields()) expected.set(field, field.value);
  } catch {
    return "mismatch";
  }
  const changedFields = (): Field[] =>
    otherFields().filter(
      (field) => field.value !== (expected.get(field) ?? ""),
    );
  // Page-side changes deferred by queueMicrotask or setTimeout(0) are flushed before the
  // comparison.
  const yieldToPage = (): Promise<void> =>
    new Promise((resolve) => {
      view.setTimeout(resolve, 0);
    });
  // A field whose value or expected value cannot be read cannot be confirmed to hold no secret, so
  // it is treated as residue.
  const isResidual = (field: Field): boolean => {
    try {
      const want = field === target ? "" : (expected.get(field) ?? "");
      return field.value !== want;
    } catch {
      return true;
    }
  };
  const residualFields = (): Field[] => {
    let others: Field[] = [];
    try {
      others = otherFields();
    } catch {
      // Even if enumerating the fields fails, the target field is cleared.
    }
    return [
      ...(isResidual(target) ? [target] : []),
      ...others.filter(isResidual),
    ];
  };
  const clearField = (field: Field): void => {
    try {
      setNativeValue(field, "");
    } catch {
      // A failure on one field does not stop clearing the others.
    }
  };
  // All changed fields are emptied so that a secret does not remain in an unintended field and get
  // submitted.
  // The page may write a value back on the event fired by emptying, so re-verification is repeated
  // a bounded number of times.
  const clearResidualFields = async (): Promise<void> => {
    for (let pass = 0; pass < 3; pass += 1) {
      const residual = residualFields();
      if (residual.length === 0) return;
      for (const field of residual) {
        clearField(field);
        if (field === target) continue;
        try {
          expected.set(field, "");
        } catch {
          // A field whose expected value cannot be updated is treated as residue again in the next
          // round and cleared again.
        }
      }
      try {
        await yieldToPage();
      } catch {
        // Even if waiting fails, re-verification and clearing continue for the remaining rounds.
      }
    }
  };
  try {
    setNativeValue(target, value);
    await yieldToPage();
    if (target.value === value && changedFields().length === 0) return "ok";
  } catch {
    // The exception text is discarded, and processing moves on to clearing the fields that may hold
    // a secret.
  }
  try {
    await clearResidualFields();
  } catch {
    // Even if an exception occurs midway through clearing, for example from tampering with built-in
    // objects, the target field is emptied.
    clearField(target);
  }
  return "mismatch";
}

async function waitForVisible(
  locator: Locator,
  stepIndex?: number,
): Promise<void> {
  try {
    await locator.waitFor({ state: "visible", timeout: 10_000 });
  } catch (error) {
    if (isTimeoutError(error)) throw new SelectorNotFoundError(stepIndex);
    throw error;
  }
}

/**
 * Sets the value on an element once it becomes visible, and raises FillMismatchError if verifying
 * the setting fails.
 */
async function fillLocator(
  locator: Locator,
  value: string,
  passwordOnly: boolean,
  stepIndex?: number,
): Promise<void> {
  await waitForVisible(locator, stepIndex);
  let status: FillStatus;
  try {
    status = await locator.evaluate(
      setValueInPage,
      { value, passwordOnly },
      { timeout: 10_000 },
    );
  } catch (error) {
    if (isTimeoutError(error)) throw new SelectorNotFoundError(stepIndex);
    throw error;
  }
  if (status !== "ok") throw new FillMismatchError(stepIndex);
}

/**
 * Sets the value on an ElementHandle element, and raises FillMismatchError if verifying the setting
 * fails.
 */
async function fillHandle(
  handle: ElementHandle,
  value: string,
  passwordOnly: boolean,
  stepIndex?: number,
): Promise<void> {
  const status = await onResolvedElement(
    () => handle.evaluate(setValueInPage, { value, passwordOnly }),
    stepIndex,
  );
  if (status !== "ok") throw new FillMismatchError(stepIndex);
}

async function fill(
  page: Page,
  selector: string,
  value: string,
  passwordOnly: boolean,
  stepIndex?: number,
): Promise<void> {
  await fillLocator(
    page.locator(selector).first(),
    value,
    passwordOnly,
    stepIndex,
  );
}

async function waitForStep(
  page: Page,
  selector: string,
  stepIndex: number,
): Promise<void> {
  await waitForVisible(page.locator(selector).first(), stepIndex);
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

async function runStep(
  page: Page,
  step: LoginStep | DeviceStep,
  stepIndex: number,
  secret: LoginRequest["secret"],
  userCode?: string,
): Promise<void> {
  if (step.action === "click") return click(page, step.selector, stepIndex);
  if (step.action === "wait_for") {
    return waitForStep(page, step.selector, stepIndex);
  }
  return fill(
    page,
    step.selector,
    substituteSecrets(step.value, secret, userCode),
    step.value === "{{password}}",
    stepIndex,
  );
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
        runStep(page, step, stepIndex, secret, userCode),
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
    await fillLocator(
      page.locator("input").nth(usernameIndex),
      secret.username,
      false,
    );
  }
  await fillLocator(password, secret.password, true);

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

// On SPA-style sites the rejection message may render late, so the wait for the next operation's
// selector can time out first.
// When a failure is caused by a missing selector, failure_selector is therefore checked again and
// classified as a rejection.
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
    await fillLocator(locator.first(), value, false);
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

const playwrightRequire = createRequire(import.meta.url);

/** Extracts the browserVersion of the full Chromium from the contents of browsers.json. */
export function chromiumVersionFromManifest(manifest: unknown): string {
  const browsers = isRecord(manifest) ? manifest.browsers : undefined;
  const entry = Array.isArray(browsers)
    ? browsers.find((item) => isRecord(item) && item.name === "chromium")
    : undefined;
  if (!isRecord(entry) || typeof entry.browserVersion !== "string") {
    throw new Error("chromium browserVersion was not found in browsers.json");
  }
  return entry.browserVersion;
}

function bundledChromiumVersion(): string {
  const packageJsonPath = playwrightRequire.resolve(
    "playwright-core/package.json",
  );
  const manifestPath = path.join(
    path.dirname(packageJsonPath),
    "browsers.json",
  );
  return chromiumVersionFromManifest(
    JSON.parse(fs.readFileSync(manifestPath, "utf8")),
  );
}

function userAgentPlatform(platform: NodeJS.Platform): string {
  if (platform === "linux") return "X11; Linux x86_64";
  if (platform === "win32") return "Windows NT 10.0; Win64; x64";
  throw new Error(`unsupported browser platform: ${platform}`);
}

/**
 * Builds the UA passed to the --user-agent launch argument. To match the UA reduction of real
 * browsers,
 * it keeps only the major version number and sets the rest to 0.
 */
export function browserUserAgent(
  browserVersion: string,
  platform: NodeJS.Platform,
): string {
  const major = browserVersion.match(/^(\d+)(?:\.|$)/)?.[1];
  if (major === undefined) {
    throw new Error(`invalid chromium browserVersion: ${browserVersion}`);
  }
  return `Mozilla/5.0 (${userAgentPlatform(platform)}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${major}.0.0.0 Safari/537.36`;
}

export type FullChromiumCheck = { ok: true } | { ok: false; reason: string };

function isExecutableFile(executablePath: string): boolean {
  if (!fs.existsSync(executablePath)) return false;
  try {
    // A directory with search permission satisfies X_OK, so it is also checked to be a regular
    // file.
    if (!fs.statSync(executablePath).isFile()) return false;
    fs.accessSync(executablePath, fs.constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

function fullChromiumMissingReason(
  detail: string,
  browsersPath: string | undefined,
): string {
  return [
    `The full Chromium browser is required, but ${detail}.`,
    "A browser installation made with --only-shell (Chromium headless shell only) does not work; install chromium without --only-shell.",
    `PLAYWRIGHT_BROWSERS_PATH=${browsersPath ?? "(unset)"}`,
  ].join(" ");
}

/**
 * Checks whether the full Chromium launched with channel: "chromium" is executable.
 * chromium.executablePath() returns a path even if it does not exist, so the real file is
 * inspected.
 */
export function checkFullChromium(
  executablePath: () => string,
  browsersPath: string | undefined,
): FullChromiumCheck {
  let resolved: string;
  try {
    resolved = executablePath();
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return {
      ok: false,
      reason: fullChromiumMissingReason(
        `its executable path could not be resolved (${message})`,
        browsersPath,
      ),
    };
  }
  if (isExecutableFile(resolved)) return { ok: true };
  return {
    ok: false,
    reason: fullChromiumMissingReason(
      `no executable was found at ${resolved}`,
      browsersPath,
    ),
  };
}

/** The response to hello. If the full Chromium is missing, returns ok: false with the reason. */
export function helloResponse(check: FullChromiumCheck): unknown {
  const identity = { uid: process.getuid?.() ?? null, pid: process.pid };
  if (check.ok) return { ok: true, ...identity };
  return { ok: false, ...identity, reason: check.reason };
}

async function openBrowserPage() {
  const port = await reservePort();
  // With the full Chromium, the first request of a tab created with a URL goes out before the
  // guard,
  // so a UA without Headless is also given through the launch arguments.
  const launchUserAgent = browserUserAgent(
    bundledChromiumVersion(),
    process.platform,
  );
  const dir = await mkdtemp(path.join(os.tmpdir(), "tegata-browser-"));
  activeTempDir = dir;
  // Isolates the settings and caches the browser references from the executor's working area.
  const browser = await chromium.launch({
    headless: true,
    channel: "chromium",
    args: [
      `--remote-debugging-port=${port}`,
      "--disable-blink-features=AutomationControlled",
      // Screen and window sizes are kept separate, and the same values are applied to pages created
      // later over CDP.
      "--screen-info={1920x1080}",
      "--window-size=1280,807",
      `--user-agent=${launchUserAgent}`,
    ],
    env: {
      ...process.env,
      HOME: dir,
      XDG_CONFIG_HOME: dir,
      XDG_CACHE_HOME: dir,
    },
  });
  activeBrowser = browser;
  // The CDP endpoint is obtained before any page operation, and the guard is installed on every
  // target.
  const endpoint = await waitForEndpoint(port);
  const guard = await openGuard(endpoint);
  activeGuard = guard;
  const browserSession = await withGuard(guard, () =>
    browser.newBrowserCDPSession(),
  );
  try {
    // The viewport is not fixed; the window and screen sizes from the launch arguments are used as
    // they are.
    const page = await withGuard(guard, () =>
      browser.newPage({ viewport: null }),
    );
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

/**
 * Copies only the fields exchanged with the daemon from a Playwright cookie.
 * Reuses the same validation and copying as toCookie. Elements that fail validation are dropped
 * (the daemon validates again, so an exception here must not fail the whole login).
 */
export function toExportedCookie(cookie: Cookie): Cookie | undefined {
  return toCookie(cookie);
}

async function readContextCookies(
  guard: CdpGuard,
  context: BrowserContext,
): Promise<Cookie[]> {
  const cookies = await withGuard(guard, () => context.cookies());
  return cookies.flatMap((cookie) => {
    const exported = toExportedCookie(cookie);
    return exported === undefined ? [] : [exported];
  });
}

/**
 * Restores cookies into the context and returns the number accepted. Chromium rejects the whole
 * bulk setting if even one cookie is not accepted,
 * so in that case the cookies are set again one at a time and those not accepted are dropped.
 * The exception of an individual failure may contain the cookie contents, so it is discarded and
 * only guard failures are propagated.
 */
async function restoreCookies(
  guard: CdpGuard,
  context: BrowserContext,
  cookies: Cookie[],
): Promise<number> {
  if (cookies.length === 0) return 0;
  try {
    await withGuard(guard, () => context.addCookies(cookies));
    return cookies.length;
  } catch {
    guard.assertOpen();
  }
  let restored = 0;
  for (const cookie of cookies) {
    try {
      await withGuard(guard, () => context.addCookies([cookie]));
      restored += 1;
    } catch {
      guard.assertOpen();
    }
  }
  return restored;
}

// The element that the default steps (steps is null) wait for first.
const DEFAULT_FIRST_STEP_SELECTOR = 'input[type="password"]';

// Upper bound on the selector wait of a step (per step).
const STEP_SELECTOR_TIMEOUT_MS = 10_000;

function firstStepSelector(steps: LoginStep[] | null): string | undefined {
  if (steps === null) return DEFAULT_FIRST_STEP_SELECTOR;
  return steps[0]?.selector;
}

// The race is decided by any visible match, so a later visible match is detected even if the first
// match is hidden.
// The final decision (waitForLoginResult etc.) is made on attach, which is a different criterion
// from the race.
async function waitUntilVisible(
  page: Page,
  selector: string,
): Promise<boolean> {
  try {
    await page
      .locator(selector)
      .filter({ visible: true })
      .first()
      .waitFor({ state: "visible", timeout: STEP_SELECTOR_TIMEOUT_MS });
    return true;
  } catch (error) {
    if (isTimeoutError(error)) return false;
    throw error;
  }
}

/**
 * Returns which becomes visible first, the success element or the first step's element.
 * Returns undefined if neither appears within the limit.
 */
export async function raceSuccessAgainstFirstStep(
  page: Page,
  successSelector: string,
  stepSelector: string,
): Promise<"success" | "steps" | undefined> {
  const success = waitUntilVisible(page, successSelector).then((visible) =>
    visible ? ("success" as const) : undefined,
  );
  const step = waitUntilVisible(page, stepSelector).then((visible) =>
    visible ? ("steps" as const) : undefined,
  );
  return raceDecisive(
    [success, step],
    Promise.all([success, step]).then(() => undefined),
  );
}

/**
 * Decides whether the restored cookies have already logged in. If so, the login can be treated as a
 * success
 * without running the steps (and without putting secrets into the page). No decision is made when
 * success_selector is absent.
 */
async function isLoggedInByRestoredCookies(
  guard: CdpGuard,
  page: Page,
  request: LoginRequest,
): Promise<boolean> {
  const successSelector = request.success_selector;
  const stepSelector = firstStepSelector(request.steps);
  if (successSelector === null || stepSelector === undefined) return false;
  const first = await withGuard(guard, () =>
    raceSuccessAgainstFirstStep(page, successSelector, stepSelector),
  );
  return first === "success";
}

type LoginOutcome = {
  endpoint: string;
  targetId: string;
  cookies: Cookie[];
  stepsSkipped: boolean;
};

async function executeLogin(request: LoginRequest): Promise<LoginOutcome> {
  const { endpoint, page, pageSession, targetId, browserContextId } =
    await openBrowserPage();
  const guard = activeGuard;
  if (guard === undefined) throw new Error("CDP guard is not available");
  const context = page.context();
  const restored = await restoreCookies(guard, context, request.cookies ?? []);
  await withGuard(guard, () => page.goto(request.target_url));
  const stepsSkipped =
    restored > 0 && (await isLoggedInByRestoredCookies(guard, page, request));
  if (!stepsSkipped) {
    await withGuard(guard, () => runSteps(page, request.steps, request.secret));
    await withGuard(guard, () =>
      waitForLoginResult(
        page,
        request.success_selector,
        request.failure_selector,
      ),
    );
  }
  const cookies = await readContextCookies(guard, context);
  await pageSession.detach().catch(() => undefined);
  activeBrowserContextId = browserContextId;
  activeLoginContext = context;
  monitorGuardFailure(guard);
  guard.assertOpen();
  return { endpoint, targetId, cookies, stepsSkipped };
}

/**
 * The stepwise login before handoff. The CDP endpoint is included in no response until handoff.
 * filled holds the fields that were filled and is used for clearing on failure.
 */
type StepwiseSession = {
  endpoint: string;
  page: Page;
  pageSession: CDPSession;
  targetId: string;
  browserContextId: string;
  guard: CdpGuard;
  successSelector: string;
  failureSelector: string | null;
  secret: LoginBeginRequest["secret"];
  cookieValues: string[];
  totpCodes: string[];
  filled: ElementHandle[];
  // The refs held by the heading lines of the previous snapshot. Replaced every time a snapshot is
  // taken.
  refs: Set<string>;
  guardMonitored: boolean;
};

type StepwiseOutcome =
  | { state: "pending"; snapshot: Snapshot }
  | {
      state: "done";
      endpoint: string;
      target_id: string;
      cookies: Cookie[];
      steps_skipped: boolean;
    }
  | { state: "aborted" };

// Errors answered without ending the stepwise login. For any other error, the browser is discarded
// before answering.
const CONTINUABLE_STEPWISE_ERRORS: ReadonlySet<ErrorCode> = new Set([
  "SELECTOR_NOT_FOUND",
]);

/**
 * Secrets of the stepwise login to replace in diagnostic lines (credentials, the entered TOTP code,
 * and restored cookie values).
 */
function stepwiseSecrets(session: StepwiseSession): string[] {
  return [
    session.secret.username,
    session.secret.password,
    ...session.totpCodes,
    ...session.cookieValues,
  ];
}

/**
 * Installs, only once, a watch that terminates the whole executor if the guard is lost on a waiting
 * browser.
 */
function monitorStepwiseGuard(session: StepwiseSession): void {
  if (session.guardMonitored) return;
  session.guardMonitored = true;
  monitorGuardFailure(session.guard);
}

/** Runs the action and then waits for the page to settle. Returns whether it settled. */
async function runWithSettle(
  session: StepwiseSession,
  action: () => Promise<unknown>,
): Promise<boolean> {
  const { guard, page } = session;
  const tracker = trackNavigation(page);
  try {
    await withGuard(guard, action);
    return await withGuard(guard, () => settlePage(page, tracker));
  } finally {
    tracker.dispose();
  }
}

/** Immediately checks the attach of success_selector and failure_selector (without waiting). */
async function readStepwiseResult(
  session: StepwiseSession,
): Promise<"success" | "failure" | undefined> {
  const { guard, page, successSelector, failureSelector } = session;
  if (await withGuard(guard, () => selectorExists(page, successSelector))) {
    return "success";
  }
  if (
    failureSelector !== null &&
    (await withGuard(guard, () => selectorExists(page, failureSelector)))
  ) {
    return "failure";
  }
  return undefined;
}

async function takeStepwiseSnapshot(
  session: StepwiseSession,
  settled: boolean,
): Promise<Snapshot> {
  const { guard, page } = session;
  session.refs = new Set();
  const raw = await withGuard(guard, () => captureAriaSnapshot(page));
  const { snapshot, refs } = finalizeSnapshot(raw, settled, {
    username: session.secret.username,
    password: session.secret.password,
    totpCodes: session.totpCodes,
  });
  session.refs = refs;
  return snapshot;
}

/**
 * Promotes the stepwise login to a normal browser session and returns a result in the same form as
 * a successful login.
 */
async function completeStepwise(
  session: StepwiseSession,
  stepsSkipped: boolean,
): Promise<StepwiseOutcome> {
  const { guard, page } = session;
  const context = page.context();
  await disposeHandles(session.filled);
  session.filled = [];
  const cookies = await readContextCookies(guard, context);
  await session.pageSession.detach().catch(() => undefined);
  activeStepwise = undefined;
  activeBrowserContextId = session.browserContextId;
  activeLoginContext = context;
  monitorStepwiseGuard(session);
  guard.assertOpen();
  return {
    state: "done",
    endpoint: session.endpoint,
    target_id: session.targetId,
    cookies,
    steps_skipped: stepsSkipped,
  };
}

/**
 * The decision after settle. On success it promotes; on failure it empties the filled fields and
 * returns INVALID_CREDENTIAL;
 * otherwise it returns the checked snapshot.
 */
async function concludeStepwise(
  session: StepwiseSession,
  settled: boolean,
  cookiesRestored: boolean,
): Promise<StepwiseOutcome> {
  const result = await readStepwiseResult(session);
  if (result === "success") return completeStepwise(session, cookiesRestored);
  if (result === "failure") {
    await clearFilledFields(session.filled);
    throw new InvalidCredentialError();
  }
  const snapshot = await takeStepwiseSnapshot(session, settled);
  monitorStepwiseGuard(session);
  return { state: "pending", snapshot };
}

async function beginStepwise(
  request: LoginBeginRequest,
): Promise<StepwiseOutcome> {
  const { endpoint, page, pageSession, targetId, browserContextId } =
    await openBrowserPage();
  const guard = activeGuard;
  if (guard === undefined) throw new Error("CDP guard is not available");
  const session: StepwiseSession = {
    endpoint,
    page,
    pageSession,
    targetId,
    browserContextId,
    guard,
    successSelector: request.success_selector,
    failureSelector: request.failure_selector,
    secret: request.secret,
    cookieValues: (request.cookies ?? []).map((cookie) => cookie.value),
    totpCodes: [],
    filled: [],
    refs: new Set(),
    guardMonitored: false,
  };
  activeStepwise = session;
  const restored = await restoreCookies(
    guard,
    page.context(),
    request.cookies ?? [],
  );
  const settled = await runWithSettle(session, () =>
    page.goto(request.target_url, { waitUntil: "commit" }),
  );
  return concludeStepwise(session, settled, restored > 0);
}

// A Playwright error indicating that the resolved element was lost, together with its document or
// frame, after resolution.
const STALE_ELEMENT_MESSAGES = [
  "Invalid frame in aria-ref selector",
  "Execution context was destroyed",
  "Element is not attached to the DOM",
];

function isStaleElementError(error: unknown): boolean {
  return (
    error instanceof Error &&
    STALE_ELEMENT_MESSAGES.some((message) => error.message.includes(message))
  );
}

/**
 * Treats a timeout or loss of the element on an operation against a resolved element as
 * SelectorNotFoundError.
 */
async function onResolvedElement<T>(
  operation: () => Promise<T>,
  stepIndex?: number,
): Promise<T> {
  try {
    return await operation();
  } catch (error) {
    if (isTimeoutError(error) || isStaleElementError(error)) {
      throw new SelectorNotFoundError(stepIndex);
    }
    throw error;
  }
}

/**
 * Resolves a ref in the previous snapshot to an ElementHandle exactly once, without waiting. Later
 * decisions and operations are made
 * on this ElementHandle and it is not resolved again (so that nothing is typed into a new document
 * even if the frame navigates after the decision).
 */
async function resolveRef(
  session: StepwiseSession,
  ref: string,
  stepIndex?: number,
): Promise<ElementHandle> {
  if (!session.refs.has(ref)) throw new SelectorNotFoundError(stepIndex);
  const handles = await onResolvedElement(
    () => session.page.locator(`aria-ref=${ref}`).elementHandles(),
    stepIndex,
  );
  const [handle, ...rest] = handles;
  await disposeHandles(rest);
  if (handle === undefined) throw new SelectorNotFoundError(stepIndex);
  return handle;
}

/**
 * Returns the origin of a URL. Returns undefined for an opaque origin (about:blank, srcdoc, data:,
 * etc.) and for an unreadable URL.
 */
function tupleOrigin(url: string): string | undefined {
  try {
    const { origin } = new URL(url);
    return origin === "null" ? undefined : origin;
  } catch {
    return undefined;
  }
}

function mainFrameOrigin(page: Page): string | undefined {
  return tupleOrigin(page.mainFrame().url());
}

/**
 * Returns whether the origin of the element's frame URL matches the origin of the main frame URL at
 * that moment.
 * The frame URL comes from the CDP frame tree and cannot be spoofed from the page's JS. If it
 * cannot be determined, it is treated as a mismatch.
 */
async function isSameOriginTarget(
  page: Page,
  handle: ElementHandle,
): Promise<boolean> {
  let frame: Frame | null;
  try {
    frame = await handle.ownerFrame();
  } catch {
    return false;
  }
  if (frame === null) return false;
  const origin = tupleOrigin(frame.url());
  return origin !== undefined && origin === mainFrameOrigin(page);
}

/**
 * Resolves a field to an ElementHandle without entering a value. A ref is resolved exactly once
 * without waiting, and a selector is resolved after waiting for it to become visible, as before.
 * A selector can also take a form that follows aria-ref or frames, so later decisions and filling
 * are made on this ElementHandle.
 */
async function resolveFillTarget(
  session: StepwiseSession,
  target: ElementTarget,
  stepIndex?: number,
): Promise<ElementHandle> {
  if ("ref" in target) return resolveRef(session, target.ref, stepIndex);
  const locator = session.page.locator(target.selector).first();
  await waitForVisible(locator, stepIndex);
  let handle: ElementHandle | null;
  try {
    handle = await locator.elementHandle({ timeout: STEP_SELECTOR_TIMEOUT_MS });
  } catch (error) {
    if (isTimeoutError(error)) throw new SelectorNotFoundError(stepIndex);
    throw error;
  }
  if (handle === null) throw new SelectorNotFoundError(stepIndex);
  return handle;
}

/**
 * Before entering any value, resolves all fields and checks the frame origin of every field. If
 * even one does not match, no value is entered in any field and
 * FillTargetRefusedError is raised. The return value is the ElementHandles in the same order as
 * fills.
 */
async function prepareStepwiseFills(
  session: StepwiseSession,
  targets: readonly ElementTarget[],
  withStepIndex: boolean,
): Promise<ElementHandle[]> {
  const handles: ElementHandle[] = [];
  try {
    for (const [index, target] of targets.entries()) {
      handles.push(
        await resolveFillTarget(
          session,
          target,
          withStepIndex ? index : undefined,
        ),
      );
    }
    for (const handle of handles) {
      if (!(await isSameOriginTarget(session.page, handle))) {
        throw new FillTargetRefusedError();
      }
    }
  } catch (error) {
    await disposeHandles(handles);
    throw error;
  }
  return handles;
}

/** Records a filled field so that it can be cleared on failure. */
function recordFilled(
  session: StepwiseSession,
  handle: ElementHandle,
  filled: ElementHandle[],
): void {
  filled.push(handle);
  session.filled.push(handle);
}

/**
 * Waits for the resolved field to become visible, records it, and then sets the value with the #43
 * verification.
 */
async function fillStepwiseHandle(
  session: StepwiseSession,
  handle: ElementHandle,
  value: string,
  passwordOnly: boolean,
  filled: ElementHandle[],
  stepIndex?: number,
): Promise<void> {
  await onResolvedElement(
    () =>
      handle.waitForElementState("visible", {
        timeout: STEP_SELECTOR_TIMEOUT_MS,
      }),
    stepIndex,
  );
  recordFilled(session, handle, filled);
  await fillHandle(handle, value, passwordOnly, stepIndex);
}

/**
 * Sets values in order, on the same ElementHandles, on the fields checked by prepareStepwiseFills.
 */
async function fillStepwiseTargets(
  session: StepwiseSession,
  fills: ReadonlyArray<{
    target: ElementTarget;
    value: string;
    passwordOnly: boolean;
  }>,
  filled: ElementHandle[],
  withStepIndex: boolean,
): Promise<void> {
  const handles = await prepareStepwiseFills(
    session,
    fills.map((fill) => fill.target),
    withStepIndex,
  );
  try {
    for (const [index, { value, passwordOnly }] of fills.entries()) {
      await fillStepwiseHandle(
        session,
        handles[index],
        value,
        passwordOnly,
        filled,
        withStepIndex ? index : undefined,
      );
    }
  } finally {
    // Releases the ElementHandles of fields that were never filled.
    await disposeHandles(handles.filter((handle) => !filled.includes(handle)));
  }
}

/** Operates on an element resolved by ref and then releases its ElementHandle. */
async function withRefElement(
  session: StepwiseSession,
  ref: string,
  stepIndex: number | undefined,
  operation: (handle: ElementHandle) => Promise<unknown>,
): Promise<void> {
  const handle = await resolveRef(session, ref, stepIndex);
  try {
    await onResolvedElement(() => operation(handle), stepIndex);
  } finally {
    await handle.dispose().catch(() => undefined);
  }
}

async function clickStepwise(
  session: StepwiseSession,
  target: ElementTarget,
  stepIndex?: number,
): Promise<void> {
  if ("selector" in target) {
    return click(session.page, target.selector, stepIndex);
  }
  await withRefElement(session, target.ref, stepIndex, (handle) =>
    handle.click({ timeout: STEP_SELECTOR_TIMEOUT_MS }),
  );
}

async function waitForStepwise(
  session: StepwiseSession,
  target: ElementTarget,
): Promise<void> {
  if ("selector" in target) {
    return waitForVisible(session.page.locator(target.selector).first());
  }
  await withRefElement(session, target.ref, undefined, (handle) =>
    handle.waitForElementState("visible", {
      timeout: STEP_SELECTOR_TIMEOUT_MS,
    }),
  );
}

async function pressEnterStepwise(
  session: StepwiseSession,
  target: ElementTarget,
  stepIndex: number,
): Promise<void> {
  if ("ref" in target) {
    await withRefElement(session, target.ref, stepIndex, (handle) =>
      handle.press("Enter", { timeout: STEP_SELECTOR_TIMEOUT_MS }),
    );
    return;
  }
  try {
    await session.page.press(target.selector, "Enter", {
      timeout: STEP_SELECTOR_TIMEOUT_MS,
    });
  } catch (error) {
    if (isTimeoutError(error)) throw new SelectorNotFoundError(stepIndex);
    throw error;
  }
}

async function submitStepwise(
  session: StepwiseSession,
  submit: StepwiseSubmit,
  stepIndex: number,
): Promise<void> {
  if ("click" in submit) {
    return clickStepwise(session, submit.click, stepIndex);
  }
  return pressEnterStepwise(session, submit.press_enter, stepIndex);
}

/**
 * Fills fills in order, submits, and performs everything up to settle as one operation. Regardless
 * of success or failure, the filled fields that remain
 * in the document with a non-empty value are emptied before returning. The step of an error is the
 * index into fills (for submit, the number of fills).
 */
async function fillAndSubmit(
  session: StepwiseSession,
  action: Extract<StepwiseAction, { action: "fill_submit" }>,
  totp: string | null,
): Promise<boolean> {
  // Checked before touching any field so that the flow does not become MFA_REQUIRED midway through
  // filling.
  const usesTotp = action.fills.some((fill) => fill.value === "{{totp}}");
  if (usesTotp && totp === null) throw new MfaRequiredError();
  if (usesTotp && totp !== null && !session.totpCodes.includes(totp)) {
    session.totpCodes.push(totp);
  }
  const secret = { ...session.secret, totp };
  const filled: ElementHandle[] = [];
  try {
    return await runWithSettle(session, async () => {
      await fillStepwiseTargets(
        session,
        action.fills.map((fill) => ({
          target: fill,
          value: substituteSecrets(fill.value, secret),
          passwordOnly: fill.value === "{{password}}",
        })),
        filled,
        true,
      );
      await submitStepwise(session, action.submit, action.fills.length);
    });
  } finally {
    await clearFilledFields(filled);
  }
}

/** Runs an action other than abort, waits until settle, and returns whether the page settled. */
async function performStepwiseAction(
  session: StepwiseSession,
  request: LoginStepRequest,
): Promise<boolean> {
  const { action } = request;
  if (action.action === "fill_submit") {
    return fillAndSubmit(session, action, request.totp);
  }
  return runWithSettle(session, async () => {
    if (action.action === "click") return clickStepwise(session, action);
    if (action.action === "wait_for") return waitForStepwise(session, action);
    if (action.action === "fill") {
      return fillStepwiseTargets(
        session,
        [
          {
            target: action,
            value: session.secret.username,
            passwordOnly: false,
          },
        ],
        [],
        false,
      );
    }
  });
}

async function stepStepwise(
  session: StepwiseSession,
  request: LoginStepRequest,
): Promise<StepwiseOutcome> {
  if (request.action.action === "abort") {
    await cleanupResources();
    return { state: "aborted" };
  }
  const settled = await performStepwiseAction(session, request);
  return concludeStepwise(session, settled, false);
}

/** `pageSecrets` takes the cookie values the context held at the time of the failure. */
type ExecutionErrorWriter = (
  stage: ExecutionStage,
  classified: ClassifiedExecutionError,
  cause: unknown,
  pageSecrets: SecretCandidates,
) => void;

function throwIfDeviceAuthorizationAborted(signal?: AbortSignal): void {
  if (signal?.aborted) throw new Error("device authorization was aborted");
}

// The element that the default device step (steps is null) fills first.
const DEFAULT_FIRST_DEVICE_STEP_SELECTOR =
  'input[name="user_code"], input[autocomplete="one-time-code"]';

/**
 * Returns the selector of the element the device step operates on first. Returns undefined if there
 * are no steps.
 */
export function firstDeviceStepSelector(
  steps: DeviceStep[] | null,
): string | undefined {
  if (steps === null) return DEFAULT_FIRST_DEVICE_STEP_SELECTOR;
  return steps[0]?.selector;
}

// The element treated as a login form in the device step race. Only visible candidates are awaited,
// so that a later visible field is detected
// even if the first password field is hidden.
const DEVICE_RACE_LOGIN_SELECTOR = 'input[type="password"]:visible';

/**
 * Returns which becomes visible first, the first element of the device step or the login form (a
 * visible password field).
 * Returns undefined if neither appears within the limit.
 */
export async function raceDeviceStageAgainstLogin(
  page: Page,
  deviceSelector: string,
): Promise<"device" | "login" | undefined> {
  const device = waitUntilVisible(page, deviceSelector).then((visible) =>
    visible ? ("device" as const) : undefined,
  );
  const login = waitUntilVisible(page, DEVICE_RACE_LOGIN_SELECTOR).then(
    (visible) => (visible ? ("login" as const) : undefined),
  );
  return raceDecisive(
    [device, login],
    Promise.all([device, login]).then(() => undefined),
  );
}

/**
 * Decides whether a device step failure that skipped the login step is one to redo from the login
 * step.
 * On sites where the approval page is displayed empty even when unauthenticated, the failure takes
 * the form of a missing target element,
 * so only the absence of an element not classified as a rejection by failure_selector is covered.
 */
export function isLoginFallbackError(error: unknown): boolean {
  return error instanceof SelectorNotFoundError;
}

/**
 * Performs each operation under abort checks and guard monitoring while recording the running step.
 */
type DeviceAuthorizationRunner = {
  page: Page;
  run: <T>(stage: ExecutionStage, action: () => Promise<T>) => Promise<T>;
};

async function runDeviceLoginStage(
  runner: DeviceAuthorizationRunner,
  request: AuthorizeDeviceRequest,
): Promise<void> {
  const { page } = runner;
  await runner.run("login", () => page.goto(request.login_url));
  await runner.run("login", () =>
    runSteps(page, null, request.secret, { automaticTotp: true }),
  );
  await runner.run("login", () => waitForLoginResult(page, null, null));
}

async function runDeviceStage(
  runner: DeviceAuthorizationRunner,
  request: AuthorizeDeviceRequest,
): Promise<void> {
  const { page } = runner;
  await runner.run("device", () => page.goto(request.verification_url));
  await runner.run("device", () => executeDeviceFlow(page, request));
}

/**
 * Decides whether the approval page is reachable with the restored cookies. Returns true only if
 * the approval page's element
 * became visible first, and the page then stays on the approval page.
 */
async function isDevicePageReachedByRestoredCookies(
  runner: DeviceAuthorizationRunner,
  request: AuthorizeDeviceRequest,
): Promise<boolean> {
  const deviceSelector = firstDeviceStepSelector(request.steps);
  if (deviceSelector === undefined) return false;
  const { page } = runner;
  await runner.run("device", () => page.goto(request.verification_url));
  const first = await runner.run("device", () =>
    raceDeviceStageAgainstLogin(page, deviceSelector),
  );
  return first === "device";
}

/**
 * Skips the login step and runs the device step on the displayed approval page. Only if it fails
 * because an element is missing,
 * redoes it once from the login step. Returns whether the login step could be skipped.
 */
async function authorizeOnReachedDevicePage(
  runner: DeviceAuthorizationRunner,
  request: AuthorizeDeviceRequest,
): Promise<boolean> {
  try {
    await runner.run("device", () => executeDeviceFlow(runner.page, request));
    return true;
  } catch (error) {
    if (!isLoginFallbackError(error)) throw error;
  }
  await runDeviceLoginStage(runner, request);
  await runDeviceStage(runner, request);
  return false;
}

/** Runs the login step and the device step, and returns whether the login step could be skipped. */
async function authorizeDevice(
  runner: DeviceAuthorizationRunner,
  request: AuthorizeDeviceRequest,
  restored: number,
): Promise<boolean> {
  if (
    restored > 0 &&
    (await isDevicePageReachedByRestoredCookies(runner, request))
  ) {
    return authorizeOnReachedDevicePage(runner, request);
  }
  await runDeviceLoginStage(runner, request);
  await runDeviceStage(runner, request);
  return false;
}

type DeviceAuthorizationOutcome = {
  cookies: Cookie[];
  stepsSkipped: boolean;
};

type DeviceAuthorizationResult =
  | ({ ok: true } & DeviceAuthorizationOutcome)
  | { ok: false; error: ClassifiedExecutionError };

/**
 * Returns the cookies and whether the login step was skipped, to include in the success response of
 * the device approval.
 */
export function formatDeviceAuthorizationFields(
  outcome: DeviceAuthorizationOutcome,
): { cookies: Cookie[]; steps_skipped: boolean } {
  return { cookies: outcome.cookies, steps_skipped: outcome.stepsSkipped };
}

// Upper bound on cookies read from the context at the time of failure, to hide them in diagnostic
// lines.
const DIAGNOSTIC_COOKIE_READ_TIMEOUT_MS = 1_000;

/**
 * Reads the cookie values the context currently holds, to use as replacement targets in diagnostic
 * lines. Cookies the page issued or updated during the run
 * are not part of the request and cannot be hidden by request-derived replacement. If there is no
 * context, if reading fails,
 * or if the upper bound is exceeded, the result is empty and does not hinder reporting the original
 * failure.
 */
async function readCookieValuesForRedaction(
  context: BrowserContext | undefined,
): Promise<string[]> {
  if (context === undefined) return [];
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const cookies = await Promise.race([
      context.cookies(),
      new Promise<[]>((resolve) => {
        timer = setTimeout(
          () => resolve([]),
          DIAGNOSTIC_COOKIE_READ_TIMEOUT_MS,
        );
      }),
    ]);
    return cookies.map((cookie) => cookie.value);
  } catch {
    return [];
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

/**
 * Performs the device approval in the browser. If `signal` is aborted, it stops after the browser
 * launch and before each step.
 * On success it returns the cookies of the context before the browser is closed. The caller handles
 * browser cleanup.
 */
async function executeAuthorizeDevice(
  request: AuthorizeDeviceRequest,
  writeError: ExecutionErrorWriter = (stage, classified, cause, pageSecrets) =>
    writeExecutorErrorLine(request, stage, classified, cause, pageSecrets),
  signal?: AbortSignal,
): Promise<DeviceAuthorizationResult> {
  let stage: ExecutionStage = "login";
  let diagnosticContext: BrowserContext | undefined;
  try {
    throwIfDeviceAuthorizationAborted(signal);
    const { page, pageSession } = await openBrowserPage();
    const guard = activeGuard;
    if (guard === undefined) throw new Error("CDP guard is not available");
    const runner: DeviceAuthorizationRunner = {
      page,
      run: (nextStage, action) => {
        stage = nextStage;
        throwIfDeviceAuthorizationAborted(signal);
        return withGuard(guard, action);
      },
    };
    try {
      const context = page.context();
      diagnosticContext = context;
      const restored = await runner.run("login", () =>
        restoreCookies(guard, context, request.cookies ?? []),
      );
      const stepsSkipped = await authorizeDevice(runner, request, restored);
      const cookies = await runner.run("device", () =>
        readContextCookies(guard, context),
      );
      return { ok: true, cookies, stepsSkipped };
    } finally {
      await pageSession.detach().catch(() => undefined);
    }
  } catch (error) {
    const classified = classifyExecutionError(error, stage);
    writeError(
      stage,
      classified,
      error,
      await readCookieValuesForRedaction(diagnosticContext),
    );
    return { ok: false, error: classified };
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
  // One line is written with a single write, like the response line, to keep the output as
  // line-delimited JSON.
  process.stdout.write(`${JSON.stringify(formatApiProxyEvent(record))}\n`);
}

export function formatOAuthTokenEvent(action: OAuthTokenAction): unknown {
  return { event: "oauth_token", action };
}

function writeOAuthTokenEvent(action: OAuthTokenAction): void {
  process.stdout.write(`${JSON.stringify(formatOAuthTokenEvent(action))}\n`);
}

export function formatMcpServerEvent(event: McpServerEvent): unknown {
  return { event: "mcp_server", ...event };
}

function writeMcpServerEvent(event: McpServerEvent): void {
  process.stdout.write(`${JSON.stringify(formatMcpServerEvent(event))}\n`);
}

function monitorGuardFailure(guard: CdpGuard): void {
  void guard.failure.then(undefined, async () => {
    if (shuttingDown) return;
    shuttingDown = true;
    await closeApiProxy();
    await closeMcpServer();
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

export async function cleanupResources(): Promise<void> {
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
  activeStepwise = undefined;
  activeBrowserContextId = undefined;
  activeLoginContext = undefined;
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

/**
 * Returns all cookies of the login context. Returns an empty array if there is no browser or login
 * context.
 * An exception's text may contain cookie contents, so no diagnostic line is emitted even on
 * failure.
 */
export async function handleExportCookies(
  request: ExportCookiesRequest,
): Promise<void> {
  const guard = activeGuard;
  const context = activeLoginContext;
  if (
    activeBrowser === undefined ||
    guard === undefined ||
    context === undefined
  ) {
    writeResponse({ ok: true, cookies: [] }, request.id);
    return;
  }

  try {
    const cookies = await readContextCookies(guard, context);
    writeResponse({ ok: true, cookies }, request.id);
  } catch {
    writeResponse(formatErrorResponse({ code: "INTERNAL" }), request.id);
  }
}

export async function handleLogin(request: LoginRequest): Promise<void> {
  if (activeBrowser !== undefined) {
    const error = new Error("browser is already active");
    const classified = classifyExecutionError(error, "login");
    writeExecutorErrorLine(request, "login", classified, error);
    writeResponse(formatErrorResponse(classified), request.id);
    return;
  }

  try {
    const { endpoint, targetId, cookies, stepsSkipped } =
      await executeLogin(request);
    writeResponse(
      {
        ok: true,
        endpoint,
        target_id: targetId,
        cookies,
        steps_skipped: stepsSkipped,
      },
      request.id,
    );
  } catch (error) {
    const classified = classifyExecutionError(error, "login");
    writeExecutorErrorLine(request, "login", classified, error);
    await cleanupResources();
    writeResponse(formatErrorResponse(classified), request.id);
  }
}

/**
 * Answers a stepwise login error. For an error that cannot continue, the browser is discarded
 * before answering.
 */
async function writeStepwiseError(
  request: LoginBeginRequest | LoginStepRequest,
  error: unknown,
  runtimeSecrets: SecretCandidates,
): Promise<void> {
  const classified = classifyExecutionError(error, "login");
  writeExecutorErrorLine(request, "login", classified, error, runtimeSecrets);
  if (!CONTINUABLE_STEPWISE_ERRORS.has(classified.code)) {
    await cleanupResources();
  }
  writeResponse(formatErrorResponse(classified), request.id);
}

export async function handleLoginBegin(
  request: LoginBeginRequest,
): Promise<void> {
  if (activeBrowser !== undefined) {
    const error = new Error("browser is already active");
    const classified = classifyExecutionError(error, "login");
    writeExecutorErrorLine(request, "login", classified, error);
    writeResponse(formatErrorResponse(classified), request.id);
    return;
  }
  try {
    writeResponse({ ok: true, ...(await beginStepwise(request)) }, request.id);
  } catch (error) {
    // At the time of login_begin there is no selector operation, so every error ends the stepwise
    // login.
    await cleanupResources();
    await writeStepwiseError(request, error, []);
  }
}

export async function handleLoginStep(
  request: LoginStepRequest,
): Promise<void> {
  const session = activeStepwise;
  if (session === undefined) {
    // A browser after handoff or after termination is not a target of stepwise login operations.
    writeResponse(formatErrorResponse({ code: "INTERNAL" }), request.id);
    return;
  }
  try {
    writeResponse(
      { ok: true, ...(await stepStepwise(session, request)) },
      request.id,
    );
  } catch (error) {
    await writeStepwiseError(request, error, stepwiseSecrets(session));
  }
}

export async function handleAuthorizeDevice(
  request: AuthorizeDeviceRequest,
): Promise<void> {
  if (activeBrowser !== undefined) {
    const error = new Error("browser is already active");
    const classified = classifyExecutionError(error, "login");
    writeExecutorErrorLine(request, "login", classified, error);
    writeResponse(formatErrorResponse(classified), request.id);
    return;
  }

  const result = await executeAuthorizeDevice(request);
  await cleanupResources();
  writeResponse(
    result.ok
      ? { ok: true, ...formatDeviceAuthorizationFields(result) }
      : formatErrorResponse(result.error),
    request.id,
  );
}

async function closeApiProxy(): Promise<void> {
  const proxy = activeApiProxy;
  activeApiProxy = undefined;
  if (proxy !== undefined) await proxy.close();
}

export async function handleApiProxyStart(
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

// The response is returned within 80 seconds of the first request (inside the daemon's 90-second
// limit for the first request). Each step of the grant is
// aborted at this deadline, and the remainder is spent on cleanup (5 seconds to wait for the
// aborted approval to finish, 5 seconds for the browser to exit, or 5 seconds for token revocation)
// and the response.
const OAUTH_GRANT_BUDGET_MS = 65_000;
// Upper bound on waiting until an approval abandoned by a deadline overrun or abort finishes
// without leaving a launched browser behind.
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
    cookies: oauth.cookies ?? null,
    secret: oauth.secret,
  };
}

/**
 * Waits up to `ms` milliseconds for `promise` to complete. Neither its result nor its failure
 * matters.
 */
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
 * Performs the device approval in the browser and closes the browser regardless of success or
 * failure.
 * On deadline overrun or abort, the approval is cut off and raised as OAuthGrantError, and late
 * diagnostic lines that arrive afterward are not emitted.
 * Cleaning up before the cut-off approval finishes launching the browser would leave the browser
 * behind, so the cleanup waits briefly for it to finish before closing.
 */
async function authorizeDeviceInBrowser(
  request: OAuthApiProxyStartRequest,
  device: DeviceAuthorization,
  deadline: number,
  signal: AbortSignal,
  runtimeSecrets: string[],
): Promise<DeviceAuthorizationResult> {
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
    (stage, classified, cause, pageSecrets) => {
      // A failure after the cut-off is reported separately as the reason for the cut-off, so it is
      // not emitted.
      if (!cancel.signal.aborted) {
        writeExecutorErrorLine(request, stage, classified, cause, [
          ...runtimeSecrets,
          ...pageSecrets,
        ]);
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

/**
 * Obtains an access token with the device-code grant. A failure in the browser step is returned as
 * a classified result.
 * On success it also returns the cookies obtained in the browser step and whether the login step
 * was skipped.
 */
async function acquireOAuthTokens(
  request: OAuthApiProxyStartRequest,
  deadline: number,
  signal: AbortSignal,
  runtimeSecrets: string[],
): Promise<
  | { tokens: TokenSet; issuedAt: number; browser: DeviceAuthorizationOutcome }
  | ClassifiedExecutionError
> {
  const { oauth } = request;
  const device = await requestDeviceAuthorization(
    oauth,
    postForm,
    Math.min(OAUTH_REQUEST_TIMEOUT_MS, deadline - Date.now()),
    signal,
  );
  const receivedAt = Date.now();
  runtimeSecrets.push(device.deviceCode, device.userCode);
  const browser = await authorizeDeviceInBrowser(
    request,
    device,
    deadline,
    signal,
    runtimeSecrets,
  );
  if (!browser.ok) return browser.error;
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
  return { tokens, issuedAt: Date.now(), browser };
}

/**
 * Starts the proxy with the obtained token. If it cannot start, the token is revoked and then an
 * exception is raised.
 */
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
    // The daemon reads an event line emitted before the response as the response, so only
    // revocation is done here.
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
    writeResponse(
      {
        ok: true,
        port,
        secret,
        ...formatDeviceAuthorizationFields(acquired.browser),
      },
      request.id,
    );
    // The daemon reads the response to the first request as the first line, so event lines are
    // emitted after the response.
    writeOAuthTokenEvent("issued");
  } catch (error) {
    const classified = classifyExecutionError(error, "oauth");
    // An abort by shutdown is not a grant failure, so no diagnostic line is emitted.
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

/** Records the running grant so that shutdown can abort it and wait for it to finish. */
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

export async function handleApiProxyStop(
  request: ApiProxyStopRequest,
): Promise<void> {
  await closeApiProxy();
  writeResponse({ ok: true }, request.id);
}

async function closeMcpServer(): Promise<void> {
  const host = activeMcpServer;
  activeMcpServer = undefined;
  if (host !== undefined) await host.close();
}

async function runMcpServerStart(
  request: McpServerStartRequest,
): Promise<void> {
  // One executor holds at most one resource of one kind, and the browser and the injection proxy do
  // not coexist.
  if (
    activeMcpServer !== undefined ||
    activeApiProxy !== undefined ||
    activeBrowser !== undefined ||
    activeOAuthStart !== undefined
  ) {
    writeResponse(
      { ok: false, error: "INTERNAL" satisfies ErrorCode },
      request.id,
    );
    return;
  }
  const streamSecret = createLoopbackSecret();
  try {
    const host = await startMcpServer({
      command: request.command,
      args: request.args,
      env: request.env,
      scan: request.scan,
      streamSecret,
      onEvent: writeMcpServerEvent,
    });
    activeMcpServer = host;
    writeResponse(
      { ok: true, port: host.port, stream_secret: streamSecret },
      request.id,
    );
    host.releaseEvents();
  } catch (error) {
    const classified = classifyExecutionError(error, "mcp_server");
    writeExecutorErrorLine(request, "mcp_server", classified, error, [
      streamSecret,
    ]);
    writeResponse(formatErrorResponse(classified), request.id);
  }
}

/**
 * Records the request being started so that shutdown can wait for the start to finish before
 * cleanup.
 */
async function handleMcpServerStart(
  request: McpServerStartRequest,
): Promise<void> {
  const done = runMcpServerStart(request);
  activeMcpStart = done;
  try {
    await done;
  } finally {
    activeMcpStart = undefined;
  }
}

async function handleMcpServerStop(
  request: McpServerStopRequest,
): Promise<void> {
  await closeMcpServer();
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
  await activeMcpStart;
  await closeApiProxy();
  await closeMcpServer();
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
          helloResponse(
            checkFullChromium(
              () => chromium.executablePath(),
              process.env.PLAYWRIGHT_BROWSERS_PATH,
            ),
          ),
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
      if (request.op === "export_cookies") {
        await handleExportCookies(request);
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
      if (request.op === "mcp_server_start") {
        await handleMcpServerStart(request);
        continue;
      }
      if (request.op === "mcp_server_stop") {
        await handleMcpServerStop(request);
        continue;
      }
      if (request.op === "login_begin") {
        await handleLoginBegin(request);
        continue;
      }
      if (request.op === "login_step") {
        await handleLoginStep(request);
        continue;
      }
      await handleLogin(request);
    } catch (error) {
      // A malformed request during a stepwise login ends it as INTERNAL, so the browser is
      // discarded before the response.
      if (activeStepwise !== undefined) await cleanupResources();
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
