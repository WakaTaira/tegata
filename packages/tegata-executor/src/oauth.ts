import type { ApiProxy } from "./api-proxy.js";

/** OAuth クライアント（公開クライアント）としての endpoint 群。 */
export type OAuthEndpoints = {
  client_id: string;
  device_authorization_url: string;
  token_url: string;
  revocation_url: string | null;
  scope: string | null;
};

export type FormResponse = { status: number; body: unknown };

export type PostForm = (
  url: string,
  params: Record<string, string>,
  timeoutMs: number,
  signal?: AbortSignal,
) => Promise<FormResponse>;

export type DeviceAuthorization = {
  deviceCode: string;
  userCode: string;
  verificationUrl: string;
  expiresIn: number;
  interval: number;
};

export type TokenSet = {
  accessToken: string;
  refreshToken: string | null;
  expiresIn: number | null;
};

export type TokenPollResult =
  | { kind: "token"; tokens: TokenSet }
  | { kind: "pending" }
  | { kind: "slow_down" };

export type OAuthTokenAction =
  | "issued"
  | "refreshed"
  | "refresh_failed"
  | "revoked";

export class OAuthGrantError extends Error {
  override name = "OAuthGrantError";
}

const DEVICE_CODE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code";
const DEFAULT_POLL_INTERVAL_SECS = 5;
const SLOW_DOWN_INCREMENT_MS = 5_000;
const MAX_POLL_WINDOW_MS = 45_000;
const REFRESH_MARGIN_CAP_MS = 60_000;
export const OAUTH_REQUEST_TIMEOUT_MS = 10_000;
export const REVOCATION_TIMEOUT_MS = 5_000;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function isSuccessStatus(status: number): boolean {
  return status >= 200 && status < 300;
}

function positiveSeconds(value: unknown): number | null {
  const seconds =
    typeof value === "number"
      ? value
      : typeof value === "string" && value.trim() !== ""
        ? Number(value)
        : Number.NaN;
  return Number.isFinite(seconds) && seconds > 0 ? seconds : null;
}

function isHttpUrl(value: string): boolean {
  try {
    const { protocol } = new URL(value);
    return protocol === "http:" || protocol === "https:";
  } catch {
    return false;
  }
}

/**
 * 通信失敗を秘密を含まない短い理由へ変換する。
 * 例外メッセージは相手先の応答や URL を含みうるため、名前と Node のエラーコードのみを用いる。
 */
export function networkFailureReason(error: unknown): string {
  if (!(error instanceof Error)) return typeof error;
  const cause = (error as { cause?: unknown }).cause;
  if (isRecord(cause) && typeof cause.code === "string") return cause.code;
  return error.name;
}

function safeErrorCode(value: string): string {
  return /^[a-z_]{1,64}$/u.test(value) ? value : "an unrecognized error";
}

/** form 形式で POST し、JSON 応答を読む。リダイレクトは追わない。 */
export const postForm: PostForm = async (url, params, timeoutMs, signal) => {
  if (!isHttpUrl(url)) {
    throw new OAuthGrantError("unsupported endpoint protocol");
  }
  const signals = [AbortSignal.timeout(Math.max(0, timeoutMs))];
  if (signal !== undefined) signals.push(signal);
  const response = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json",
    },
    body: new URLSearchParams(params).toString(),
    redirect: "manual",
    signal: AbortSignal.any(signals),
  });
  const text = await response.text();
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    body = undefined;
  }
  return { status: response.status, body };
};

/** device authorization 応答を検証する。`verification_uri_complete` があればそれを優先する。 */
export function parseDeviceAuthorization(
  response: FormResponse,
): DeviceAuthorization {
  const body = response.body;
  if (!isSuccessStatus(response.status) || !isRecord(body)) {
    throw new OAuthGrantError(
      `device authorization endpoint returned HTTP ${response.status}`,
    );
  }
  const expiresIn = positiveSeconds(body.expires_in);
  const interval =
    body.interval === undefined || body.interval === null
      ? DEFAULT_POLL_INTERVAL_SECS
      : positiveSeconds(body.interval);
  const verificationUrl =
    typeof body.verification_uri_complete === "string" &&
    body.verification_uri_complete !== ""
      ? body.verification_uri_complete
      : body.verification_uri;
  if (
    typeof body.device_code !== "string" ||
    body.device_code === "" ||
    typeof body.user_code !== "string" ||
    body.user_code === "" ||
    typeof verificationUrl !== "string" ||
    !isHttpUrl(verificationUrl) ||
    expiresIn === null ||
    interval === null
  ) {
    throw new OAuthGrantError("device authorization response was malformed");
  }
  return {
    deviceCode: body.device_code,
    userCode: body.user_code,
    verificationUrl,
    expiresIn,
    interval,
  };
}

export async function requestDeviceAuthorization(
  endpoints: OAuthEndpoints,
  post: PostForm,
  timeoutMs: number,
  signal?: AbortSignal,
): Promise<DeviceAuthorization> {
  const params: Record<string, string> = { client_id: endpoints.client_id };
  if (endpoints.scope !== null) params.scope = endpoints.scope;
  let response: FormResponse;
  try {
    response = await post(
      endpoints.device_authorization_url,
      params,
      timeoutMs,
      signal,
    );
  } catch (error) {
    if (error instanceof OAuthGrantError) throw error;
    throw new OAuthGrantError(
      `device authorization request failed: ${networkFailureReason(error)}`,
    );
  }
  return parseDeviceAuthorization(response);
}

function parseTokenSet(body: unknown): TokenSet | null {
  if (
    !isRecord(body) ||
    typeof body.access_token !== "string" ||
    body.access_token === ""
  ) {
    return null;
  }
  return {
    accessToken: body.access_token,
    refreshToken:
      typeof body.refresh_token === "string" && body.refresh_token !== ""
        ? body.refresh_token
        : null,
    expiresIn: positiveSeconds(body.expires_in),
  };
}

/** token endpoint の応答をポーリングの状態へ分類する。継続不能な応答は例外とする。 */
export function classifyTokenResponse(response: FormResponse): TokenPollResult {
  const body = response.body;
  if (isRecord(body) && typeof body.error === "string") {
    if (body.error === "authorization_pending") return { kind: "pending" };
    if (body.error === "slow_down") return { kind: "slow_down" };
    throw new OAuthGrantError(
      `token endpoint returned ${safeErrorCode(body.error)}`,
    );
  }
  const tokens = isSuccessStatus(response.status) ? parseTokenSet(body) : null;
  if (tokens === null) {
    throw new OAuthGrantError(
      `token endpoint returned an unusable response (HTTP ${response.status})`,
    );
  }
  return { kind: "token", tokens };
}

/**
 * ポーリングの期限を求める。device code 自体の寿命（応答受信から expires_in）、
 * ポーリング開始から 45 秒、応答全体の期限のうち最も早いものとする。
 */
export function tokenPollDeadline(options: {
  receivedAt: number;
  expiresIn: number;
  pollStartedAt: number;
  budgetDeadline: number;
}): number {
  return Math.min(
    options.receivedAt + options.expiresIn * 1000,
    options.pollStartedAt + MAX_POLL_WINDOW_MS,
    options.budgetDeadline,
  );
}

export function abortableSleep(
  ms: number,
  signal?: AbortSignal,
): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(new OAuthGrantError("the grant was aborted"));
      return;
    }
    const onAbort = (): void => {
      clearTimeout(timer);
      reject(new OAuthGrantError("the grant was aborted"));
    };
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}

export type PollDependencies = {
  post: PostForm;
  now: () => number;
  sleep: (ms: number, signal?: AbortSignal) => Promise<void>;
  signal?: AbortSignal;
};

/**
 * token endpoint を interval ごとにポーリングする。
 * 最後の要求（初回は device authorization 応答の受信）から interval 経過するまで次の要求を送らない。
 */
export async function pollForToken(
  endpoints: OAuthEndpoints,
  device: DeviceAuthorization,
  timing: { receivedAt: number; deadline: number },
  deps: PollDependencies,
): Promise<TokenSet> {
  let intervalMs = device.interval * 1000;
  let lastRequestAt = timing.receivedAt;
  for (;;) {
    const nextAt = lastRequestAt + intervalMs;
    if (nextAt >= timing.deadline) {
      throw new OAuthGrantError("device code polling timed out");
    }
    const waitMs = nextAt - deps.now();
    if (waitMs > 0) await deps.sleep(waitMs, deps.signal);
    lastRequestAt = deps.now();
    const remaining = timing.deadline - lastRequestAt;
    if (remaining <= 0) {
      throw new OAuthGrantError("device code polling timed out");
    }
    let response: FormResponse;
    try {
      response = await deps.post(
        endpoints.token_url,
        {
          grant_type: DEVICE_CODE_GRANT_TYPE,
          device_code: device.deviceCode,
          client_id: endpoints.client_id,
        },
        Math.min(OAUTH_REQUEST_TIMEOUT_MS, remaining),
        deps.signal,
      );
    } catch (error) {
      if (error instanceof OAuthGrantError) throw error;
      throw new OAuthGrantError(
        `token request failed: ${networkFailureReason(error)}`,
      );
    }
    const result = classifyTokenResponse(response);
    if (result.kind === "token") return result.tokens;
    if (result.kind === "slow_down") intervalMs += SLOW_DOWN_INCREMENT_MS;
  }
}

export async function refreshTokens(
  endpoints: OAuthEndpoints,
  current: TokenSet,
  post: PostForm,
  signal?: AbortSignal,
): Promise<TokenSet> {
  if (current.refreshToken === null) {
    throw new OAuthGrantError("no refresh token was issued");
  }
  const response = await post(
    endpoints.token_url,
    {
      grant_type: "refresh_token",
      refresh_token: current.refreshToken,
      client_id: endpoints.client_id,
    },
    OAUTH_REQUEST_TIMEOUT_MS,
    signal,
  );
  const result = classifyTokenResponse(response);
  if (result.kind !== "token") {
    throw new OAuthGrantError("token endpoint did not refresh the token");
  }
  return {
    ...result.tokens,
    // refresh 応答が新しい refresh token を含まない場合、従来の refresh token が引き続き有効である（RFC 6749 6 節）。
    refreshToken: result.tokens.refreshToken ?? current.refreshToken,
  };
}

/** 発行から refresh までの待ち時間。残りが min(60 秒, expires_in / 2) を切る時点とする。 */
export function refreshDelayMs(expiresIn: number): number {
  const lifetimeMs = expiresIn * 1000;
  return Math.max(
    0,
    lifetimeMs - Math.min(REFRESH_MARGIN_CAP_MS, lifetimeMs / 2),
  );
}

/**
 * value template の `{{secret}}` を token へ置換する。
 * String.prototype.replace の置換文字列は `$&` 等を解釈するため、token を文字どおり埋めるよう分割して結合する。
 */
export function renderValueTemplate(template: string, token: string): string {
  return template.split("{{secret}}").join(token);
}

/** RFC 7009 の revocation を best effort で行う。各要求は 5 秒で打ち切り、結果は問わない。 */
export async function revokeTokens(
  endpoints: OAuthEndpoints,
  tokens: TokenSet,
  post: PostForm,
): Promise<void> {
  const url = endpoints.revocation_url;
  if (url === null) return;
  const targets: Array<[string, string]> = [
    [tokens.accessToken, "access_token"],
  ];
  if (tokens.refreshToken !== null) {
    targets.push([tokens.refreshToken, "refresh_token"]);
  }
  await Promise.allSettled(
    targets.map(([token, hint]) =>
      post(
        url,
        { token, token_type_hint: hint, client_id: endpoints.client_id },
        REVOCATION_TIMEOUT_MS,
      ),
    ),
  );
}

export type OAuthProxySessionOptions = {
  endpoints: OAuthEndpoints;
  proxy: Pick<ApiProxy, "setHeaderValue" | "markUnavailable" | "close">;
  valueTemplate: string;
  tokens: TokenSet;
  issuedAt: number;
  onEvent: (action: OAuthTokenAction) => void;
  post?: PostForm;
  now?: () => number;
};

/**
 * 1 つの注入プロキシに紐づく token の寿命（refresh と revocation）を管理する。
 * token は外部へ公開せず、プロキシの注入値としてのみ用いる。
 */
export class OAuthProxySession {
  readonly #options: OAuthProxySessionOptions;
  readonly #post: PostForm;
  readonly #now: () => number;
  #tokens: TokenSet;
  #timer: ReturnType<typeof setTimeout> | undefined;
  #refreshAbort: AbortController | undefined;
  #refreshDone: Promise<void> | undefined;
  #closing: Promise<void> | undefined;

  constructor(options: OAuthProxySessionOptions) {
    this.#options = options;
    this.#post = options.post ?? postForm;
    this.#now = options.now ?? Date.now;
    this.#tokens = options.tokens;
    this.#schedule(options.issuedAt);
  }

  #schedule(issuedAt: number): void {
    const expiresIn = this.#tokens.expiresIn;
    if (expiresIn === null || this.#closing !== undefined) return;
    const delay = Math.max(
      0,
      issuedAt + refreshDelayMs(expiresIn) - this.#now(),
    );
    this.#timer = setTimeout(() => {
      this.#timer = undefined;
      this.#refreshDone = this.#refresh();
    }, delay);
  }

  async #refresh(): Promise<void> {
    const controller = new AbortController();
    this.#refreshAbort = controller;
    try {
      const tokens = await refreshTokens(
        this.#options.endpoints,
        this.#tokens,
        this.#post,
        controller.signal,
      );
      const issuedAt = this.#now();
      // 注入値の差し替えに失敗しても新しい token を失効対象に含めるため、先に保持する。
      this.#tokens = tokens;
      this.#options.proxy.setHeaderValue(
        renderValueTemplate(this.#options.valueTemplate, tokens.accessToken),
      );
      this.#options.onEvent("refreshed");
      this.#schedule(issuedAt);
    } catch {
      if (controller.signal.aborted) return;
      this.#options.proxy.markUnavailable();
      this.#options.onEvent("refresh_failed");
    } finally {
      this.#refreshAbort = undefined;
    }
  }

  /**
   * refresh を止め、revocation endpoint があれば token を失効させてからリスナーを閉じる。
   * 進行中の refresh は中断し、その完了を待ってから最新の token を失効させる。
   */
  close(): Promise<void> {
    this.#closing ??= (async () => {
      if (this.#timer !== undefined) clearTimeout(this.#timer);
      this.#timer = undefined;
      this.#refreshAbort?.abort();
      await this.#refreshDone?.catch(() => undefined);
      if (this.#options.endpoints.revocation_url !== null) {
        await revokeTokens(this.#options.endpoints, this.#tokens, this.#post);
        this.#options.onEvent("revoked");
      }
      await this.#options.proxy.close();
    })();
    return this.#closing;
  }
}
