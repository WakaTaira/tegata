import http from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, test, vi } from "vitest";
import {
  classifyError,
  formatExecutorErrorLine,
  formatOAuthTokenEvent,
  parseRequest,
} from "../src/index.js";
import {
  type DeviceAuthorization,
  type FormResponse,
  OAuthGrantError,
  OAuthProxySession,
  type OAuthTokenAction,
  type PostForm,
  pollForToken,
  postForm,
  refreshDelayMs,
  renderValueTemplate,
  requestDeviceAuthorization,
  tokenPollDeadline,
} from "../src/oauth.js";

const ENDPOINTS = {
  client_id: "tegata-client",
  device_authorization_url: "http://127.0.0.1:1/oauth/device_authorization",
  token_url: "http://127.0.0.1:1/oauth/token",
  revocation_url: "http://127.0.0.1:1/oauth/revoke",
  scope: null,
};

const OAUTH_REQUEST = {
  client_id: "tegata-client",
  device_authorization_url: "https://auth.example.test/device/code",
  token_url: "https://auth.example.test/token",
  revocation_url: "https://auth.example.test/revoke",
  scope: "repo",
  login_url: "https://auth.example.test/login",
  steps: [
    { action: "fill", selector: "#code", value: "{{user_code}}" },
    { action: "click", selector: "#approve" },
  ],
  success_selector: "#approved",
  failure_selector: "#denied",
  secret: { username: "alice", password: "login-password", totp: "123456" },
};

type PostCall = {
  url: string;
  params: Record<string, string>;
  timeoutMs: number;
  at: number;
};

/** 応答列を順に返す POST のスタブ。呼び出しの時刻と引数を記録する。 */
function stubPost(
  responses: Array<FormResponse | Error>,
  now: () => number = Date.now,
): { post: PostForm; calls: PostCall[] } {
  const calls: PostCall[] = [];
  const post: PostForm = async (url, params, timeoutMs) => {
    calls.push({ url, params, timeoutMs, at: now() });
    const next = responses.shift();
    if (next === undefined) throw new Error("unexpected request");
    if (next instanceof Error) throw next;
    return next;
  };
  return { post, calls };
}

/** 仮想時計。sleep は時計を進めるだけで実時間を消費しない。 */
function virtualClock(start = 1_000_000) {
  let current = start;
  return {
    now: () => current,
    sleep: async (ms: number) => {
      current += ms;
    },
  };
}

const DEVICE: DeviceAuthorization = {
  deviceCode: "device-code-value",
  userCode: "USER-CODE",
  verificationUrl: "http://127.0.0.1:1/device",
  expiresIn: 600,
  interval: 1,
};

const cleanups: Array<() => Promise<void>> = [];

afterEach(async () => {
  vi.useRealTimers();
  while (cleanups.length > 0) await cleanups.pop()?.();
});

describe("api_proxy_start parsing", () => {
  test("parses an oauth request with typed fields", () => {
    const request = parseRequest(
      JSON.stringify({
        op: "api_proxy_start",
        id: 1,
        upstream: "https://api.example.test",
        header: "Authorization",
        header_value: null,
        value_template: "Bearer {{secret}}",
        oauth: OAUTH_REQUEST,
      }),
    );

    expect(request).toEqual({
      op: "api_proxy_start",
      id: 1,
      upstream: "https://api.example.test",
      header: "Authorization",
      value_template: "Bearer {{secret}}",
      oauth: OAUTH_REQUEST,
    });
  });

  test("defaults the optional oauth fields to null", () => {
    const request = parseRequest(
      JSON.stringify({
        op: "api_proxy_start",
        id: 2,
        upstream: "https://api.example.test",
        header: "Authorization",
        value_template: "Bearer {{secret}}",
        oauth: {
          client_id: "tegata-client",
          device_authorization_url: "https://auth.example.test/device/code",
          token_url: "https://auth.example.test/token",
          login_url: "https://auth.example.test/login",
          success_selector: "#approved",
          secret: { username: "alice", password: "login-password" },
        },
      }),
    );

    expect(request).toMatchObject({
      oauth: {
        revocation_url: null,
        scope: null,
        steps: null,
        failure_selector: null,
        secret: { username: "alice", password: "login-password", totp: null },
      },
    });
  });

  test("still parses a static token request", () => {
    expect(
      parseRequest(
        JSON.stringify({
          op: "api_proxy_start",
          id: 3,
          upstream: "https://api.example.test",
          header: "Authorization",
          header_value: "Bearer static",
          oauth: null,
        }),
      ),
    ).toEqual({
      op: "api_proxy_start",
      id: 3,
      upstream: "https://api.example.test",
      header: "Authorization",
      header_value: "Bearer static",
    });
  });

  test.each([
    [
      "both a static value and oauth",
      {
        header_value: "Bearer static",
        value_template: "Bearer {{secret}}",
        oauth: OAUTH_REQUEST,
      },
    ],
    ["neither a static value nor oauth", {}],
    [
      "a static value with a template",
      {
        header_value: "Bearer static",
        value_template: "Bearer {{secret}}",
      },
    ],
    ["oauth without a template", { oauth: OAUTH_REQUEST }],
    [
      "oauth without a login secret",
      {
        value_template: "Bearer {{secret}}",
        oauth: { ...OAUTH_REQUEST, secret: undefined },
      },
    ],
    [
      "oauth with a non-string revocation url",
      {
        value_template: "Bearer {{secret}}",
        oauth: { ...OAUTH_REQUEST, revocation_url: 1 },
      },
    ],
    [
      "oauth with an unknown step placeholder",
      {
        value_template: "Bearer {{secret}}",
        oauth: {
          ...OAUTH_REQUEST,
          steps: [{ action: "fill", selector: "#x", value: "{{secret}}" }],
        },
      },
    ],
    [
      "oauth without a success selector",
      {
        value_template: "Bearer {{secret}}",
        oauth: { ...OAUTH_REQUEST, success_selector: null },
      },
    ],
  ])("rejects %s", (_name, fields) => {
    expect(() =>
      parseRequest(
        JSON.stringify({
          op: "api_proxy_start",
          id: 4,
          upstream: "https://api.example.test",
          header: "Authorization",
          ...fields,
        }),
      ),
    ).toThrow();
  });
});

describe("device authorization", () => {
  test("prefers verification_uri_complete and sends the scope", async () => {
    const { post, calls } = stubPost([
      {
        status: 200,
        body: {
          device_code: "dc",
          user_code: "UC",
          verification_uri: "https://auth.example.test/device",
          verification_uri_complete:
            "https://auth.example.test/device?user_code=UC",
          expires_in: 900,
          interval: 2,
        },
      },
    ]);

    const device = await requestDeviceAuthorization(
      { ...ENDPOINTS, scope: "repo" },
      post,
      10_000,
    );

    expect(device).toEqual({
      deviceCode: "dc",
      userCode: "UC",
      verificationUrl: "https://auth.example.test/device?user_code=UC",
      expiresIn: 900,
      interval: 2,
    });
    expect(calls[0].params).toEqual({
      client_id: "tegata-client",
      scope: "repo",
    });
  });

  test("falls back to verification_uri and the default interval", async () => {
    const { post, calls } = stubPost([
      {
        status: 200,
        body: {
          device_code: "dc",
          user_code: "UC",
          verification_uri: "https://auth.example.test/device",
          expires_in: 900,
        },
      },
    ]);

    const device = await requestDeviceAuthorization(ENDPOINTS, post, 10_000);

    expect(device.verificationUrl).toBe("https://auth.example.test/device");
    expect(device.interval).toBe(5);
    expect(calls[0].params).toEqual({ client_id: "tegata-client" });
  });

  test.each<[string, FormResponse | Error]>([
    ["an error status", { status: 400, body: { error: "invalid_client" } }],
    ["a non-JSON body", { status: 200, body: undefined }],
    [
      "a missing device code",
      {
        status: 200,
        body: {
          user_code: "UC",
          verification_uri: "https://auth.example.test/device",
          expires_in: 900,
        },
      },
    ],
    [
      "a non-http verification uri",
      {
        status: 200,
        body: {
          device_code: "dc",
          user_code: "UC",
          verification_uri: "file:///etc/passwd",
          expires_in: 900,
        },
      },
    ],
    ["a network error", new TypeError("fetch failed")],
  ])("fails the grant on %s", async (_name, response) => {
    const { post } = stubPost([response]);
    await expect(
      requestDeviceAuthorization(ENDPOINTS, post, 10_000),
    ).rejects.toBeInstanceOf(OAuthGrantError);
  });
});

describe("token polling", () => {
  test("waits through pending and slow_down before returning the token", async () => {
    const clock = virtualClock();
    const receivedAt = clock.now();
    const { post, calls } = stubPost(
      [
        { status: 400, body: { error: "authorization_pending" } },
        { status: 400, body: { error: "slow_down" } },
        { status: 400, body: { error: "authorization_pending" } },
        {
          status: 200,
          body: {
            access_token: "access-1",
            refresh_token: "refresh-1",
            expires_in: 3600,
            token_type: "bearer",
          },
        },
      ],
      clock.now,
    );

    const tokens = await pollForToken(
      ENDPOINTS,
      DEVICE,
      { receivedAt, deadline: receivedAt + 45_000 },
      { post, now: clock.now, sleep: clock.sleep },
    );

    expect(tokens).toEqual({
      accessToken: "access-1",
      refreshToken: "refresh-1",
      expiresIn: 3600,
    });
    expect(calls.map((call) => call.at - receivedAt)).toEqual([
      1_000, 2_000, 8_000, 14_000,
    ]);
    expect(calls[0].params).toEqual({
      grant_type: "urn:ietf:params:oauth:grant-type:device_code",
      device_code: "device-code-value",
      client_id: "tegata-client",
    });
  });

  test("polls immediately when the interval already passed during approval", async () => {
    const clock = virtualClock();
    const receivedAt = clock.now() - 10_000;
    const { post, calls } = stubPost(
      [{ status: 200, body: { access_token: "access-1" } }],
      clock.now,
    );

    const tokens = await pollForToken(
      ENDPOINTS,
      DEVICE,
      { receivedAt, deadline: clock.now() + 45_000 },
      { post, now: clock.now, sleep: clock.sleep },
    );

    expect(tokens).toEqual({
      accessToken: "access-1",
      refreshToken: null,
      expiresIn: null,
    });
    expect(calls[0].at).toBe(clock.now());
  });

  test.each([["access_denied"], ["expired_token"], ["invalid_grant"]])(
    "fails the grant on %s",
    async (error) => {
      const clock = virtualClock();
      const { post } = stubPost([{ status: 400, body: { error } }], clock.now);

      await expect(
        pollForToken(
          ENDPOINTS,
          DEVICE,
          { receivedAt: clock.now(), deadline: clock.now() + 45_000 },
          { post, now: clock.now, sleep: clock.sleep },
        ),
      ).rejects.toThrow(
        new OAuthGrantError(`token endpoint returned ${error}`),
      );
    },
  );

  test("fails the grant on a non-JSON response", async () => {
    const clock = virtualClock();
    const { post } = stubPost([{ status: 502, body: undefined }], clock.now);

    await expect(
      pollForToken(
        ENDPOINTS,
        DEVICE,
        { receivedAt: clock.now(), deadline: clock.now() + 45_000 },
        { post, now: clock.now, sleep: clock.sleep },
      ),
    ).rejects.toBeInstanceOf(OAuthGrantError);
  });

  test("fails the grant once the deadline passes while pending", async () => {
    const clock = virtualClock();
    const receivedAt = clock.now();
    const pending = { status: 400, body: { error: "authorization_pending" } };
    const { post, calls } = stubPost(
      Array.from({ length: 100 }, () => pending),
      clock.now,
    );

    await expect(
      pollForToken(
        ENDPOINTS,
        { ...DEVICE, interval: 5 },
        { receivedAt, deadline: receivedAt + 45_000 },
        { post, now: clock.now, sleep: clock.sleep },
      ),
    ).rejects.toThrow("device code polling timed out");
    expect(calls).toHaveLength(8);
    expect(clock.now() - receivedAt).toBeLessThan(45_000);
  });

  test("bounds the polling window by expires_in, 45 seconds and the budget", () => {
    expect(
      tokenPollDeadline({
        receivedAt: 0,
        expiresIn: 900,
        pollStartedAt: 10_000,
        budgetDeadline: 70_000,
      }),
    ).toBe(55_000);
    expect(
      tokenPollDeadline({
        receivedAt: 0,
        expiresIn: 20,
        pollStartedAt: 10_000,
        budgetDeadline: 70_000,
      }),
    ).toBe(20_000);
    expect(
      tokenPollDeadline({
        receivedAt: 0,
        expiresIn: 900,
        pollStartedAt: 40_000,
        budgetDeadline: 70_000,
      }),
    ).toBe(70_000);
  });
});

describe("form requests", () => {
  test("posts a form, asks for JSON and does not follow redirects", async () => {
    const received: Array<{
      url: string;
      contentType?: string;
      accept?: string;
      body: string;
    }> = [];
    const server = http.createServer((request, response) => {
      let body = "";
      request.setEncoding("utf8");
      request.on("data", (chunk: string) => {
        body += chunk;
      });
      request.on("end", () => {
        received.push({
          url: request.url ?? "",
          contentType: request.headers["content-type"],
          accept: request.headers.accept,
          body,
        });
        if (request.url === "/redirect") {
          response.writeHead(302, { Location: "/elsewhere" });
          response.end();
          return;
        }
        response.writeHead(200, { "Content-Type": "application/json" });
        response.end(JSON.stringify({ ok: true }));
      });
    });
    await new Promise<void>((resolve) =>
      server.listen(0, "127.0.0.1", resolve),
    );
    cleanups.push(
      () => new Promise<void>((resolve) => server.close(() => resolve())),
    );
    const { port } = server.address() as AddressInfo;

    const ok = await postForm(
      `http://127.0.0.1:${port}/token`,
      { client_id: "tegata client", scope: "a b" },
      5_000,
    );
    const redirected = await postForm(
      `http://127.0.0.1:${port}/redirect`,
      { client_id: "tegata-client" },
      5_000,
    );

    expect(ok).toEqual({ status: 200, body: { ok: true } });
    expect(redirected.status).toBe(302);
    expect(received.map((request) => request.url)).toEqual([
      "/token",
      "/redirect",
    ]);
    expect(received[0]).toMatchObject({
      contentType: "application/x-www-form-urlencoded",
      accept: "application/json",
    });
    expect(Object.fromEntries(new URLSearchParams(received[0].body))).toEqual({
      client_id: "tegata client",
      scope: "a b",
    });
  });

  test("refuses endpoints that are not http or https", async () => {
    await expect(
      postForm("data:application/json,{}", {}, 5_000),
    ).rejects.toBeInstanceOf(OAuthGrantError);
  });
});

describe("token lifetime", () => {
  test("refreshes when min(60 s, expires_in / 2) remains", () => {
    expect(refreshDelayMs(4)).toBe(2_000);
    expect(refreshDelayMs(100)).toBe(50_000);
    expect(refreshDelayMs(120)).toBe(60_000);
    expect(refreshDelayMs(3600)).toBe(3_540_000);
  });

  test("substitutes the token literally into the value template", () => {
    expect(renderValueTemplate("Bearer {{secret}}", "a$&b$1")).toBe(
      "Bearer a$&b$1",
    );
    expect(renderValueTemplate("token {{secret}} {{secret}}", "t")).toBe(
      "token t t",
    );
  });

  test("formats the token event without token values", () => {
    expect(formatOAuthTokenEvent("refreshed")).toEqual({
      event: "oauth_token",
      action: "refreshed",
    });
  });
});

type FakeProxy = {
  values: string[];
  unavailable: boolean;
  closed: boolean;
  setHeaderValue: (value: string) => void;
  markUnavailable: () => void;
  close: () => Promise<void>;
};

function fakeProxy(): FakeProxy {
  const proxy: FakeProxy = {
    values: [],
    unavailable: false,
    closed: false,
    setHeaderValue: (value) => {
      proxy.values.push(value);
    },
    markUnavailable: () => {
      proxy.unavailable = true;
    },
    close: async () => {
      proxy.closed = true;
    },
  };
  return proxy;
}

describe("OAuth proxy session", () => {
  test("refreshes before expiry and replaces the injected value", async () => {
    vi.useFakeTimers();
    const proxy = fakeProxy();
    const events: OAuthTokenAction[] = [];
    const { post, calls } = stubPost([
      {
        status: 200,
        body: { access_token: "access-2", expires_in: 4 },
      },
      {
        status: 200,
        body: { access_token: "access-3", refresh_token: "refresh-3" },
      },
      { status: 200, body: undefined },
      { status: 200, body: undefined },
    ]);
    const session = new OAuthProxySession({
      endpoints: ENDPOINTS,
      proxy,
      valueTemplate: "Bearer {{secret}}",
      tokens: {
        accessToken: "access-1",
        refreshToken: "refresh-1",
        expiresIn: 4,
      },
      issuedAt: Date.now(),
      onEvent: (action) => events.push(action),
      post,
    });

    await vi.advanceTimersByTimeAsync(1_999);
    expect(calls).toHaveLength(0);
    await vi.advanceTimersByTimeAsync(1);
    expect(calls[0].params).toEqual({
      grant_type: "refresh_token",
      refresh_token: "refresh-1",
      client_id: "tegata-client",
    });
    expect(proxy.values).toEqual(["Bearer access-2"]);
    await vi.advanceTimersByTimeAsync(2_000);
    expect(calls[1].params.refresh_token).toBe("refresh-1");
    expect(proxy.values).toEqual(["Bearer access-2", "Bearer access-3"]);
    expect(events).toEqual(["refreshed", "refreshed"]);
    expect(proxy.unavailable).toBe(false);

    await vi.advanceTimersByTimeAsync(3_600_000);
    expect(calls).toHaveLength(2);
    await session.close();
    expect(calls.slice(2).map((call) => call.params.token)).toEqual([
      "access-3",
      "refresh-3",
    ]);
    expect(events).toEqual(["refreshed", "refreshed", "revoked"]);
  });

  test("reports refresh_failed once and answers 503 without a refresh token", async () => {
    vi.useFakeTimers();
    const proxy = fakeProxy();
    const events: OAuthTokenAction[] = [];
    const { post, calls } = stubPost([]);
    const session = new OAuthProxySession({
      endpoints: { ...ENDPOINTS, revocation_url: null },
      proxy,
      valueTemplate: "Bearer {{secret}}",
      tokens: { accessToken: "access-1", refreshToken: null, expiresIn: 4 },
      issuedAt: Date.now(),
      onEvent: (action) => events.push(action),
      post,
    });

    await vi.advanceTimersByTimeAsync(10_000);
    await session.close();

    expect(calls).toHaveLength(0);
    expect(proxy.unavailable).toBe(true);
    expect(events).toEqual(["refresh_failed"]);
    expect(proxy.closed).toBe(true);
  });

  test("reports refresh_failed when the token endpoint rejects the refresh", async () => {
    vi.useFakeTimers();
    const proxy = fakeProxy();
    const events: OAuthTokenAction[] = [];
    const { post } = stubPost([
      { status: 400, body: { error: "invalid_grant" } },
    ]);
    new OAuthProxySession({
      endpoints: { ...ENDPOINTS, revocation_url: null },
      proxy,
      valueTemplate: "Bearer {{secret}}",
      tokens: {
        accessToken: "access-1",
        refreshToken: "refresh-1",
        expiresIn: 4,
      },
      issuedAt: Date.now(),
      onEvent: (action) => events.push(action),
      post,
    });

    await vi.advanceTimersByTimeAsync(10_000);

    expect(proxy.unavailable).toBe(true);
    expect(proxy.values).toEqual([]);
    expect(events).toEqual(["refresh_failed"]);
  });

  test("revokes both tokens before closing the listener", async () => {
    const proxy = fakeProxy();
    const events: string[] = [];
    const calls: PostCall[] = [];
    const post: PostForm = async (url, params, timeoutMs) => {
      calls.push({ url, params, timeoutMs, at: Date.now() });
      expect(proxy.closed).toBe(false);
      return { status: 200, body: undefined };
    };
    const session = new OAuthProxySession({
      endpoints: ENDPOINTS,
      proxy,
      valueTemplate: "Bearer {{secret}}",
      tokens: {
        accessToken: "access-1",
        refreshToken: "refresh-1",
        expiresIn: null,
      },
      issuedAt: Date.now(),
      onEvent: (action) => events.push(action),
      post,
    });

    await Promise.all([session.close(), session.close()]);

    expect(
      calls.map((call) => [call.url, call.params, call.timeoutMs]),
    ).toEqual([
      [
        ENDPOINTS.revocation_url,
        {
          token: "access-1",
          token_type_hint: "access_token",
          client_id: "tegata-client",
        },
        5_000,
      ],
      [
        ENDPOINTS.revocation_url,
        {
          token: "refresh-1",
          token_type_hint: "refresh_token",
          client_id: "tegata-client",
        },
        5_000,
      ],
    ]);
    expect(events).toEqual(["revoked"]);
    expect(proxy.closed).toBe(true);
  });

  test("closes without a revoked event when no revocation endpoint is set", async () => {
    vi.useFakeTimers();
    const proxy = fakeProxy();
    const events: string[] = [];
    const { post, calls } = stubPost([]);
    const session = new OAuthProxySession({
      endpoints: { ...ENDPOINTS, revocation_url: null },
      proxy,
      valueTemplate: "Bearer {{secret}}",
      tokens: {
        accessToken: "access-1",
        refreshToken: "refresh-1",
        expiresIn: 4,
      },
      issuedAt: Date.now(),
      onEvent: (action) => events.push(action),
      post,
    });

    await session.close();
    await vi.advanceTimersByTimeAsync(10_000);

    expect(calls).toEqual([]);
    expect(events).toEqual([]);
    expect(proxy.closed).toBe(true);
    expect(vi.getTimerCount()).toBe(0);
  });
});

describe("oauth diagnostics", () => {
  test("classifies grant failures in the oauth stage", () => {
    expect(classifyError(new OAuthGrantError("denied"), "oauth")).toBe(
      "OAUTH_GRANT_FAILED",
    );
    expect(classifyError(new Error("other"), "oauth")).toBe("INTERNAL");
  });

  test("redacts login secrets, codes and tokens from the error line", () => {
    const request = parseRequest(
      JSON.stringify({
        op: "api_proxy_start",
        id: 9,
        upstream: "https://api.example.test",
        header: "Authorization",
        value_template: "Bearer {{secret}}",
        oauth: OAUTH_REQUEST,
      }),
    );
    if (request.op !== "api_proxy_start") throw new Error("unexpected op");
    const runtimeSecrets = [
      "device-code-value",
      "USER-CODE",
      "access-token-value",
      "refresh-token-value",
    ];

    const line = formatExecutorErrorLine(
      request,
      "oauth",
      "OAUTH_GRANT_FAILED",
      new OAuthGrantError(
        "alice login-password 123456 device-code-value USER-CODE access-token-value refresh-token-value",
      ),
      runtimeSecrets,
    );

    const payload = JSON.parse(
      line.slice("tegata-executor: error ".length).trimEnd(),
    );
    expect(payload).toEqual({
      op: "api_proxy_start",
      stage: "oauth",
      code: "OAUTH_GRANT_FAILED",
      name: "OAuthGrantError",
      message: Array(7).fill("[REDACTED]").join(" "),
    });
    for (const secret of [
      "alice",
      "login-password",
      "123456",
      ...runtimeSecrets,
    ]) {
      expect(line).not.toContain(secret);
    }
  });
});
