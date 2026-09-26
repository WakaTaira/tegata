import http from "node:http";
import net, { type AddressInfo } from "node:net";
import { afterEach, describe, expect, test } from "vitest";
import {
  type ApiProxy,
  type ApiProxyRequestRecord,
  filterHeaders,
  hasUnsafePathSegment,
  matchSecretPath,
  startApiProxy,
} from "../src/api-proxy.js";
import { formatApiProxyEvent, parseRequest } from "../src/index.js";

const INJECTED = "Bearer injected-token-value";

type ReceivedRequest = {
  method: string;
  url: string;
  headers: http.IncomingHttpHeaders;
  rawHeaders: string[];
  body: string;
};

type Upstream = {
  url: string;
  received: ReceivedRequest[];
  close: () => Promise<void>;
};

type RawResponse = {
  status: number;
  headers: http.IncomingHttpHeaders;
  body: string;
};

const cleanups: Array<() => Promise<void>> = [];

afterEach(async () => {
  while (cleanups.length > 0) await cleanups.pop()?.();
});

async function startUpstream(
  handler: (
    request: http.IncomingMessage,
    response: http.ServerResponse,
  ) => void = (_request, response) => {
    response.writeHead(200, { "Content-Type": "application/json" });
    response.end(JSON.stringify({ user: "fixture" }));
  },
  basePath = "",
  host = "127.0.0.1",
): Promise<Upstream> {
  const received: ReceivedRequest[] = [];
  const server = http.createServer((request, response) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk: string) => {
      body += chunk;
    });
    request.on("end", () => {
      received.push({
        method: request.method ?? "",
        url: request.url ?? "",
        headers: request.headers,
        rawHeaders: request.rawHeaders,
        body,
      });
      handler(request, response);
    });
  });
  await new Promise<void>((resolve) => server.listen(0, host, resolve));
  const { port } = server.address() as AddressInfo;
  const close = async () => {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  };
  cleanups.push(close);
  const urlHost = host.includes(":") ? `[${host}]` : host;
  return { url: `http://${urlHost}:${port}${basePath}`, received, close };
}

/** IPv6 を無効化した環境では ::1 へ bind できないため、事前に確かめる。 */
function ipv6LoopbackAvailable(): Promise<boolean> {
  return new Promise((resolve) => {
    const probe = net.createServer();
    probe.once("error", () => resolve(false));
    probe.listen(0, "::1", () => probe.close(() => resolve(true)));
  });
}

async function startProxy(
  upstream: string,
  header = "Authorization",
): Promise<{ proxy: ApiProxy; events: ApiProxyRequestRecord[] }> {
  const events: ApiProxyRequestRecord[] = [];
  const proxy = await startApiProxy({
    upstream,
    header,
    headerValue: INJECTED,
    onRequest: (record) => events.push(record),
  });
  cleanups.push(() => proxy.close());
  return { proxy, events };
}

/** fetch はヘッダを正規化するため、生の要求を送れる http.request を用いる。 */
function rawRequest(
  port: number,
  requestPath: string,
  options: {
    method?: string;
    headers?: http.OutgoingHttpHeaders;
    body?: string;
  } = {},
): Promise<RawResponse> {
  return new Promise((resolve, reject) => {
    const request = http.request(
      {
        host: "127.0.0.1",
        port,
        path: requestPath,
        method: options.method ?? "GET",
        headers: options.headers,
        agent: false,
      },
      (response) => {
        let body = "";
        response.setEncoding("utf8");
        response.on("data", (chunk: string) => {
          body += chunk;
        });
        response.on("end", () =>
          resolve({
            status: response.statusCode ?? 0,
            headers: response.headers,
            body,
          }),
        );
      },
    );
    request.on("error", reject);
    request.end(options.body);
  });
}

describe("API proxy secret path", () => {
  test("matches only the exact secret segment and strips it", () => {
    expect(matchSecretPath("/abc/api/whoami?q=1", "abc")).toEqual({
      matched: true,
      path: "/api/whoami",
      query: "?q=1",
    });
    expect(matchSecretPath("/abc", "abc")).toEqual({
      matched: true,
      path: "/",
      query: "",
    });
    expect(matchSecretPath("/abc?x=1", "abc")).toEqual({
      matched: true,
      path: "/",
      query: "?x=1",
    });
    expect(matchSecretPath("/abcd/api", "abc")).toEqual({
      matched: false,
      path: "/api",
    });
    expect(matchSecretPath("/ab/api", "abc")).toEqual({
      matched: false,
      path: "/api",
    });
    expect(matchSecretPath("/abcx", "abc")).toEqual({
      matched: false,
      path: "/",
    });
    expect(matchSecretPath("http://host/abc/api", "abc")).toEqual({
      matched: false,
      path: "/",
    });
  });

  test("rejects missing or wrong secrets with 404 without contacting upstream", async () => {
    const upstream = await startUpstream();
    const { proxy, events } = await startProxy(upstream.url);

    expect(proxy.secret).toMatch(/^[A-Za-z0-9_-]{22}$/);
    const missing = await rawRequest(proxy.port, "/api/whoami");
    const wrong = await rawRequest(proxy.port, "/different-secret/api/whoami");
    const suffixed = await rawRequest(proxy.port, `/${proxy.secret}x/api`);

    expect(missing.status).toBe(404);
    expect(wrong.status).toBe(404);
    expect(suffixed.status).toBe(404);
    expect(upstream.received).toEqual([]);
    // secret を持たない要求は監査の増幅に使えないよう、イベントを出さない。
    expect(events).toEqual([]);
  });

  test("detects dot segments, encoded dots, and backslashes", () => {
    for (const path of [
      "/api/../admin",
      "/api/./whoami",
      "/..",
      "/api/%2e%2e/admin",
      "/api/%2E/whoami",
      "/api/v%2e1",
      "/api\\..\\admin",
      "/api/%5c",
      "/api/%E0%A4%A",
    ]) {
      expect(hasUnsafePathSegment(path), path).toBe(true);
    }
    for (const path of ["/", "/api/whoami", "/api/v1.2/.well", "/a..b/c"]) {
      expect(hasUnsafePathSegment(path), path).toBe(false);
    }
  });

  test("rejects dot segments with 404 without contacting upstream", async () => {
    const upstream = await startUpstream(undefined, "/base");
    const { proxy, events } = await startProxy(upstream.url);

    for (const suffix of [
      "/../admin",
      "/api/./whoami",
      "/%2e%2e/admin",
      "/api/%2E%2E",
      "/api\\..\\admin",
    ]) {
      const response = await rawRequest(
        proxy.port,
        `/${proxy.secret}${suffix}`,
      );
      expect(response.status, suffix).toBe(404);
    }
    expect(upstream.received).toEqual([]);
    expect(events).toEqual([]);
  });
});

describe("API proxy forwarding", () => {
  test("filters every hop-by-hop header and the connection-listed names", () => {
    expect(
      filterHeaders(
        [
          "Connection",
          "close, X-Listed",
          "Keep-Alive",
          "timeout=5",
          "Proxy-Authorization",
          "Basic abc",
          "TE",
          "trailers",
          "Trailer",
          "X-Trail",
          "Transfer-Encoding",
          "chunked",
          "Upgrade",
          "websocket",
          "X-Listed",
          "1",
          "Host",
          "agent.invalid",
          "X-Kept",
          "1",
        ],
        new Set(["host"]),
      ),
    ).toEqual(["X-Kept", "1"]);
  });

  test("replaces the caller header with the injected value", async () => {
    const upstream = await startUpstream();
    const { proxy } = await startProxy(upstream.url);

    const response = await rawRequest(
      proxy.port,
      `/${proxy.secret}/api/whoami`,
      {
        headers: { authorization: "Bearer wrong", "X-Other": "kept" },
      },
    );

    expect(response.status).toBe(200);
    expect(JSON.parse(response.body)).toEqual({ user: "fixture" });
    const [received] = upstream.received;
    const authorizations = received.rawHeaders.filter(
      (_value, index) =>
        index % 2 === 0 &&
        received.rawHeaders[index].toLowerCase() === "authorization",
    );
    expect(authorizations).toHaveLength(1);
    expect(received.headers.authorization).toBe(INJECTED);
    expect(received.headers["x-other"]).toBe("kept");
    expect(JSON.stringify(response)).not.toContain("injected-token-value");
  });

  test("matches the configured header name case-insensitively", async () => {
    const upstream = await startUpstream();
    const { proxy } = await startProxy(upstream.url, "X-Api-Key");

    await rawRequest(proxy.port, `/${proxy.secret}/v1`, {
      headers: { "x-API-key": "caller-value" },
    });

    expect(upstream.received[0].headers["x-api-key"]).toBe(INJECTED);
  });

  test("removes hop-by-hop headers and rewrites host in both directions", async () => {
    const upstream = await startUpstream((_request, response) => {
      response.writeHead(200, {
        "Content-Type": "text/plain",
        "Keep-Alive": "timeout=99",
        "Proxy-Authenticate": "Basic",
        "X-Upstream-Hop": "drop",
        Connection: "X-Upstream-Hop",
        "X-Upstream": "kept",
      });
      response.end("ok");
    });
    const { proxy } = await startProxy(upstream.url);

    const response = await rawRequest(proxy.port, `/${proxy.secret}/hop`, {
      headers: {
        Host: "agent.invalid",
        Connection: "keep-alive, X-Drop-Me",
        "Keep-Alive": "timeout=5",
        "X-Drop-Me": "1",
        "Proxy-Authorization": "Basic abc",
        "Proxy-Connection": "keep-alive",
        TE: "trailers",
        Upgrade: "websocket",
        "X-Kept": "1",
      },
    });

    const received = upstream.received[0];
    const names = received.rawHeaders
      .filter((_value, index) => index % 2 === 0)
      .map((name) => name.toLowerCase());
    for (const name of [
      "keep-alive",
      "x-drop-me",
      "proxy-authorization",
      "proxy-connection",
      "te",
      "trailer",
      "upgrade",
      "transfer-encoding",
    ]) {
      expect(names).not.toContain(name);
    }
    expect(names.filter((name) => name === "host")).toHaveLength(1);
    expect(received.headers.host).toBe(new URL(upstream.url).host);
    expect(received.headers["x-kept"]).toBe("1");

    expect(response.status).toBe(200);
    expect(response.headers["x-upstream"]).toBe("kept");
    expect(response.headers["x-upstream-hop"]).toBeUndefined();
    expect(response.headers["proxy-authenticate"]).toBeUndefined();
    // プロキシ自身の接続に対する Keep-Alive は Node が付与するため、上流の値だけを検査する。
    expect(response.headers["keep-alive"]).not.toBe("timeout=99");
  });

  test("forwards path and query under the upstream base path and records the path without query", async () => {
    const upstream = await startUpstream(undefined, "/base/");
    const { proxy, events } = await startProxy(upstream.url);

    const response = await rawRequest(
      proxy.port,
      `/${proxy.secret}/api/whoami?q=secretish&x=1`,
    );

    expect(response.status).toBe(200);
    expect(upstream.received[0].url).toBe("/base/api/whoami?q=secretish&x=1");
    expect(events).toEqual([
      { http_method: "GET", path: "/api/whoami", status: 200 },
    ]);
    const line = JSON.stringify(formatApiProxyEvent(events[0]));
    expect(line).toBe(
      '{"event":"api_proxy_request","http_method":"GET","path":"/api/whoami","status":200}',
    );
    expect(line).not.toContain("secretish");
  });

  test("streams request bodies and passes redirects through", async () => {
    const upstream = await startUpstream((_request, response) => {
      response.writeHead(302, { Location: "https://elsewhere.invalid/" });
      response.end();
    });
    const { proxy, events } = await startProxy(upstream.url);

    const response = await rawRequest(proxy.port, `/${proxy.secret}/submit`, {
      method: "POST",
      headers: { "Content-Type": "text/plain", "Transfer-Encoding": "chunked" },
      body: "payload",
    });

    expect(response.status).toBe(302);
    expect(response.headers.location).toBe("https://elsewhere.invalid/");
    expect(upstream.received).toHaveLength(1);
    expect(upstream.received[0].method).toBe("POST");
    expect(upstream.received[0].body).toBe("payload");
    expect(events).toEqual([
      { http_method: "POST", path: "/submit", status: 302 },
    ]);
  });

  test("answers 502 when the upstream is unreachable", async () => {
    const upstream = await startUpstream();
    await upstream.close();
    const { proxy, events } = await startProxy(upstream.url);

    const response = await rawRequest(
      proxy.port,
      `/${proxy.secret}/api/whoami`,
    );

    expect(response.status).toBe(502);
    expect(events).toEqual([
      { http_method: "GET", path: "/api/whoami", status: 502 },
    ]);
  });
});

describe("API proxy IPv6 upstream", () => {
  test("forwards to a bracketed IPv6 loopback upstream", async (context) => {
    if (!(await ipv6LoopbackAvailable())) {
      context.skip("IPv6 loopback is unavailable on this host");
      return;
    }
    const upstream = await startUpstream(undefined, "", "::1");
    expect(upstream.url).toMatch(/^http:\/\/\[::1\]:\d+$/);
    const { proxy, events } = await startProxy(upstream.url);

    const response = await rawRequest(
      proxy.port,
      `/${proxy.secret}/api/whoami`,
    );

    expect(response.status).toBe(200);
    expect(JSON.parse(response.body)).toEqual({ user: "fixture" });
    expect(upstream.received[0].headers.host).toBe(new URL(upstream.url).host);
    expect(events).toEqual([
      { http_method: "GET", path: "/api/whoami", status: 200 },
    ]);
  });
});

describe("API proxy lifecycle", () => {
  test("closes the listener and existing connections on close", async () => {
    const upstream = await startUpstream();
    const { proxy } = await startProxy(upstream.url);
    const keepAlive = new http.Agent({ keepAlive: true });
    cleanups.push(async () => keepAlive.destroy());

    const first = await new Promise<number>((resolve, reject) => {
      http
        .get(
          {
            host: "127.0.0.1",
            port: proxy.port,
            path: `/${proxy.secret}/api/whoami`,
            agent: keepAlive,
          },
          (response) => {
            response.resume();
            response.on("end", () => resolve(response.statusCode ?? 0));
          },
        )
        .on("error", reject);
    });
    expect(first).toBe(200);
    const sockets = Object.values(keepAlive.freeSockets).flat();
    expect(sockets.length).toBeGreaterThan(0);
    const socketClosed = Promise.all(
      sockets.map(
        (socket) =>
          new Promise<void>((resolve) =>
            socket?.once("close", () => resolve()),
          ),
      ),
    );

    await proxy.close();
    await socketClosed;

    await expect(
      rawRequest(proxy.port, `/${proxy.secret}/api/whoami`),
    ).rejects.toMatchObject({ code: "ECONNREFUSED" });
  });

  test("rejects invalid header values before listening", async () => {
    await expect(
      startApiProxy({
        upstream: "http://127.0.0.1:1",
        header: "Authorization",
        headerValue: "bad\r\nvalue",
        onRequest: () => undefined,
      }),
    ).rejects.toThrow();
    await expect(
      startApiProxy({
        upstream: "ftp://127.0.0.1/",
        header: "Authorization",
        headerValue: INJECTED,
        onRequest: () => undefined,
      }),
    ).rejects.toThrow();
  });
});

describe("API proxy protocol", () => {
  test("parses start and stop requests", () => {
    expect(
      parseRequest(
        JSON.stringify({
          op: "api_proxy_start",
          id: 3,
          upstream: "https://api.example.test",
          header: "Authorization",
          header_value: INJECTED,
        }),
      ),
    ).toEqual({
      op: "api_proxy_start",
      id: 3,
      upstream: "https://api.example.test",
      header: "Authorization",
      header_value: INJECTED,
    });
    expect(parseRequest('{"op":"api_proxy_stop","id":4}')).toEqual({
      op: "api_proxy_stop",
      id: 4,
    });
    expect(() =>
      parseRequest('{"op":"api_proxy_start","id":5,"upstream":"x"}'),
    ).toThrow();
  });
});
