import { randomBytes, timingSafeEqual } from "node:crypto";
import http from "node:http";
import https from "node:https";
import type { AddressInfo } from "node:net";

export type ApiProxyRequestRecord = {
  http_method: string;
  path: string;
  status: number;
};

export type ApiProxyOptions = {
  upstream: string;
  header: string;
  headerValue: string;
  onRequest: (record: ApiProxyRequestRecord) => void;
};

export type ApiProxy = {
  port: number;
  secret: string;
  /** 以後の要求に注入する値を差し替える。不正なヘッダ値は例外とし、現在の値を保つ。 */
  setHeaderValue: (value: string) => void;
  /** 以後の要求を上流へ送らず 503 で応答させる。 */
  markUnavailable: () => void;
  close: () => Promise<void>;
};

export type SecretPathMatch =
  | { matched: true; path: string; query: string }
  | { matched: false; path: string };

type InjectionState = {
  headerValue: string;
  unavailable: boolean;
};

type Upstream = {
  url: URL;
  hostname: string;
  basePath: string;
  transport: typeof http | typeof https;
  agent: http.Agent;
};

const HOP_BY_HOP_HEADERS = new Set([
  "connection",
  "keep-alive",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);

function splitQuery(target: string): { pathname: string; query: string } {
  const index = target.indexOf("?");
  return index < 0
    ? { pathname: target, query: "" }
    : { pathname: target.slice(0, index), query: target.slice(index) };
}

function secretEquals(candidate: string, secret: string): boolean {
  const candidateBytes = Buffer.from(candidate, "utf8");
  const secretBytes = Buffer.from(secret, "utf8");
  // secret の長さは公開情報であるため、長さの不一致は即座に拒否してよい。
  if (candidateBytes.length !== secretBytes.length) return false;
  return timingSafeEqual(candidateBytes, secretBytes);
}

/**
 * 要求 target の先頭 segment を secret と照合する。
 * 不一致の場合も先頭 segment（secret の位置）は記録用 path に含めない。
 * 誤って secret に文字が連結された要求が監査へ secret を運ぶことを防ぐためである。
 */
export function matchSecretPath(
  target: string,
  secret: string,
): SecretPathMatch {
  const { pathname, query } = splitQuery(target);
  if (!pathname.startsWith("/")) return { matched: false, path: "/" };
  const end = pathname.indexOf("/", 1);
  const segment = end < 0 ? pathname.slice(1) : pathname.slice(1, end);
  const rest = end < 0 ? "/" : pathname.slice(end);
  if (!secretEquals(segment, secret)) return { matched: false, path: rest };
  return { matched: true, path: rest, query };
}

/**
 * secret を剥がした後の path が、上流で base path の外へ解決されうる形を含むかを判定する。
 * パーセントデコード後に `.` / `..` となる segment、`%2e` 表記、バックスラッシュ（`%5c` を含む）を拒否する。
 * デコードできない segment は解釈が上流次第となるため、同じく拒否する。
 */
export function hasUnsafePathSegment(path: string): boolean {
  if (path.includes("\\") || /%2e/i.test(path)) return true;
  return path.split("/").some((segment) => {
    let decoded: string;
    try {
      decoded = decodeURIComponent(segment);
    } catch {
      return true;
    }
    return decoded === "." || decoded === ".." || decoded.includes("\\");
  });
}

function isHopByHop(name: string, connectionTokens: Set<string>): boolean {
  return (
    HOP_BY_HOP_HEADERS.has(name) ||
    name.startsWith("proxy-") ||
    connectionTokens.has(name)
  );
}

function connectionTokensOf(rawHeaders: string[]): Set<string> {
  const tokens = new Set<string>();
  for (let index = 0; index < rawHeaders.length; index += 2) {
    if (rawHeaders[index].toLowerCase() !== "connection") continue;
    for (const token of rawHeaders[index + 1].split(",")) {
      const trimmed = token.trim().toLowerCase();
      if (trimmed !== "") tokens.add(trimmed);
    }
  }
  return tokens;
}

/** rawHeaders 形式の配列から hop-by-hop と除外指定のヘッダを取り除く。 */
export function filterHeaders(
  rawHeaders: string[],
  excluded: Set<string> = new Set(),
): string[] {
  const connectionTokens = connectionTokensOf(rawHeaders);
  const filtered: string[] = [];
  for (let index = 0; index < rawHeaders.length; index += 2) {
    const name = rawHeaders[index];
    const lower = name.toLowerCase();
    if (isHopByHop(lower, connectionTokens) || excluded.has(lower)) continue;
    filtered.push(name, rawHeaders[index + 1]);
  }
  return filtered;
}

function parseUpstream(upstream: string): Upstream {
  const url = new URL(upstream);
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error("unsupported upstream protocol");
  }
  const transport = url.protocol === "https:" ? https : http;
  return {
    url,
    // WHATWG URL は IPv6 リテラルの hostname を角括弧付きで返すが、http.request は括弧なしの
    // アドレスを要求するため、ここで剥がしておく。
    hostname: url.hostname.replace(/^\[(.*)\]$/, "$1"),
    basePath: url.pathname.replace(/\/+$/, ""),
    transport,
    agent: new transport.Agent({ keepAlive: true }),
  };
}

function respondNotFound(response: http.ServerResponse): void {
  response.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
  response.end("not found");
}

function respondUnavailable(response: http.ServerResponse): void {
  response.writeHead(503, { "Content-Type": "text/plain; charset=utf-8" });
  response.end("service unavailable");
}

function respondBadGateway(response: http.ServerResponse): void {
  if (response.headersSent) {
    response.destroy();
    return;
  }
  response.writeHead(502, { "Content-Type": "text/plain; charset=utf-8" });
  response.end("bad gateway");
}

function forward(
  request: http.IncomingMessage,
  response: http.ServerResponse,
  upstream: Upstream,
  options: ApiProxyOptions,
  headerValue: string,
  target: { path: string; query: string },
  record: (status: number) => void,
): void {
  const injected = options.header.toLowerCase();
  const headers = filterHeaders(
    request.rawHeaders,
    new Set(["host", injected]),
  );
  headers.push("Host", upstream.url.host, options.header, headerValue);

  const path = `${upstream.basePath}${target.path}`;
  const upstreamRequest = upstream.transport.request({
    protocol: upstream.url.protocol,
    hostname: upstream.hostname,
    port: upstream.url.port === "" ? undefined : upstream.url.port,
    method: request.method,
    path: `${path === "" ? "/" : path}${target.query}`,
    headers,
    agent: upstream.agent,
  });

  upstreamRequest.on("response", (upstreamResponse) => {
    const status = upstreamResponse.statusCode ?? 502;
    record(status);
    response.writeHead(
      status,
      upstreamResponse.statusMessage,
      filterHeaders(upstreamResponse.rawHeaders),
    );
    upstreamResponse.pipe(response);
    upstreamResponse.on("error", () => response.destroy());
  });
  upstreamRequest.on("error", () => {
    record(502);
    respondBadGateway(response);
  });
  // agent 側が応答完了前に切断した場合は、上流への要求も打ち切る。
  response.on("close", () => {
    if (!response.writableFinished) upstreamRequest.destroy();
  });
  response.on("error", () => upstreamRequest.destroy());
  request.pipe(upstreamRequest);
}

function handleRequest(
  request: http.IncomingMessage,
  response: http.ServerResponse,
  upstream: Upstream,
  secret: string,
  options: ApiProxyOptions,
  state: InjectionState,
): void {
  const match = matchSecretPath(request.url ?? "", secret);
  // secret を持たない要求は記録しない。loopback の任意の利用者が、リース所有者の名義で
  // 監査行を増やせないようにするためである。上流へ送らない要求も同じく記録の対象外とする。
  if (!match.matched || hasUnsafePathSegment(match.path)) {
    request.resume();
    respondNotFound(response);
    return;
  }
  if (state.unavailable) {
    request.resume();
    respondUnavailable(response);
    return;
  }
  const method = request.method ?? "";
  let recorded = false;
  const record = (status: number): void => {
    if (recorded) return;
    recorded = true;
    options.onRequest({ http_method: method, path: match.path, status });
  };
  forward(
    request,
    response,
    upstream,
    options,
    state.headerValue,
    match,
    record,
  );
}

function listen(server: http.Server): Promise<number> {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.removeListener("error", reject);
      resolve((server.address() as AddressInfo).port);
    });
  });
}

/**
 * 上流へ固定ヘッダを注入する loopback の HTTP プロキシを起動する。
 * 注入値・secret・query は例外メッセージを含めどこにも出力しない。
 */
export async function startApiProxy(
  options: ApiProxyOptions,
): Promise<ApiProxy> {
  http.validateHeaderName(options.header);
  http.validateHeaderValue(options.header, options.headerValue);
  const upstream = parseUpstream(options.upstream);
  const secret = randomBytes(16).toString("base64url");
  const state: InjectionState = {
    headerValue: options.headerValue,
    unavailable: false,
  };
  const server = http.createServer((request, response) => {
    handleRequest(request, response, upstream, secret, options, state);
  });

  let port: number;
  try {
    port = await listen(server);
  } catch (error) {
    upstream.agent.destroy();
    throw error;
  }

  let closing: Promise<void> | undefined;
  const close = (): Promise<void> => {
    closing ??= new Promise<void>((resolve) => {
      server.close(() => resolve());
      server.closeAllConnections();
      upstream.agent.destroy();
    });
    return closing;
  };
  const setHeaderValue = (value: string): void => {
    http.validateHeaderValue(options.header, value);
    state.headerValue = value;
  };
  const markUnavailable = (): void => {
    state.unavailable = true;
  };
  return { port, secret, setHeaderValue, markUnavailable, close };
}
