import { timingSafeEqual } from "node:crypto";
import http from "node:http";
import https from "node:https";
import { createLoopbackSecret, listenLoopback } from "./loopback.js";

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
  /**
   * Replaces the value injected into subsequent requests. An invalid header value throws and keeps
   * the current value.
   */
  setHeaderValue: (value: string) => void;
  /** Makes subsequent requests answer 503 without being sent upstream. */
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
  // The secret length is public, so a length mismatch may be rejected immediately.
  if (candidateBytes.length !== secretBytes.length) return false;
  return timingSafeEqual(candidateBytes, secretBytes);
}

/**
 * Matches the first segment of the request target against the secret.
 * Even on a mismatch, the first segment (the secret position) is excluded from the logged path.
 * This keeps a request with characters accidentally appended to the secret from carrying the secret
 * into the audit log.
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
 * Determines whether the path left after stripping the secret could resolve outside the base path
 * upstream.
 * Rejects segments that become `.` / `..` after percent-decoding, `%2e` notation, and backslashes
 * (including `%5c`).
 * Segments that cannot be decoded are rejected as well, because their interpretation is left to the
 * upstream.
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

/** Removes hop-by-hop and excluded headers from an array in rawHeaders format. */
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
    // WHATWG URL returns an IPv6 literal hostname in brackets, but http.request expects the
    // address without brackets, so they are stripped here.
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
  // If the agent disconnects before the response completes, the upstream request is aborted too.
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
  // Requests without the secret are not logged, so that an arbitrary loopback user cannot
  // add audit lines under the lease owner's name. Requests not sent upstream are likewise excluded
  // from logging.
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

/**
 * Starts a loopback HTTP proxy that injects fixed headers upstream.
 * The injected value, the secret, and the query are never emitted anywhere, including exception
 * messages.
 */
export async function startApiProxy(
  options: ApiProxyOptions,
): Promise<ApiProxy> {
  http.validateHeaderName(options.header);
  http.validateHeaderValue(options.header, options.headerValue);
  const upstream = parseUpstream(options.upstream);
  const secret = createLoopbackSecret();
  const state: InjectionState = {
    headerValue: options.headerValue,
    unavailable: false,
  };
  const server = http.createServer((request, response) => {
    handleRequest(request, response, upstream, secret, options, state);
  });

  let port: number;
  try {
    port = await listenLoopback(server);
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
