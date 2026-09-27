# API injection proxy

`open_api_proxy` gives an unattended agent authenticated access to a REST API
without ever handing it the token. The daemon resolves the credential and hands
it to the executor, which runs a loopback HTTP relay that injects the value on
the way out. The agent receives a URL, not a secret.

This is the shape for a Terraform run, a CI job, or an autonomous agent that
must call an API such as Tailscale's or GitHub's but has no business holding the
long-lived token that authenticates it.

## Configuring a proxy

Each proxy is named, fixed to one upstream, and injects one credential:

```toml
[[api_proxy]]
name       = "tailscale"
cred_id    = "vw:a1b2c3d4"
upstream   = "https://api.tailscale.com"
header     = "Authorization"       # default
value      = "Bearer {{secret}}"   # default
```

`upstream` must be `https://`, or `http://` to a loopback host
(`127.0.0.1`, `::1`, `localhost`) for local test targets. `value` must contain
`{{secret}}`, which is replaced with the credential's password. An empty or
duplicate `name`, a `cred_id` that is not `<namespace>:<entry id>`, a
non-loopback `http://` upstream, or a `value` without `{{secret}}` refuses
startup.

On NixOS, the equivalent is `services.tegata.apiProxies`, an attribute set keyed
by the same `name`:

```nix
services.tegata.apiProxies.tailscale = {
  credId = "vw:a1b2c3d4";
  upstream = "https://api.tailscale.com";
  # header and value both default as above
};
```

See [setup-linux.md](setup-linux.md#configuration-reference) for where
`[[api_proxy]]` sits among the daemon's other configuration keys.

## OAuth device flow

An OAuth proxy lets tegata obtain an access token with a public OAuth device-code
grant. The token stays inside the executor process: it is not exposed to the
daemon, agent, audit log, or logs. The daemon refuses a proxy that sets both
`cred_id` and `oauth`, or neither.

```toml
[[api_proxy]]
name = "github"
upstream = "https://api.github.com"
value = "Bearer {{secret}}"
[api_proxy.oauth]
client_id = "Iv1.xxxx"
device_authorization_url = "https://github.com/login/device/code"
token_url = "https://github.com/login/oauth/access_token"
revocation_url = "https://auth.example.com/oauth/revoke"   # optional
scope = "repo"                                              # optional
login_cred_id = "vw:github-login"
steps = [ ... ]                                             # optional
success_selector = "[data-testid=authorized]"
failure_selector = "[data-testid=denied]"                   # optional
```

`device_authorization_url`, `token_url`, and `revocation_url` follow the same
rule as `upstream`: `https://`, or `http://` to a loopback host; any other URL
refuses startup. `revocation_url`, `scope`, `steps`, and `failure_selector` are
optional. `login_cred_id` and `steps` use the same browser-login configuration as
`authorize_device`; `success_selector` identifies successful approval and
`failure_selector` can identify a rejected approval. tegata logs into the
provider in a browser using the vault credential and approves the device grant.
The grant lives exactly as long as the lease. On `logout`, `lock_vault`, or TTL
expiry, tegata best-effort revokes it when `revocation_url` is configured, then
closes the lease. Grants are not persisted and every lease obtains a new grant.

When the remaining lifetime reaches `min(60 s, expires_in / 2)`, the executor
uses a refresh-token grant. If there is no refresh token or refresh fails, later
requests return `503`; the agent must open the proxy again. Client secrets and
authorization-code grants are not supported. Grant failures return
`OAUTH_GRANT_FAILED`; browser-stage failures use the same codes as
`authorize_device`. Audit records use `api_proxy_oauth` with `oauth_action` set
to `issued`, `refreshed`, `refresh_failed`, or `revoked`; `revoked` is recorded
only when every revocation request succeeded.

Opening an OAuth proxy runs the whole grant before it returns, which can take up
to 80 seconds. Set the agent's MCP client request timeout to at least 90
seconds. With a shorter timeout, the client gives up while the daemon still
completes the grant, and the resulting lease stays open, unused, until its TTL
expires.

An approval grant from `approval_grant_ttl_secs` is keyed by
`(principal, credential)`, not by method. A grant earned by a `login` with the
proxy's `login_cred_id` also lets the same principal call `open_api_proxy` for
the OAuth proxy without a new approval, and the reverse holds as well.

## Calling it

```json
{ "name": "tailscale" }
```

returns

```json
{ "session_id": "3f2b1c9e-...", "base_url": "http://127.0.0.1:41263/Ax7f...q2" }
```

`base_url` already carries the path secret — a 128-bit random token, base64url
encoded — as its path prefix. Requests to `<base_url>/<anything>` are relayed to
`<upstream>/<anything>` with the configured header injected, replacing whatever
the agent sent for that header. A request against the bare port, without the
secret prefix, or with a different session's secret, gets a 404 and never
reaches upstream.

The path of `upstream` is a prefix, not a boundary: the upstream API decides
what a path under it means. The relay does refuse dot segments, though. A
request whose path after the secret contains a `.` or `..` segment (after
percent-decoding), any `%2e`, or a backslash (including `%5c`) gets a 404 and
is not forwarded, so the agent cannot walk out of the configured base path by
path normalization.

A Terraform provider that takes its token from an environment variable, or a
`base_url`-shaped setting, points at this directly:

```sh
export TAILSCALE_BASE_URL="$base_url"
```

A remote MCP server configuration that takes a `url` works the same way — point
it at `base_url` instead of the real API host, and the server never sees the
token either. This does not apply to an MCP server the agent talks to over
`stdio`; it has no `url` to redirect and is out of scope here.

`open_api_proxy` goes through the same approval hook as `login`, when one is
configured. The hook's environment carries `TEGATA_METHOD=open_api_proxy`,
`TEGATA_TARGET_URL=<upstream>`, and `TEGATA_CRED_ID`, in place of the login
destination. On Windows, `approve_operator` holds the call in the operator's
pending approval queue instead, with the upstream as its target URL — see
[setup-windows-wsl.md](setup-windows-wsl.md#the-approval-hook). See
[security.md](security.md#human-in-the-loop-approval).

Starting a relay is rate-limited the same way starting a browser for `login`
is, per caller and proxy `name`: more than 3 starts in 10 minutes, or a call
during the 2, 5, then 15 second backoff after a failed start, returns
`RATE_LIMITED`.

## Session lifetime

`open_api_proxy` opens a lease exactly like `login` does: it has a TTL, it is
torn down by `logout`, and `lock_vault` closes every proxy in the locked
namespace along with everything else. Once the lease ends — by `logout`, TTL
expiry, or `lock_vault` — the relay stops accepting connections; the path
secret that leaked into a log or a saved configuration is worthless once its
session is gone.

## Audit

Every request through the relay writes one `api_proxy_request` audit line,
carrying the session's `principal`, the proxy's `name`, the HTTP method, the
upstream's `status`, and the path with the secret prefix stripped — but never
the query string, since a query is a plausible place for a caller to put
something sensitive. The recorded path is cut to 512 bytes, and a leading
segment shaped like a path secret is recorded as `[redacted]`. `outcome` is
`ok` for a status below 400, `upstream_unreachable` when the relay could not
reach the upstream (502), and `upstream_error` otherwise. A request without the
session's secret, or one refused for its dot segments, is answered with a 404
and not audited, so that any local user who can reach the port cannot add lines
under the session owner's name. `open_api_proxy` itself is audited like
`login`, with `target_url` set to the upstream.

## Residual risk

**The agent can use the token without reading it.** As long as the agent holds
`base_url`, it can make authenticated calls to the upstream API — that is the
point. What it cannot do is recover the token's value: the injected header
never appears in a request the agent constructs, only in what the relay sends
onward.

**An upstream that reflects the token back leaks it.** Some APIs echo request
headers into an error body or a debug response. If the upstream in your
threat model does that, the token is only as isolated as that response is
unread by the agent — which the relay itself does not protect against.

**There is no TLS interception.** The relay terminates the agent's plaintext
loopback connection and makes its own TLS connection to `upstream`; it does not
decrypt and re-inspect traffic beyond adding the one header. Response bodies
pass through untouched.

**Fixed upstream, not a general proxy.** The agent selects a proxy by name; it
cannot ask a configured proxy to reach a different host, and 3xx responses are
returned to the agent rather than followed.
