# Hosted stdio MCP servers

Some stdio MCP servers take an API key through an environment variable and
connect to a fixed upstream themselves — there is no URL to redirect the way
[`open_api_proxy`](api-proxy.md) redirects an HTTP client. Running such a
server directly on the agent's machine puts the key in the agent's own
environment. `open_mcp_server` and `tegata-mcp-run` start the server behind
the boundary instead: the executor spawns it with the resolved credential in
its environment, and the agent gets a stdio relay with no secret in it.

## Configuring a server

Each server is named, has one fixed command, and injects one credential:

```toml
[[mcp_server]]
name    = "brave"
cred_id = "vw:a1b2c3d4"
command = "/nix/store/…/bin/brave-search-mcp"   # absolute path, required
args    = ["--stdio"]                            # optional
[mcp_server.env]
BRAVE_API_KEY = "{{secret}}"
```

`command` must be an absolute path — the agent never supplies it, so there is
nothing to resolve against `PATH`. `env` values may use `{{secret}}` (the
credential's password), `{{username}}`, or `{{totp}}` (the credential's
current TOTP code), or be literal strings; at least one placeholder must
appear somewhere in `env`, or startup is refused. An empty or duplicate
`name`, a relative `command`, or a `cred_id` that is not
`<namespace>:<entry id>` also refuses startup.

On NixOS, the equivalent is `services.tegata.mcpServers`, an attribute set
keyed by the same `name`:

```nix
services.tegata.mcpServers.brave = {
  credId = "vw:a1b2c3d4";
  command = "/nix/store/…/bin/brave-search-mcp";
  args = [ "--stdio" ];
  env.BRAVE_API_KEY = "{{secret}}";
};
```

## Registering the runner with an agent

The agent does not talk to `open_mcp_server` itself — that is an RPC the
runner uses, not an MCP tool (see [mcp-tools.md](mcp-tools.md#open_mcp_server)).
Instead, register `tegata-mcp-run <name>` as an ordinary stdio MCP server in
the agent's own MCP client, the same way any other stdio server is
registered. For Claude Code:

```sh
claude mcp add brave --env TEGATA_SOCKET=/run/tegata/tegatad.sock \
  -- tegata-mcp-run brave
```

or, as JSON configuration:

```json
{
  "mcpServers": {
    "brave": {
      "command": "tegata-mcp-run",
      "args": ["brave"],
      "env": { "TEGATA_SOCKET": "/run/tegata/tegatad.sock" }
    }
  }
}
```

`tegata-mcp-run` ships as a second binary in the same `tegata-mcp` flake
package as the broker — `nix build github:WakaTaira/tegata#tegata-mcp` and
use `result/bin/tegata-mcp-run`, or put the package on the agent's `PATH`
(for example through `environment.systemPackages`) and reference the bare
command as above. Without Nix, the runner is `run.js` next to the broker's
`index.js` in the same node bundle — see the
[releases page](https://github.com/WakaTaira/tegata/releases).

## Bridge and container use

When the daemon is a Windows service and the agent runs in WSL, or the agent
runs in a container reached through `tegata-bridge`, set `TEGATA_BRIDGE=1` in
the runner's environment, the same as for `login` and `open_api_proxy`
([mcp-tools.md](mcp-tools.md#the-bridge-and-cdp-endpoints)). The runner
tunnels the relay port through the bridge instead of connecting to it
directly; nothing else about the registration changes.

## Approval

Where an approval hook is configured, it gates `open_mcp_server` the same way
it gates `login` and `open_api_proxy`: the hook's environment carries
`TEGATA_METHOD=open_mcp_server` and `TEGATA_TARGET_URL=mcp:<name>` in place of
the login destination. A time-limited grant earned this way, or by a `login`
or `open_api_proxy` call for the same credential, also covers
`open_mcp_server` for that credential, and the reverse holds as well.

## Lifetime

The server is a lease like a browser or an API proxy: it ends at `logout`,
`lock_vault` for its namespace, its session TTL, or the deployment's
`browser_max_lifetime_secs`, whichever comes first. The runner itself calls
`logout` as soon as its own stdin closes, the relay connection drops, or it
receives SIGTERM or SIGINT — the way an MCP client usually stops a stdio
server. Independently of the runner, the executor stops the server as soon as
the relay connection closes, since that connection is never re-established, so
closing the agent's MCP client tears down the server too, even one that
ignores the end of its stdin and even if the runner dies before it can log
out. When the server exits on its own, or is stopped because its connection
closed, the executor reports the exit and the daemon ends the lease. Stopping the server always means SIGTERM, then SIGKILL two seconds later
if it has not exited (Windows: a plain kill).

## Leak containment, and its limits

The executor reads the server's stdout one newline-delimited line at a time —
matching how MCP stdio framing works — and checks each line for the
credential values it injected before forwarding it: the password, and every
`env` value that contained `{{secret}}` or `{{totp}}`, as it reads after
substitution, each both verbatim and in its JSON-escaped form. An `env` value
whose only placeholder is `{{username}}` is not scanned. A line containing one
of those values is dropped, the server is killed, and the connection is
closed; the audit log records the leak instead of the line.

This is a substring check on the literal value, not a general secret
detector. **Base64, URL-encoding, hex, whitespace-splitting across two lines,
or any other transformation of the value defeats it.** So does anything below
line granularity — the check runs once per line, after the whole line has
arrived, up to a 16 MiB cap per line (a line beyond that is treated as a hit).
The server's stderr is not scanned at all; it is discarded. None of this is a
substitute for choosing servers you trust: the allowlist in `[[mcp_server]]`
is the actual control, not the scan. Treat the scan as a backstop against a
server that mishandles the value by accident, not as protection against one
that deliberately tries to exfiltrate it.

## Execution environment

The server's working directory and `HOME` are a per-session temporary
directory, removed when the lease ends. Its environment is exactly the
`PATH` the executor itself runs with, plus the `env` table from
configuration — none of the executor's other environment variables are
passed through. On Windows, `SYSTEMROOT` and `WINDIR` are also passed through
when the executor has them, because Node and many other runtimes on Windows
require `SYSTEMROOT`.

## Audit

`open_mcp_server` is audited like `login` and `open_api_proxy`, with
`target_url` set to `mcp:<name>` and `mcp_server` set to `<name>`. Each
relay event — a connection accepted, the server exiting on its own, or a
leak — writes a line with `method: "mcp_server"`, the session id,
`mcp_server`, and `mcp_action` set to `connected`, `exit`, or `leak`
respectively; an `exit` line also carries the process's exit code.
