# tegata

**A credential isolation sandbox for AI agents.**

You want an AI agent to operate a site that requires a login. You do not want the
agent to ever hold the password.

tegata resolves credentials on the far side of an operating system boundary that
the agent cannot cross, performs the login there, and hands the agent back only a
connection to the resulting authenticated browser session. The agent drives a
browser that is already logged in, and never learns how it got that way.

The name comes from *tegata* (手形), the travel pass a traveller presented at an
Edo-period checkpoint: proof enough to pass through, without surrendering their
identity.

## What the agent never sees

Everything below stays on the isolated side of the boundary, by construction:

| Never crosses the boundary | Why it cannot |
| --- | --- |
| The vault master password | Entered into, or unsealed by, the isolated daemon only |
| Usernames and passwords | Resolved in the daemon, written to the executor over a pipe |
| TOTP seeds | Codes are computed on the isolated side; the seed is never serialized outward |
| Cookies, `storageState`, session tokens | The session is shared as a live browser, never as a file |
| Traces, videos, HAR files, screenshots | The executor never enables them |

What the agent *does* receive is a credential catalog with names but no values, a
CDP (Chrome DevTools Protocol) endpoint for an authenticated browser, and — for
entries explicitly marked `totp_exposable` — the current six-digit TOTP code,
rate-limited to one per 30 seconds and written to the audit log.

## How it works

```
┌─────────────────────────────────────────────────────────────────┐
│ Agent (Claude Code, or any MCP client)                          │
│                                                                 │
│ sees: credential names · tool calls · a CDP endpoint            │
└───────────────────────────┬─────────────────────────────────────┘
                            │ MCP over stdio
┌───────────────────────────▼─────────────────────────────────────┐
│ Broker — packages/tegata-mcp                                    │
│ Runs as the agent's own user. Holds no secrets. Forwards        │
│ five tools to the daemon and returns classified errors.         │
└───────────────────────────┬─────────────────────────────────────┘
                            │
════════════════════════════╪═════════════════════════════════════
      the boundary          │  UNIX socket + SO_PEERCRED  (Linux)
      enforced by the OS    │  named pipe + SID           (Windows)
                            │  loopback TCP + token       (WSL client)
════════════════════════════╪═════════════════════════════════════
                            │
┌───────────────────────────▼─────────────────────────────────────┐
│ tegatad — crates/tegatad                                        │
│ Separate user account. Files it owns are unreadable to          │
│ the agent's user. Every response is scanned for known           │
│ secret values before it is written back.                        │
│                                                                 │
│  ┌───────────────────────────┐  ┌───────────────────────────┐   │
│  │ ProviderRegistry          │  │ Executor                  │   │
│  │ namespaced providers:     │─▶ packages/tegata-executor   │   │
│  │ bitwarden · age · pass    │  │ Playwright form login     │   │
│  └───────────────────────────┘  └─────────────┬─────────────┘   │
└────────────────────────────────────────────────┼────────────────┘
                                                 │ launches
                                    ┌────────────▼────────────┐
                                    │ Chromium, logged in     │
                                    │ CDP endpoint ───────────┼──▶ back to the agent
                                    └─────────────────────────┘
```

The agent asks for `login`. The daemon resolves the credential, spawns the
executor, and passes the secret to it on stdin — never through `argv`, never
through the environment. The executor fills the form in a browser it launched
itself, verifies that the login took, and returns the browser's CDP endpoint.
That endpoint is all that travels back out.

See [docs/architecture.md](docs/architecture.md) for the layer-by-layer detail.

## Threat model in brief

tegata assumes the agent is fully capable and possibly compromised:

- it can run arbitrary shell commands — `env`, `ps`, `cat`, walking the filesystem
- it can write and execute its own code
- it may follow instructions injected through a web page it is reading

Under those assumptions, "the agent has been told not to look" is not a boundary.
Only a boundary the agent's own privileges cannot cross counts: a separate user
account, a service account, a separate host. tegata puts every secret behind one
of those and exposes a small allowlisted RPC surface across it.

What tegata does *not* protect against: an agent with an authenticated session can
do anything that session can do. Constrain that with dedicated accounts,
read-only roles, and site allowlists — not with tegata.

An injected instruction can also make the agent request a login it is entitled to
make, which no boundary can tell apart from a legitimate one. For credentials whose
misuse you could not undo, configure an approval hook so a human has to say yes
before the login happens.

Full threat model, invariants, and the operator hardening checklist:
[docs/security.md](docs/security.md).

## Platform support

| Boundary | Platform | Mechanism | Peer authentication | Sealed storage | Status |
| --- | --- | --- | --- | --- | --- |
| systemd | Linux, WSL | Dedicated user + hardened systemd unit | UNIX socket, `SO_PEERCRED` | askpass at unlock | Implemented |
| Windows service | Windows | Virtual service account `NT SERVICE\tegatad` | Named pipe + SID; loopback TCP + token for the WSL client | DPAPI | Implemented |
| Container | Containerized agents | Separate container, no shared volume | Socket + token | Secret mount | Not implemented |
| Remote host | Any | Separate host or VM | mTLS / Tailscale identity | Server-side | Not implemented |

The Windows service boundary is the recommended configuration for a WSL agent:
the daemon runs as a Windows service account, and a WSL process — which reaches
Windows with the privileges of the user who started WSL — cannot read files owned
by that service account. The trust direction points away from the agent.

## Quick start

On NixOS, a working deployment is a module import and one MCP registration.

**1. Deploy the daemon.** Add the flake as an input
(`tegata.url = "github:WakaTaira/tegata"`) and import its module:

```nix
{
  imports = [ tegata.nixosModules.tegata ];

  services.tegata = {
    enable = true;
    allowedUsers = [ "alice" ];          # the user the agent runs as
    providers = [{
      namespace   = "vw";
      type        = "bitwarden-cli";
      server_url  = "https://vault.example.com";
      email       = "vault-account@example.com";
      askpass_cmd = "…";                 # how the master password enters — see the setup guide
    }];
  };
}
```

**2. Register the broker with the agent.** The broker is a flake package, so no
checkout is needed. For Claude Code:

```sh
claude mcp add tegata --env TEGATA_SOCKET=/run/tegata/tegatad.sock \
  -- nix run github:WakaTaira/tegata#tegata-mcp
```

**3. Ask the agent to log in.** `list_credentials` shows names and ids, never
values; `login` returns a CDP endpoint for a browser that is already
authenticated.

Everything else — other platforms and vault backends, the approval hook,
deployment without Nix — is in the setup guides:

- **Linux / NixOS** — [docs/setup-linux.md](docs/setup-linux.md)
- **Windows service + WSL client** — [docs/setup-windows-wsl.md](docs/setup-windows-wsl.md)

## MCP tools

The agent-facing surface is five tools. Nothing else crosses the boundary.

| Tool | Input | Output |
| --- | --- | --- |
| `list_credentials` | `{namespace?}` | Catalog entries: `id`, `name`, `uri`, `kind`, `source`, `status`. No values. |
| `login` | `{cred_id, target_url, steps?, success_selector?, failure_selector?}` | `{session_id, channel: {kind: "cdp", endpoint}}` |
| `logout` | `{session_id}` | `{ok}` — destroys the session and its browser |
| `get_totp` | `{cred_id}` | `{code, expires_in}` — opt-in entries only, rate-limited |
| `lock_vault` | `{namespace?}` | `{ok}` — locks one provider, or all of them |

Login steps are written with placeholders — `{{username}}`, `{{password}}`,
`{{totp}}` — and are the only values a `fill` step will accept. Substitution
happens on the isolated side, so a step can never carry a literal secret in
either direction.

Full request and response shapes, and the error classification codes:
[docs/mcp-tools.md](docs/mcp-tools.md).

## How the isolation is verified

The boundary is tested, not asserted. Development and test runs never use a real
credential; a throwaway vault is provisioned with high-entropy canary values, and
the suite then hunts for those canaries across every surface the agent can observe.

```sh
nix flake check                       # clippy, fmt, biome, cargo-test, boundary VM test
nix develop -c npm run test:acceptance
```

- **`leakscan`** (`crates/leakscan`) scans files, directories, and streams for
  canaries in raw, base64, percent-encoded, hex, and JSON-escaped form, because
  leaks tend to arrive transformed.
- **`leak-guard`** (`packages/leak-guard`) wraps an acceptance test: it registers
  the canaries at setup and, at teardown, checks RPC responses, agent-readable
  files, process arguments, and environments for any of them.
- **A negative control** deliberately leaks a canary and asserts the checker
  catches it, so a broken detector cannot show up as a green suite.
- **The NixOS `boundary` check** builds a two-user VM and verifies the real
  thing: the agent's user cannot read the daemon's state, the socket refuses a
  peer whose uid is not on the allowlist, and a full login driven as the agent's
  uid — with `ps -eo args` sampled throughout — leaves no canary in anything that
  user could observe or read.
- **The Windows suite** (`tests/acceptance/windows`) exercises a real service over
  a real WSL boundary, including a WMI sampler that would catch a canary appearing
  in a Windows command line.

The acceptance tests under `tests/acceptance/` are the contract for the system;
they are meant to be read as the specification of what the boundary guarantees.

## Repository layout

| Path | Contents |
| --- | --- |
| `crates/tegatad` | The isolation daemon: providers, RPC, transports, audit log |
| `crates/tegata-core` | Shared secret type, TOTP, JSON wire types |
| `crates/tegata-bridge` | WSL-side bridge from a UNIX socket to the Windows daemon |
| `crates/leakscan` | Canary scanner, as a library and a CLI |
| `packages/tegata-mcp` | The MCP broker the agent connects to |
| `packages/tegata-executor` | Playwright login executor sidecar |
| `packages/leak-guard` | Leak detection fixture for the acceptance suite |
| `packages/target-fixture` | Local login target used by the tests |
| `packages/provision-test-vault` | Throwaway vault provisioning for the tests |
| `nix/` | NixOS modules, packages, and the boundary VM test |
| `tests/acceptance/` | End-to-end acceptance contract |

## Documentation

- [Architecture](docs/architecture.md) — layers, abstractions, sequence, audit log
- [Security](docs/security.md) — threat model, invariants, unlock and TOTP design
- [MCP tools](docs/mcp-tools.md) — the full agent-facing contract
- [Linux setup](docs/setup-linux.md) — NixOS module and `config.toml` reference
- [Windows / WSL setup](docs/setup-windows-wsl.md) — service, token, seal, bridge
- [Security policy](SECURITY.md) — how to report a vulnerability privately

## Roadmap

Implemented today: the systemd and Windows service boundaries; three credential
backends behind the provider trait — Bitwarden CLI, age-encrypted file, and GNU
pass — usable together; the Playwright form executor; the five MCP tools;
human-in-the-loop login approval; and an audit log covering both agent calls and
the daemon's own session and vault events.

Planned, tracked in the
[issue tracker](https://github.com/WakaTaira/tegata/issues):

- **Container boundary** ([#6](https://github.com/WakaTaira/tegata/issues/6)) —
  the daemon in its own container, no shared volume, for containerized agents
- **Remote-host boundary** ([#7](https://github.com/WakaTaira/tegata/issues/7)) —
  the daemon on a separate host or VM, authenticated by mTLS or tailnet identity
- **OAuth device-flow executor**
  ([#8](https://github.com/WakaTaira/tegata/issues/8)) — device-code grants
  completed on the isolated side, alongside the form executor
- **Release binaries** ([#1](https://github.com/WakaTaira/tegata/issues/1)) —
  prebuilt artifacts for non-Nix deployments

Each feature is designed in a private brief before implementation; what lands
publicly is the design's contract, as acceptance tests under `tests/acceptance/`.

## Contributing

Build and test commands, workspace layout, and the constraints on the acceptance
suite are documented in [CLAUDE.md](CLAUDE.md).

## License

tegata is dual-licensed under either the MIT license or the Apache License 2.0,
at your option. See [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE).
