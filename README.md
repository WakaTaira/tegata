# tegata

tegata is a credential isolation sandbox for AI agents. The agent does not receive actual authentication credentials, such as a Bitwarden vault password. It receives only the raw CDP (Chrome DevTools Protocol) endpoint of an authenticated browser.
For credentials explicitly opted in to `totp_exposable`, it can expose TOTP codes with a 30-second rate limit.

## Architecture

The Rust side contains the isolation daemon `tegatad` (`crates/tegatad`), the leak detection tool `leakscan` (`crates/leakscan`), and shared logic in `tegata-core` (`crates/tegata-core`).

The TypeScript side contains the MCP broker (`packages/tegata-mcp`) and the Playwright executor sidecar (`packages/tegata-executor`). Supporting packages include `packages/leak-guard`, `packages/target-fixture`, and `packages/provision-test-vault`.

The daemon authorizes processes across a Unix Domain Socket (UDS) boundary using `SO_PEERCRED`. Before a response leaves the boundary, it is scanned against the set of secret values resolved at that point. The test suite verifies this path with canary values. `leak-guard` and `leakscan` provide the leakage detection path.

## Development

Enter the development shell with:

```sh
nix develop
```

The shell provides Rust tooling (`rustc`, `cargo`, `clippy`, and `rustfmt`), `nodejs_24`, `biome`, `bitwarden-cli`, `vaultwarden`, and `playwright-driver`.

On NixOS, the `nixosModules.tegata` module deploys tegata for production use through `services.tegata`.

## Tests

Run the Nix checks with:

```sh
nix flake check
```

This runs the `clippy`, `fmt`, `biome`, `cargo-test`, and `boundary` checks, including the `boundary` NixOS test.

Run the acceptance suite with:

```sh
nix develop -c npm run test:acceptance
```

The `pretest:acceptance` hook first runs `cargo build -p tegatad --features mock-provider`; the command then runs the acceptance tests with Vitest.

## Windows setup

The Windows service requires Node LTS, Bitwarden CLI `2025.9.0`, and the Playwright browsers installed under the path configured by `browsers_path`. Grant the service account read access to that path with an ACL. The service runs in session 0, so a headed browser does not appear on the desktop.

Run the following commands from an elevated PowerShell or command prompt:

```sh
tegatad.exe service install --config C:\ProgramData\tegata\config.toml
```

This registers the service, adds a firewall rule for the daemon TCP port limited to the WSL interface, creates `C:\ProgramData\tegata`, configures its ACL, and grants the configured operator SID permission to start and stop the service. The command requires elevation.

Issue a bootstrap token from an elevated shell. The plaintext token is printed to standard output once; copy it to the WSL client and store it with mode `0600`.

```sh
tegatad.exe token issue
```

Seal the master password from an elevated shell. The command prompts for the password and seals it with user-scope DPAPI. The daemon automatically unseals it after subsequent service restarts.

```sh
tegatad.exe seal
```

The main Windows transport settings are:

| Key | Description |
| --- | --- |
| `tcp_port` | Daemon TCP port; defaults to `21575`. |
| `tcp_bind` | IPv4 bind address or `auto`; defaults to `auto`. |
| `pipe_name` | Named pipe name; defaults to `tegatad`. |
| `allowed_sids` | SIDs allowed to connect to the named pipe. |
| `operator_sid` | Optional SID allowed to start and stop the service. |
| `browsers_path` | Playwright browser path passed to child processes as `PLAYWRIGHT_BROWSERS_PATH`. |
| `bw_path` | Bitwarden CLI path; defaults to `bw`. |
| `node_path` | Optional Node.js executable path. |

To inspect a headed browser running in session 0, expose or obtain its CDP endpoint from the service-side executor, open `chrome://inspect` in a browser in an interactive session, choose `Configure...`, add the endpoint host and port, and select `Inspect` for the discovered target. The DevTools window is the viewing window; the service session itself remains invisible.

Do not use a real vault password in tests or acceptance environments.

The daemon listens on the Windows side of the WSL NAT and is firewalled to the WSL interface. The WSL client connects through this Windows-side endpoint.

## WSL client setup

Build `tegata-bridge` from the repository or install its GitHub Release binary:

```sh
cargo build --release -p tegata-bridge
```

Copy the token issued by `tegatad.exe token issue` into WSL and restrict the file to its owner:

```sh
install -m 600 /path/to/issued-token ~/.config/tegata/bridge.token
```

Create a user systemd unit. The `--daemon-addr` option is optional; when omitted, `tegata-bridge` resolves the default gateway automatically.

```ini
[Unit]
Description=tegata WSL bridge

[Service]
ExecStart=/path/to/tegata-bridge --socket %h/.local/state/tegata/bridge.sock --token-file %h/.config/tegata/bridge.token
Restart=on-failure

[Install]
WantedBy=default.target
```

Enable the unit with `systemctl --user enable --now tegata-bridge`. Start the MCP server with both `TEGATA_BRIDGE=1` and `TEGATA_SOCKET` set to the bridge socket path from the unit, for example:

```sh
TEGATA_BRIDGE=1 TEGATA_SOCKET=~/.local/state/tegata/bridge.sock node packages/tegata-mcp/dist/index.js
```

On NixOS, `services.tegata-bridge` provides an alternative systemd module with configurable package, user, and socket path.

## License

tegata is dual-licensed under either the MIT license or Apache License 2.0. See `LICENSE-MIT` and `LICENSE-APACHE`.
