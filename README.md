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

## License

tegata is dual-licensed under either the MIT license or Apache License 2.0. See `LICENSE-MIT` and `LICENSE-APACHE`.
