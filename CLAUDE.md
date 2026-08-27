# Contributor guidance

## Repository layout

- `crates/` contains the Rust workspace: the `tegatad` isolation daemon, `leakscan`, and shared `tegata-core` logic.
- `packages/` contains the TypeScript workspace, including the MCP broker, Playwright executor sidecar, leak guard, target fixture, and test-vault provisioning tool.
- `tests/acceptance/` contains end-to-end acceptance tests for the complete stack.
- `nix/` contains the NixOS module, package definitions, and the NixOS boundary test.
- `docs/secret/` contains private design and planning material and is not part of the public documentation.
- `flake.nix` defines the development shell, packages, NixOS module, and checks.

## Build and test commands

Run all build, test, and tooling commands through the development shell with `nix develop -c`.

```sh
nix develop -c cargo build
nix develop -c cargo test --features mock-provider
nix develop -c npm run test:acceptance
nix develop -c biome check .
```

Use the `biome` binary provided by the development shell. Do not use `npx biome`.

Bitwarden integration tests are ignored by default and require an explicit request:

```sh
nix develop -c cargo test --features mock-provider -- --ignored
```

The relevant integration test is `crates/tegatad/tests/bw_integration.rs`.

## Constraints

Do not casually modify `tests/acceptance/`; it defines the acceptance contract for the system. Never use real authentication credentials, including a real vault password, in tests or development.

All public artifacts must be written in English, including `README.md`, `CLAUDE.md`, CI definitions, and commit messages.
