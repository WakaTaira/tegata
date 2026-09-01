{
  inputs.nixpkgs.url = "nixpkgs";

  outputs = { self, nixpkgs, ... }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; };
      tegataPackages = import ./nix/packages.nix { inherit pkgs; };
    in
    {
      devShells.${system}.default = pkgs.mkShell {
        packages = with pkgs; [
          rustc
          cargo
          clippy
          rustfmt
          nodejs_24
          biome
          pass
          gnupg
          age
          bitwarden-cli
          vaultwarden
          # The Bitwarden integration test mints a throwaway TLS certificate for its vault.
          openssl
          playwright-driver
        ];

        PLAYWRIGHT_BROWSERS_PATH = "${pkgs.playwright-driver.browsers}";
        PLAYWRIGHT_SKIP_VALIDATE_HOST_REQUIREMENTS = "true";
      };

      packages.${system} = {
        tegata-bridge = tegataPackages.tegata-bridge;
        tegata-mcp = tegataPackages.tegata-mcp;
        tegata-executor = tegataPackages.executor;
        inherit (tegataPackages)
          leakscan
          tegatad
          tegatad-mock
          target-fixture
          provision-test-vault;
      };

      nixosModules.tegata = import ./nix/module.nix {
        tegatadPackage = tegataPackages.tegatad;
        executorEntry = "${tegataPackages.executor}/lib/tegata-executor/index.js";
        bitwardenCliPackage = pkgs.bitwarden-cli;
        # Pass the browser from this flake's nixpkgs rather than the host-side pkgs. The
        # playwright-core bundled with the executor must match the browser revision, while the
        # host-side playwright-driver may have a divergent version (confirmed to fail at launch).
        playwrightBrowsersPackage = pkgs.playwright-driver.browsers;
      };

      nixosModules.tegata-bridge = import ./nix/bridge-module.nix {
        tegataBridgePackage = tegataPackages.tegata-bridge;
      };

      checks.${system} = {
        clippy = pkgs.stdenv.mkDerivation {
          pname = "tegata-clippy";
          version = "0.1.0";
          src = ./.;
          nativeBuildInputs = [
            pkgs.cargo
            pkgs.clippy
            pkgs.rustc
            pkgs.rustPlatform.cargoSetupHook
          ];
          cargoDeps = pkgs.rustPlatform.importCargoLock {
            lockFile = ./Cargo.lock;
          };
          buildPhase = ''
            export CARGO_TARGET_DIR="$TMPDIR/target"
            cargo clippy --workspace --all-targets --locked --offline -- -D warnings
          '';
          installPhase = "touch $out";
        };

        fmt = pkgs.stdenv.mkDerivation {
          pname = "tegata-fmt";
          version = "0.1.0";
          src = ./.;
          nativeBuildInputs = [
            pkgs.cargo
            pkgs.rustfmt
            pkgs.rustPlatform.cargoSetupHook
          ];
          cargoDeps = pkgs.rustPlatform.importCargoLock {
            lockFile = ./Cargo.lock;
          };
          buildPhase = ''
            export CARGO_TARGET_DIR="$TMPDIR/target"
            cargo fmt --all -- --check
          '';
          installPhase = "touch $out";
        };

        biome = pkgs.runCommand "tegata-biome" {
          nativeBuildInputs = [ pkgs.biome ];
        } ''
          cd ${./.}
          biome check .
          touch $out
        '';

        cargo-test = pkgs.stdenv.mkDerivation {
          pname = "tegata-cargo-test";
          version = "0.1.0";
          src = ./.;
          nativeBuildInputs = [
            pkgs.cargo
            pkgs.rustc
            pkgs.rustPlatform.cargoSetupHook
            # The daemon integration tests spawn fake node executors.
            pkgs.nodejs_24
          ];
          cargoDeps = pkgs.rustPlatform.importCargoLock {
            lockFile = ./Cargo.lock;
          };
          buildPhase = ''
            export CARGO_TARGET_DIR="$TMPDIR/target"
            cargo test --workspace --features tegatad/mock-provider --locked --offline
          '';
          installPhase = "touch $out";
        };

        boundary = import ./nix/vm-test.nix {
          inherit pkgs;
          tegataModule = self.nixosModules.tegata;
          tegataPackages = {
            inherit (tegataPackages)
              leakscan
              target-fixture
              provision-test-vault;
          };
        };

        tegata-bridge-eval =
          let
            evaluated = nixpkgs.lib.nixosSystem {
              inherit system;
              modules = [
                self.nixosModules.tegata-bridge
                {
                  services.tegata-bridge = {
                    enable = true;
                    user = "agent";
                    tokenFile = "/run/tegata-bridge/token";
                  };
                  users.users.agent = {
                    isNormalUser = true;
                  };
                }
              ];
            };
          in
            assert evaluated.config.systemd.services.tegata-bridge.serviceConfig.RuntimeDirectory
              == "tegata-bridge";
            assert evaluated.config.systemd.services.tegata-bridge.serviceConfig.ExecStart
              == "${tegataPackages.tegata-bridge}/bin/tegata-bridge --socket /run/tegata-bridge/bridge.sock --token-file /run/tegata-bridge/token";
            pkgs.runCommand "tegata-bridge-eval" {} "touch $out";
      };
    };
}
