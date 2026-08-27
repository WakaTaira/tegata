{
  inputs.nixpkgs.url = "nixpkgs";
  inputs.nixpkgs-bw.url = "github:NixOS/nixpkgs/nixos-25.05";

  outputs = { self, nixpkgs, nixpkgs-bw, ... }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; };
      pkgsBw = import nixpkgs-bw { inherit system; };
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
          pkgsBw.bitwarden-cli
          vaultwarden
          playwright-driver
        ];

        PLAYWRIGHT_BROWSERS_PATH = "${pkgs.playwright-driver.browsers}";
        PLAYWRIGHT_SKIP_VALIDATE_HOST_REQUIREMENTS = "true";
      };

      packages.${system} = {
        bitwarden-cli-compat = pkgsBw.bitwarden-cli;
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
        bitwardenCliPackage = pkgsBw.bitwarden-cli;
        # ブラウザはホスト側 pkgs ではなく本 flake の nixpkgs から渡す。executor に同梱される
        # playwright-core とブラウザ revision が一致している必要があり、ホスト側の
        # playwright-driver はバージョンが乖離しうるため（実配備で launch 即失敗を確認済み）。
        playwrightBrowsersPackage = pkgs.playwright-driver.browsers;
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
      };
    };
}
