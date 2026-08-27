{
  inputs.nixpkgs.url = "nixpkgs";
  inputs.nixpkgs-bw.url = "github:NixOS/nixpkgs/nixos-25.05";

  outputs = { nixpkgs, nixpkgs-bw, ... }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; };
      pkgsBw = import nixpkgs-bw { inherit system; };
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

      packages.${system}.bitwarden-cli-compat = pkgsBw.bitwarden-cli;
    };
}
