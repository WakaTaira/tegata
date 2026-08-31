{ pkgs }:
let
  root = ../.;

  rustPackage = { pname, binary, features ? [ ] }:
    pkgs.rustPlatform.buildRustPackage {
      inherit pname;
      version = "0.1.0";
      src = root;

      cargoLock.lockFile = ../Cargo.lock;
      cargoBuildFlags = [ "--package" pname ]
        ++ pkgs.lib.optionals (features != [ ]) [ "--features" (builtins.concatStringsSep "," features) ];
      doCheck = false;

      installPhase = ''
        binary_path="$(${pkgs.findutils}/bin/find target -type f -executable -name ${binary} -print -quit)"
        if [ -z "$binary_path" ]; then
          echo "could not find built binary: ${binary}" >&2
          exit 1
        fi
        install -Dm755 "$binary_path" "$out/bin/${binary}"
      '';
    };

  npmPackage = { pname, workspace, directory, binary }:
    pkgs.buildNpmPackage {
      inherit pname;
      version = "0.1.0";
      src = root;

      npmDepsHash = "sha256-D378P9/oz35GV+YmiksjwawqXCQRmf8M+cOI4QOeIGE=";
      npmBuildScript = "build";
      npmBuildFlags = [ "--workspace" workspace ];

      installPhase = ''
        install -Dm755 packages/${directory}/dist/index.js $out/bin/${binary}
      '';
    };

  executor = pkgs.buildNpmPackage {
    pname = "tegata-executor";
    version = "0.1.0";
    src = root;

    npmDepsHash = "sha256-D378P9/oz35GV+YmiksjwawqXCQRmf8M+cOI4QOeIGE=";
    npmBuildScript = "build";
    npmBuildFlags = [ "--workspace" "@tegata/executor" ];

    installPhase = ''
      install -Dm644 packages/tegata-executor/dist/index.js \
        $out/lib/tegata-executor/index.js
      mkdir -p $out/lib/tegata-executor/node_modules
      cp -rL node_modules/playwright-core \
        $out/lib/tegata-executor/node_modules/
    '';
  };

  # The MCP broker the agent connects to. tsc does not bundle, so the broker
  # resolves its dependencies at run time: prune the workspace tree down to
  # production dependencies, ship it next to the entry point, and wrap with the
  # Node.js the workspace is built against so `nix run` needs nothing on PATH.
  tegata-mcp = pkgs.buildNpmPackage {
    pname = "tegata-mcp";
    version = "0.1.0";
    src = root;

    npmDepsHash = "sha256-D378P9/oz35GV+YmiksjwawqXCQRmf8M+cOI4QOeIGE=";
    npmBuildScript = "build";
    npmBuildFlags = [ "--workspace" "@tegata/mcp" ];

    nativeBuildInputs = [ pkgs.makeWrapper ];

    installPhase = ''
      npm prune --omit=dev
      install -Dm644 packages/tegata-mcp/dist/index.js \
        $out/lib/tegata-mcp/index.js
      cp -rL node_modules $out/lib/tegata-mcp/node_modules
      makeWrapper ${pkgs.nodejs_24}/bin/node $out/bin/tegata-mcp \
        --add-flags $out/lib/tegata-mcp/index.js
    '';

    meta.mainProgram = "tegata-mcp";
  };
in
{
  leakscan = rustPackage {
    pname = "leakscan";
    binary = "leakscan";
  };

  tegatad = rustPackage {
    pname = "tegatad";
    binary = "tegatad";
  };

  tegata-bridge = rustPackage {
    pname = "tegata-bridge";
    binary = "tegata-bridge";
  };

  tegatad-mock = rustPackage {
    pname = "tegatad";
    binary = "tegatad";
    features = [ "mock-provider" ];
  };

  target-fixture = npmPackage {
    pname = "tegata-target-fixture";
    workspace = "@tegata/target-fixture";
    directory = "target-fixture";
    binary = "tegata-target-fixture";
  };

  provision-test-vault = npmPackage {
    pname = "tegata-provision-test-vault";
    workspace = "@tegata/provision-test-vault";
    directory = "provision-test-vault";
    binary = "provision-test-vault";
  };

  inherit executor tegata-mcp;
}
