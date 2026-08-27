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

  inherit executor;
}
