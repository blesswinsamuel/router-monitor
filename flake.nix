{
  description = "Export prometheus metrics from a Raspberry Pi router";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";
    # rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs = { self, nixpkgs }:
    let
      # Systems supported
      allSystems = [
        "x86_64-linux" # 64-bit Intel/AMD Linux
        "aarch64-linux" # 64-bit ARM Linux
        "x86_64-darwin" # 64-bit Intel macOS
        "aarch64-darwin" # 64-bit ARM macOS
      ];

      # Helper to provide system-specific attributes
      forAllSystems = f: nixpkgs.lib.genAttrs allSystems (system: f {
        inherit system;
        pkgs = import nixpkgs { inherit system; };
      });
    in
    {
      packages = forAllSystems ({ system, pkgs }: {
        default = pkgs.rustPlatform.buildRustPackage {
          name = "router-monitor";
          src = ./.;
          buildInputs = [ pkgs.pkg-config pkgs.openssl ] ++ (nixpkgs.lib.optionals (pkgs.stdenv.isDarwin) [ pkgs.darwin.apple_sdk.frameworks.Security ]);
          cargoLock = {
            lockFile = ./Cargo.lock;
          };
        };
      });
    };
}
