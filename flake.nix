{
  inputs = {
    nixpkgs.url = "nixpkgs/nixos-unstable";
    fenix = { url = "github:nix-community/fenix"; inputs.nixpkgs.follows = "nixpkgs"; };
    naersk = { url = "github:nix-community/naersk"; inputs.nixpkgs.follows = "nixpkgs"; };
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, fenix, flake-utils, naersk, nixpkgs }:
    flake-utils.lib.eachDefaultSystem (system: {
      packages.default =
        let
          pkgs = nixpkgs.legacyPackages.${system};
          target = "aarch64-unknown-linux-gnu";
          toolchain = with fenix.packages.${system}; combine [
            minimal.cargo
            minimal.rustc
            targets.${target}.latest.rust-std
          ];
        in

        (naersk.lib.${system}.override {
          cargo = toolchain;
          rustc = toolchain;
        }).buildPackage {
          src = ./.;

          nativeBuildInputs = [ pkgs.pkg-config ];
          # buildInputs = [ pkgs.openssl ];

          CARGO_BUILD_TARGET = target;
          CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER =
            let
              inherit (pkgs.pkgsCross.aarch64-multiplatform.stdenv) cc;
            in
            "${cc}/bin/${cc.targetPrefix}cc";
        };
    });
}
