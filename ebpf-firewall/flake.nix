{
  description = "A flake for building Hello World";

  inputs.nixpkgs.url = github:NixOS/nixpkgs/nixos-23.11;
  inputs.flake-utils.url = "github:numtide/flake-utils";

  outputs = { self, nixpkgs, flake-utils }:

    # https://ryantm.github.io/nixpkgs/stdenv/stdenv/
    flake-utils.lib.eachDefaultSystem (system: {
      packages = rec {
        router-monitor =
          let
            pkgs = import nixpkgs { inherit system; };
          in
          pkgs.stdenv.mkDerivation {
            name = "router-monitor";
            src = self;
            buildInputs = [
              pkgs.gcc
            ];
            buildPhase = "gcc -o router-monitor ./hello.c";
            installPhase = "mkdir -p $out/bin; install -t $out/bin router-monitor";
            # name = "router-monitor";
            # src = self;
            # buildInputs = [
            #   pkgs.gcc
            #   pkgs.go
            # ];
            # buildPhase = "go generate";
            # installPhase = "mkdir -p $out/bin; install -t $out/bin counter";
          };
        default = router-monitor;
      };
    });
}
