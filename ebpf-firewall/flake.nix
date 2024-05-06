{
  description = "A flake for building Hello World";

  inputs.nixpkgs.url = github:NixOS/nixpkgs/nixos-unstable;
  inputs.flake-utils.url = "github:numtide/flake-utils";

  outputs = { self, nixpkgs, flake-utils }:

    # https://ryantm.github.io/nixpkgs/stdenv/stdenv/
    flake-utils.lib.eachDefaultSystem (system: {
      packages = rec {
        ebpf-firewall =
          let
            pkgs = import nixpkgs { inherit system; };
          in
          # pkgs.stdenv.mkDerivation {
            #   name = "ebpf-firewall";
            #   src = self;
            #   buildInputs = [
            #     pkgs.gcc
            #     pkgs.go
            #     pkgs.dig
            #   ];
            #   # buildPhase = "gcc -o ebpf-firewall ./hello.c";
            #   # installPhase = "mkdir -p $out/bin; install -t $out/bin ebpf-firewall";
            #   # name = "ebpf-firewall";
            #   # src = self;
            #   buildPhase = ''
            #     export HOME=$(pwd)
            #     dig google.com
            #     CGO_ENABLED=0 go mod download
            #     go generate ./...
            #     go build -o ebpf-firewall
            #   '';
            #   installPhase = "mkdir -p $out/bin; install -t $out/bin ebpf-firewall";
            # };
          pkgs.buildGoModule
            {
              pname = "ebpf-firewall";
              version = "0.0.1";

              src = ./.;

              modPostBuild = ''
                go generate ./...
              '';

              # proxyVendor = true;
              # vendorHash = "";
              vendorHash = "sha256-34+UzVtcH0DohkFNM9dpsAdBh8tCoS7WksiN01j1tng=";
            };
        default = ebpf-firewall;
      };
    });
}
