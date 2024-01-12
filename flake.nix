# {
#   inputs = {
#     nixpkgs.url = "github:nixos/nixpkgs";
#     flake-utils.url = "github:numtide/flake-utils";
#     gitignore = {
#       url = "github:hercules-ci/gitignore.nix";
#       inputs.nixpkgs.follows = "nixpkgs";
#     };
#   };

#   outputs = { self, nixpkgs, flake-utils, gitignore }:
#     flake-utils.lib.eachDefaultSystem (system:
#       let
#         pkgs = nixpkgs.legacyPackages.${system};
#         inherit (gitignore.lib) gitignoreSource;
#       in
#       {
#         packages.router-monitor = mkDerivation {
#           name = "router-monitor";
#           src = gitignoreSource ./;
#         };

#         # legacyPackages = packages;
#         defaultPackage = packages.router-monitor;

#         # devShell = pkgs.mkShell { buildInputs = with pkgs; [ cargo rustc git ]; };
#       });
# }
# https://github.com/reckenrode/verify-archive/blob/f452420680bdf4e037a441e2eb30f4c00a6d7edf/flake.nix
{
  description = ''
    Export prometheus metrics from a Raspberry Pi router.
  '';

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      inherit (nixpkgs) lib;
      forAllSystems = lib.genAttrs lib.systems.flakeExposed;
    in
    {
      packages = forAllSystems (system:
        let pkgs = nixpkgs.legacyPackages.${system}; in rec {
          default = router-monitor;
          router-monitor = pkgs.callPackage ./default.nix { };
        });

      apps = forAllSystems (system: rec {
        default = router-monitor;
        router-monitor = {
          type = "app";
          program = "${lib.getBin self.packages.${system}.router-monitor}/bin/router-monitor";
        };
      });
    };
}
