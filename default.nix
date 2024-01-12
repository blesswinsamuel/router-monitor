# { pkgs ? import <nixpkgs> { }
# , stdenv ? pkgs.stdenv
# , lib ? stdenv.lib
#   # A set providing `buildRustPackage :: attrsets -> derivation`
# , rustPlatform ? pkgs.rustPlatform
# , fetchFromGitHub ? pkgs.fetchFromGitHub
# , gitignoreSrc ? null
# , pkgconfig ? pkgs.pkgconfig
# , gtk3 ? pkgs.gtk3
# , glib ? pkgs.glib
# , gobject-introspection ? pkgs.gobject-introspection
# }:

# let
#   gitignoreSource =
#     if gitignoreSrc != null
#     then gitignoreSrc.gitignoreSource
#     else (import
#       (fetchFromGitHub {
#         owner = "hercules-ci";
#         repo = "gitignore";
#         rev = "c4662e662462e7bf3c2a968483478a665d00e717";
#         sha256 = "0jx2x49p438ap6psy8513mc1nnpinmhm8ps0a4ngfms9jmvwrlbi";
#       })
#       { inherit lib; }).gitignoreSource;
# in
# rustPlatform.buildRustPackage rec {
#   pname = "router-monitor";
#   version = "0.0.1";

#   src = gitignoreSource ./.;

#   buildInputs = [
#     gtk3
#     glib
#     gobject-introspection
#   ];
#   nativeBuildInputs = [ pkgconfig ];
#   cargoSha256 = "sha256-0hfmV4mbr3l86m0X7EMYTOu/b+BjueVEbbyQz0KgOFY=";

#   meta = with stdenv.lib; {
#     homepage = "";
#     description = "Sample flake repository for a Rust application";
#     license = licenses.mit;
#   };
# }
{ lib
, stdenv
, fetchFromGitHub
, rustPlatform
, pkg-config
, bzip2
, zstd
, openssl
, darwin
}:

rustPlatform.buildRustPackage rec {
  pname = "router-monitor";
  version = "1.3.2";

  src = fetchFromGitHub {
    owner = "blesswinsamuel";
    repo = "router-monitor";
    rev = "v${version}";
    hash = "sha256-OP61Bk9KMby5g50+23Ii2fq2fJ1UVoSysuZRwYWz9sQ=";
  };

  configurePhase = ''
    # export BZIP2_SYS_USE_PKG_CONFIG=1 ZSTD_SYS_USE_PKG_CONFIG=1
  '';

  buildInputs = [ darwin.apple_sdk.frameworks.Security pkg-config openssl ];
  nativeBuildInputs = [ pkg-config ];

  cargoLock = {
    lockFile = src + /Cargo.lock;
  };

  meta = let inherit (lib) licenses platforms; in {
    description = "Export prometheus metrics from a Raspberry Pi router";
    homepage = "https://github.com/blesswinsamuel/router-monitor";
    # license = licenses.gpl3Only;
    # platforms = platforms.unix ++ platforms.windows;
  };
}
