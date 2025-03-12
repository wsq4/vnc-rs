{
  inputs = {
    flake-utils.url = "github:numtide/flake-utils";
    naersk.url = "github:nix-community/naersk";
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    fenix.url = "github:nix-community/fenix";
  };

  outputs = {
    self,
    flake-utils,
    naersk,
    nixpkgs,
    fenix,
  }:
    flake-utils.lib.eachDefaultSystem (
      system: let
        pkgs = (import nixpkgs) {
          inherit system;
          overlays = [fenix.overlays.default];
        };

        naersk' = pkgs.callPackage naersk {};
      in rec {
        defaultPackage = naersk'.buildPackage {
          src = ./.;
        };

        devShell = pkgs.mkShell {
          shellHook = ''
            export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:${
              with pkgs;
              lib.makeLibraryPath [ libGL xorg.libX11 xorg.libXi xorg.libXcursor  ]
            }"
          '';

          nativeBuildInputs = with pkgs; [
            alejandra
            rust-analyzer
            (pkgs.fenix.stable.withComponents [
              "cargo"
              "clippy"
              "rust-src"
              "rustc"
              "rustfmt"
            ])
            libiconv
            pkg-config openssl
          ];
        };
      }
    );
}
