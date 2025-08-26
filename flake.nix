{
  description = "Rust development environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };
        fs = pkgs.lib.fileset;
        getRust = rs: rs.default.override {
          extensions = [ "rust-src" "rust-analyzer" ];
        };

        rustToolchain = getRust pkgs.rust-bin.stable.latest;
        rustToolchainNightly = getRust pkgs.rust-bin.nightly."2025-08-01";
      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            rustToolchain
          ];
        };
        devShells.fuzz = pkgs.mkShell rec {
          buildInputs = with pkgs; [
            rustToolchainNightly
            pkgs.cargo-fuzz
          ];
        };
      }
    );
}
