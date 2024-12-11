{
rust-overlay ? builtins.fetchTarball
  "https://github.com/oxalica/rust-overlay/archive/0043c3f92304823cc2c0a4354b0feaa61dfb4cd9.tar.gz"
, pkgs ? import <nixpkgs> { overlays = [ (import rust-overlay) ]; } }:
let
  rust-toolchain = pkgs.rust-bin.stable."1.79.0".default.override {
    extensions = ["clippy" "rust-analyzer" "rust-src"];
  };
in pkgs.mkShell {
  buildInputs = [
    rust-toolchain
  ] ++ (with pkgs.darwin.apple_sdk.frameworks; [
    Security
    SystemConfiguration
  ]);
}
