{ pkgs ? import <nixpkgs> {} }:
with pkgs; mkShell rec {
  nativeBuildInputs = [
    llvmPackages.bintools
  ];

  buildInputs = [
    gnum4
  ];

  LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath buildInputs;
}
