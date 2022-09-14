with (import <nixpkgs> {});
mkShell {
  buildInputs = [
    caddy
  ];
}
