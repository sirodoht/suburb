with (import <nixpkgs> {});
mkShell {
  buildInputs = [
    nginx
  ];
}
