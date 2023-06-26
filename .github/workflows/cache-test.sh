#!/bin/sh

set -e
set -ux

seed=$(date)

outpath=$(nix-build .github/workflows/cache-tester.nix --argstr seed "$seed")
nix copy --to 'http://127.0.0.1:37515' "$outpath"
rm ./result
nix store delete "$outpath"
if [ -f "$outpath" ]; then
    echo "$outpath still exists? can't test"
    exit 1
fi

rm -rf ~/.cache/nix

echo "-------"
echo "Trying to substitute the build again..."
echo "if it fails, the cache is broken."

nix-store --realize -vvvvvvvv "$outpath"
