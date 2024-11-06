#! /usr/bin/env bash

set -e
set -ux

seed=$(date)

log="${MAGIC_NIX_CACHE_DAEMONDIR}/daemon.log"

binary_cache=https://cache.flakehub.com

# Check that the action initialized correctly.
if [ "$EXPECT_FLAKEHUB" == "true" ]; then
  grep 'FlakeHub cache is enabled' "${log}"
  grep 'Using cache' "${log}"
else
  grep 'FlakeHub cache is disabled' "${log}"
fi

if [ "$EXPECT_GITHUB_CACHE" == "true" ]; then
  grep 'GitHub Action cache is enabled' "${log}"
else
  grep 'Native GitHub Action cache is disabled' "${log}"
fi

# Build something.
outpath=$(nix-build .github/workflows/cache-tester.nix --argstr seed "$seed")

# Wait until it has been pushed succesfully.
found=
for ((i = 0; i < 60; i++)); do
    sleep 1
    if grep "✅ $(basename "${outpath}")" "${log}"; then
        found=1
        break
    fi
done
if [[ -z $found ]]; then
    echo "FlakeHub push did not happen." >&2
    exit 1
fi

# Check the FlakeHub binary cache to see if the path is really there.
nix path-info --store "${binary_cache}" "${outpath}"

# FIXME: remove this once the daemon also uploads to GHA automatically.
nix copy --to 'http://127.0.0.1:37515' "${outpath}"

rm ./result
nix store delete "${outpath}"
if [ -f "$outpath" ]; then
    echo "$outpath still exists? can't test"
    exit 1
fi

rm -rf ~/.cache/nix

echo "-------"
echo "Trying to substitute the build again..."
echo "if it fails, the cache is broken."

nix-store --realize -vvvvvvvv "$outpath"
