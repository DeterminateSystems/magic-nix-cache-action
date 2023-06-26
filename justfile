# A creds.json can be specified to test auto-caching locally.
# See <https://github.com/DeterminateSystems/magic-nix-cache> for
# instructions on how to obtain this file.
github_creds_json := env_var_or_default('GITHUB_CREDS_JSON', '')

# List available recipes
default:
  @just --list --unsorted --justfile {{justfile()}}

# Install dependencies
install:
  bun i --no-summary --ignore-scripts

# Build the action
build: install
  bun run build

# Run CI locally
act job='run-x86_64-linux': build
  act -j {{job}} -P ubuntu-22.04=catthehacker/ubuntu:act-22.04 \
    {{ if github_creds_json != '' { "--env-file <(jq -r '. | to_entries[] | .key + \"=\" + .value' " + github_creds_json + ")" } else { '' } }}
