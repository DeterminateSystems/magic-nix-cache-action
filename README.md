# The Magic Nix Cache Action

Cut CI time by 50% or more by caching to GitHub Actions' cache, for free. No configuration required.

<!--
cat action.yml| nix run nixpkgs#yq-go -- '[[ "Parameter", "Description", "Required", "Default" ], ["-", "-", "-", "-"]] + [.inputs | to_entries | sort_by(.key) | .[] | ["`" + .key + "`", .value.description, .value.required // "", .value.default // ""]] | map(join(" | ")) | .[] | "| " + . + " |"' -r
-->

```yaml
name: Flake Check

on:
  pull_request:
  push:
    branches: [main]

jobs:
  flake-check:
    runs-on: ubuntu-22.04
    steps:
      - uses: actions/checkout@v3
      - uses: DeterminateSystems/flake-checker-action@v4
        with:
          fail-mode: true
      - name: Install Nix
        uses: DeterminateSystems/nix-installer-action@v4
      - uses: DeterminateSystems/nix-installer-action-cache@focus-on-cache

      - name: "Nix Flake Check"
        run: nix flake check . -L
```

| Parameter | Description | Required | Default |
| - | - | - | - |
| `diagnostic-endpoint` | Diagnostic endpoint url where diagnostics and performance data is sent. To disable set this to an empty string. |  | https://install.determinate.systems/magic-nix-cache/perf |
| `listen` | The host and port to listen on. |  | 127.0.0.1:37515 |
| `source-binary` | Run a version of the cache binary from somewhere already on disk. Conflicts with all other `source-*` options. |  |  |
| `source-branch` | The branch of `magic-nix-cache` to use. Conflicts with all other `source-*` options. |  |  |
| `source-pr` | The PR of `magic-nix-cache` to use. Conflicts with all other `source-*` options. |  |  |
| `source-revision` | The revision of `nix-magic-nix-cache` to use. Conflicts with all other `source-*` options. |  |  |
| `source-tag` | The tag of `magic-nix-cache` to use. Conflicts with all other `source-*` options. |  |  |
| `source-url` | A URL pointing to a `magic-nix-cache` binary. Overrides all other `source-*` options. |  |  |
| `upstream-cache` | Your preferred upstream cache. Store paths in this store will not be cached in GitHub Actions' cache. |  | https://cache.nixos.org |
