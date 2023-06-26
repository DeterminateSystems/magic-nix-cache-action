# Magic Nix Cache

Save 30-50%+ of CI time without any effort or cost.
Use Magic Nix Cache, a totally free and zero-configuration binary cache for Nix on GitHub Actions.

Add our [GitHub Action][action] after installing Nix, in your workflow, like this:

```yaml
- uses: DeterminateSystems/magic-nix-cache-action@main
```

See [Usage](#usage) for a detailed example.

## Why use the Magic Nix Cache?

Magic Nix Cache uses the GitHub Actions [built-in cache][ghacache] to share builds between Workflow runs, and has many advantages over alternatives.

1. Totally free: backed by GitHub Actions' cache, there is no additional service to pay for.
1. Zero configuration: add our action to your workflow.
   That's it.
   Everything built in your workflow will be cached.
1. No secrets: Forks and pull requests benefit from the cache, too.
1. Secure: Magic Nix Cache follows the [same semantics as the GitHub Actions cache][semantics], and malicious pull requests cannot pollute your project.
1. Private: The cache is stored in the GitHub Actions cache, not with an additional third party.

> **Note:** the Magic Nix Cache doesn't offer a publicly available cache.
> This means the cache is only usable in CI.
> [Zero to Nix][z2n] has an article on binary caching if you want to [share Nix builds][z2ncache] with users outside of CI.

## Usage

Add it to your Linux and macOS GitHub Actions workflows, like this:

```yaml
name: CI

on:
  push:
  pull_request:

jobs:
  check:
    runs-on: ubuntu-22.04
    steps:
      - uses: actions/checkout@v3
      - uses: DeterminateSystems/nix-installer-action@main
      - uses: DeterminateSystems/magic-nix-cache-action@main
      - run: nix flake check
```

That's it.
Everything built in your workflow will be cached.

## Usage Notes

The GitHub Actions Cache has a rate limit on reads and writes.
Occasionally, large projects or large rebuilds may exceed those rate-limits, and you'll see evidence of that in your logs.
The error looks like this:

```
error: unable to download 'http://127.0.0.1:37515/<...>': HTTP error 418
       response body:
       GitHub API error: API error (429 Too Many Requests): StructuredApiError { message: "Request was blocked due to exceeding usage of resource 'Count' in namespace ''." }
```

The caching daemon and Nix both handle this gracefully, and won't cause your CI to fail.
When the rate limit is exceeded while pulling dependencies, your workflow may perform more builds than usual.
When the rate limit is exceeded while uploading to the cache, the remainder of those store paths will be uploaded on the next run of the workflow.


# Action Options
<!--
cat action.yml| nix run nixpkgs#yq-go -- '[[ "Parameter", "Description", "Required", "Default" ], ["-", "-", "-", "-"]] + [.inputs | to_entries | sort_by(.key) | .[] | ["`" + .key + "`", .value.description, .value.required // "", .value.default // ""]] | map(join(" | ")) | .[] | "| " + . + " |"' -r
-->

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
