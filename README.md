# Magic Nix Cache

Save 30-50%+ of CI time without any effort or cost.
Use Magic Nix Cache, a totally free and zero-configuration binary cache for Nix on GitHub Actions.

In your workflow, add our [GitHub Action][action] after installing Nix, like this:

```yaml
- uses: DeterminateSystems/determinate-nix-action@main
- uses: DeterminateSystems/flakehub-cache-action@main
```

See [Usage](#usage) for a detailed example.

> [!NOTE]
>
> You can upgrade to [FlakeHub Cache][flakehub-cache] and get **one month free** using the coupon code **`FHC`**.

## Why use the Magic Nix Cache?

Magic Nix Cache uses the GitHub Actions [built-in cache][gha-cache] to share builds between workflow runs, and has many advantages over alternatives.

1. **Totally free**. Backed by GitHub Actions' cache, there is no additional service to pay for.
1. **Zero configuration**. Add our Action to your workflow.
   That's it.
   Everything built in your workflow is cached.
1. **No secrets**. Forks and pull requests benefit from the cache, too.
1. **Secure**. Magic Nix Cache follows the [same semantics as the GitHub Actions cache][semantics] and malicious pull requests cannot pollute your project.
1. **Private**. The cache is stored in the GitHub Actions cache, not with an additional third party.

> [!NOTE]
>
> The Magic Nix Cache doesn't offer a publicly available cache.
> This means the cache is only usable in CI.
> Use [FlakeHub Cache][cache] if you want to [share Nix builds][z2ncache] with users outside of CI.

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
    permissions:
      id-token: "write"
      contents: "read"
    steps:
      - uses: actions/checkout@v4
      - uses: DeterminateSystems/determinate-nix-action@v3
      - uses: DeterminateSystems/flakehub-cache-action@main
      - uses: DeterminateSystems/flake-checker-action@main
      - name: Run `nix build`
        run: nix build .
```

That's it.
Everything built in your workflow is cached.

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
When the rate limit is exceeded while uploading to the cache, the remainder of those store paths is uploaded on the next run of the workflow.

## Concepts

### Upstream cache

When you configure an upstream cache for the Magic Nix Cache, any store paths fetched from that source are _not_ cached because they are known to be fetchable on future workflow runs.
The default is `https://cache.nixos.org` but you can set a different upstream:

```yaml
- uses: DeterminateSystems/flakehub-cache-action@main
  with:
    upstream-cache: https://my-binary-cache.com
```

## Action Options

<!--
cat action.yml| nix run nixpkgs#yq-go -- '[[ "Parameter", "Description", "Required", "Default" ], ["-", "-", "-", "-"]] + [.inputs | to_entries | sort_by(.key) | .[] | ["`" + .key + "`", .value.description, .value.required // "", .value.default // ""]] | map(join(" | ")) | .[] | "| " + . + " |"' -r
-->

| Parameter                   | Description                                                                                                     | Required | Default                                                  |
| --------------------------- | --------------------------------------------------------------------------------------------------------------- | -------- | -------------------------------------------------------- |
| `diagnostic-endpoint`       | Diagnostic endpoint url where diagnostics and performance data is sent. To disable set this to an empty string. |          | https://install.determinate.systems/magic-nix-cache/perf |
| `diff-store`                | Whether or not to diff the store before and after Magic Nix Cache runs.                                         |          | `false`                                                  |
| `flakehub-api-server`       | The FlakeHub API server.                                                                                        |          | https://api.flakehub.com                                 |
| `flakehub-cache-server`     | The FlakeHub binary cache server.                                                                               |          | https://cache.flakehub.com                               |
| `flakehub-flake-name`       | The name of your flake on FlakeHub. The empty string autodetects your FlakeHub flake.                           |          | `""`                                                     |
| `listen`                    | The host and port to listen on.                                                                                 |          | 127.0.0.1:37515                                          |
| `source-binary`             | Run a version of the cache binary from somewhere already on disk. Conflicts with all other `source-*` options.  |          |                                                          |
| `source-branch`             | The branch of `magic-nix-cache` to use. Conflicts with all other `source-*` options.                            |          | main                                                     |
| `source-pr`                 | The PR of `magic-nix-cache` to use. Conflicts with all other `source-*` options.                                |          |                                                          |
| `source-revision`           | The revision of `nix-magic-nix-cache` to use. Conflicts with all other `source-*` options.                      |          |                                                          |
| `source-tag`                | The tag of `magic-nix-cache` to use. Conflicts with all other `source-*` options.                               |          |                                                          |
| `source-url`                | A URL pointing to a `magic-nix-cache` binary. Overrides all other `source-*` options.                           |          |                                                          |
| `startup-notification-port` | The port magic-nix-cache uses for daemon startup notification.                                                  |          | 41239                                                    |
| `upstream-cache`            | Your preferred upstream cache. Store paths in this store aren't cached in GitHub Actions' cache.                |          | https://cache.nixos.org                                  |
| `use-flakehub`              | Whether to upload build results to FlakeHub Cache (private beta).                                               |          | true                                                     |
| `use-gha-cache`             | Whether to upload build results to the GitHub Actions cache.                                                    |          | true                                                     |

[action]: https://github.com/DeterminateSystems/magic-nix-cache-action
[attic]: https://github.com/zhaofengli/attic
[colmena]: https://github.com/zhaofengli/colmena
[detsys]: https://determinate.systems
[flakehub-cache]: https://flakehub.com/cache
[gha-cache]: https://docs.github.com/en/rest/actions/cache
[installer]: https://github.com/DeterminateSystems/nix-installer/
[privacy]: https://determinate.systems/policies/privacy
[semantics]: https://docs.github.com/en/actions/using-workflows/caching-dependencies-to-speed-up-workflows#restrictions-for-accessing-a-cache
[telemetry]: https://github.com/DeterminateSystems/magic-nix-cache/blob/main/magic-nix-cache/src/telemetry.rs
[z2n]: https://zero-to-nix.com
[z2ncache]: https://zero-to-nix.com/concepts/caching#binary-caches
[zhaofeng]: https://github.com/zhaofengli
