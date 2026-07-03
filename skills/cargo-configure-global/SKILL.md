---
name: cargo-configure-global
description: Point your machine-wide Cargo at a dependably sparse registry via ~/.cargo/config.toml
ecosystem: cargo
scope: global
inputs:
  - DEPENDABLY_BASE_URL
  - DEPENDABLY_TOKEN
---

## When to use this

You want every Cargo project on your machine to resolve (and optionally publish)
crates through your dependably instance's sparse index, without editing each
crate's `.cargo/config.toml`.

## Inputs

Ask the user for:

1. **DEPENDABLY_BASE_URL** — the base URL of your dependably org, e.g.
   `https://repo.example.com`. Single-tenant uses the bare host; multi-tenant
   puts the org in the subdomain. Trailing slash is stripped.
2. **DEPENDABLY_TOKEN** — created under **Tokens**. Stored in Cargo's separate
   credentials file, not in `config.toml`.

## Files to write

**1. Registry index** — Linux/macOS `~/.cargo/config.toml`, Windows
`%USERPROFILE%\.cargo\config.toml`:

```toml
[registries.dependably]
index = "sparse+https://repo.example.com/cargo/"

# Make dependably the default source for crates.io (mirror all deps through it):
[source.crates-io]
replace-with = "dependably"
[source.dependably]
registry = "sparse+https://repo.example.com/cargo/"
```

The `[source.crates-io] replace-with` block is optional — include it to route
*all* crate resolution through dependably; omit it to only use dependably for
crates that explicitly declare `registry = "dependably"`.

**2. Token** — either run:

```bash
cargo login --registry dependably     # writes ~/.cargo/credentials.toml
```

or write `~/.cargo/credentials.toml` directly:

```toml
[registries.dependably]
token = "your-token"
```

Substitutions:
- Replace `https://repo.example.com` with `DEPENDABLY_BASE_URL` (keep the
  `sparse+` prefix and trailing `/cargo/`).

> **HTTP gotcha.** For an `http://` base URL, allow the insecure protocol:
> ```toml
> [registries.dependably]
> index = "sparse+http://repo.example.com/cargo/"
> protocol = "sparse"
> ```
> and set `CARGO_HTTP_CAINFO`/`CARGO_NET_GIT_FETCH_WITH_CLI` only if a corporate
> TLS proxy is in play. Dependably also accepts a bare, unprefixed token in the
> `Authorization` header as a Cargo-specific fallback.

## Verify it works

```bash
cargo search --registry dependably serde     # queries the sparse index
cargo publish --registry dependably          # if you publish crates
```

The first fetch records a `first_fetch` entry on the dependably **Activity**
page. A `401` means the token in `credentials.toml` is missing or wrong.

## Reverting

Remove the `[registries.dependably]` / `[source.*]` blocks from
`~/.cargo/config.toml` and the entry from `~/.cargo/credentials.toml`. Cargo
returns to crates.io.
