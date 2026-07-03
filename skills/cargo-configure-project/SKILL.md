---
name: cargo-configure-project
description: Point Cargo at a dependably sparse registry for a single crate via ./.cargo/config.toml
ecosystem: cargo
scope: project
inputs:
  - DEPENDABLY_BASE_URL
  - DEPENDABLY_TOKEN
---

## When to use this

You want one Cargo workspace to resolve crates through your dependably instance,
so anyone who clones it inherits the registry — without changing global Cargo
settings. Cargo reads a `.cargo/config.toml` from the workspace root, so the
registry URL is committed there while the token stays in each developer's global
`~/.cargo/credentials.toml`.

## Inputs

Ask the user for:

1. **DEPENDABLY_BASE_URL** — the base URL of your dependably org, e.g.
   `https://repo.example.com` or `http://192.168.1.50:8080`.
2. **DEPENDABLY_TOKEN** — created under **Tokens**. Never commit it: Cargo keeps
   tokens in `~/.cargo/credentials.toml`, outside the repo.

## File to write

Create `.cargo/config.toml` in the workspace root (commit this — it holds no
secret):

```toml
[registries.dependably]
index = "sparse+https://repo.example.com/cargo/"

# Route all crate resolution through dependably for this workspace:
[source.crates-io]
replace-with = "dependably"
[source.dependably]
registry = "sparse+https://repo.example.com/cargo/"
```

Then each developer adds the token to their global credentials file once (NOT
committed):

```bash
cargo login --registry dependably     # writes ~/.cargo/credentials.toml
```

Substitutions:
- Replace `https://repo.example.com` with `DEPENDABLY_BASE_URL` (keep the
  `sparse+` prefix and trailing `/cargo/`).

> **HTTP gotcha.** For an `http://` base URL add `protocol = "sparse"` under
> `[registries.dependably]` (see the `cargo-configure-global` skill).

## Verify it works

```bash
cargo build                    # resolves deps through dependably for this repo
cargo publish --registry dependably
```

The first fetch records a `first_fetch` entry on the dependably **Activity**
page.

## Never commit the token

`.cargo/config.toml` holds only the registry URL, so it is safe to commit. The
token lives in `~/.cargo/credentials.toml`. In CI, pass it as an env var —
`CARGO_REGISTRIES_DEPENDABLY_TOKEN=${{ secrets.DEPENDABLY_TOKEN }}` — instead of
writing a credentials file.

## Reverting

Delete `.cargo/config.toml` from the repo. Cargo returns to crates.io.
