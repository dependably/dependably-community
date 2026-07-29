# Cargo registry

dependably serves Cargo as a **sparse registry**: your crates published to it, plus a
pull-through cache of crates.io (or whichever upstream your operator configured). One registry
URL covers both — `cargo` does not know or care which side a crate came from.

- [Point Cargo at the registry](#point-cargo-at-the-registry)
- [Authenticating](#authenticating)
- [Consuming crates](#consuming-crates)
- [Publishing a crate](#publishing-a-crate)
- [Yanking a version](#yanking-a-version)
- [Crate ownership](#crate-ownership)
- [What the registry exposes](#what-the-registry-exposes)

## Point Cargo at the registry

Add the registry to `~/.cargo/config.toml` (or a project's `.cargo/config.toml`). The `sparse+`
prefix and the trailing slash are both required by Cargo:

```toml
[registries.dependably]
index = "sparse+https://dependably.example.com/cargo/"
```

Cargo fetches `/cargo/config.json` from that base to learn where downloads and the API live; you
do not configure those separately.

If your instance runs in multi-tenant mode, each org is served from its own subdomain
(`https://my-org.dependably.example.com/cargo/`). In single-tenant mode the bare host is the org.

The exact snippet for your instance — with the right host already filled in — is under **Setup**
in the web UI ("Setup Snippets"), which is visible to every user.

## Authenticating

```bash
cargo login --registry dependably
```

Paste a dependably token when prompted. Cargo stores it in `~/.cargo/credentials.toml` and sends
it as the `Authorization` header on every request. You can also set it directly:

```toml
[registries.dependably]
token = "<token>"
```

Mint tokens in the web UI under **Tokens** (a personal token) or **Settings → Service tokens**
(for CI). Two capabilities matter for Cargo:

| Capability | Needed for |
| --- | --- |
| `publish:cargo` | `cargo publish` |
| `yank:cargo` | `cargo yank` and `cargo yank --undo` |

Reads need no particular capability, but they may need a token at all: when the org has
**anonymous pull** disabled, an unauthenticated index or download request is answered `401` with
a `WWW-Authenticate: Bearer realm="cargo"` challenge. With anonymous pull enabled, reads work
without one.

Tokens are org-scoped. A token minted in one org is treated as absent by another org's endpoints —
it does not partially authenticate, so the anonymous-pull rule governs and you get a `401` rather
than another tenant's data.

## Consuming crates

Depend on a crate from the registry the usual way:

```toml
[dependencies]
my-crate = { version = "1.2", registry = "dependably" }
```

A crate the org has not seen before is fetched from the configured upstream on first use,
verified, cached, and served; later builds hit the cache. If your org publishes a version with the
same name and version as an upstream one, **the local version wins** — the sparse index shadows
the upstream line, and the download serves your bytes.

Crates can also be searched, which is what `cargo search --registry dependably` uses:

```bash
cargo search serde --registry dependably
```

Search covers both the crates your org has published and the ones it has cached.

## Publishing a crate

```bash
cargo publish --registry dependably
```

Requires a token with `publish:cargo`. On success the version appears in the sparse index
immediately and is downloadable straight away.

Publishing is refused on an [edge node](edge-node.md) — an edge is a cache, so it answers `405`
and tells you to publish to the master registry instead.

## Yanking a version

```bash
cargo yank --registry dependably --version 1.2.3 my-crate
cargo yank --registry dependably --version 1.2.3 --undo my-crate
```

Requires a token with `yank:cargo`. A yanked version is hidden from dependency resolution but
stays downloadable by exact coordinate, so existing lockfiles keep resolving — the same semantics
crates.io has.

## Crate ownership

**`cargo owner --add` and `cargo owner --remove` do not work against this registry.** They answer
`501 Not Implemented`, deliberately.

Access to a crate is governed by **org membership and roles**, not by a per-crate owner list.
Anyone in the org with `publish:cargo` can publish any crate name the org owns; nobody outside the
org can, whatever a crate-level list might say. Implementing Cargo's owner model would stand up a
second authorization model that would have to be reconciled with tenant roles on every access
decision — two sources of truth that can disagree, on the path that decides who may publish.

To change who can publish, change who is in the org:

- **Web UI** — **Users** ("Users & Invites") to invite someone, change a role, or remove them.
- **API** — the user-management endpoints under `/api/v1/`, documented at `/api/v1/docs/`.

`cargo owner --list` **does** work, and is honest about the model: it lists the org's members, so
what you see is the set of people who can actually publish.

## What the registry exposes

| Route | Purpose |
| --- | --- |
| `GET /cargo/config.json` | Registry configuration — download and API base URLs |
| `GET /cargo/{prefix}/{name}` | Sparse index file for a crate (newline-delimited JSON, one line per version) |
| `GET /cargo/api/v1/crates/{name}/{version}/download` | Download a `.crate` |
| `GET /cargo/api/v1/crates?q=` | Search |
| `PUT /cargo/api/v1/crates/new` | Publish |
| `DELETE /cargo/api/v1/crates/{name}/{version}/yank` | Yank |
| `PUT /cargo/api/v1/crates/{name}/{version}/unyank` | Unyank |
| `GET /cargo/api/v1/crates/{name}/owners` | List owners (the org's members) |
| `PUT`/`DELETE /cargo/api/v1/crates/{name}/owners` | **`501`** — see [Crate ownership](#crate-ownership) |

The full protocol reference, including request and response shapes, is served at `/docs/` on your
instance.
