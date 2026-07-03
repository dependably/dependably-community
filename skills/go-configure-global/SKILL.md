---
name: go-configure-global
description: Point your machine-wide Go toolchain at a dependably GOPROXY via go env + ~/.netrc
ecosystem: go
scope: global
inputs:
  - DEPENDABLY_BASE_URL
  - DEPENDABLY_TOKEN
---

## When to use this

You want every `go` command on your machine to fetch modules through your
dependably instance's GOPROXY. Go is **proxy-only** in dependably (no hosted
publish) — you consume modules through it; you do not push to it.

## Inputs

Ask the user for:

1. **DEPENDABLY_BASE_URL** — the base URL of your dependably org, e.g.
   `https://repo.example.com`. Single-tenant uses the bare host; multi-tenant
   puts the org in the subdomain. Trailing slash is stripped.
2. **DEPENDABLY_TOKEN** — created under **Tokens**. The Go toolchain has no
   header-injection mechanism, so credentials are carried in `~/.netrc`.

## Files to write

**1. Point GOPROXY at dependably** (writes to `~/.config/go/env`):

```bash
go env -w GOPROXY=https://repo.example.com/go,direct
```

`,direct` lets Go fall back to the origin for anything the proxy declines. Drop
it (`GOPROXY=https://repo.example.com/go`) to force all fetches through
dependably.

**2. Credentials** — Linux/macOS `~/.netrc`, Windows `%USERPROFILE%\_netrc`:

```
machine repo.example.com login your-username password your-token
```

**3. Private module paths** — skip the public checksum database for modules
served privately by dependably (otherwise `go` tries to verify them against
`sum.golang.org` and fails):

```bash
go env -w GONOSUMCHECK=1
go env -w GOPRIVATE=example.com/private/*
go env -w GONOSUMDB=example.com/private/*
```

Substitutions:
- Replace `https://repo.example.com` with `DEPENDABLY_BASE_URL` (keep `/go`).
- Replace `repo.example.com` in `~/.netrc` with the host portion of the URL.

> **HTTP gotcha.** Go allows a plaintext `http://` GOPROXY without extra flags,
> but `~/.netrc` credentials are sent in the clear — only use `http://` on a
> trusted LAN. `chmod 600 ~/.netrc`.

## Verify it works

```bash
go env GOPROXY                 # should print the dependably URL
GOFLAGS=-mod=mod go get github.com/google/uuid@latest
```

The first fetch records a `first_fetch` entry on the dependably **Activity**
page. A `410`/`404` with a valid module usually means GONOSUMDB/GOPRIVATE is not
set for a private path.

## Reverting

```bash
go env -u GOPROXY GOPRIVATE GONOSUMDB
```

and remove the `machine … dependably` line from `~/.netrc`. Go returns to the
public `proxy.golang.org`.
