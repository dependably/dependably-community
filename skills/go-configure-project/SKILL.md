---
name: go-configure-project
description: Scope a dependably GOPROXY to a single Go repo via a committed .envrc / CI env
ecosystem: go
scope: project
inputs:
  - DEPENDABLY_BASE_URL
  - DEPENDABLY_TOKEN
---

## When to use this

You want builds of one Go repository to fetch modules through dependably, without
changing the machine-wide `go env`. The Go toolchain has no per-project proxy
file (GOPROXY is an environment variable), so "project scope" means committing a
repo-local environment that sets `GOPROXY` for anyone building inside the repo —
via `direnv` (an `.envrc` auto-loader) locally and env vars in CI.

## Inputs

Ask the user for:

1. **DEPENDABLY_BASE_URL** — the base URL of your dependably org, e.g.
   `https://repo.example.com` or `http://192.168.1.50:8080`.
2. **DEPENDABLY_TOKEN** — created under **Tokens**. Keep it out of source
   control: reference it from an env var, never commit the literal.

## Files to write

**1. `.envrc` in the repo root** (loaded by direnv; commit this — it holds no
secret):

```bash
export GOPROXY=https://repo.example.com/go,direct
export GOPRIVATE=example.com/private/*
export GONOSUMDB=example.com/private/*
# Token comes from the environment, never committed:
export GONOSUMCHECK=1
```

Run `direnv allow` once after creating it.

**2. Credentials** stay in each developer's `~/.netrc` (see the
`go-configure-global` skill) — Go reads netrc regardless of scope:

```
machine repo.example.com login your-username password your-token
```

**3. CI** — set the same values as job env vars and write a netrc from a secret,
e.g. GitHub Actions:

```yaml
env:
  GOPROXY: https://repo.example.com/go,direct
  GOPRIVATE: example.com/private/*
steps:
  - run: echo "machine repo.example.com login ci password ${{ secrets.DEPENDABLY_TOKEN }}" > ~/.netrc && chmod 600 ~/.netrc
```

Substitutions:
- Replace `https://repo.example.com` with `DEPENDABLY_BASE_URL` (keep `/go`).
- Replace `repo.example.com` in the netrc host with the URL's host.

> **HTTP gotcha.** With an `http://` base URL, netrc credentials travel in the
> clear — only on a trusted LAN.

## Verify it works

```bash
direnv allow                   # loads .envrc
go env GOPROXY                 # prints the dependably URL inside the repo
go mod download
```

## Never commit the token

`.envrc` holds only non-secret env values. The token lives in `~/.netrc` locally
and in a CI secret (`DEPENDABLY_TOKEN`) in the pipeline — never in the repo.

## Reverting

Delete `.envrc` (`direnv` reloads automatically) and remove the CI env/netrc
step. The build uses the machine-wide `go env` again.
