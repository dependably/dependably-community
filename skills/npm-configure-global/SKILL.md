---
name: npm-configure-global
description: Point your machine-wide npm at a dependably org via ~/.npmrc
ecosystem: npm
scope: global
inputs:
  - DEPENDABLY_BASE_URL
  - NPM_TOKEN
---

## When to use this

You want every project on your machine to install from your dependably instance
by default, without touching each repo's `.npmrc`. The token lives in your home
directory only — not in source control.

## Inputs

Ask the user for:

1. **DEPENDABLY_BASE_URL** — the base URL of your dependably org, e.g.
   `https://repo.example.com`. Multi-tenant deployments put the org in the
   subdomain (`https://my-org.repo.example.com`); single-tenant deployments use
   the bare host.
2. **NPM_TOKEN** — created in dependably under **Tokens**.

## File to write

Linux / macOS: `~/.npmrc`
Windows: `%USERPROFILE%\.npmrc`

```ini
registry=https://repo.example.com/npm/
//repo.example.com/npm/:_authToken=<token>
# Uncomment the line below if dependably is served over plain HTTP:
# strict-ssl=false
```

> Unlike the project-level recipe, the global file embeds the literal token
> because it is not under source control. Keep file permissions tight:
> ```bash
> chmod 600 ~/.npmrc
> ```

## Verify it works

```bash
npm config get registry       # should print the dependably URL
npm ping                      # 200 from /-/ping → registry is reachable
npm whoami                    # prints your email; `service:<name>` for service tokens
npm install is-odd
```

If `npm ping` succeeds but `npm whoami` returns "ENEEDAUTH", your token line in
`~/.npmrc` is missing or malformed — fix that before running `npm install`.

## Reverting

Either delete `~/.npmrc` or run:

```bash
npm config delete registry --location=user
npm config delete //repo.example.com/npm/:_authToken --location=user
```
