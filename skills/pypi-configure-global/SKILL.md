---
name: pypi-configure-global
description: Point machine-wide pip at a dependably org via the user-level pip.conf
ecosystem: pypi
scope: global
inputs:
  - DEPENDABLY_BASE_URL
  - DEPENDABLY_TOKEN
---

## When to use this

You want every Python tool on your machine (pip, build, twine, …) to default to
your dependably instance, without per-project config.

## Inputs

Ask the user for:

1. **DEPENDABLY_BASE_URL** — the base URL of your dependably org, e.g.
   `https://repo.example.com`. Multi-tenant deployments put the org in the
   subdomain (`https://my-org.repo.example.com`); single-tenant deployments use
   the bare host.
2. **DEPENDABLY_TOKEN** — from dependably **Tokens**.

## File to write

Choose the path for the user's OS:

- Linux / macOS: `~/.config/pip/pip.conf` (newer pip) or `~/.pip/pip.conf`
- Windows: `%APPDATA%\pip\pip.ini`

```ini
[global]
index-url = https://user:<token>@repo.example.com/simple/
# Uncomment if served over plain HTTP:
# trusted-host = repo.example.com
```

> Unlike the project-level recipe, the global file embeds the literal token —
> tighten permissions:
> ```bash
> chmod 600 ~/.config/pip/pip.conf
> ```

## Verify it works

```bash
pip config list               # should show your dependably index-url
pip install requests
```

## Reverting

Either remove the file or run:

```bash
pip config unset --user global.index-url
```

## Note on Poetry / uv

Poetry and uv each maintain their own config independent of pip. The
project-level recipe shows how to point them at dependably; for a global
default, run the same `poetry config` / `UV_INDEX_*` commands at the user
shell-profile level (`~/.bashrc`, `~/.zshrc`).
