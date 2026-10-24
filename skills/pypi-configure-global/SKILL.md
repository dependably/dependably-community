---
name: pypi-configure-global
description: Point machine-wide pip and uv at a dependably org via the user-level pip.conf and uv.toml
ecosystem: pypi
scope: global
inputs:
  - DEPENDABLY_BASE_URL
  - DEPENDABLY_TOKEN
---

## When to use this

You want every Python tool on your machine (pip, build, twine, uv, …) to default
to your dependably instance, without per-project config. pip and uv read
separate config files, so set up both if you use both.

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

## uv

uv never reads `pip.conf`. Inside a project it takes its index from
`pyproject.toml` (see the project-level recipe), but `uv tool install`, `uvx`
and `uv pip` outside a project have no project file, so with only the pip
config above they still go straight to pypi.org. Give uv its own user-level
config:

- Linux / macOS: `~/.config/uv/uv.toml`
- Windows: `%APPDATA%\uv\uv.toml`

```toml
[[index]]
name = "dependably"
url = "https://repo.example.com/simple/"
default = true
```

The table is `[[index]]` in `uv.toml`, not the `[[tool.uv.index]]` form used in
`pyproject.toml`. Then export the credentials for that index from the shell
profile (`~/.bashrc`, `~/.zshrc`):

```bash
export UV_INDEX_DEPENDABLY_USERNAME=user
export UV_INDEX_DEPENDABLY_PASSWORD=<token>
```

The exports only supply credentials for an index named `dependably`; without
the `uv.toml` above they configure nothing.

Large wheels (`torch`, `triton`, CUDA libraries) can outlast uv's 30-second
HTTP timeout on a cold cache. Raise it if downloads time out:

```bash
export UV_HTTP_TIMEOUT=300
```

Verify with `uvx ruff --version`. To revert, delete the `[[index]]` block and
unset the variables.

## Poetry

Poetry has no machine-wide default index: sources are declared per project in
`pyproject.toml` (see the project-level recipe). `poetry config
http-basic.dependably user <token>` is user-level, so it only needs running
once per machine.
