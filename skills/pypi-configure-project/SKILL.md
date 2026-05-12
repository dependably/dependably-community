---
name: pypi-configure-project
description: Point pip / Poetry / uv at a dependably org for a single project
ecosystem: pypi
scope: project
inputs:
  - DEPENDABLY_BASE_URL
  - ORG_SLUG
  - DEPENDABLY_TOKEN
---

## When to use this

You have a Python project and want every contributor to install packages from
your dependably instance, regardless of their global pip config. The recipe
covers raw pip, Poetry, and uv.

## Inputs

Ask the user for:

1. **DEPENDABLY_BASE_URL** — e.g. `https://repo.example.com` or
   `http://192.168.1.50:8080`.
2. **ORG_SLUG** — e.g. `default`.
3. **DEPENDABLY_TOKEN** — created in dependably under **Tokens**. PyPI uses
   HTTP Basic auth with `user` as the username and the token as the password.

## Files to write

### Raw pip — `pip.conf` next to your `pyproject.toml` or `requirements.txt`

```ini
[global]
index-url = https://user:${DEPENDABLY_TOKEN}@repo.example.com/o/default/simple/
# Uncomment if served over plain HTTP:
# trusted-host = repo.example.com
```

Run pip with `PIP_CONFIG_FILE=./pip.conf pip install ...` so it picks up the
local file rather than `~/.pip/pip.conf`.

### Poetry — append to `pyproject.toml`

```toml
[[tool.poetry.source]]
name = "dependably"
url = "https://repo.example.com/o/default/simple/"
priority = "primary"
```

Then store the token (Poetry supports keyring-backed auth):

```bash
poetry config http-basic.dependably user ${DEPENDABLY_TOKEN}
```

### uv — append to `pyproject.toml`

```toml
[[tool.uv.index]]
name = "dependably"
url = "https://repo.example.com/o/default/simple/"
default = true
```

Provide credentials via env vars (uv reads them per index name):

```bash
export UV_INDEX_DEPENDABLY_USERNAME=user
export UV_INDEX_DEPENDABLY_PASSWORD=$DEPENDABLY_TOKEN
```

> **HTTP gotcha.** If `DEPENDABLY_BASE_URL` is `http://`, set
> `trusted-host` (pip), `--allow-insecure` (uv `--allow-insecure-host`), or
> equivalent — TLS-strict by default is intentional, override deliberately.

## Verify it works

```bash
pip install requests          # or `poetry add requests`, `uv add requests`
```

A first-fetch activity entry will appear in the dependably **Activity** page.

## .gitignore

If your tooling writes credentials to a local file (`poetry.toml`,
`.pypirc`, `.env`), add it to `.gitignore`. The `pip.conf` shown above is safe
to commit only because it references `${DEPENDABLY_TOKEN}` rather than embedding
the literal value.
