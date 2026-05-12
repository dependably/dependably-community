---
name: npm-configure-project
description: Point npm at a dependably org for a single repository via .npmrc
ecosystem: npm
scope: project
inputs:
  - DEPENDABLY_BASE_URL
  - ORG_SLUG
  - NPM_TOKEN
---

## When to use this

You have a Node.js project and want anyone who clones it to install dependencies
from your dependably instance — without changing global settings on each
machine. The token is read from an env var so no secret is committed.

## Inputs

Ask the user for:

1. **DEPENDABLY_BASE_URL** — e.g. `https://repo.example.com` or
   `http://192.168.1.50:8080`. Trailing slash will be stripped.
2. **ORG_SLUG** — e.g. `default`.
3. **NPM_TOKEN** — created in dependably under **Tokens** (any scope). Keep
   it out of source control; reference it as `${NPM_TOKEN}` in the file.

## File to write

Create `.npmrc` in the repository root (alongside `package.json`):

```ini
registry=https://repo.example.com/o/default/npm/
//repo.example.com/o/default/npm/:_authToken=${NPM_TOKEN}
# Uncomment the line below if dependably is served over plain HTTP:
# strict-ssl=false
```

Substitutions:
- Replace `repo.example.com` with the host portion of `DEPENDABLY_BASE_URL`.
- Replace `default` with `ORG_SLUG`.
- Keep `${NPM_TOKEN}` literal — npm reads it from the environment.

> **HTTP gotcha.** If your `DEPENDABLY_BASE_URL` starts with `http://` (no `s`),
> uncomment the `strict-ssl=false` line. Without it, npm will refuse to talk to
> the registry on most platforms.

## Verify it works

```bash
export NPM_TOKEN=<paste the token here>
npm install is-odd            # public package proxied through dependably
npm view is-odd registry      # should print the dependably URL
```

The first install records a `first_fetch` activity entry in the dependably
**Activity** page — check there to confirm the proxy is being hit.

## Add to .gitignore

If you set `NPM_TOKEN` via a `.env` file, add `.env` to `.gitignore` — the
`.npmrc` itself is safe to commit because it only references the variable.
