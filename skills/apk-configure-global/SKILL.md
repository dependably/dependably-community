---
name: apk-configure-global
description: Point Alpine apk at a dependably org via /etc/apk/repositories
ecosystem: apk
scope: global
inputs:
  - DEPENDABLY_BASE_URL
  - DEPENDABLY_TOKEN
---

## When to use this

You want `apk` on an Alpine host (or in an Alpine container image) to resolve
packages through your dependably instance. `/etc/apk/repositories` is a
machine-level file, so there is no "project" scope — this one recipe covers the
whole system.

## Inputs

Ask the user for:

1. **DEPENDABLY_BASE_URL** — the base URL of your dependably org, e.g.
   `https://repo.example.com` or `http://192.168.1.50:8080`. Tenancy is
   host-resolved: single-tenant deployments use the bare host; multi-tenant
   deployments put the org in the subdomain
   (`https://my-org.repo.example.com`).
2. **DEPENDABLY_TOKEN** — created in dependably under **Tokens**. apk is
   install-only on this registry, so a **pull** token is enough.

## File to write

Replace `/etc/apk/repositories` (or append these lines and comment out the
upstream ones):

```ini
https://user:<token>@repo.example.com/apk/v3.22/main
https://user:<token>@repo.example.com/apk/v3.22/community
```

Substitutions:
- Replace `https://repo.example.com` with `DEPENDABLY_BASE_URL`.
- Replace `<token>` with `DEPENDABLY_TOKEN`. The `user` half is filler —
  dependably authenticates on the token alone and never reads the username.
- Replace `v3.22` with the Alpine release you are building against.

**URL userinfo is apk's only authentication mechanism** — it has no credential
file and no auth header option, so the token necessarily sits in this file in
clear text. Keep it off the machine's image layers where you can, and restrict
it:

```bash
chmod 600 /etc/apk/repositories
```

> **HTTP gotcha.** apk will use a plain-`http://` repository, so the token
> travels in clear text on every request. Use it only on a trusted network, or
> terminate TLS in front of dependably.

apk is **proxy-only** on this registry: there is no hosted publish path, so
there is nothing to configure for pushing.

## Verify it works

```bash
apk update
apk policy busybox
```

`update` proves reachability and authentication (it fetches `APKINDEX`);
`policy` proves resolution and prints which repository a package resolves from.

## In a Dockerfile

Write the file before the first `apk add`, and use a build secret rather than a
literal so the token does not land in an image layer:

```dockerfile
RUN --mount=type=secret,id=dependably_token \
    printf 'https://user:%s@repo.example.com/apk/v3.22/main\n' \
      "$(cat /run/secrets/dependably_token)" > /etc/apk/repositories \
 && apk update
```

## Reverting

Restore the distribution defaults:

```bash
printf 'https://dl-cdn.alpinelinux.org/alpine/v3.22/main\nhttps://dl-cdn.alpinelinux.org/alpine/v3.22/community\n' > /etc/apk/repositories
apk update
```
