---
name: docker-configure-global
description: Log Docker / any OCI client in to a dependably registry via docker login
ecosystem: oci
scope: global
inputs:
  - DEPENDABLY_BASE_URL
  - DEPENDABLY_TOKEN
---

## When to use this

You want to pull and push container images through your dependably instance's
OCI registry. OCI is authenticated per-host by the Docker/containerd credential
store, so there is no meaningful "project" scope — this one recipe covers every
repo on the machine (and CI).

## Inputs

Ask the user for:

1. **DEPENDABLY_BASE_URL** — the base URL of your dependably org, e.g.
   `https://repo.example.com`. Single-tenant uses the bare host; multi-tenant
   puts the org in the subdomain. Only the **host** matters to Docker — the
   registry lives at `/v2/` per the OCI Distribution Spec, with no org path
   segment.
2. **DEPENDABLY_TOKEN** — created under **Tokens**. Dependably advertises Basic
   auth (there is no Bearer token-endpoint realm), so the token is the password.

## Configure

```bash
# Log in (host only — no scheme, no path). Any username is accepted:
docker login repo.example.com
#   Username: your-username
#   Password: <paste your dependably token>

# Pull and push use the host as the image prefix:
docker pull repo.example.com/<image>:<tag>
docker tag  <local-image> repo.example.com/<image>:<tag>
docker push repo.example.com/<image>:<tag>
```

Substitutions:
- Replace `repo.example.com` with the **host** of `DEPENDABLY_BASE_URL` (drop
  `https://` and any trailing slash).

> **HTTP gotcha.** For a plain-`http://` instance, Docker refuses the registry
> until you mark it insecure. Add to `/etc/docker/daemon.json`:
> ```json
> { "insecure-registries": ["repo.example.com:PORT"] }
> ```
> then `systemctl restart docker`. (Podman: add the host under
> `[[registry]] insecure = true` in `/etc/containers/registries.conf`.)

## Verify it works

```bash
docker login repo.example.com    # "Login Succeeded"
docker pull repo.example.com/library/alpine:3.20   # proxied through dependably
```

The first pull of a not-yet-cached image records a `first_fetch` entry on the
dependably **Activity** page. A `401` after login means the token is wrong; a
`http: server gave HTTP response to HTTPS client` error is the insecure-registry
gotcha above.

## CI

Non-interactive login (never echoes the token to logs):

```bash
echo "$DEPENDABLY_TOKEN" | docker login repo.example.com -u ci --password-stdin
```

## Reverting

```bash
docker logout repo.example.com
```

and remove the `insecure-registries` entry from `daemon.json` if you added one.
