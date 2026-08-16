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
   Scope it for what you intend to do: pulling needs `pull:oci` or
   `read:artifact` (the **pull** preset); pushing needs `publish:oci` (the
   **push** preset, which mints `publish:*`, or **both**). A push token is not a
   pull token — a publish-only token may probe a blob with `HEAD` so a push can
   skip layers the registry already holds, but it cannot `docker pull` or list
   tags. Use the **both** preset for a credential that does each.

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
dependably **Activity** page. A `http: server gave HTTP response to HTTPS client`
error is the insecure-registry gotcha above.

**`401` vs `403` after a successful login.** These are different faults and the
distinction is the whole diagnosis:

- **`401 Authentication required.`** — the credential did not resolve: wrong
  value, expired, revoked, or belonging to another tenant.
- **`403 Insufficient scope: … required.`** — the credential resolved fine and
  is scoped wrong for this route. The message also names what the token *does*
  grant, so compare the two lists before re-minting anything.

`docker login` succeeding tells you neither: the `/v2/` ping only checks that the
credential resolves, and performs no capability check at all. A pull-scoped token
logs in cleanly and then fails at the first write.

If the 403 reports grants you did not intend for that credential, suspect the
client, not the token — `docker login` adds an entry to `~/.docker/config.json`
rather than replacing whatever is already there, so a pre-seeded read credential
(a CI runner's `DOCKER_AUTH_CONFIG`, for instance) can coexist with the publish
one under a differently-spelled key for the same host, and which one is sent is
then unspecified. `jq -r '.auths | keys[]' ~/.docker/config.json` prints the keys
without printing any secret; more than one entry for the same host is the bug.
Log out or remove the file before logging in with the credential you want used.

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
