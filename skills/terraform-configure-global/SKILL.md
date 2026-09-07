---
name: terraform-configure-global
description: Point Terraform provider installation at a dependably network mirror via ~/.terraformrc
ecosystem: terraform
scope: global
inputs:
  - DEPENDABLY_BASE_URL
  - DEPENDABLY_TOKEN
---

## When to use this

You want `terraform init` to fetch providers through your dependably instance
instead of registry.terraform.io. `provider_installation` is CLI-level
configuration and applies to every provider every configuration requests, so
there is no per-repository file — this one recipe covers every Terraform project
on the machine.

## Inputs

Ask the user for:

1. **DEPENDABLY_BASE_URL** — the base URL of your dependably org, e.g.
   `https://repo.example.com`. Tenancy is host-resolved: single-tenant
   deployments use the bare host; multi-tenant deployments put the org in the
   subdomain (`https://my-org.repo.example.com`).
   **This must be `https://`** — see the HTTP gotcha below, which for Terraform
   is a hard blocker rather than a warning.
2. **DEPENDABLY_TOKEN** — created in dependably under **Tokens**. Terraform is
   install-only on this registry, so a **pull** token is enough.

## File to write

Create `~/.terraformrc` in your home directory (`%APPDATA%\terraform.rc` on
Windows):

```hcl
provider_installation {
  network_mirror {
    url = "https://user:<token>@repo.example.com/terraform/"
  }
}
```

Substitutions:
- Replace `https://repo.example.com` with `DEPENDABLY_BASE_URL`.
- Replace `<token>` with `DEPENDABLY_TOKEN`. The `user` half is filler —
  dependably authenticates on the token alone and never reads the username.
- Keep the **trailing slash** on the URL. Terraform appends the provider path to
  it verbatim.

This file holds the token in clear text. It lives in your home directory, not a
repository, so keep it that way and restrict it:

```bash
chmod 600 ~/.terraformrc
```

To point one shell at dependably without changing the machine default, write the
same content elsewhere and set `TF_CLI_CONFIG_FILE=/path/to/that/file`.

> **HTTP gotcha — this one cannot be worked around.** Terraform rejects an
> `http://` `network_mirror` URL while *parsing* the file, before it makes any
> request, and there is no client-side override. A plain-HTTP dependably
> deployment simply cannot be used as a Terraform mirror: terminate TLS in front
> of it first.

Terraform is **proxy-only** on this registry — there is no hosted publish path,
so there is nothing to configure for pushing.

## Existing lock files keep working

You do not need to delete `.terraform.lock.hcl`. Terraform recomputes each
provider's `h1:` hash from the archive it downloads and verifies it against the
lock, and dependably serves the same bytes the upstream registry does — so a
lock recorded against registry.terraform.io still verifies through the mirror.

## Verify it works

```bash
terraform init
terraform providers
```

`init` proves reachability, authentication and resolution in one step;
`providers` prints where each one came from. A `403 Forbidden` during `init` is a
credential that resolved but is scoped wrong; a parse error naming the mirror URL
is the HTTP gotcha above.

## Reverting

```bash
rm ~/.terraformrc
rm -rf .terraform .terraform.lock.hcl   # in each project, to re-resolve upstream
terraform init
```
