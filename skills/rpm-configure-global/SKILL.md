---
name: rpm-configure-global
description: Point dnf / yum at a dependably org via /etc/yum.repos.d/dependably.repo
ecosystem: rpm
scope: global
inputs:
  - DEPENDABLY_BASE_URL
  - DEPENDABLY_TOKEN
---

## When to use this

You want dnf or yum on this machine (or in a container image) to resolve RPMs
through your dependably instance. A yum repository definition is a machine-level
file, so there is no meaningful "project" scope — this one recipe covers every
build on the host.

## Inputs

Ask the user for:

1. **DEPENDABLY_BASE_URL** — the base URL of your dependably org, e.g.
   `https://repo.example.com` or `http://192.168.1.50:8080`. Tenancy is
   host-resolved: single-tenant deployments use the bare host; multi-tenant
   deployments put the org in the subdomain
   (`https://my-org.repo.example.com`). Trailing slash will be stripped.
2. **DEPENDABLY_TOKEN** — created in dependably under **Tokens**. Dependably
   authenticates on the token alone, so it goes in the `password` field; the
   `username` is filler and any value works.

## File to write

Create `/etc/yum.repos.d/dependably.repo` (root-owned, machine-level):

```ini
[dependably]
name=dependably
baseurl=https://repo.example.com/rpm/
enabled=1
gpgcheck=0
username=user
password=<token>
```

Substitutions:
- Replace `https://repo.example.com` with `DEPENDABLY_BASE_URL`.
- Replace `<token>` with `DEPENDABLY_TOKEN`.

This file **holds the token in clear text**. It lives outside any repository, so
keep it that way — never copy it into a source tree, and restrict it:

```bash
sudo chmod 600 /etc/yum.repos.d/dependably.repo
```

`gpgcheck=0` is deliberate. Package signature trust in dependably is configured
per-org under **Settings → Trust Anchors**, and an upstream-fetched GPG key is
never the trust root. Turn `gpgcheck=1` on only once you have imported the key
you actually trust with `rpm --import`.

> **HTTP gotcha.** dnf will talk to a plain-`http://` repository without
> complaint, which means the token travels in clear text on every request. Use
> it only on a trusted network, or put TLS in front of dependably.

## Publishing

There is no config file for publishing — an upload is one request:

```bash
curl -u user:$DEPENDABLY_TOKEN --upload-file pkg.rpm https://repo.example.com/rpm/upload
```

That needs a token with the **push** preset; the read recipe above only needs
**pull**. Hosted publish also requires `Rpm:UpstreamMode=merged` — under the
default `passthrough` the instance forwards upstream repodata verbatim and
refuses a hosted publish.

## Verify it works

```bash
dnf clean all
dnf repolist dependably
dnf --disablerepo='*' --enablerepo=dependably list available
```

`repolist` proves reachability and authentication; `list available` proves
resolution. A `Status code: 401` from `repolist` is the credential; a `403` is a
credential that resolved but is scoped wrong.

## Reverting

```bash
sudo rm /etc/yum.repos.d/dependably.repo
sudo dnf clean all
```
