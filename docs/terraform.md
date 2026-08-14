# Terraform provider mirror

Dependably serves Terraform providers over the **Provider Network Mirror Protocol** at
`/terraform/`. Once a client is pointed at it, `terraform init` resolves and downloads every
provider through Dependably instead of reaching `registry.terraform.io` and
`releases.hashicorp.com`.

This is the ecosystem where proxying pays off most visibly. A stack using `hashicorp/aws` and
`hashicorp/random` unpacks to roughly 665 MB of provider binaries, and CI runners keep no
`.terraform` directory between jobs — so without a mirror, every pipeline re-downloads the
archives.

## Client setup

Provider installation is configured in Terraform's **CLI configuration**, not per project. There is
no per-repository file to edit and no change to any `required_providers` block.

Create `~/.terraformrc` (Linux/macOS) or `%APPDATA%\terraform.rc` (Windows):

```hcl
provider_installation {
  network_mirror {
    url = "https://dependably.example.com/terraform/"
  }
}
```

In CI, where `$HOME` may not be the runner's, point Terraform at the file explicitly:

```bash
export TF_CLI_CONFIG_FILE=/path/to/terraformrc
terraform init
```

For a multi-tenant deployment, use the org's subdomain
(`https://my-org.dependably.example.com/terraform/`) — the ecosystem path is unchanged.

### HTTPS is mandatory

Terraform rejects an `http://` mirror URL **while parsing the CLI configuration**, before it makes
any request:

```
Cannot use "http://…" as a URL for a network provider mirror: the mirror must be at an https: URL.
```

Unlike the other ecosystems, a plain-HTTP self-hosted deployment cannot serve this one. Terminate
TLS in front of Dependably before configuring the mirror.

### Authentication

When the org has `AnonymousPull` disabled, the mirror answers `401` with a
`WWW-Authenticate: Bearer` challenge. Terraform's network mirror does not send credentials of its
own, so put them in the URL's userinfo:

```hcl
url = "https://user:<token>@dependably.example.com/terraform/"
```

Mint tokens in the web UI under **Tokens** (a personal token) or **Settings → Service tokens**
(for CI). The username is ignored; only the token is checked.

## Lock files keep working

Existing `.terraform.lock.hcl` files need no change and no `-upgrade` run. Terraform recomputes each
provider's `h1:` hash from the archive it downloads and verifies it against the lock file, so a
lock recorded against the public registry validates the mirrored copy — the bytes are identical.

That is also why the mirror does not emit the protocol's optional `hashes` field: the lock file is
what detects substituted content, and it does so whether or not the mirror asserts a hash. A
configuration with no committed lock file gets no verification — the same exposure it already
accepts when installing directly, since the lock file is what records expected hashes in the first
place.

## What is mirrored, and what is not

**Providers are mirrored. Modules are not.** Terraform's module registry is a separate protocol with
no network-mirror equivalent, so `terraform init` still reaches the public registry for any
`module` block sourced from a registry. Provider archives are where the bytes are, so this still
removes the large majority of egress — but a deployment that must eliminate registry traffic
entirely needs to vendor modules or source them from Git.

**Only configured registry hosts are mirrored.** A provider is addressed by its own source address
(`{hostname}/{namespace}/{type}`), so the request path always names a host the client chose.
Dependably matches that host against the org's configured upstreams rather than fetching from it —
otherwise any caller could steer a server-side request at an arbitrary host. To mirror a provider
from a private registry, add that registry under **Settings → Proxy → Upstream registries**.

## Why a mirror and not a registry

Terraform exposes two server-side protocols and they are not interchangeable:

- The **Provider Registry Protocol** (what `registry.terraform.io` speaks) resolves a provider to a
  version list and, per version and platform, a `download_url` pointing at a *different* host. A
  registry implementation hands out URLs; it does not serve archives. Implementing it would have
  left the bytes still coming from HashiCorp.
- The **Provider Network Mirror Protocol** replaces both halves, serving metadata and archives from
  one base URL.

There is also no OCI route. Terraform's `provider_installation` accepts only `direct`,
`filesystem_mirror`, `network_mirror`, and `dev_overrides` — an `oci_mirror` block is rejected as an
unknown installation method — so serving providers as OCI artifacts from the existing `/v2/`
surface is not possible.

Full reasoning: [`ADR-terraform-provider-network-mirror`](https://gitlab.northwardlabs.ca/moonlitlabs/dependably-community.spec/-/blob/main/specs/adr/ADR-terraform-provider-network-mirror.md).

## Edge nodes

Edge nodes chain Terraform through the master like every other ecosystem: point the client at the
edge's `/terraform/` and it serves from its own cache, filling from the master on a miss.

Terraform is the one ecosystem whose edge upstream row has to say which protocol the master speaks.
Everywhere else the master serves the same protocol the edge's fetcher speaks, so the row is only a
URL. Here the master serves the *network mirror* protocol while the fetcher's default is the
*registry* protocol, so the seeded row carries `upstream_protocol = 'mirror'`. This is automatic —
`EdgeUpstreamSeeder` writes it on every boot — and needs no operator action.

Two consequences worth knowing:

- **The master stays authoritative over what may be mirrored.** An edge forwards any provider source
  address to the master rather than filtering by hostname itself, because on this path the hostname
  is a path segment beneath the master URL and never a host the edge connects to. Which registries
  may be mirrored is therefore configured once, on the master.
- **Enforcement reaches edge sites.** The archive is fetched through the edge's own proxy pipeline,
  so the block gate, reserved namespaces, source pinning and `cache_artifact` recording all apply at
  the edge and not only at the master.

## Supply-chain controls

Provider fetches run the same record → scan → gate sequence as npm and PyPI:

- **Source pinning** binds a provider to the registry host that first served it and refuses a later
  serve from a different one — the dependency-confusion guard.
- **Checksum verification** against the `shasum` the registry reports for that exact platform,
  before the archive is stored.
- **Block gate** on first fetch *and* on every cache hit, so an operator block or a revocation
  applies to an already-cached provider.
- **Reserved namespaces** follow `local_only` semantics: a reserved provider address never pulls
  from upstream.

Two controls behave differently here, both deliberately:

- **No OSV advisories.** OSV publishes no Terraform provider ecosystem, so vulnerability scanning
  finds nothing to match. Providers are therefore never queried and never stamped as scanned: the
  UI reports them as **No advisory feed**, never as clean, so an artefact with zero advisory
  coverage cannot be mistaken for one screened against a live feed. Every other gate still applies.
- **No declared licences.** Provider archives carry no licence manifest, so Terraform is absent from
  the declared-licence ecosystems: under `license_enforcement_mode=block`, recording zero licences
  is the normal case rather than an unknown-licence signal, and does not block.

## Troubleshooting

**`Cannot use "http://…" as a URL for a network provider mirror`** — Terraform rejects a
plain-HTTP `network_mirror.url` while parsing the CLI configuration, before any request is made.
See [HTTPS is mandatory](#https-is-mandatory): terminate TLS in front of Dependably before
configuring the mirror.

**A provider resolves to no installable versions** — `index.json` answers `404` when the
provider's hostname is not among the org's configured upstream registries (see
[What is mirrored, and what is not](#what-is-mirrored-and-what-is-not)). Terraform then reports
the provider has no available versions, the same as if it did not exist at all, rather than a
clear "this registry is not configured" error. Add the registry under **Settings → Proxy →
Upstream registries**, or check `required_providers` for a typo in the hostname.

**Only some platforms' archives seem to be cached** — a version document lists every platform the
upstream registry advertises for that version, but each archive is fetched from upstream, verified,
and cached only on its own first download. Running `terraform init` on Linux does not warm the
macOS arm64 archive; the next `init` on that platform is what fetches it.
