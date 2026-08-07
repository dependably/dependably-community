# ADR 0003 — Terraform providers: network mirror, not a provider registry

## Context

Terraform provider installation is the last major package ecosystem Dependably does not proxy, and it
is an expensive one to leave unproxied. A single small stack (`hashicorp/aws` + `hashicorp/random`)
unpacks to 665 MB, and CI runners hold no `.terraform` directory between jobs, so every pipeline run
re-downloads the provider archives from `releases.hashicorp.com`. Operators who block that host to
control egress have no cached path left: `terraform init` fails outright.

Terraform exposes two different server-side protocols, and they are not interchangeable:

- The **Provider Registry Protocol** (what `registry.terraform.io` speaks) resolves a provider
  source address to a version list and, per version and platform, a `download_url` pointing at a
  *separate* host — in HashiCorp's case `releases.hashicorp.com`. A registry implementation does not
  serve the archives; it hands out URLs to them.
- The **Provider Network Mirror Protocol** replaces the registry *and* the download host for the
  providers it covers, serving both metadata and archives from one base URL. It is selected in the
  CLI configuration (`provider_installation { network_mirror { url = … } }`), so it applies to every
  provider a configuration requests, independent of each provider's own source address.

There is no OCI-based path. `provider_installation` accepts only `direct`, `filesystem_mirror`,
`network_mirror`, and `dev_overrides`; an `oci_mirror` block is rejected as an unknown installation
method. Serving providers as OCI artifacts from Dependably's existing `/v2/` surface therefore
cannot work, however convenient that would have been.

## Decision

Dependably implements the **Provider Network Mirror Protocol**, not the Provider Registry Protocol.

The mirror is a three-endpoint surface, rooted at a configurable base URL and keyed by the
provider's fully-qualified source address (`<hostname>/<namespace>/<type>`):

| Request | Response |
| --- | --- |
| `GET <base>/<hostname>/<namespace>/<type>/index.json` | `{"versions": {"3.9.0": {}}}` |
| `GET <base>/<hostname>/<namespace>/<type>/<version>.json` | `{"archives": {"linux_amd64": {"url": "…zip", "hashes": ["zh:…"]}}}` |
| `GET <base>/<hostname>/<namespace>/<type>/<archive>.zip` | the provider archive |

The `url` in a version document is resolved **relative to that document**, which keeps the archive
addressable without the mirror having to know its own external base URL.

**The mirror serves no `h1:` hash.** Terraform's dirhash is a base64 SHA-256 over a
canonically-sorted listing of the archive's member hashes — an algorithm with no C# implementation in
this codebase and no independent value outside this one field. For a *direct client* omitting it
costs nothing, because the lock file remains the anchor: Terraform computes `h1:` from the archive it
actually downloaded and compares it against `.terraform.lock.hcl`, so a mirror serving anything other
than byte-identical upstream content fails that comparison on the client. Configurations with no
committed lock file get no verification — the same exposure they already accept when installing
directly, since the lock file is what records the expected hashes in the first place.

**The mirror does serve `zh:`, because a chained edge has no lock file to fall back on.** The
`hashes` field is where a downstream mirror gets its fetch-time checksum, and it is its *only*
source: on the mirror-protocol fetch path the archive URL is resolved relative to the version
document, and nothing else in that document describes the bytes. A version document with no hashes
therefore leaves a chained edge hashing whatever arrived, storing it under a coordinate-addressed
blob key, and re-serving it to every subsequent `terraform init` as authoritative.

The lock-file argument above does not cover that, for two reasons. The lock file is a *client-side*
control and does not protect the edge's own cache, whose `cache_artifact` row is what the edge's
supply-chain gates then read; and it only applies to providers already pinned in a committed lock
file, since a first-time provider add records whatever the mirror served as the expected hash.

`zh:` costs nothing to emit and closes that: it is the archive's SHA-256 in hex, which the cache
plane already holds on `cache_artifact.content_hash` for every archive this instance has fetched. No
`h1:` implementation is required, and the ADR's stated reason for omitting the field — the cost of
the dirhash — does not apply to it. A version document therefore carries `zh:` for each platform this
instance has cached, and otherwise passes through whatever hashes its own upstream mirror published,
so a hash propagates down a chain of any depth.

**A mirror that publishes no `zh:` is trusted on first use, not refused.** The archive is fetched,
hashed, and the SHA-256 recorded as an observed fact rather than a verified one — the same posture
apk takes, where no full-file digest exists to verify against. This is a deliberate exception to the
"a security gate never degrades to allow because its input signal is missing" rule, on the grounds
that there is no gate here to degrade: `hashes` is optional in the protocol, no Terraform mirror is
obliged to publish it, and refusing a mirror that omits it would refuse a legitimate topology on a
signal that was never promised. Chaining Dependably to Dependably — the topology the rule most wants
to protect — always has the hash. Making the strict posture available for a third-party mirror needs
a per-org policy setting alongside the other `verify_*` modes, which is a larger change than this
one.

**HTTPS is mandatory.** Terraform rejects an `http://` mirror URL during CLI-configuration parsing,
before any request is made. Plain-HTTP self-hosted deployments — supported for other ecosystems and
documented in `skills/` — cannot serve this one, and the client guide says so rather than leaving
operators to discover it as a config-parse error.

**Upstream fetches span two hosts.** Filling the cache means speaking the registry protocol to
`registry.terraform.io` to resolve versions and per-platform download URLs, then fetching the archive
from whatever host those URLs name (`releases.hashicorp.com` for HashiCorp's own providers). This is
unlike every other ecosystem Dependably proxies, where one upstream host serves both metadata and
artefacts, and it is why the `upstream_registry` row carries the registry host while the archive host
is discovered per version rather than configured.

**Serving one protocol and fetching another makes Dependably unable to chain itself by URL alone.**
For every other ecosystem an upstream row can name Dependably or the public registry
interchangeably, because the served and fetched protocols coincide; the row is just a URL. Here they
do not, so an upstream row carries `upstream_protocol` to say which shape the fetcher should use —
unset for the registry protocol, `'mirror'` for a Dependably (or any other network mirror) upstream.
The value cannot be inferred: the two protocols share no path, so a wrong guess fails every fetch
rather than degrading. An edge node's row is seeded with `'mirror'` automatically.

A mirror upstream also admits providers on different grounds. A registry upstream is matched by
host, because the requested source address is client-chosen and must never become a host the server
connects to. On a mirror upstream that address is a path segment beneath the configured base and
never a host, so any provider is forwarded and the upstream mirror applies its own admission — the
correct layering for a chained node. What a mirror upstream must *not* be trusted with is where to
fetch bytes: an archive URL is resolved relative to the version document and required to stay
beneath the configured base, and — because a published URL that passes that check could still `302`
elsewhere — every redirect hop of the fetch is pinned to the same base as well (a containment option
threaded to `SsrfAwareRedirectHandler`, on top of the SSRF-range check every hop already gets). A
mirror therefore cannot redirect the fetch at a host of its choosing the way the registry protocol
legitimately does, by URL or by redirect. The registry protocol passes no containment base, because
its `download_url` is expected to name a release host the upstream chose.

## Consequences

- Provider *modules* are out of scope. The Module Registry Protocol is a separate surface with no
  network-mirror equivalent, so `terraform init` still reaches the public registry for modules. The
  egress this ADR addresses is provider archives, which is where the bytes are.
- The mirror covers every provider a configuration requests once configured, including providers
  whose source address is not `registry.terraform.io`. Dependably must return a well-formed empty
  version list for providers it cannot resolve upstream rather than an error, or a single unresolvable
  provider fails the whole `init`.
- Because the protocol is selected by CLI configuration rather than by the provider source address,
  no change to Terraform configurations is required — only a `.terraformrc` and the environment
  variable that points at it. Existing `.terraform.lock.hcl` files keep working unchanged.
- `terraform:1.10` is sufficient on the client side; the protocol needs no newer CLI. Operators do not
  have to upgrade Terraform to adopt the mirror.
- A provider source address is canonicalized to lowercase where it is parsed, because Terraform
  matches addresses case-insensitively. Two spellings would otherwise mint two blob keys, two
  `cache_artifact` rows and two source pins, and an operator's block on one would silently not apply
  to the other.
- The source pin binds a provider to the **registry** authority that resolved it, not to the host its
  archive came from. On the registry protocol those differ by design: `download_url` names a shared
  release CDN that serves every provider of a given publisher, so pinning on it would bind unrelated
  providers to one authority — no dependency-confusion signal, and a false block whenever a
  legitimate registry rotates its release host. The archive URL is still recorded on the cache-plane
  row, which is where "what host served these bytes" belongs.
- For the same reason the upstream's credential stops at the configured authority. A registry-protocol
  `download_url` points at a host the *upstream* chose; attaching the org's token to that request
  would disclose it to a third party.
