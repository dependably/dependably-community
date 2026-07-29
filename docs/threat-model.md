# Threat model

A one-page orientation for contributors: who the adversaries are, where the trust
boundaries sit, and what dependably deliberately does **not** try to defend. Detailed
per-mechanism reasoning lives next to the code (search the source for the named services)
and in the ADRs under [`docs/adr/`](adr/); this page ties those decisions to the boundaries
they defend so a new contributor knows which invariants are load-bearing.

dependably is a self-hosted, multi-tenant artifact registry and upstream-proxy. Three of its
boundaries *are* the product — the tenant boundary, the upstream-proxy boundary, and the
anonymous-pull boundary — so a change that weakens one is a change to the security posture,
not a refactor.

## Trust boundaries

Each boundary names its adversary, the primary defence, and the code that enforces it.

### 1. Anonymous internet → registry

- **Adversary:** an unauthenticated caller reaching any public route.
- **Defence:** every management-plane action carries an explicit authorization decision
  (enforced by `AuthorizationDecisionComplianceTests`; there is no `FallbackPolicy`).
  Protocol routes authenticate per-ecosystem inside the controller. Anonymous **read** is a
  per-org switch (`AnonymousPull`); when off, even reads require a token. Every routed
  protocol action declares a rate-limit policy (`RateLimitPolicyComplianceTests`), and the
  global limiter is default-deny per-IP.
- **Non-goal:** volumetric DDoS absorption — that is the reverse proxy's job, not the app's.

### 2. Tenant A → tenant B (cross-tenant isolation)

- **Adversary:** a fully authenticated user of one org trying to read, write, enumerate, or
  delete another org's data (BOLA / IDOR / confused deputy).
- **Defence:** tenancy is host-resolved and every tenant-scoped query filters on
  `org_id`/`tenant_id` (enforced by `OrgIdFilteringComplianceTests`, whose table set is
  derived from the schema). Blobs are namespaced per org via `BlobKeys`
  (`BlobKeyConstructionComplianceTests`). JWT sessions carry a `tid` claim that
  `RouteScopeFilter` checks. Users are 1:1 with a tenant — there is no org switcher.
- **Residual gap the gate cannot close:** the compliance scanner is syntactic; it cannot tell
  whether `@orgId` was bound from the authenticated principal or straight off a route
  parameter. **Only a reviewer closes the data-flow gap** — treat any `@orgId` sourced from
  request input as a BOLA finding regardless of a green gate.

### 3. Tenant user → instance operator (privilege boundary)

- **Adversary:** a tenant admin trying to reach instance-wide (control-plane) state or another
  tenant's configuration.
- **Defence:** control-plane surfaces (apex host, `scope=system`) are separate from tenant
  data-plane surfaces; a token scoped to a tenant cannot act on system routes. Secrets at rest
  can be envelope-encrypted under an operator-held KEK (`DEPENDABLY_MASTER_KEY`, ADR 0002).
- **Non-goal:** defending the operator from themselves — an operator with host/DB access is
  inside the TCB.

### 4. Registry → upstream (proxy / supply-chain boundary)

- **Adversary:** a malicious or compromised upstream registry, or a public squatter racing a
  private name (dependency confusion).
- **Defence:** proxied artifacts are stored under their SHA-256 (`BlobKeys.Proxy`) and the
  checksum is verified on the fetch-MISS path before the blob is admitted to cache. A security
  gate never degrades to "allow" because its input signal is missing (unreachable advisory
  source → *deferred*, not passed; empty trust-anchor set under `verify_*=block` → *deny*).
  Optional source pinning (`PROXY_SOURCE_PINNING`, off by default) binds a proxied name to its
  first-serving upstream host; **any deployment mixing a private and a public registry should
  turn it on.** Upstream-fetched GPG/signing keys are never the trust root — trust anchors are
  operator-pinned and per-org.
- **Residual gap (documented, no code change):** X.509 chain building at the pinned-anchor
  verification sites (`SamlController`, `NuGetProvenanceVerifier`, `PyPiProvenanceVerifier`)
  uses `X509RevocationMode.NoCheck` — deliberately, because the trust decision is an operator
  pin, not a CA chain, and an air-gapped deployment must not fail open or hang on an
  unreachable OCSP/CRL endpoint. **The consequence is a manual dependency: a compromised-and-
  revoked pinned anchor stays trusted until an operator removes it.** Anchor rotation is an
  operator responsibility; rotate promptly on any suspected key compromise. Legacy digest
  algorithms (SHA-1) reflect upstream ecosystem reality and are bounded by SHA-256 content
  addressing, not treated as strong integrity.

### 5. CI → release artifact (build/publish boundary)

- **Adversary:** a poisoned pipeline or a leaked publish credential producing an artifact that
  is not what was reviewed.
- **Defence:** `main` is protected (direct push server-rejected); every change ships through an
  MR. Release tags are validated (`validate-release-tag`: annotated, ancestor of `main`,
  version-matched). Secret scanning and DAST run on every MR and block. Private-registry CI
  variables are unprotected-by-design so MR pipelines are reproducible.
- **Non-goal (today):** full SLSA build provenance / signed attestations — tracked separately;
  not yet a shipped guarantee.

## Explicit non-goals

- Absorbing volumetric DoS at the application layer (reverse proxy / CDN concern).
- Defending against an adversary with host, database-file, or operator-credential access —
  that principal is inside the trusted computing base.
- Real-time revocation of externally-issued certificates (the pinned-anchor model rotates by
  operator action, see boundary 4).
- Confidentiality of data an operator deliberately exposes via `AnonymousPull`.

## Where the detail lives

- Auth hybrid rationale: [`docs/adr/0001-auth-identity-hybrid.md`](adr/0001-auth-identity-hybrid.md).
- Secrets-at-rest envelope encryption: [`docs/adr/0002-envelope-encryption-db-secrets.md`](adr/0002-envelope-encryption-db-secrets.md).
- The `Category=Compliance` static-scan gates (in `tests/Dependably.Tests/Compliance/`) are the
  machine-checked half of these invariants; this page is the human-readable map of what they
  defend.
