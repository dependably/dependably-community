# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.7.0] - 2026-08-16

### Changed

- **Pulling a moving OCI tag (`:latest`, `python:3.11-slim`) through the proxy is now reliable
  across upstream rate limits and outages.** Moving-tag freshness is governed by three orthogonal
  policies. `Oci:ManifestTagTtl` (default raised 5 minutes → 1 hour) answers only "when is upstream
  asked again" — moving tags rebuild on the order of days, so hourly revalidation cuts Docker Hub
  429 exposure ~12× without delaying acceptance. The org's `min_release_age_hours` now also gates
  OCI tag *promotion*: a newly observed digest younger than the threshold is recorded as pending on
  `oci_tags` (new `pending_digest` / `pending_first_seen_at` columns) while the previously accepted
  digest keeps serving — the age is measured from the digest's first local observation, never the
  publisher-controlled image `created` timestamp, so a backdated rebuild cannot bypass the cooldown.
  And a new `Oci:ManifestTagStaleGrace` (default 24 hours) serves the last accepted digest through
  an upstream failure, marked `X-Cache: STALE` (an additive value alongside HIT/MISS) and audited;
  the window is anchored at the moment the entry went stale and is never extended by further failed
  attempts, so an outage cannot become serve-stale-forever — past the grace the pull fails 502.

### Fixed

- **A Docker Hub 429 (or any upstream 5xx) no longer tells `docker pull` the image does not
  exist.** Upstream answers are classified: 404 (and the data plane's 401/403, which Docker Hub
  returns for nonexistent repositories) stay `MANIFEST_UNKNOWN`/`BLOB_UNKNOWN`; 429/5xx and
  token-exchange failures (previously an unhandled 500) surface as 502 `UNAVAILABLE` — or a stale
  serve within the tag grace window. A tags listing with nothing held locally reports a failed
  upstream as 502 rather than "repository unknown".
- **HEAD revalidation is durable.** A HEAD that confirms the tag's digest unchanged refreshes
  `last_revalidated`, so HEAD-then-GET-by-digest clients (containerd snapshotter, BuildKit) regain
  the fresh window instead of paying an upstream round-trip on every pull after the first TTL
  expiry. A changed digest never repoints from a HEAD — it is recorded as a pending observation and
  the next GET-by-tag fetches the body and repoints, preserving the body-before-tag write ordering.
- **N tenants no longer multiply upstream polls for the same public moving tag.** The upstream
  tag → digest observation is coalesced instance-wide per credential identity (single-flight plus a
  TTL-bounded cache); only the observation is shared — acceptance, promotion timing, licence
  gating, audit rows, and all bytes stay strictly per-org, and tenants with differing upstream
  credentials never share anything.

- **A `docker push` refused for the wrong scope now says which credential was refused.**
  `403 Insufficient scope: publish:oci required.` named the capability the route wanted and nothing
  about the credential presented, which collapses two very different faults: a token scoped wrong,
  and a client sending a different credential than the operator believes it is. The second is the
  common one and the message pointed away from it — `docker login` succeeds either way, because the
  `/v2/` ping only checks that a token resolves and runs no capability check, and a read-scoped
  token additionally clears the blob `HEAD` probes a push issues before each layer (those render as
  `Layer already exists`). The denial now carries an eight-character prefix of the token's id and
  the trace ref, in `message` and in the Distribution Spec's `detail` field, which was previously
  always null. A token reference the operator does not recognise means the client sent something
  other than what was minted. The granted capability set is deliberately **not** on the wire — `/v2/`
  error bodies travel into CI logs and screenshots, and enumerating a token's powers there would
  hand the holder of a stolen token in one silent response what they would otherwise sweep endpoints
  to learn. The full set is written to the server log and to a new `oci.scope_denied` audit row,
  coalesced to one row per (org, token, route) per 10 minutes so a multi-layer push cannot flood the
  audit log.

- **The Tokens page now shows what a token actually grants.** The scope badge was inferred from a
  prefix scan, so a token holding only `publish:nuget` rendered the identical "push only" badge as
  one holding `publish:*` — and only the second can push an OCI image. `tenant:configure` was
  checked first and swallowed the label entirely, hiding publish rights behind "admin". No screen
  anywhere rendered the stored capability array, so two credentials with different powers were
  indistinguishable. The badge now matches a preset's exact capability set or reads `custom`, and
  both the personal-token and service-token tables render the real grant beside it. A malformed
  capability value displays as "no grants" rather than salvaging the readable entries, matching how
  the server reads the same column — it deserializes all-or-nothing, so one bad element means the
  token grants nothing.

- **Every audit row names the actor behind it.** A service token's display name is denormalized onto
  `audit_log` / `activity` at write time, because `service_tokens` is hard-deleted on revocation and
  the join stops resolving exactly when an operator is asking who used a credential. Service-token
  publishes are attributed to the token rather than to anonymous, publish rows record what was
  pushed, and the block-gate factories carry the actor label through every arm.

- **Version tables sort newest-first by default** instead of by the order rows came back.

- Pinned `nanoid` to close an infinite loop on a zero-size input.

### Removed

- **The six per-ecosystem `import:` capabilities (`import:npm`, `import:pypi`, `import:nuget`,
  `import:maven`, `import:rpm`, `import:oci`) are no longer mintable.** They authorized nothing:
  both import routes require `import:*`, and capability matching only widens — a wildcard grants its
  leaves, never the reverse — so a token minted with a leaf satisfied no route anywhere while
  reading as a working import credential. Import is not per-ecosystem by construction: both routes
  accept a mixed batch and classify each artefact from its own magic bytes, so there is no single
  ecosystem to scope the grant to at the point the decision is made.

  **Action required (API callers only):** a `POST /api/v1/tokens` or `/api/v1/service-tokens`
  request naming one of these capabilities now returns `400` instead of minting a token. Use
  `import:*`. Nothing changes for tokens already issued — the stored string still resolves and still
  matches nothing, exactly as before — and nothing changes for the UI, which never offered them.

## [0.6.0] - 2026-08-13

### Added

- **Alert email is delivered through a durable outbox.** Every alert message is persisted to a new
  `email_outbox` table before any delivery attempt, so an SMTP outage longer than one retry pass —
  or than one process lifetime — no longer loses the message. Delivery retries on an exponential
  backoff until an explicit terminal policy retires the row: `delivered`; `dead_letter`, meaning the
  message or the configuration is bad (a permanent SMTP rejection, an invalid recipient) and
  retrying cannot help; or `expired`, meaning the retry or retention ceiling passed and the relay
  needed fixing sooner. Terminal rows are pruned after `EMAIL_OUTBOX_TERMINAL_RETENTION_DAYS`.
  Claims take a per-row lease, so a multi-replica Postgres deployment never attempts a message
  twice. Credential-bearing mail — password-reset links, email-change verification, invites — stays
  deliberately off the outbox: a rendered body would put a live credential at rest in the database,
  so those keep the synchronous fail-silent path, where the recovery is requesting another one.

- **The shared SMTP transport is circuit-broken, and alert bursts coalesce into digests.** Repeated
  transport-level failures — connection refused, timeouts, the classes that indict the relay rather
  than any one message — trip a breaker that stops the outbox claiming work until a cooldown
  elapses, then sends a single probe before reopening the flow, so a relay outage is not met with
  the whole backlog stampeding it the moment it recovers. A permanent per-message failure never
  trips it: a relay that answers with a definitive verdict has proven itself reachable. The breaker
  never reads or writes any org's `email_enabled` — configuration is intent, the breaker is health.
  Thresholds and cooldowns are tunable (`EMAIL_TRANSPORT_BREAKER_FAILURE_THRESHOLD`,
  `EMAIL_TRANSPORT_BREAKER_INITIAL_COOLDOWN_SECONDS`, `EMAIL_TRANSPORT_BREAKER_MAX_COOLDOWN_MINUTES`).
  Alongside it, a burst of the same alert — same org, alert kind, and package coordinate — folds
  into one pending digest row carrying an occurrence count instead of sending one email per
  occurrence. A coalesced occurrence still records its own outcome on its own alert row, and a race
  with the delivery worker resolves toward a fresh enqueue rather than a lost alert.

- **Operators get an aggregate relay-health surface.** `GET /api/v1/instance/email-health` (single
  mode) and `GET /api/v1/system/email-health` (the apex console in multi mode) report the shared
  relay's health across every tenant: how many orgs are currently failing to deliver, the worst
  consecutive-failure streak and when it started, and the outbox backlog — queue depth, oldest
  pending message age, dead-lettered and expired counts. Both routes read the same aggregator so
  the two surfaces cannot drift; every field is a count or an aggregate timestamp, and no tenant
  identifier is ever included. Rendered as a relay-health panel on the corresponding settings page.

- **Each release ships its debug symbols as a `.snupkg`; the container images ship none.** The
  portable PDBs are exported from the same compilation that produced the shipped assemblies — a
  second build would mint new PDB signatures and leave every symbol permanently unresolvable — and
  published as a symbols package alongside the release, while the runtime images strip them. A stack
  trace from a production container carries no source file/line detail on its own; load the
  release's symbols package to resolve it.

- **System admins choose a display timezone for the apex console.** A per-admin preference on the
  apex profile page; the timestamps the console renders — tenant lists, audit views, the dashboard —
  display in it. The zone is validated server-side against the runtime's tz database.

- **The alert bell can clear the whole active set.** A clear-all action on the bell panel dismisses
  every active alert for the org in one call instead of one row at a time. Dismissal stays a shared
  flag, so every admin in the org sees the same cleared set.

### Security

- **OCI pulls require a read capability; any active token was enough before.** The pull path
  resolved the presented token and checked only that it was active and belonged to the org — never
  what it was scoped for — so a token with no read grant at all could pull every hosted and proxied
  image in the org. That includes tokens minted by a role that itself holds no artifact read, so a
  role barred from reading artifacts could reach them anyway by minting a token. Pulls now require
  `pull:oci` or `read:artifact`. The push protocol's own read probes — the manifest GET/HEAD and
  blob HEAD a push performs before writing — still admit a publish-only token; blob GET, the tag
  list, and the referrers list do not, so a push token never gains a general pull licence.

- **Flipping a tenant to SSO-only now revokes its password-backed sessions.** Disabling forms login
  closed the door on new password logins but left already-minted JWTs valid on their own for up to
  their remaining eight-hour lifetime. The disable transition now moves `token_version` forward for
  the org's password-backed users, invalidating those sessions on their next request.
  SAML-provisioned members keep their sessions, and a save that leaves forms login unchanged never
  churns anyone's.

- **Percent-encoded traversal is rejected in RPM proxied path segments.** ASP.NET decodes a route
  value once, so a double-encoded traversal arrived at the handler as the literal `%2e%2e%2f` — no
  `..`, no `/`, clearing every existing rule — and was carried intact into the composed upstream
  URL, where the upstream's own decode turns it back into `../`. Path segments that are composed
  into an upstream fetch URL now reject `%` outright before any fetch; no legitimate RPM package or
  repodata filename contains one.

- **Source pinning actually runs for Maven proxy fetches.** The Maven serve path never threaded the
  resolved fetch URL into the cache-plane record, and pinning keys off an absolute URL or does not
  run at all — so the dependency-confusion guard, which refuses serving a coordinate from a
  different upstream than the one that first resolved it, was silently inert for the one ecosystem
  where a public repository routinely sits beside a private one in the same list. The URL is now
  threaded, binding each coordinate to the authority of the repository that resolved it. Several
  repositories on one host — releases, snapshots, a central proxy — share an authority, so the
  normal multi-repository shape raises nothing.

- **Credential-bearing mail refuses an unencrypted SMTP transport.** A password-reset link, an
  email-change verification link, or an invite token grants what a stolen password would, and the
  relay connection carrying it was allowed to be cleartext. Sending those over an unencrypted
  transport is now refused per-send and treated exactly like an unconfigured relay: nothing is
  sent, and each flow's existing no-relay fallback applies unchanged — a 202 with no email for
  reset and email-change, the invite link returned in the API response (which already reaches the
  inviting admin over an authenticated HTTPS session). Alert email and security-event notices carry
  no bearer secret and are unaffected. An operator who accepts the risk opts in with
  `SMTP_ALLOW_INSECURE_CREDENTIAL_MAIL`; loopback and private-range relay hosts are not exempt.

- **Retargeting an owner's email address requires `tenant:admin`.** An admin holding only
  `tenant:configure` could repoint an owner's email to an address they control, confirm the change
  themselves, and ride the password-reset flow into the owner's account. Changing an owner's email
  now takes the same tier-2 `tenant:admin` gate that touching an owner's role or membership already
  does. Self-service changes still re-enter the password, and SAML-managed accounts remain refused
  — the IdP is authoritative for those.

- **Cross-tenant proxy cache poisoning: a tenant admin could decide what bytes another tenant is
  served.** `cache_artifact` is keyed by `(ecosystem, name, version, filename)` alone — no org, no
  upstream — while upstream registries are per-org and tenant-admin configurable, so one row stood
  for "the bytes for this coordinate" across every tenant. An admin pointing an upstream at a host
  they control could publish a tarball together with the matching `dist.integrity`, pass checksum
  verification (both came from the same host), and create the shared row with their blob key. Every
  other org that later proxied the same coordinate from its own genuine upstream was served its own
  bytes exactly once, off the miss path, and the attacker's bytes from the next request on — with
  the attacker's hash echoed as the ETag and in the rewritten packument, so the client's own
  integrity check passed against the poisoned value.

  `tenant_artifact_access` now carries each tenant's own content binding — `content_hash`,
  `blob_key`, `size_bytes` — written only from a fetch that tenant actually performed, and every
  per-tenant projection resolves the bytes fields through it before the shared row. Two tenants that
  resolve the same bytes still share one row and one blob; a tenant whose upstream served something
  else reads its own. No coordinate is ever refused, so a hostile tenant reaching one first cannot
  deny it to anybody.

  **A tenant poisoned BEFORE this release stays poisoned.** The one-time backfill binds every
  existing tenant to the row it is being served today, which for a victim is the attacker's bytes —
  so it keeps hitting cache and never re-fetches. The binding stops the substitution happening
  again; it cannot undo one that already happened, because nothing recorded what that tenant's own
  upstream would have served. **Repair it by deleting the cached version** (Packages → the version →
  Delete, or `DELETE /api/v1/packages/{ecosystem}/{name}/{version}`), which drops the
  tenant's access row and makes the next request a fresh fetch from that org's own upstream. Letting
  the cache-eviction sweep age the coordinate out has the same effect on a longer timescale. Orgs
  worth checking first are any that share a proxied coordinate with an org whose upstream registries
  you do not control; `Cache-plane content divergence detected` warnings in the logs name the
  coordinate and the requesting org whenever two upstreams disagree.

  A tenant whose bytes diverge is also no longer advertised the shared row's claims *about* bytes.
  `dist.shasum`, `dist.integrity` and the stored install manifest live only on the shared row, and
  the npm packument replaces the upstream version object with the locally rendered one so the
  advertised integrity matches what the tarball route streams — so publishing a foreign SRI beside
  the tenant's own SHA-256 turned every install of that coordinate into `EINTEGRITY`, a refusal the
  tenant could not clear and another tenant caused. Those three claims are now omitted for a
  diverging tenant rather than guessed, which is the shape the renderers already handle; the
  tenant's own SHA-256 still stands, because it describes the bytes it holds. Non-diverging
  tenants — every tenant in normal operation — keep all three.

  The Cargo sparse-index line's `cksum` is now covered too: it is stored once against the shared
  catalogue row, and the sparse-index spec has no absent form for it the way npm's `dist.integrity`
  has, so a diverging tenant is served a line rewritten to its own bound `content_hash` rather than
  omitted or left describing the other tenant's `.crate` bytes — `cksum` and `content_hash` are the
  same SHA-256-of-the-file digest, so the rewritten value is exactly what the download route
  verifies against. RPM's proxy checksum resolves through the same tenant binding as the blob key
  and size (`COALESCE(taa.content_hash, ca.content_hash)` in `RpmRepodataService`), so it never
  described another tenant's bytes to begin with; its `header-range` offsets are not currently
  populated for proxy packages (always `0`) and so cannot diverge either.

  The block gate is divergence-aware too: byte-derived findings recorded against the shared row no
  longer speak for a tenant whose bytes differ from it. For that tenant, install-script detection
  reads as unknown — which the gate treats as script-present, the cautious arm — provenance reads
  as unverifiable, and licence evidence reads as absent, resolving to each ecosystem's
  unknown-licence posture under `license_enforcement_mode=block`. OSV advisories still apply
  unmasked, deliberately: they are keyed by package coordinate, not by bytes, so they describe the
  diverging tenant's artifact as much as anyone's. Every gate evaluation that sees a divergence
  also queues it into the review queue as its own reviewable item, whether or not anything on that
  request blocked — divergence itself, not any one gate's reaction to it, is the actionable
  signal. Giving a divergent coordinate a genuinely separate row with its own scan state remains
  the contract-release step below.

  **Deferred to a later release:** `cache_artifact`'s uniqueness key stays
  `(ecosystem, name, version, filename)`. Re-keying it to include `content_hash` — so a divergent
  coordinate resolves to a genuinely separate row carrying its own scan state, provenance verdict
  and index metadata — requires dropping that constraint, which a preceding release's
  `ON CONFLICT (ecosystem, name, version, filename)` still needs during a blue-green cutover. The
  per-tenant binding is what closes the serve path in the meantime, and it needs no such drop.

- **One org could obtain another org's proxy-cached private OCI layers by digest.**
  `GET /v2/{name}/blobs/{digest}` resolved against the content-addressed blob store, whose key
  (`oci/{algo}/{hex}`) carries no org segment, so in the default single-store deployment every
  tenant's layers share one key space. Entitlement was proved by nothing stronger than the caller
  having *some* configured upstream matching the caller-supplied repository name — and every org is
  seeded with a catch-all Docker Hub upstream whose empty prefix matches every repository. A tenant
  that learned a digest (they leak routinely through SBOMs, CI logs, and pinned references) could
  therefore read layers pulled from a private registry it holds no credential for, with no upstream
  call and no authorization against the owning org's registry. Serving a shared-store hit now
  requires the caller's own org to already hold an `oci_blobs` row for the digest — its own prior
  upload or its own prior proxy fetch.

- **The same bytes were reachable through the concurrent-fetch window, and that path also minted a
  standing grant.** The single-flight coordinator that collapses concurrent blob misses was keyed
  on the content-addressed blob key alone, while the work item behind that key captured one
  caller's org, upstream, and credentials. A caller from another org arriving inside the window
  joined that fetch and received the bytes verbatim, then had its own `oci_blobs` row written — so
  every later request passed the entitlement check above and served the layer from the shared store
  for good. The coordinator is now keyed on `(org id, blob key)`, so the only callers that can
  share a fetch are callers of the org whose credentials it uses, and no row is granted to a caller
  the fetch did not run for. Single-tenant deployments are unaffected: every row is already the one
  org's.

- **A `local_only` claim transition could delete a proxy blob another tenant still referenced.**
  The purge deletes the blobs its evicted rows dereferenced. On the legacy uploaded plane —
  `package_versions` rows carrying `origin = 'proxy'`, written before proxy fetches moved to the
  cache plane — the key is the content-addressed `proxy/{sha256}`, which every tenant whose
  upstream served byte-identical content records identically, and the delete was unconditional.
  One org claiming a name could therefore strand another org's cached artifact as a serve-time
  404. Content-addressed keys on that plane now go through the same locked refcount guard the
  cache-plane loop uses; org-namespaced (`hosted/{orgId}/…`) keys are still reclaimed outright.

- **A caller reaching the app port directly could name any tenant under `DEPLOYMENT_MODE=header`.**
  The header-routed tenancy mode exists for transparent-intercept deployments, where the request
  host belongs to an impersonated public registry and cannot carry the org slug, so the edge proxy
  names the tenant in a header (`TENANT_HEADER_NAME`, default `X-Dependably-Tenant`). That header
  was honoured from any socket peer — and on the anonymous protocol surfaces (`/simple/`, `/npm/`,
  `/v2/`) there is no JWT for `RouteScopeFilter` to cross-check it against, so wherever anonymous
  pull is on, any client that could reach the application directly could read another org's
  artifacts just by naming that org. The header is now honoured only when the request's raw socket
  peer is listed in `TRUSTED_PROXIES` — the same fail-closed rule forwarded headers already follow,
  matched by the same matcher, against the peer address recorded *before* forwarded-header
  processing rewrites it to a client address the proxy chose. `TRUSTED_PROXIES` unset means no peer
  qualifies and every request resolves to no tenant; a startup warning names the requirement when
  the mode is selected without it.

- **Two accounts differing only in email case can no longer coexist.** Every account lookup folds
  case (`lower(email) = lower(@email)`) while the uniqueness constraint compared bytes, so
  `Owner@corp.com` and `owner@corp.com` could exist as two rows that both satisfy every lookup —
  and which one authenticates for that address is whichever row the query engine returns first,
  which is how an accepted invite could mint a second login for an address that already belongs to
  someone. Emails are now stored canonically (trimmed, lowercased) at every write, accepting an
  invite for an address the tenant already holds answers 409 instead of creating a duplicate, and
  a boot-time pass canonicalizes what is already stored and installs a case-insensitive unique
  index so a future writer that forgets to fold cannot regress it. A database that already holds
  case-variant duplicates keeps serving: the collision is reported in the log together with the
  query that finds the rows, the index is deferred to a later boot, and nothing new can be created
  in that shape in the meantime because the write path already canonicalizes.

- **A NuGet registration leaf can no longer hand the client an upstream-controlled download URL.**
  When an upstream registration leaf carried no usable version, the URL rewrite left its
  `packageContent` download URL pointing at the upstream verbatim — routing the client's actual
  package download straight past the proxy's checksum verification, scan, and block gate. Such a
  leaf is now removed from its page (and refused rather than forwarded when requested alone), and
  an externalized registration page whose address is not host-pinned to one of the org's
  configured upstreams is dropped for the same reason: a client dereferencing it would fetch
  download URLs from a host the operator never configured.

- **A SAML response without a signature is refused by Dependably's own check, not only the
  library's.** Rejecting an unsigned response was behaviour of the SAML library's unbind path,
  asserted nowhere in this repository — a dependency bump that relaxed it would have shipped
  green, and the failure mode is a forged assertion minting a session for any account in any
  SSO tenant. The ACS endpoints now state the precondition themselves: a response carrying no XML
  signature anywhere is refused outright, while whether a present signature is *valid* and chains
  to the tenant's pinned certificate stays with the library check that runs immediately after, so
  the two fail closed independently.

- **Logging out takes effect on every replica immediately.** The per-request session-validity
  reads — user and system-admin token versions, and the JWT revocation list — sat behind a
  60-second per-process cache whose eviction reached only the replica that performed the logout,
  password change, or MFA disable; a sibling replica kept honouring the killed session until its
  own TTL rolled, so a stolen cookie could outlive the logout that was supposed to end it by up to
  a minute per replica. Under `DEPENDABLY_DEPLOYMENT_MODE=ha` those stores now read through to the
  database on every request, making revocation exact on the next request anywhere; single-replica
  deployments keep the cache, where the local eviction is already the whole invalidation.

- **The per-tenant active-token cap is enforced atomically.** The count and the insert ran as
  separate statements, so N concurrent creates could all read the same pre-cap total and all
  insert — eight concurrent creates landed eight rows past a cap of five, and the overshoot was
  bounded only by the caller's concurrency. The count and the insert now commit in one per-tenant
  serialized transaction, for user and service tokens alike, so the create that would cross the
  ceiling is the one refused.

- **The session cookie is marked `Secure` behind a TLS-terminating proxy the app does not trust.**
  With `TRUSTED_PROXIES` unset — the documented fail-closed default — `X-Forwarded-Proto` is
  discarded, so a deployment whose browser-facing hop is HTTPS but whose proxy-to-app hop is
  plaintext issued the session cookie without `Secure`, and the browser would attach it to any
  plaintext request an attacker could provoke at the same host. The cookie decision now also
  honours a raw `X-Forwarded-Proto: https`, trusted or not, which is safe for this decision
  specifically: a forged value can only add `Secure` to the forger's own cookie, restricting it.
  URL building keeps ignoring the untrusted header, where a forged value would be reflected to
  other callers.

- **Email-change verification mail is throttled per destination address.** The email-change
  endpoint's per-IP rate limit bounds one caller, but nothing was keyed on the recipient, so a
  distributed caller could aim unbounded verification mail at one mailbox through the operator's
  shared relay. Sends now consume the same per-address budget the password-reset flow already
  holds — as an independent budget, so mail aimed through one flow cannot lock the other out for
  that address. The refusal is a plain 429 rather than a uniform accept: the caller is
  authenticated and already knows the account exists, so there is no enumeration oracle to
  protect, and a silent drop would read as a delivery failure.

- **Login lockout counts concurrent failures exactly.** Recording a failed attempt read the
  counter, added one in application code, and wrote the sum back — so concurrent failures against
  one account overwrote each other and advanced the count by less than the true attempt count,
  inflating the online guessing budget precisely when someone is hammering a single account. Both
  stores now increment atomically, with the lock decision in the same operation: a single UPSERT
  whose threshold check reads the post-increment value in SQL, and a Lua script on the Redis
  store, so N concurrent failures always advance the counter by exactly N.

- **Proxy-fetch audit details are serialized, never interpolated.** The checksum-failure and
  source-pin-violation audit rows built their JSON detail by string interpolation over values an
  upstream or a client controls — the upstream packument's own integrity string, the requested
  filename, the package name — letting either close a quote and forge sibling keys in a detail
  the SIEM export parses. Both now go through the JSON serializer.

### Changed — action required

- **The per-org SMTP transport for alert email is removed. SMTP is an instance-level transport.**
  A tenant configures how Dependably *uses* that transport — whether alert mail is sent and to whom
  — never how mail is transported. The SMTP fields are gone from the tenant surface entirely: `GET
  /api/v1/alert-settings` no longer returns `emailInheritInstance`, `emailSmtp*`,
  `hasEmailSmtpPassword`, or `emailSmtpCleartextCredentials`. What remains of the tenant email
  surface is a delivery channel — the send-by-email toggle, the recipient list, the channel's
  delivery health, and the test send — edited on Settings → Integrations beside the Slack and
  webhook channels, while Settings → Alerts keeps only what *raises* an alert (the severity floor
  and per-type toggles). The write surface is split one endpoint per editing surface: `PUT
  /api/v1/alert-settings` carries the gates alone, `PUT /api/v1/alert-settings/email` the email
  channel, `PUT /api/v1/alert-settings/slack` the Slack channel — a combined PUT lets a tab that no
  longer renders a field bind it to `false` and silently disable another tab's channel. **If you
  script the base `PUT /api/v1/alert-settings`, `emailEnabled` and `emailRecipients` are no longer
  read there** — write them through `/alert-settings/email`.

  **If any org had opted out of inheriting the instance transport, its alert email now sends over
  the instance relay instead — or over nothing at all if that relay is not configured, and it fails
  silently.** Configure it at Settings → Instance settings → Instance email (SMTP) in single mode,
  or the apex System settings → Email (SMTP) in multi-tenant mode. An unconfigured relay shows up on
  the operator relay-health panel: alert mail is written to the outbox before any delivery attempt
  and an unconfigured relay claims nothing, so it accumulates as queue depth with a climbing oldest-
  message age, and as expired messages once the retention bounds retire them.

  **The stored per-org SMTP settings are cleared on upgrade.** A one-time migration sets host, port,
  security, username, password and from-address to NULL for every org and sets every org back to
  inheriting the instance transport, so nothing is left holding an envelope-encrypted credential that
  no code path reads or writes. The columns themselves stay in place, and that is deliberate: a
  release still in the field names all seven of them in its alert-settings queries, blue-green runs
  that release against the same database for the length of a cutover, and removing them would break
  that slot's entire alert-settings read — the Alerts page and the delivery gate, not merely the
  transport. They are dropped in a later release, once the oldest release Dependably supports
  upgrading from no longer reads them. Nothing about the clearing depends on which release you
  upgrade from, so there is no upgrade order to follow.

  **Clearing a value is not erasing the bytes.** Neither `UPDATE … NULL` nor `DROP COLUMN` reclaims
  the pages a value occupied, on either provider, so the credential's ciphertext can survive in
  SQLite freelist pages or Postgres dead tuples until that space is reused. If you want those bytes
  actually gone, run `VACUUM` (SQLite) or `VACUUM FULL alert_settings` (Postgres — takes an exclusive
  lock on the table) after upgrading. Rotating the credential at your relay provider retires it
  regardless of what remains on disk, and is the step that matters if the credential was ever
  exposed.

- **Alert email delivery failure no longer disables an org's email channel.** Because every org now
  shares the operator's relay, auto-disabling each channel would turn one infrastructure outage into
  dozens of independent tenant configuration failures, each needing a manual re-enable for a problem
  the tenant cannot see the cause of or fix. Failures are still recorded and shown beside the email
  channel on the Integrations tab — `email_consecutive_failures` and friends keep climbing — but
  `email_enabled` is never rewritten, so delivery resumes by itself when the relay recovers. Slack
  delivery is unchanged and still auto-disables: a webhook URL is tenant-owned and tenant-fixable.

- **Cookie-authenticated non-browser clients posting form-shaped bodies must send `Origin`.**
  SameSite is scoped to the registrable domain, not the exact host, so a page on a sibling tenant
  subdomain is *same-site* and the strict session cookie rides its requests; Fetch Metadata closes
  that for browsers that send it, but a state-changing request carrying neither `Sec-Fetch-Site`
  nor `Origin` was allowed through. The CSRF middleware now refuses such a request when it both
  carries the session cookie and declares one of the three content types an HTML form can produce
  without a CORS preflight — `application/x-www-form-urlencoded`, `multipart/form-data`, or
  `text/plain` — which is exactly the shape a cross-site form post takes and only when the request
  carries the credential the attack rides. **Real browsers are unaffected** (they send Fetch
  Metadata or `Origin` on cross-origin posts), and so is every client authenticating with an
  `Authorization` token or posting JSON. A scripted client that authenticates with the session
  cookie and posts one of those content types now gets 403: send an `Origin` header matching the
  host, or switch to an API token.

- **Webhook and Slack delivery queues are per-org, and their capacity semantics change with
  them.** Delivery ran as one process-wide, unpartitioned queue per channel; it is now one lane
  per org, served round-robin under a hard per-envelope deadline (see the fix below). Two
  consequences are operator-visible. `WEBHOOK_QUEUE_CAPACITY` (default 1024) now sizes **each
  org's lane rather than the instance**, so worst-case in-memory depth is that value times the
  number of orgs with a simultaneous backlog — lower it on instances with a large tenant count and
  a small memory budget. And webhook subscriptions are now capped at **50 per org** (the request
  past the cap is refused with 422): every subscription multiplies the delivery work one event
  creates, and the per-envelope budget can only bound a fan-out of the same order of magnitude.
  The new tuning knobs — `WEBHOOK_DISPATCH_WORKERS`, `WEBHOOK_FANOUT_CONCURRENCY`,
  `WEBHOOK_ENVELOPE_BUDGET_SECONDS`, and for Slack `ALERT_SLACK_QUEUE_CAPACITY`,
  `ALERT_SLACK_WORKERS`, `ALERT_SLACK_BUDGET_SECONDS` — are documented in the `CONTRIBUTING.md`
  environment-variable tables; the outbound HTTP clients carry fixed per-attempt timeouts (15
  seconds webhook, 10 seconds Slack) that the budgets depend on.

- **The on-demand vulnerability rescan endpoint is rate-limited, and bulk import caps its file
  count.** The rescan endpoint's own cooldown is per-package, so nothing bounded a caller fanning
  out across many distinct packages — each rescan is upstream OSV work. It now carries its own
  sliding-window limit, `RESCAN_RATE_LIMIT_PERMITS` (default 20 per minute per caller); a script
  driving bulk rescans faster than that now sees 429. Bulk import refuses a batch of more than
  5,000 files with 413 before any staging begins: the existing 1 GB aggregate byte cap does not
  bound a batch of many near-empty files, whose per-file work — staging, detection, a
  claim-resolution query, an audit row — scales with count rather than bytes.

### Changed — behavior

- **A tenant's proxy storage total is measured from its own bytes.** The `org_storage_bytes` quota
  view and the dashboard's per-ecosystem storage breakdown both resolve a proxy artefact's size
  through the tenant's own content binding before the shared row's, so the two agree and a tenant
  whose upstream served larger or smaller bytes is charged for what it actually holds rather than for
  another tenant's copy.

- **The proxy cache size cap and every reclamation path now see tenant-bound blobs.** A tenant whose
  upstream served content other than a coordinate's shared row stores its own bytes under a key no
  `cache_artifact` row names. `CACHE_MAX_SIZE_BYTES` now counts those bytes toward the measured
  total, and the LRU sweep, the per-org retention passes, the `local_only` claim purge and the
  cache-plane version delete all reclaim them alongside the shared blob — each still guarded by the
  shared-key refcount, so a second tenant that resolved the same bytes keeps its copy. Without this
  a divergent tenant's blob was invisible to every cap and every sweep, and became an unreachable
  orphan the moment its coordinate was evicted. **A cache that has been serving divergent content
  may measure larger than it did before and evict sooner**; the extra bytes were always on disk,
  they were simply not counted.

- **The global cache size and count caps now reclaim OCI storage.** `CACHE_MAX_SIZE_BYTES` and
  `CACHE_MAX_ARTIFACTS` previously excluded OCI from both the eviction candidate query and the
  measured totals, so an image neither counted toward a cap nor could be evicted to relieve one —
  on an OCI-heavy instance the caps could not be reached at all. All three move together, because
  totals that count rows the candidate query will not select make a cap unreachable and the sweep
  spins.

  Eviction of an OCI manifest is not a plain cache-plane delete: a manifest casts two shadows — the
  shared `cache_artifact` row this sweep selects, and one `oci_blobs` row per org that pulled it.
  The sweep now releases each holding org's digest claim first and never routes an OCI blob through
  the cache-plane deleter, which is guarded only against sibling `cache_artifact` rows and would
  otherwise delete manifest bytes out from under another tenant. Physical reclaim is left to
  `OciBlobReclaimer`, which frees a digest only once every claim is gone and also collects the
  layer closure. **If you rely on OCI images being exempt from the global caps, set the caps
  accordingly** — images are now evictable, and the sweep logs the OCI share of the measured
  totals whenever a cap is breached.

- **An OCI blob is no longer served from the shared store to an org that has not fetched it
  itself.** A layer another tenant proxy-cached is no longer a cache hit for your org: the first
  pull of that digest by your org issues its own upstream request, against your org's own upstream
  and credentials, before the bytes are served. Two consequences are worth planning for:

  - **A layer your org never cached can now fail when its own upstream is unreachable.** Where the
    shared store previously answered the request with no upstream call at all, the same request now
    depends on your org's upstream being reachable and on the credential attached to it — so a
    registry outage, an expired credential, or a digest that has since been deleted upstream
    surfaces as a 404 or 502 rather than silently resolving from another tenant's copy.
  - **N orgs pulling the same public base image now issue N upstream pulls from one egress IP.**
    Anonymous Docker Hub pull quotas are counted per source address, so a multi-tenant instance
    whose tenants share a base image can trip them where the collapsed single pull did not. Give
    the shared upstream an authenticated credential, or stagger the tenants' first pull, if the
    instance sits near a quota.

  Bytes are still stored once — the blob store is content-addressed and the write is idempotent —
  so only the upstream request is duplicated, not the storage. Repeat pulls within one org still
  hit the shared store, and concurrent misses within one org still collapse to a single pull.

- **Single-mode instance settings are editable by admins, not only the owner.** The instance
  endpoints — settings, metrics access, the SMTP transport, background-job status — now require
  `tenant:configure`, the capability both the admin and owner roles hold, instead of the owner-only
  `tenant:admin`. In single mode the org *is* the deployment and its admins are the people running
  the instance: an admin who already configures the registry's security posture — block gates,
  licence enforcement, trust anchors, proxy upstreams — could not point the mail relay at a host or
  raise an upload limit, a distinction without a difference at that scope. Multi-tenant deployments
  are untouched: these routes still return 404 there, and instance-wide settings remain behind the
  separate `system_admin` identity on the apex.

- **A searched audit or activity CSV export is bounded, and says so in a response header.** An
  export's search term runs as a leading-wildcard match no index can serve, and nothing stopped a
  single `read:audit` holder from re-issuing it at will — each request a full scan of the org's
  history, a cost lever rather than a one-shot. A search inside a CSV export is now bounded to the
  same newest-50,000-row window the paged lists use, and when the bound engages the response
  carries **`X-Export-Truncated: true`** so the truncation is never silent — narrow the export
  with the indexed `action`/`since` filters, or drop the search term: an export with no search
  term deliberately stays unbounded, so a complete extract is always available.

- **`/version` no longer appears in the published OpenAPI documents.** It is an IP-allowlisted
  operator surface, like `/metrics`, and advertising its route and schema in the fully public
  protocol document contradicts the allowlist's purpose. The endpoint itself is unchanged.

### Fixed

- **On Postgres, seventeen read projections could not materialize at all — breaking per-org
  webhooks, Slack alerts, alert email and the email outbox, the GDPR self-export, OCI push, Go and
  Cargo proxy serving, RPM repodata, multi-file PyPI serving, and the session context the SPA
  reads on every page load.** Dapper's default positional-record binding demands an exact CLR type
  match for each constructor parameter, and the two providers disagree about what an `INTEGER`
  column is — SQLite reports `Int64`, Postgres `Int32` — so seventeen row records whose signatures
  matched one provider threw on the other, and every one of them had only ever run against SQLite.
  SQLite deployments were never affected. All seventeen now bind through explicit constructors,
  which is what lets one `long`-typed signature serve both providers; a compliance gate scans
  every Dapper positional record so a new projection cannot reintroduce the mismatch, and a
  Postgres-backed materialization test covers the repaired rows against a real database.

- **Omitting a field from `PUT /api/v1/proxy-settings` never changes it.** The whole endpoint now
  carries one absent-field posture: a field left out of the payload leaves the stored value
  unchanged, for every field. Previously only the `verify_*` fields behaved that way; the rest
  bound their C# defaults on absence, so a client or UI tab that did not render a field silently
  rewrote it on save. The two gates whose "off" state is itself SQL NULL — `min_release_age_hours`
  and `max_epss_tolerance` — are carried tri-state, so an explicit `null` still deliberately
  switches the gate off while a missing key leaves it alone; the generated OpenAPI schema for both
  still renders as a plain nullable number. Partial updates are now safe from any client.

- **Omitting `anonymousPull` or `allowlistMode` from `PUT /api/v1/settings` leaves them
  unchanged.** Both are security gates, and both were non-nullable on the request record, so a
  client that did not send one bound its C# default — `false` — on save: a script updating only an
  upload cap silently disabled allowlist enforcement, or flipped anonymous pull, as a side effect
  of writing something else. An absent field now flows through to the stored column, the same
  leave-unchanged-on-absent contract the proxy-settings endpoint carries. The upload-cap fields
  keep their existing meaning — null is their own domain value ("no org-level cap"), so sending
  null still clears a cap.

- **Every audit write carries its origin, and the read surfaces show it.** Dozens of audit sites —
  protocol pushes and fetches, settings changes, login flows, token management — dropped
  `source_ip` or the acting principal's kind on the floor, leaving those rows unattributable, and
  the rows that did record a source IP lost it again on read: the tenant audit list and the SIEM
  export never projected the column. Every write path now records both (a compliance gate over
  every audit call site keeps it that way), and the audit list, activity list, and SIEM export
  return `source_ip`.

- **The audit and activity search no longer times out on large instances.** A search issues
  leading-wildcard matches across six columns, which no index can serve, so each keystroke's
  request read every row in the filtered window. A paged search is now bounded to the newest
  50,000 rows of the window, and when the bound engages the response reports the total as capped
  and the UI says so. The CSV export's searches share the same bound and report their truncation
  through a response header — see "Changed — behavior".

- **`audit_event` rows get the same personal-data horizons as `audit_log`.** The retention sweep
  now clears `source_ip` and `user_agent` from `audit_event` rows after 90 days
  (`AUDIT_EVENT_PII_DAYS`), keeping the forensic skeleton, exactly as it already did for
  `audit_log`. Erasing a user pseudonymizes their retained `audit_event` rows the same way, and
  hard-deleting a tenant pseudonymizes rather than deletes them — `audit_event.org_id` carries an
  `ON DELETE SET NULL` foreign key, so the schema already intends those rows to outlive their
  tenant.

- **An upstream OCI blob fetch is capped at the shared 600 MB response limit.** Every other
  ecosystem's upstream fetch already enforced the cap; the OCI resolver streamed without one, so a
  hostile or misconfigured upstream could stream unbounded bytes into cache staging. A declared
  `Content-Length` over the cap is refused before a byte is read, a chunked response is cut off at
  the same bound mid-stream, and the staged entry is deleted on refusal so a capped fetch never
  leaves partial bytes behind for a later request to find. A layer larger than the cap can no
  longer be proxied — the bound every other ecosystem already had.

- **A multi-layer OCI push is no longer rejected by the push rate limiter.** An image push bursts
  structurally — the protocol spends three requests per layer, issued concurrently — and the push
  policy had no queue, so pushing an image with more than a handful of layers failed mid-upload
  with an empty `toomanyrequests:` error. The policy now queues requests past its per-second
  ceiling instead of rejecting them (`PUSH_RATE_LIMIT_PERMITS`, `PUSH_RATE_LIMIT_QUEUE`), and the
  shipped defaults are pinned by tests rather than only ever running under raised test-harness
  limits.

- **CDN-shaped PyPI download URLs resolve.** pip-tools and poetry pin the
  `files.pythonhosted.org` URL shape — `/packages/<2 hex>/<2 hex>/<sha256>/<filename>` — into
  lockfiles, and only the flat `/packages/<filename>` form was served, so installs from such a
  lockfile through the proxy answered 404. GET and HEAD now serve the multi-segment shape as an
  alias of the flat route. The embedded digest is compared against the on-record checksum only
  after the same auth gate every other download path applies, so an unauthenticated caller learns
  nothing about whether a digest matches; the three hash segments are constrained to exact-length
  hex at the route, so nothing traversal-shaped reaches the handler.

- **Transparent intercept routes PyPI by path, not only by host.** PyPI is the one ecosystem whose
  protocol surface is split across unprefixed roots — PEP 503's `/simple/` and the download host's
  `/packages/` — while the JSON API and twine's upload endpoint genuinely live under `/pypi`. The
  intercept prepended `/pypi` to every request on a PyPI-routed host regardless of path, which
  broke the unprefixed surfaces. It now leaves `/simple/` and `/packages/` requests alone and
  prepends the segment only where the route needs it — chiefly `upload.pypi.org`'s bare-host
  `/legacy/` upload.

- **A chained Terraform edge can verify a provider its master has not cached yet.** The version
  document's `zh:` hash — the only fetch-time checksum a downstream node has — was published only
  for platforms already in the master's cache, so an edge's first fetch of an uncached platform
  had nothing to verify against. For a registry-protocol upstream, the master now sources the hash
  from the per-platform `shasum` the registry publishes on its download document; only a
  mirror-protocol upstream that publishes no hashes of its own still leaves a platform without
  one.

- **The deprecation/latest-version refresh resolves npm and PyPI upstreams per-org.** The daily
  refresh read the instance-level seed settings instead of each org's configured upstream
  registries, so an org pointing at a private or authenticated upstream had its packages checked
  against the wrong host — or against a default the org had deliberately removed. The refresh now
  resolves upstreams through the same per-org registry list every other fetch uses, honours its
  credentials, and skips an (org, ecosystem) with zero configured upstreams outright, since an
  empty list means proxying is deliberately disabled.

- **Timezone preferences work in the container images, and each org can set a default.** The
  runtime images shipped no tz database, so resolving any IANA zone failed inside the container
  and every display-timezone preference silently fell back to UTC; the images now ship `tzdata`,
  and a compliance test asserts zone resolution inside the built image rather than only on
  developer machines. Settings → General gains an org default timezone that applies to members
  without a personal preference, and saving a preference now takes effect immediately — the SPA
  re-reads the session context after the save instead of showing the old zone until the next full
  reload.

- **A failed tenant hard-delete can no longer strand personal data beyond recovery.** The erasure
  spans six relations, and the sweep finds its work by selecting soft-deleted tenants out of
  `orgs` — but the sequence deleted the `orgs` row first and ran un-transacted, so a failure
  partway through (a dropped connection, a busy database) removed the only row that could ever
  list the tenant again and permanently stranded whatever remained: login attempts, banners, and
  audit rows keyed to a tenant no pass could find. The whole per-tenant erasure now commits as a
  single transaction, with the `tenant.hard_deleted` audit row inside it — a failure anywhere
  rolls everything back including the `orgs` row, the tenant stays in the worklist, and the next
  pass retries cleanly over whatever the previous attempt left.

- **One tenant's unreachable endpoint no longer stalls webhook and Slack delivery for every
  tenant.** Each channel's delivery ran as a single process-wide queue drained in order, so a
  subscriber that black-holed connections — accepted, never responded — held the delivery workers
  for its full retry budget while every other org's events, security alerts included, queued
  behind it. Delivery is now partitioned into per-org lanes served round-robin, one envelope per
  org per turn, under a hard per-envelope deadline, so a broken or hostile endpoint costs only its
  own org's lane and an overflow sheds only the events of the org that created it. The webhook,
  Slack, and email consecutive-failure counters are also incremented by the database in the same
  statement that reads them back, rather than read-modify-written in application code, so
  concurrent failures — one queue per replica on Postgres — cannot under-count and delay the
  auto-disable and health signals they drive.

- **A failed NuGet symbol-index rebuild no longer wipes a working index.** Rebuilding a version's
  symbol index is a delete-then-insert by nature, and the two ran as separate statements — a
  failure between them (a busy database, a dropped connection, a cancelled request) left the
  version's symbols empty or partial where a complete, working index existed before the rebuild
  started. The delete and the re-insert now commit as one transaction, so a failed rebuild rolls
  back to the previous index.

- **A final PyPI release whose local version identifier contains "dev" is not a dev-release.**
  PEP 440 phase detection fell back to a whole-string substring scan for "dev", so a version like
  `1.0+ubuntu.dev1` classified as a development release and sorted below every final release.
  Dev-ness is now read only from the version's own dev segment, and a combined
  pre-release-and-dev version keeps its alpha/beta rank, so `2.0.0b1.dev1` still orders above
  `2.0.0a1.dev1`.

- **npm publish with an empty `versions` object answers 422, not 500.** A publish body carrying
  `"versions": {}` beside an attachment crashed the handler on the empty sequence; it now falls
  through to the same validation refusal every other malformed publish body receives.

- **The SIEM webhook forwarder no longer buffers the collector's response, and its drops are
  visible as metrics.** The forwarder only needs the response status code, but it read the whole
  body — fully controlled by whatever answers at the configured collector URL — into managed
  memory on every send; it now discards the body unread, matching the webhook and Slack delivery
  clients. Alongside it, the forwarder's queue-full and retries-exhausted drop counts, which were
  tracked internally but wired to nothing, are now exported as OTel counters so a lossy SIEM
  pipeline is observable rather than silent.

- **The syslog SIEM forwarder no longer leaks TLS state on a failed send.** The TLS stream was
  disposed only at the end of a fully successful send, so every failed handshake or mid-write
  failure against the collector — an expired certificate, a TLS version mismatch, a peer reset —
  leaked the stream's TLS session state, a slow leak keyed to exactly the condition that recurs
  on every retry. Both stream layers are now disposed on every path.

- **Truncating audit User-Agent and package description text cannot split a character.** Both
  truncations cut at a fixed UTF-16 code-unit index over caller-controlled text, so an
  astral-plane character (an emoji, for instance) could be positioned to straddle the cut —
  leaving a lone surrogate that is invalid UTF-16 and does not round-trip through storage or the
  SIEM and webhook JSON exports. The cut now backs off one unit rather than split a pair.

- **List pages no longer render a response a newer request has superseded.** Five pages — Audit,
  Packages, Quarantine, Risk, and Vulnerabilities — issued a fresh load on every page, filter, or
  search change without discarding the in-flight one, so a slower older response could land after
  a faster newer one and overwrite the table with the previous query's rows. Each load now carries
  a sequence token, and a response that is no longer the latest is dropped, errors included.

- **Logging out ends the session watcher for good.** The watcher that re-validates the session
  when a tab regains focus could be resurrected by its own in-flight request: a logout landing
  while the re-validation's `GET /me` was on the wire let the stale continuation re-arm the expiry
  timer for a session that no longer exists. The re-validation now drops its result whenever a
  logout or a newer login happened while it was in flight.

- **Sizes at and above 1024 GB render in TB and PB.** The byte formatter had no unit above GB, so
  a terabyte-scale storage total rendered as a four-or-more-digit GB figure.

## [0.5.0] - 2026-08-06

A feature release adding **Terraform providers** as a new ecosystem, served over the Provider
Network Mirror Protocol at `/terraform/` with the full supply-chain control set. Alongside it,
two read surfaces stop reporting signals they never had: artefacts in an ecosystem OSV publishes
no feed for are labelled **No advisory feed** instead of unscanned, and paged audit/activity
totals are capped rather than timing out. **Operators consuming the version-status field or the
audit list API: see "Changed — action required" below.**

### Added

- **Terraform provider mirror.** A new ecosystem at `/terraform/`, speaking the **Provider Network
  Mirror Protocol** — so `terraform init` resolves *and* downloads every provider through
  Dependably instead of reaching `registry.terraform.io` and `releases.hashicorp.com`. Configure it
  in Terraform's CLI configuration (`~/.terraformrc` / `%APPDATA%\terraform.rc`), not per project:
  a `provider_installation { network_mirror { url = "https://…/terraform/" } }` block, with no
  change to any `required_providers`. Existing `.terraform.lock.hcl` files keep working with no
  `-upgrade` run — Terraform recomputes each `h1:` hash from the archive it downloads, and the
  bytes are identical.

  Three constraints are worth knowing before you point a client at it:

  - **HTTPS is mandatory.** Terraform rejects an `http://` mirror URL while *parsing* the CLI
    configuration, before any request. Unlike every other ecosystem, a plain-HTTP deployment cannot
    serve this one — terminate TLS in front of Dependably first.
  - **Providers are mirrored; modules are not.** Terraform's module registry is a separate protocol
    with no network-mirror equivalent, so `module` blocks sourced from a registry still reach it.
  - **Only configured registry hosts are mirrored.** A provider is addressed by its own source
    address (`{hostname}/{namespace}/{type}`), so the request path always names a host the *client*
    chose. That hostname is matched against the org's configured upstreams rather than fetched
    from, so a caller cannot steer a server-side request at an arbitrary host. Add private
    registries under **Settings → Proxy → Upstream registries**.

  Terraform is proxy-only (no hosted push), like Go and apk. Provider fetches run the same
  record → scan → gate sequence as npm and PyPI: source pinning, checksum verification against the
  registry's reported `shasum` before storage, the block gate on first fetch *and* on every cache
  hit, and `local_only` reserved-namespace semantics. See `docs/terraform.md`.

- **Publisher-signed SHASUMS chain verification for Terraform providers.** A new per-org
  `verify_terraform_signatures` policy — `off` (default) / `warn` / `block` — verifies the
  registry-published SHASUMS file against the publisher's PGP signature on provider fetch.
  Enabling `warn` or `block` requires at least one per-org Terraform PGP anchor under
  **Settings → Trust Anchors**; consistent with the other `verify_*` gates, `block` with an empty
  anchor set denies every Terraform artefact rather than degrading to a no-op.

- **Edge nodes chain the Terraform mirror through their master.** Point a client at the edge's
  `/terraform/` and it serves from its own cache, filling from the master on a miss. Terraform is
  the one ecosystem whose edge upstream row must record *which protocol the master speaks* — the
  master serves the network mirror protocol while the fetcher's default is the registry protocol —
  so the seeded row carries `upstream_protocol = 'mirror'`. This is automatic (`EdgeUpstreamSeeder`
  writes it on every boot) and needs no operator action. The archive is fetched through the edge's
  own proxy pipeline, so the block gate, reserved namespaces, source pinning, and `cache_artifact`
  recording all apply at the edge, not only at the master.

- **Version documents publish the protocol's optional `hashes` field.** For every platform this
  instance has cached, a `zh:` entry carries the archive's SHA-256 — the hash already held on the
  cache-plane row; otherwise the hashes an upstream mirror published are passed through. This is
  what gives a chained node something to verify: a downstream edge takes its fetch-time checksum
  from exactly this field, and the client-side `.terraform.lock.hcl` anchor does not protect an
  intermediate cache. Terraform's own `h1:` dirhash is still not emitted — it is a different
  computation over the extracted contents, and the lock file remains the client's anchor for it.

- **`upstream_protocol` on upstream registries.** A Terraform upstream speaking the mirror protocol
  can be configured by hand as well as seeded: `POST /api/v1/upstream-registries` accepts a
  `protocol` field (`mirror`, or omitted for the ecosystem default), and **Settings → Proxy**
  exposes it. It is Terraform-only — supplying it for any other ecosystem is rejected, since
  everywhere else the upstream serves the same protocol the fetcher speaks.

- **Existing orgs are backfilled with the default Terraform upstream.** A one-shot migration seeds
  the `registry.terraform.io` row for orgs created before the ecosystem existed. Without it an
  existing org has no configured Terraform upstream at all, and since a provider's hostname is
  matched against exactly that list, the mirror would answer nothing rather than merely losing a
  fallback. Honours a `Terraform__Upstream` override. Only Terraform is seeded — the full default
  set is never re-run, so a deliberately deleted upstream is not resurrected.

### Changed — action required

- **Artefacts in an ecosystem with no OSV feed now report `no_feed`, not `unscanned`.** OSV
  publishes no advisory feed for **OCI** images (container vulnerabilities are image-scan
  territory) or **Terraform** providers, so every lookup returns an empty advisory list whatever
  the artefact contains. Those artefacts were already left unscanned rather than stamped — what
  changes is the read surface: the version-status field returned by `/api/v1` and rendered in the
  UI now carries a distinct **`no_feed`** value ("No advisory feed") instead of folding them in
  with `unscanned`, and it sorts ahead of `unscanned` because an unscanned artefact is waiting for
  the next pass while one with no feed will never be covered at all.

  **If you consume the version-status field, add `no_feed` to your handling** — a consumer that
  switches on the known set will see an unrecognised value. RPM is deliberately *not* in this set:
  OSV has no single "RPM" ecosystem but does publish distro feeds (Rocky, AlmaLinux, Red Hat) that
  a `pkg:rpm` query resolves against, so RPM keeps scanning and stamping.

- **Paged audit and activity totals are capped at 10,000.** On large instances the exact `COUNT`
  behind `GET /api/v1/orgs/{org}/audit` and `…/activity` joined the actor tables and timed out with
  a 504. The count now probes one past the cap and skips the actor joins when no search is active.
  Both responses gain a **`totalCapped`** boolean; when it is true, `total` is the cap rather than
  an exact count and the UI renders "of 10000+". CSV export is unaffected — it never computed a
  total. **If you read `total` from these endpoints, read `totalCapped` alongside it**, or a
  history past the cap will read as exactly 10,000 rows.

### Security

- **Stale frontend dev-dependency pins holding vulnerable versions are unpinned.** The `overrides`
  block in `web/package.json` had gone stale and was pinning four packages to versions that later
  advisories marked vulnerable — the pins were *blocking* the patched releases from resolving
  rather than protecting against them. Clears 21 advisories across `fast-uri`, `undici`, `js-yaml`,
  `tar` (including critical `GHSA-w8wr-v893-vjvp`), `postcss`, `ip-address`, and `brace-expansion`.
  Build-time dependencies only — no shipped runtime code is affected.

The remainder are in the Terraform provider mirror, found while hardening it before release. None
affects a previously shipped ecosystem.

- **The org's upstream credential is no longer sent to the archive host.** Under the registry
  protocol the `download_url` names a host the *upstream* chose (`releases.hashicorp.com` for
  HashiCorp's own providers), not one the operator configured. The `Authorization` credential is
  now attached only to requests against the configured upstream base authority — the mirror surface
  and the registry's own metadata endpoints — so a registry cannot harvest an org's upstream
  credential by pointing `download_url` at itself.
- **Reserved namespaces are enforced on all three protocol documents, not just the archive.**
  Forwarding a reserved private provider source address to a public registry to build a version
  list discloses the name and serves that registry's answer for it — the exact opposite of
  `local_only`. Every document for a reserved address is now a 404.
- **A registry-protocol archive with no published `shasum` is refused rather than stored.** The
  shasum is the only thing binding third-party bytes on a foreign authority to the registry that
  vouched for them; without one there is nothing to verify, so the bytes are no longer accepted
  trust-on-first-use from a host the operator never configured. The mirror protocol's hash-less
  TOFU remains a deliberate, documented exception — a mirror serves its own bytes from beneath the
  configured base.
- **One tenant can no longer dictate the integrity anchor another advertises.** `cache_artifact` is
  a global plane row with no `org_id`, so its `content_hash` belongs to whichever tenant fetched
  the coordinate first. The `zh:` hash is now emitted only when the row's `blob_key` is this org's
  own, proving the hash describes bytes this org holds. A chained edge takes `zh:` as its only
  fetch-time checksum, so a mismatched anchor would have denied the provider to every downstream.
  Single-tenant deployments are unaffected — every row is already this org's.
- **Malformed platform tokens are rejected before any fetch.** A trailing-underscore token such as
  `linux_` passed the segment check and yielded an empty arch, composing a malformed upstream
  `/download/{os}/` URL; an interior underscore is now required.
- **The blob stream is disposed when the block gate refuses a cached provider.** On an S3 or Azure
  backend that stream is a live HTTP response, so a client retry loop against a blocked provider
  stranded one connection per request until the pool drained.
- **A checksum mismatch on the archive host answers 502, not an opaque 500** — matching every peer
  proxy. The staged file is discarded before the throw, so nothing enters the blob store.

### Fixed

- **Redirects on the mirror archive fetch are contained to the fetch base.** `SsrfAwareRedirectHandler`
  gains an opt-in per-hop containment base: when set, every redirect target must sit beneath it or
  the hop is refused, on top of the SSRF-range check each hop already gets. Without it a compliant
  published URL could `302` to an arbitrary — and therefore SSRF-clean — host of the mirror's
  choosing. The constraint propagates across hops, so it holds for the whole chain, not just the
  first. Protocols that legitimately redirect to an arbitrary CDN are unaffected: the option is
  absent by default.
- **Cached provider metadata is served when the upstream cannot answer.** A version-list or
  version document already in cache is served on an upstream outage instead of failing the
  `terraform init`.
- **Terraform and Maven capture the upstream publish timestamp**, so the release-age cooldown gate
  measures against the real upstream publication time rather than first-fetch time.
- **Terraform is present in the reserved-namespace vocabulary**, the dashboard ecosystem donut, and
  the SPA-fallback path list — a `/terraform/` request no longer falls through to the SPA, and a
  reserved Terraform namespace is enforced rather than silently accepted.
- **Go advisories that enumerate `v`-prefixed versions now match.** OSV records some Go advisories
  with explicit `v1.2.3` version lists rather than ranges; those were previously missed against the
  unprefixed module version.
- **Download counts are keyed by row identity, not purl.** A purl is not unique on either plane —
  Maven and RPM map one purl to several filenames — so a purl-keyed counter credited a single
  file's download to every sibling file and refreshed their `last_used`, which also perturbed LRU
  eviction order.
- **A repeatedly failing upstream no longer blocks the deprecation-refresh queue.** Both feeder
  queries order by staleness ascending and take a fixed batch, so a group whose fetch threw was
  re-selected first every pass; once batch-many such groups existed, no other group was ever
  reached. A failed fetch now moves the group to the back of the queue. Only the attempt timestamps
  advance — the deprecation verdict and recorded upstream-latest are left untouched, so a transient
  outage does not erase state.
- **A request for the bare mirror base URL answers 404, not 400.** A client probing the base
  matched the catch-all with nothing bound and tripped implicit model validation ("The path field
  is required"); 404 is the protocol's own answer for "not mirrored here".
- **Dashboard deep-link parameters survive the held route transition** — filters carried in a
  deep link are no longer dropped when the target page defers its render.

### Internal

- **Every CI image pull resolves through the mirror**, enforced by a new `image-registry-guard`
  that looks past `FROM` lines at the pulls the build tooling makes on its own: `docker buildx
  create` booting BuildKit from its own image, BuildKit resolving a `# syntax=` directive before
  reading the first instruction, and `ARG *IMAGE*=` defaults. Mark a deliberate public pull with
  `# image-registry-ok: <reason>`. Four working bypasses in the guard were closed, and it now scans
  the repo's own files rather than nested checkouts. The OpenTelemetry collector image routes
  through the mirror like everything else.

## [0.4.5] - 2026-08-02

A feature release completing the NuGet symbol server that 0.4.0 introduced: proxied
packages now get symbols too, `.snupkg` upload handling matches what `dotnet pack`
really produces, and symbol packages are visible in the UI. **Postgres blue-green
operators: upgrade to 0.4.5 from 0.4.4 only** — see "Changed" below.

### Added

- **Proxied NuGet packages resolve symbols.** An SSQP debug-id lookup that misses the
  local index now falls through to the upstream's symbol server, and the fetched PDB is
  cached and indexed against the proxy cache plane. Each NuGet upstream carries its own
  **symbol-server base URL** (a symbol server is a different host from the v3 index, so it
  cannot be derived): nuget.org upstreams are seeded with
  `https://symbols.nuget.org/download/symbols` automatically — including pre-existing rows —
  while every other feed starts empty, which **disables symbol proxying for it** rather than
  guessing a host and sending private PDB names to a third party. Set it from
  Settings → Proxy or `PUT /api/v1/upstream-registries/{id}/symbol-server`
  (requires `tenant:configure`); an empty value clears it.
- **Symbol packages are visible in the UI.** A version that carries a `.snupkg` shows it,
  with the count of PDBs indexed from it, and a **re-index action** re-derives the SSQP
  index from the stored archive — the recovery path for symbol packages stored before
  indexing existed or after a failed index pass.
- **A hosted multi-file version lists and serves every file it carries** (e.g. a PyPI
  release's sdist and each wheel) from the version detail panel, not just the primary
  artifact.

### Fixed

- **The block gate now runs on both symbol read paths.** A blocked, quarantined, or
  revoked package could previously still serve its PDBs over SSQP and its `.snupkg`
  download; both reads now pass through the same gate as every other serve path.
- **`.snupkg` upload handling matches real `dotnet pack` output.** The upload/import path
  accepts a `.snupkg` and validates it against the reduced nuspec a genuine symbol package
  carries (earlier validation assumed the full package nuspec shape); a `.nupkg` and its
  `.snupkg` share one version row instead of colliding; the flatcontainer package endpoint
  never serves the `.snupkg` in place of the package; and proxied PDBs no longer leak into
  the package catalogue.
- **Healthcheck ping interval and timeout are floored at 1 second.**
  `HEALTHCHECK_PING_INTERVAL_SECONDS` / `HEALTHCHECK_PING_TIMEOUT_SECONDS` values below `1`
  are raised to `1` with a startup warning instead of producing a tight ping loop or a
  zero timeout.
- **Protocol route metrics use the route templates ASP.NET itself emits**, so the
  `http.route` attribute matches what tracing middleware reports and stays a closed,
  low-cardinality set.

### Changed

- **Existing Postgres databases gain the canonical-timestamp CHECK constraints on boot.**
  Each temporal column's constraint is added `NOT VALID` then validated; a column with
  unfixable legacy rows is left `NOT VALID` (still enforced for new writes) rather than
  failing the boot. **Action required only for blue-green Postgres deployments: the old
  slot must be running 0.4.4** — earlier releases write timestamp shapes the new
  constraint rejects, so skipping 0.4.4 would 500 the old slot's publish and proxy
  first-fetch writes during the cutover window. Single-slot deployments and SQLite
  deployments are unaffected (SQLite is repaired by the existing boot-time sweep, not
  constrained).

## [0.4.4] - 2026-07-29

A build- and test-only patch. **No operator action is required** and no runtime behaviour
changes from 0.4.3.

### Fixed

- **Two tests could fail under load without indicating a product fault.**
  `DomainTimerTests` listened to the process-wide activity source filtered only by source
  name, so spans from product code and from observability tests running in parallel landed
  in its own bag and broke a count-based assertion; activities are now namespaced per test
  instance. `SchemaViewIdempotencyTests` could have its concurrent reader starved until
  after cancellation, tripping its own liveness guard before the real assertion ran; the
  apply now waits for the reader's first poll.
- **The backend build stage is cross-compiled rather than emulated**, removing the
  emulation dependency from the image build.

## [0.4.3] - 2026-07-29

A patch release carrying the 0.4.1 and 0.4.2 cycles, which shipped without their own
sections here. **Read "Changed — action required" before upgrading**: existing browser
sessions are signed out, API tokens minted before the `capabilities` column are deleted,
and two weak-hash acceptances become default-off opt-ins.

### Added

- **Unexpected server errors now return a problem document with a correlation id.** A request
  that fails in a way no typed handler covers previously produced a bare `500` with an empty
  body; it now returns localized `application/problem+json` (en/fr) carrying a `correlationId`
  — the request's W3C trace id, the same value the logs and traces are stamped with — so an
  operator can find the failure from what the caller quotes. The body still carries no
  exception type, message, or stack trace. Applies to both the community and edge images.
- **`RATE_LIMIT_REDIS_FAILURE_MODE` — fail-open vs fail-closed for the Redis-backed
  abuse-prevention limiters** (`login`, `invite`, `token-create`). `open` (the default, and the
  behaviour every existing deployment already has) grants the request when Redis cannot be
  reached; `closed` denies it with `429`. **Only `open` and `closed` are accepted — any other
  value fails startup** rather than resolving to the permissive default, so a misspelled `closed`
  can never read as configured fail-closed while behaving fail-open. Ignored by edge nodes, which
  run only in-process limiters.
- **`dependably.rate_limit.backend_unavailable` counter** (attributes: `policy`, `decision`),
  incremented alongside a `Warning` log every time one of those limiters resolves a request
  without Redis. Under the default fail-open posture this is the only signal that login rate
  limiting is currently switched off — alert on it.

### Deprecated

- **`org_settings.storage_used_bytes` is dormant and will be dropped in the release after this
  one.** Every quota check now derives a tenant's stored bytes from the live `org_storage_bytes`
  view, so there is one definition of "bytes this org holds" and nothing to drift; nothing in this
  release reads or writes the counter. The column itself is deliberately retained — 0.4.2 still
  *increments* it, and dropping it now would fail that slot's quota `UPDATE` for the whole
  blue-green cutover window. No operator action is needed for this release, in either direction: a
  0.4.2 slot keeps working alongside it, and rolling back to 0.4.2 keeps the counter's stored value.

### Changed — action required

- **Weak-hash acceptance is now an explicit, default-off operator opt-in, in the two places a
  broken digest still carried weight in a security decision.**
  - `Npm__AcceptSha1Shasum` (default `false`) — an npm packument carrying only a hex SHA-1
    `dist.shasum` and no `sha512` SRI is now treated as **unverified** for proxy cache admission
    rather than checksum-verified. The tarball still serves, on the same footing as an upstream
    that publishes no digest at all; the registry simply no longer records a
    chosen-prefix-collision-broken digest as an integrity guarantee. Packages carrying a `sha512`
    SRI — everything published this decade — are unaffected, as is every SHA-256/SHA-512 spec.
  - `Apk__AcceptSha1IndexSignatures` (default `false`) — a SHA-1 `.SIGN.RSA.<keyname>` entry in an
    `APKINDEX.tar.gz` no longer satisfies index signature verification. The digest algorithm there
    is named by the upstream-supplied index itself, so an attacker who can produce a chosen-prefix
    SHA-1 collision was choosing the weak arm. Refusal is a verification failure (new reason
    `weak_signature_algorithm` on `dependably.apk.index_signature_failures`); the index is neither
    cached nor served. **Alpine's own mirrors still sign with SHA-1**, so an org that has pinned an
    apk trust anchor (or set `Apk__VerifyIndexSignature=true`) must set this opt-in to keep
    verifying a stock Alpine index. Orgs with no apk anchor never ran verification and are
    unaffected. `.SIGN.RSA256.*` / `.SIGN.RSA512.*` signatures verify in either posture.

  Each acceptance and each refusal logs once per process, mirroring
  `Mfa__AcceptLegacyRecoveryCodes`.

- **Signature trust anchors must clear a minimum-strength floor at import.** `POST
  /api/v1/trust-anchors` (Settings → Trust Anchors) now rejects material whose key is below
  RSA/DSA/ElGamal 2048 bits or a 255-bit elliptic-curve field, across every `anchor_kind` that
  carries a key — `rsa` (apk), `pgp` (RPM, Maven), `spki` (npm), `x509` (NuGet), `sigstore_root`
  and `rekor_key` (PyPI). An anchor bounds the strength of every signature verdict derived from
  it, and RSA below 2048 has been under the NIST SP 800-57 / BSI TR-02102 floor since 2010. This
  is a hard floor rather than an opt-in because the anchor key is the operator's own choice, not
  something an upstream ecosystem forces. **Anchors already stored are not re-checked** and keep
  verifying — the floor applies only when adding one, so no upgrade breaks a running deployment;
  rotate a legacy key at your own pace.

- **Existing browser sessions are signed out on upgrade.** Session JWTs now carry a bound
  `iss`/`aud` pair, and validation requires both, so a session cookie minted by an earlier
  version no longer authenticates. Users log in again once; nothing else is affected — API
  tokens, service tokens, and `token_version` invalidation are unchanged. There is no new
  configuration: the issuer and audience are fixed values, since tokens are already signed with
  the instance's own `jwt_secret`.

- **API tokens that carry no capability set are deleted on upgrade and must be re-minted.**
  The `capabilities` column was added to `user_tokens` / `service_tokens` by an `ALTER TABLE
  ADD COLUMN` with no default, so every token minted before it exists with `capabilities =
  NULL`. Such a token authenticates but grants nothing — an API token's capability set is its
  ceiling and never falls back to its owner's role — so it now fails every capability-gated
  route and management action. Rather than leave those rows listed as live while denying them
  at each request, the `purge_legacy_null_capability_tokens` migration deletes them at startup.
  **Any automation still using a pre-capabilities token stops working and the token disappears
  from Settings → Tokens; mint a replacement with an explicit capability set.** Tokens created
  with capabilities are untouched, and fresh installs have nothing to purge.

- **RPM signature verification now checks the payload digest, so an RPM signed only with
  `RPMSIGTAG_RSA` and carrying no `RPMTAG_PAYLOADDIGEST` records `failed` instead of `verified`.**
  That tag signs the main header, not the payload; the payload is bound to it by the digest inside
  the signed header, which is now recomputed over the streamed payload rather than assumed. With
  no digest present nothing binds the payload, so the verdict is fail-closed. rpm has written the
  digest since 4.14 and older packages carry a header+payload signature that is verified directly,
  so this affects only packages that have neither. Under `verify_rpm_signatures=block` such a
  package is refused; under `warn`/`off` behaviour is unchanged.

### Security

- **Deleting a hosted version no longer frees its coordinates for reuse under a blocking
  version-overwrite policy.** Each hard delete records a version tombstone, and a republish of
  a tombstoned `(org, ecosystem, name, version)` is refused with `409 version_tombstoned` under
  exactly the policy that would refuse overwriting the live version. This closes
  delete-then-republish as a way around `version_overwrite_policy=block` (the default) using
  only publish + delete rights. Orgs on `allow`, or on `exception` with a package-level
  `allow` override, are unaffected. Only deletions from this release forward are remembered,
  and retention/cache-eviction deletes never tombstone. To republish a deleted coordinate,
  an administrator relaxes the org's version-overwrite policy (Settings → Gates).
- **A JWT's type is now bound into the token, not inferred from its `scope` claim.** Every JWT
  the instance mints is signed with the same `jwt_secret`, so a pre-second-factor MFA challenge
  and a full session token were distinguishable only by an application-layer scope check that had
  to name each non-session scope explicitly. Session tokens now carry the session audience and
  challenge tokens the challenge audience, and each validator pins the one it accepts — so a
  token minted for another purpose is refused during token validation, before any claim check
  runs, and a new token type added later inherits the refusal without an allow-list update. The
  scope check is retained as a second, independent barrier.

### Fixed

- **A Redis outage no longer disables login, invite, and token-create rate limiting silently.**
  The Redis fixed-window limiter caught every exception and granted the request from a bare
  `catch` with no log and no metric, so there was no way to know it was happening, alert on it, or
  size the exposure afterwards. Grants (and, under the new fail-closed posture, denials) are now
  logged at `Warning` with the policy name and counted. Account lockout is unaffected and was
  never bypassed by this: the lockout store's errors propagate and the login path does not catch
  them, so an attempt that cannot read or write lockout state fails closed before any session is
  issued.

  **This does not mean lockout state is durable in HA.** With `DEPENDABLY_DEPLOYMENT_MODE=ha`
  the lockout store is Redis-resident with no database fallback, so a flush, an eviction under
  `maxmemory`, or a failover to a lagging replica resets every account's failed-attempt counter
  — and unlike an outage, that path returns *successfully*, reading as a clean account rather
  than an error. Run Redis with `maxmemory-policy noeviction` so lockout keys are never evicted
  to make room, and treat a failover as a security-relevant event. See CONTRIBUTING.md →
  "Account lockout state in HA is Redis-resident".

## [0.4.0] - 2026-07-17

A minor release: new protocol and operator surfaces, a large correction to how proxied
artefacts are catalogued, and several fail-closed security changes. **Read "Changed —
action required" before upgrading**; three items change how an existing deployment
behaves, and one (legacy `SMTP_*`) fails silently if ignored.

### Changed — action required

- **Legacy `SMTP_*` environment variables are ignored.** Email configuration is now
  database-backed and there is no environment-to-database seed, so `SMTP_HOST`,
  `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM`, and `SMTP_STARTTLS` have no
  effect. **An upgraded deployment that still sets them stops sending org invite emails
  with no error** — the invite endpoint falls back to returning the invite link in the API
  response body. Reconfigure the relay at **Settings → Instance settings → Instance email
  (SMTP)**, then remove the variables. Alert email delivery is configured separately at
  **Settings → Integrations → Email**, and which alerts fire on the **Alerts** tab. A
  startup warning now names any legacy variable it finds present-but-ignored.
- **A `/0` CIDR in `TRUSTED_PROXIES` now fails startup.** `0.0.0.0/0` or `::/0` told the
  forwarded-headers middleware to trust every peer, letting any client forge
  `X-Forwarded-For` and impersonate an allowlisted caller against the `/metrics`,
  `/version`, and management OpenAPI IP gates. This is refused at boot, consistent with the
  existing fail-fast on malformed entries. Narrower-but-still-broad ranges (a proxy fleet
  subnet, a VPC CIDR) remain an operator judgment call. **A deployment carrying `/0` will
  not start until the entry is narrowed.**
- **MFA recovery codes issued before the keyed-hash scheme are rejected by default.** The
  legacy form is a bare unsalted SHA-256 over Identity's ~47-bit code space —
  brute-forceable offline from a database dump and then usable as a second factor. A legacy
  digest cannot be upgraded in place (the plaintext exists only during redemption), so
  unredeemed codes kept the weak form indefinitely. Affected users must regenerate their
  recovery codes. To open a temporary migration window, set
  `Mfa:AcceptLegacyRecoveryCodes=true`; the first rejection logs a warning naming the
  setting. New installs have no legacy rows and are unaffected.
- **The management OpenAPI surface now requires an authenticated session.**
  `/openapi/management.json` and `/api/v1/docs/*` were gated by the metrics IP allowlist
  alone, so any caller inside it could enumerate the whole control-plane API contract
  unauthenticated. Both now also require a validated JWT carrying `scope=tenant` or
  `scope=system`. **Anything that scraped the management spec anonymously must now
  authenticate.** The protocol document (`/openapi/protocol.json`, `/docs/`) stays public —
  package-manager clients discover it by spec.

### Changed — behavior

- **A proxy fetch that cannot be recorded on the cache plane is now refused with 503**
  rather than served. An artefact the registry cannot catalogue cannot be scanned or gated,
  and one it cannot vouch for is not served. The cache-plane record is retried before the
  fetch gives up; the staged bytes make the client's retry cheap. This is a 503 and never a
  404 — the artefact exists upstream, it just could not be admitted. Under sustained
  metadata-store trouble, proxy installs now fail loudly instead of silently minting
  uncatalogued rows.
- **`maven-metadata.xml` now lists cached proxy versions.** The document built its local
  version set from `package_versions` only, so whenever the upstream merge contributed
  nothing (proxying off for the coordinate, or upstream unreachable) it omitted versions the
  org had cached and could serve by exact coordinate — breaking version discovery and
  SNAPSHOT/`latest` resolution. It now unions the org's cache-plane versions. **Expect
  one-time ETag churn**: wherever an org had cached proxy versions the document content
  changes on first serve after upgrade, and changes again as new versions are cached, so
  clients revalidate and refetch. The body stays byte-stable for a given version set.
  `<latest>`/`<release>` are now resolved by version order rather than row position: the
  union was ordered by `MAX(created_at)` alone, but the cache-plane backfill stamps one
  shared timestamp into every row it writes, so on an upgraded deployment every proxied
  version of a coordinate tied — leaving `<latest>` free to land on an arbitrary older
  version and to move between cache rebuilds, an unstable ETag against the byte-stability
  the generated `.sha1`/`.md5` sidecars depend on.
- **A `local_only` claim now purges the cache plane too.** The purge only deleted
  `origin='proxy'` rows from `package_versions`, but every current proxy fetch lands on the
  shared cache plane — so flipping a name to `local_only` left cached upstream copies
  catalogued, still advertised, still served, and their bytes never reclaimed.
  `purged_count` (in the API response, the claim history row, and the audit detail) now
  counts versions removed from **both** planes, so the number an operator sees may be
  larger than in 0.3.1 for the same action.
- **`GET /api/v1/lookup` answers a definitively-absent package with `200` and
  `found=false`**, not `404` — an absent package is an answer to the query, not a failed
  request. An unreachable upstream is still `503`. Clients that treated `404` as
  "not found" must read the `found` field.
- **NuGet proxy fetches no longer mask metadata-store failures as `404`.** The rethrow
  predicate was SQLite-only, so under `DB_PROVIDER=postgres` a transient DB error (pool
  exhaustion, failover) fell through to a blanket 404: the client reported a real package as
  nonexistent (NU1102) and, because 404 is not retried, the restore failed outright. These
  now surface as a retryable 5xx, matching npm/PyPI. PyPI's equivalent 404-masking was fixed
  alongside it.
- **SAML login fails closed on an expired pinned IdP signing certificate.** Production
  SP-initiated login returns a 503 Problem instead of redirecting into a doomed round-trip,
  and the ACS path returns a closed 401, where both previously logged a warning and
  proceeded. The admin **Test SSO** path stays warn-only so an expired cert is still
  diagnosable.
- **Host filtering fails closed when `BASE_URL` is unset or localhost** — requests arriving
  through a reverse proxy under a real domain are rejected with 400 until `BASE_URL` names
  that domain. The CORS policy warns rather than silently trusting a localhost origin.

### Added

- **NuGet symbol server (SSQP).** Pushing a `.snupkg` to `PUT /nuget/symbols` indexes every
  Portable PDB it contains by its debug-id, so a debugger can fetch a single PDB from
  `GET /nuget/symbols/{pdb}/{key}/{pdb}` — the
  [Simple Symbol Query Protocol](https://github.com/dotnet/symstore/blob/main/docs/specs/Simple_Symbol_Query_Protocol.md)
  route Visual Studio and `dotnet-symbol` speak. The whole archive stays downloadable at
  `GET /nuget/symbols/{id}/{version}/{file}`, and the symbol-server endpoint is advertised
  from the v3 service index so clients discover it. The index is per-org and every lookup is
  tenant-scoped, so a debug-id belonging to another tenant is never served. Reads follow the
  same auth posture as every other NuGet read: a token is required unless the org has
  AnonymousPull enabled. Serving a package feed and serving symbols are separate
  capabilities — most private registries store `.snupkg` files without indexing what is in
  them.

  **Known limitations.** Indexing covers **Portable PDBs only**; a `.snupkg` carrying
  native/Windows PDBs is stored and downloadable but contributes nothing to the index.
  `.snupkg` is the accepted symbol-package format — the legacy `.symbols.nupkg` shape is
  not. SSQP source-file retrieval is not served, so a debugger resolves sources elsewhere.
  These match the limits nuget.org's own symbol server documents.
- **npm audit works.** `POST /npm/-/npm/v1/security/advisories/bulk` previously refused with
  a deliberate 501; it now answers from the registry's OSV-backed advisory data, projected
  into npm's bulk-advisory wire format. Version ranges are evaluated under npm's native
  semver ordering (`fixed` exclusive, `last_affected` inclusive). Queries go through the
  existing `IOsvSource` batch path, so remote and air-gapped (local dump) hosts behave
  alike. The audit is refused rather than answered when the advisory source cannot be
  vouched for — a clean report from an unavailable source would be a false all-clear.
- **Operator-facing JWT signing-secret rotation** — `POST /api/v1/system/jwt-secret/rotate`.
  The secret is generated server-side, never accepted, echoed, or logged, and becomes
  effective on the serving replica before the response is written; other replicas converge
  within `Auth:JwtSigningKeyRefreshSeconds` (default 1 s), and the response reports that
  window. **Rotation signs everybody out, including the caller** — there is no old-key grace
  period, because a leaked `jwt_secret` forges any session on the instance and honouring the
  old key would keep an attacker's forged tokens alive just as long. Expect the next request
  to 401. Previously an operator's only remedy for a suspected key compromise was a manual DB
  edit plus a restart — and doing that on a live instance broke it, since the validation key
  was captured once at process start.
- **PEP 691 JSON Simple API** for modern pip/uv — `GET /simple/` and `/simple/{package}/`
  now negotiate the response representation from the `Accept` header
  (`application/vnd.pypi.simple.v1+json` vs. `text/html`, quality-value aware), defaulting to
  HTML so existing installs are unaffected. The JSON projection shares the HTML renderer's
  block-gate filtering, so a client negotiating JSON cannot discover an artifact the download
  gate would deny.
- **Instance and per-org email delivery, and operator Slack.** An instance SMTP transport
  (Settings → Instance settings) delivers org invites; per-org alert email settings with a
  delivery gate and recipients live on the **Alerts** tab, with the transport itself on
  **Settings → Integrations → Email**. Operator-realm Slack notifications cover tenant
  lifecycle and admin events.
- **Risk drill-down API and UI** — the rows behind the Overview dashboard's risk tiles.
  `GET /api/v1/risk/operational` lists the versions at or over the versions-behind threshold
  (and returns the tile's own distinct-package count alongside the row total);
  `GET /api/v1/risk/license` lists versions carrying a blocklisted SPDX identifier or no
  license at all, labelling each row `blocklisted` or `unknown`. Both union the uploaded and
  proxied storage planes exactly as the tiles do, so a list agrees with the count it came
  from, and both gate on `read:packages` — the capability that already serves the tiles — so
  they are not admin-only. The dashboard tiles drill down into them.
- **Activity time window** — `GET /api/v1/activity` accepts `since=24h|7d|30d|90d`, honoured
  by the paged list and the `format=csv` export alike, so the blocked-pull drill-down scopes
  to the same 30-day window the dashboard tile counts.
- **PAT auth on license-policy and lookup reads** — `GET /api/v1/license-policy` (plus its
  `/allowlist` and `/blocklist` views) and `GET /api/v1/lookup` now accept a PAT or service
  token carrying `read:packages`, joining the rest of the read-only management surface.
  Policy mutations stay JWT-session-only.
- **`artifact_inventory` read model** — one canonical place that merges a package's two
  catalogues (uploaded and proxied). The storage baseline, license-risk tile, and version
  lists read from it rather than each re-deriving the union.
- **Copy remediation brief** action on the Vulnerabilities page, with CWE-to-skill coverage
  across nine curated skills.
- **OCI cross-repository blob mount**, with the sub-operation pinned in the inventory.
- **Maven version-level SNAPSHOT metadata** with `snapshot`/`snapshotVersions`.

### Fixed

#### Tenant isolation and security

- **Cross-tenant OCI blob read (critical) and existence oracle (high).** The `oci_blobs`
  store is content-addressed with no org segment, so in the default single-store deployment
  (cache == registry) one tenant's bytes resolve under the identical key any other tenant
  would compute — a bare store hit was never proof of authorization. Blob `GET` now confirms
  entitlement before serving a shared-store hit, and `HEAD` answers a cache hit only from an
  `oci_blobs` row scoped to the caller's own org.
- **`local_only` was bypassed on the proxy cache-hit serve path** — a dependency-confusion
  bypass: the claim was enforced on the fetch path but not when serving an already-cached
  artefact.
- **Per-tenant storage quota is enforced on the cache-fill path.** The proxy cache-MISS
  write paths streamed verified upstream bytes into the cache tier with no quota check,
  letting a tenant with proxy passthrough enabled grow the shared cache plane without bound.
  The quota gate also now accounts for in-flight fills: deriving the ceiling from a live
  `SUM` was racy, since a fill is invisible to it until recorded after the fetch returns, so
  K concurrent pulls of K distinct artefacts all admitted themselves against the same
  pre-fill sum. Upstream registries are per-org and tenant-admin configured, so a tenant
  could point its org at a server it controls and burst far past its ceiling onto shared disk.
- **Percent-encoded path traversal** rejected in Go proxy module/version, Maven proxy path
  segments, and lookup `ValidateName`.
- **OCI `aws_ecr` auth fails closed** rather than falling back to anonymous.
- **`/edge/status`** is gated behind the metrics IP allowlist.
- **npm scoped-name allow/blocklist gate**, and rate limiting extended to the dist-tag and
  unpublish mutation routes.
- **Raw exception text** (SMTP and other test-send paths) no longer leaks to API responses.
- **Upstream metadata TTL cache is isolated per credential**, so one tenant's authenticated
  upstream response cannot be served to another.
- **A session-invalidation race in `UserTokenVersionStore`** (invalidate-then-fill) is closed,
  and logout revocation failures are no longer swallowed.

#### Proxy cataloguing and the storage planes

This release completes the move of proxied artefacts onto the shared cache plane
(`cache_artifact` + `tenant_artifact_access`). Several read surfaces still joined
`package_versions` and so were blind to proxied artefacts:

- **Proxy zombie rows: a second sweep.** The one-shot migration ran on deployed databases
  while the fetch path could still mint an `origin='proxy'` row in `package_versions`
  (it fell back to the hosted plane whenever it could not record on the cache plane). Rows
  written after that first pass ledgered itself were left uncleaned — invisible to the
  vulnerability sweep and to retention, which both read `package_versions` as
  `origin='uploaded'`, so unscanned and unreclaimable. The fetch path now catalogues
  exclusively on the cache plane and refuses a fetch it cannot record there, so no new zombie
  is produced; this release re-runs the idempotent backfill-and-delete once more to catch the
  stragglers. On a database with none it is a no-op. **Back up your database before
  upgrading** — the sweep deletes `package_versions` rows after re-cataloguing them.
- **The storage baseline counts every plane**, and no longer drops orphan artifacts.
- **Proxied version counts counted files, not versions.** `cache_artifact` is keyed
  `UNIQUE (ecosystem, name, version, filename)`, so one proxied version owns one row per
  file — but the package tile's `VersionCount` and retention both read a row as a version.
  A proxied Maven version (jar + pom + sources + javadoc) reported 4, NuGet with its
  `.nuspec` 2, multi-file PyPI 2, and a version held on both planes counted twice, while the
  detail page showed one. Both now count distinct versions, so tile counts and retention
  agree with the detail page.
- **A release-age hold stays raised on the proxy plane**, and a proxy version can be manually
  blocked or approved (both previously only worked for uploaded versions).
- **The deprecation refresh revisits stale hosted-only packages** the cache pass cannot see.
- **PyPI gates a first fetch even when the blob is a global cache hit**, and gates a proxy
  first-fetch *before* adopting it rather than after.
- **The orphan-blob reconciler unions every table holding a hosted blob key** —
  `package_versions` plus `package_version_files`, `maven_version_files`, and
  `nuget_symbol_index`, whose rows are the sole reference to a Maven `.pom`/sources jar, a
  PyPI sdist published alongside a wheel, or a NuGet symbols package. Reconciling against
  `package_versions` alone deleted live artefacts.
- **Quarantine decisions match proxy artifacts by cache-plane coordinate.**
- **A plane-coverage compliance gate** now routes and marks every uploaded-catalogue read, so
  a new read surface cannot silently go plane-blind.

#### OCI

- **Every OCI image reported as having no license.** An image's SPDX expression was captured
  only on its `oci_blobs` manifest row, never in the shared `package_version_licenses` table
  every other ecosystem uses — so the package-detail page rendered no licenses for any image,
  and the license-risk tile and its drill-down counted correctly-licensed images as "no
  license" while never flagging one whose license was on the blocklist. An image's license is
  now projected onto whichever plane catalogued it as an ordinary license row, and existing
  images are backfilled. The OCI special-casing is gone from every license reader.
- **A crash-loop on multi-tenant upgrade** from the OCI licence backfill.
- **A shared manifest blob is no longer destroyed** by a management version delete; the
  physical blob delete is gated on a real cross-org refcount and serialised on the per-key
  lock, closing quota and dangling-row races.
- **Single-flight blob joiners get their own per-org `oci_blobs` row.**
- **Both catalogue planes are guarded** against scanning and evicting images.

#### Correctness and robustness

- **Hosted blob keys are content-addressed on every publish path**, so bytes and checksum
  cannot diverge; this closes a publish blob-checksum race and covers the RPM/Maven paths
  outside the publish service.
- **A transient DB failure in one stats refresh pass no longer stops the host**, and a cache
  blob delete that persistently fails no longer livelocks eviction.
- **Durable delivery bookkeeping survives shutdown**, and a quota double-decrement is fixed.
- **npm packument rebuilds are request-lifetime-safe and invalidation-safe**; NuGet
  proxy-merged registration rebuilds are `HttpContext`-independent; a lost-invalidation
  window in `RenderedResponseCache` rebuilds is closed.
- **Package search**: substring search restored, case folding aligned across providers, and
  the `LIKE` pattern anchored to the name prefix.
- **Maven advisories match in `OSV_MODE=local`** by converting the purl name to colon form.
- **Webhook dispatch and SIEM retry backoff are driven off `TimeProvider`.**
- **`RpmHeaderParser` bounds header-intro overflow and offset reads.**
- **PyPI advertises the local sha256** for filenames hosted both locally and upstream, and
  renders local files before upstream in the JSON merged index.
- **The operational-risk tile no longer undercounts cross-ecosystem name collisions** — it
  counts distinct `(ecosystem, name)` pairs, matching what the drill-down lists.
- **The unread `metadata_cache` table is dropped**, as is a Postgres-broken duplicate
  `ListInstanceSettingsAsync`.

### Known limitations

- **A proxied/cache-plane version cannot be deleted from the management UI or API** (#385).
  `DELETE /api/v1/packages/{ecosystem}/{name}/{version}` resolves through `package_versions`
  only, so it returns 404 for proxy versions across every proxy ecosystem, and their bytes
  keep counting toward the org storage total. For OCI this is permanent, since cache-plane
  manifests are also excluded from automated retention/eviction by design.
- **An OCI protocol manifest delete leaves a UI zombie** (#399).
  `DELETE /v2/{repo}/manifests/{digest}` cleans `oci_tags`, `oci_blobs`, and the refcounted
  blob, but not the tag-push `package_versions` shadow row — so the management package page
  and `artifact_inventory` keep listing the deleted digest as a version.

## [0.3.1] - 2026-07-12

This file was introduced during the 0.3.1 cycle; releases before it are not catalogued here.
The entries below describe surfaces that shipped in or before 0.3.1.

### Added

- **Go module proxy** — GOPROXY protocol surface at `/go/`. Implements `@v/list`, `.info`, `.mod`, `.zip`, and `@latest` routes with bang-encoding decode at the route boundary and re-encode on upstream URL construction. All requests go through the proxy cache-miss path; `.zip` fetches record a `package_versions` row in the catalogue. Proxy-only (no hosted push path).
- **Cargo sparse registry** — sparse index protocol at `/cargo/`. Serves `config.json`, sparse index files (per-name path layout), and crate downloads at `api/v1/crates/{name}/{version}/download`. Local versions shadow upstream on collision; crate downloads are cached in the blob store on first fetch. OSV vulnerability scanning and PURL normalization (`pkg:cargo/{name}@{version}`) are included.
- **Staging-disk guardrails** — `StagingDiskMonitor` samples staging volume free space every 60 s and emits OTel gauges and a Serilog `Warning` when free space falls below `STAGING_DISK_WARN_THRESHOLD_PERCENT` (default 10 %). Proxy fetches are rejected with 507 Insufficient Storage when available bytes fall below `STAGING_DISK_FLOOR_BYTES` (default 512 MiB); when `Content-Length` is present the effective floor is `max(STAGING_DISK_FLOOR_BYTES, 2 × Content-Length)`.
