# Edge node — operator runbook

A dependably **edge node** is a headless, cache-only replica that sits inside your network and
points at one central dependably instance (the **master**) as its sole upstream for every
ecosystem. It serves npm, PyPI, NuGet, Maven, RPM, Cargo, Go, and OCI locally, fills its cache on
first miss by pulling from the master, and ships no management plane. It is the JFrog Artifactory
Edge Node / Docker registry pull-through mirror pattern: a thin, disposable cache close to the
consumers (a CI fleet, a branch office, a data center).

The edge deployment artifacts run the dedicated **`dependably/edge`** image. That image contains
**no management plane at all** — not disabled, absent. The admin/auth/SAML/SPA/OpenAPI closure is
excluded by two mechanisms: (1) the **assembly reference graph** — the edge composition root
(`Dependably.Edge`) references only `Dependably.Core`, never `Dependably.Management`, so the
management-plane packages (SAML, the IdentityModel/JWT stack, BCrypt, zxcvbn, Redis, OpenApi) never
enter the publish closure; and (2) a **per-MR closure guard** in CI (`edge-closure-guard`) that
scans the edge SBOM and fails the pipeline if any excluded package reappears. The community image
run with `DEPLOYMENT_MODE=edge` remains a fully supported alternative (see the fallback below); that
path strips the management surface at runtime rather than by absence, and its stripping convention
stays tested.

## What an edge does — and does not

An edge node:

- Serves registry reads for every ecosystem from a local warm cache.
- On a cache miss, fetches from the master (authenticated with the edge token), verifies the
  SHA-256, stores the artifact in the cache tier, and serves it. A repeat request is a warm hit.

An edge node does **not**:

- **Publish.** Every push/upload/import (npm publish, NuGet push, Maven PUT, RPM upload, OCI
  manifest/blob PUT, Cargo yank, bulk import) fails fast with **HTTP 405** and the message
  "This node is a cache edge — publish to the master registry." Publish to the master instead.
- **Run a UI or login.** No admin UI, no orgs/users, no MFA/SSO, no first-boot wizard. An edge is
  configured entirely from the environment.
- **Own policy or scanning.** Vulnerability scanning, license/policy enforcement, and the durable
  registry tier all stay central on the master. The edge is a dumb cache.

## Enrollment (three steps)

1. **Mint a reader-scoped service token on the master.** In the master UI, go to
   **Settings → Service Tokens**, create a named token (e.g. `edge-ci-01`) with the **pull**
   (read-only) preset, in the org whose packages this edge serves. This token is the edge's
   identity; revoking it later takes the edge cold-only immediately. One token per edge node gives
   per-node revocation and audit attribution.

2. **Set the edge variables** in the edge node's environment:

   ```
   EDGE_MASTER_URL=https://dependably.example.com
   EDGE_MASTER_TOKEN=<the reader service token from step 1>
   ```

   `EDGE_MASTER_URL` and `EDGE_MASTER_TOKEN` are both required — the node refuses to start without
   them. The token is held in memory from the environment; do not commit it.

   You do **not** set `DEPLOYMENT_MODE` on the `dependably/edge` image: that image is
   constitutionally an edge (its composition root pins edge mode internally and rejects any tenancy
   value), so the variable is neither read nor needed. Setting `DEPLOYMENT_MODE=edge` is still
   accepted; any other value (`single`/`multi`/…) fails fast as a misconfiguration. On the
   community-image fallback below, `DEPLOYMENT_MODE=edge` is **required** — that is what selects
   edge mode on the full image.

3. **Start the node.** The compose defaults pull the prebuilt `dependably/edge` image, so
   `up -d` pulls it on first start:

   ```
   docker compose -f docker-compose.edge.yml up -d
   ```

   The image is multi-arch (linux/amd64 + linux/arm64). If your registry mirror requires
   authentication for the pull, log in first:

   ```
   docker login dependably.northwardlabs.ca   # any username; password = a reader token
   ```

   The username is ignored — Basic auth takes everything after the first colon as the
   token, so put a reader-scoped token in the password field. When the org's
   `AnonymousPull` is enabled, the pull needs no login at all.

   **Bare `docker run` alternative (direct testing).** For a quick one-off node without the
   compose file — for example to smoke-test enrollment — run the image directly:

   ```
   docker run -d --name dependably-edge -p 8080:8080 \
     -v dependably-edge-data:/data \
     -e EDGE_MASTER_URL=https://dependably.example.com \
     -e EDGE_MASTER_TOKEN=<reader token> \
     dependably.northwardlabs.ca/dependably/edge:latest
   ```

   The image exposes port **8080** and declares `VOLUME /data`. Because this invocation sets no
   `DB_PATH` / `LOCAL_STORAGE_PATH` / `PROXY_STAGING_PATH`, the cache index, cached blobs, and the
   staging directory all default under `/data` — so the single mounted `dependably-edge-data`
   volume holds everything and survives `docker rm` + recreate. This is the simplest durable shape;
   the compose file instead co-locates all of that under a single named `/cache` volume (it points
   `DB_PATH`, `LOCAL_STORAGE_PATH`, and `PROXY_STAGING_PATH` there explicitly), which stays the
   recommended production layout because it names the cache tier the whole edge value depends on.
   Either way the rule is the same: **one persistent volume, one edge process** (see the
   single-writer guard below).

### Fallback — the community image with `DEPLOYMENT_MODE=edge`

If you build locally, or standardize on the single `dependably/community` image everywhere, the
full community image run with `DEPLOYMENT_MODE=edge` is a fully supported alternative. It selects
the same headless cache-only behavior and strips the management surface at runtime (rather than the
`dependably/edge` image's by-absence exclusion), and that stripping convention stays tested. To use
it, point the image reference at `dependably.northwardlabs.ca/dependably/community:latest` (or a
local build) and add `DEPLOYMENT_MODE=edge` to the environment. The behavior an edge client sees is
identical; only the image contents and the enforcement mechanism differ.

## Inbound client auth — anonymous vs pre-shared token

By default an edge accepts **anonymous** reads and logs the startup warning:

> edge node accepting anonymous clients — intended for trusted networks only

Anonymous mode is for **trusted LANs only** — anyone who can reach the edge can pull whatever the
edge's master token can see, including that org's private packages. Set `EDGE_ACCESS_TOKEN` to a
pre-shared token whenever the edge is reachable beyond a trusted network or the master token can
see private/hosted content. When set, the edge seeds it as a reader token in its own database,
disables anonymous pull, and requires clients to authenticate (`Authorization: Bearer <token>`,
or Basic for PyPI/NuGet). Rotating the value replaces the row on the next restart.

## Hardening a fresh node

A fresh edge with only the two required variables set logs a handful of first-boot warnings. Each
one is accurate for an edge and points at exactly one setting. None abort startup — an edge on a
trusted LAN can run with all of them unset — but here is what each means **on an edge** and what to
set to clear it:

- **`edge node accepting anonymous clients — intended for trusted networks only`.** No
  `EDGE_ACCESS_TOKEN` is set, so anyone who can reach the edge pulls whatever the master token can
  see (including that org's private packages). Set **`EDGE_ACCESS_TOKEN`** whenever the edge is
  reachable beyond a trusted LAN or the master token can see private/hosted content (see *Inbound
  client auth* above).
- **`BASE_URL is not set` → permissive host filtering.** With no `BASE_URL`, `AllowedHosts` is `*`
  and any `Host` header is accepted, which allows Host-header injection into absolute links. (The
  edge issues no session cookies and runs no login, so the cookie half of this warning does not
  apply to an edge and is not emitted.) Set **`BASE_URL`** to the URL clients use to reach the edge
  (e.g. `https://edge.internal.example.com`) so unknown `Host` values are rejected.
- **`TRUSTED_PROXIES is not set` → forwarded headers ignored (fail-closed).** `X-Forwarded-For` /
  `-Proto` / `-Host` are discarded, so the edge sees the reverse proxy's socket address as the
  client, not the real caller. Set **`TRUSTED_PROXIES`** to your reverse proxy's IP(s)/CIDR(s) when
  one fronts the edge, so real client IPs are visible for rate limiting and logs.
- **`DEPENDABLY_MASTER_KEY not set` → the master enrollment token is stored unencrypted.** On an
  edge the only recoverable secret held at rest is the seeded `EDGE_MASTER_TOKEN` (in the cache
  database's `upstream_registry` secret column), used to authenticate upstream fetches from the
  master. Set **`DEPENDABLY_MASTER_KEY`** to envelope-encrypt it at rest, or put the database file
  on an OS-encrypted volume (LUKS/dm-crypt, encrypted EBS) instead. The key format and behavior
  (inline base64-encoded 32-byte key or a path to a file containing one, fail-closed if encrypted
  secrets exist without the key) are documented in
  [CONTRIBUTING.md → Environment variables](../CONTRIBUTING.md#environment-variables) and
  [ADR 0002](adr/0002-envelope-encryption-db-secrets.md); generate the value per that convention.
  The edge stores no `jwt_secret` or `mfa_encryption_key` (it runs no login or MFA), so — unlike the
  full host — those are not among what this key protects on an edge.
- **DataProtection keys in the container filesystem.** ASP.NET Core logs that the DataProtection key
  ring is not persisted. On an edge this is harmless: the durable DataProtection ring is a
  management-plane feature (it lives in `Dependably.Management`, which the edge image does not
  contain), so an edge configures no persistent ring and holds no DataProtection-protected durable
  state. The edge protects its one at-rest secret with `DEPENDABLY_MASTER_KEY` (envelope
  encryption), not with the DataProtection ring, and it re-seeds `EDGE_MASTER_TOKEN` from the
  environment and re-protects it on every boot. Recreating the container therefore loses only an
  ephemeral in-memory ring that nothing durable depends on — no action needed.

## Central revocation

The edge holds no authoritative data. To cut an edge off, revoke its `EDGE_MASTER_TOKEN` on the
master (Settings → Service Tokens → delete). The edge can still serve whatever is already warm in
its cache, but every cache miss to the master then fails auth — the edge goes **cold-only** until
re-enrolled with a fresh token. This is the blast-radius control: a compromised edge box never
holds anything durable and is revoked with one token operation on the master.

## Outbound traffic beyond the master (OSV)

The scheduled vulnerability-scan job is off on an edge node, but the **inline first-fetch scan**
still runs on every cache miss: with the default remote OSV source, each newly fetched artifact
triggers an outbound query to `api.osv.dev` (an observer on that path sees the package names the
edge fetches). Edge nodes on private networks that should talk **only** to the master can set
`OSV_MODE=local` (with a local OSV mirror) or `AIR_GAPPED=true` to remove that egress; the block
gate then enforces from whatever advisory data is already ingested.

## Persistent cache volume (required)

The whole point of an edge — offloading the master and surviving a flaky link for warm content —
depends on the **cache tier surviving restarts**. An ephemeral per-job cache is all cold misses
and saves nothing. The compose file mounts a named `dependably-edge-cache` volume; on Kubernetes,
back the cache with a `PersistentVolumeClaim`. Keep it persistent, and size it against your working set
(`CACHE_MAX_SIZE_BYTES` caps the cache; least-recently-accessed artifacts are evicted above it).

`PROXY_STAGING_PATH` points at a disk-backed path on that volume. The container's `/tmp` is
RAM-backed tmpfs, which defeats the memory bounding for large artifacts — always stage on disk.

## Status endpoint

An edge node exposes a read-only, anonymous status surface at **`GET /edge/status`**. It is mapped
**only in edge mode** — on a standard (non-edge) instance the route does not exist (404). Like
`/health`, it takes no auth; the payload is deliberately non-sensitive (no token, no org data, no
full upstream URL, no filesystem paths — only the master's scheme+host and disk numbers).

Everything it reports is derived passively from state the process already holds. In particular,
master reachability is inferred from the outcome of upstream fetches the edge was already making —
the endpoint never probes the master itself.

```
curl http://my-edge.internal/edge/status
```

```json
{
  "masterReachability": {
    "state": "ok",
    "lastSuccessfulPullAt": "2026-07-02T09:14:03Z",
    "lastFailedPullAt": null
  },
  "cache": {
    "hits": 1842,
    "misses": 219,
    "hitRate": 0.8938
  },
  "disk": {
    "cacheVolumeTotalBytes": 107374182400,
    "cacheVolumeAvailableBytes": 41203806208,
    "stagingUsedBytes": 0
  },
  "node": {
    "deploymentMode": "edge",
    "masterHost": "https://dependably.example.com",
    "version": "1.4.2",
    "startedAt": "2026-07-02T06:00:00Z",
    "uptimeSeconds": 11643
  }
}
```

**Fields:**

- **`masterReachability.state`** — coarse, derived from the most recent upstream fetch outcome:
  `ok` when the last fetch succeeded, `degraded` when the last fetch failed (network error,
  timeout, exhausted retries, a 5xx, or a checksum mismatch), and `unknown` before the edge has
  attempted any fetch since it started. `lastSuccessfulPullAt` / `lastFailedPullAt` are the last
  time each outcome was observed (UTC, `null` until it has happened at least once). A steady
  `degraded` with a recent `lastFailedPullAt` means the link to the master is down or the edge
  token has been revoked; warm content still serves.
- **`cache.hits` / `misses` / `hitRate`** — counts since the process started (not windowed) and
  the derived ratio (`hits / (hits + misses)`, 0 when nothing has been counted). These count the
  content-addressed proxy-fetch path; a restart resets them.
- **`disk.*`** — cache-volume capacity/free bytes and the current staging-directory usage, in
  bytes. A value of `-1` means the figure could not be read. Numbers only — never paths.
- **`node.*`** — `deploymentMode` is always `"edge"`; `masterHost` is the master's **scheme+host
  only** (never the token or a full URL); `version` is the running build; `startedAt` /
  `uptimeSeconds` measure liveness since process start.

## Single-writer guard (shared SQLite)

An edge stores its cache index in a single SQLite file on the cache volume. SQLite tolerates
exactly one writing process, so **run one edge process per volume** — on Kubernetes that means
`replicas: 1` with the `Recreate` strategy (do not raise it; scale out with a second edge and its
own volume, not replicas on one volume).

A startup guard enforces this. Each process claims a heartbeat lock in the database:

- A second process started against the same file while the first is alive **fails fast** with an
  error naming the current holder, rather than corrupting the database.
- A crashed predecessor's stale heartbeat (older than `INSTANCE_LOCK_STALE_SECONDS`, default 90s)
  is taken over automatically on the next start.
- The lock is released on graceful shutdown, so a normal `docker compose` recreate restarts
  immediately without waiting out the window.

**Recovering from a false positive:** if a node crashed uncleanly and the guard now refuses to
start because it still sees a "fresh" heartbeat, either wait out `INSTANCE_LOCK_STALE_SECONDS` and
restart, or clear the lock row (`DELETE FROM instance_lock` against the cache database) before
restarting. There is deliberately no flag to disable the guard entirely.
