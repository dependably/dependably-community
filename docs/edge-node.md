# Edge node — operator runbook

A dependably **edge node** is a headless, cache-only replica that sits inside your network and
points at one central dependably instance (the **master**) as its sole upstream for every
ecosystem. It serves npm, PyPI, NuGet, Maven, RPM, Cargo, Go, and OCI locally, fills its cache on
first miss by pulling from the master, and ships no management plane. It is the JFrog Artifactory
Edge Node / Docker registry pull-through mirror pattern: a thin, disposable cache close to the
consumers (a CI fleet, a branch office, a data center).

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

2. **Set the three edge variables** in the edge node's environment:

   ```
   DEPLOYMENT_MODE=edge
   EDGE_MASTER_URL=https://dependably.example.com
   EDGE_MASTER_TOKEN=<the reader service token from step 1>
   ```

   `EDGE_MASTER_URL` and `EDGE_MASTER_TOKEN` are both required — the node refuses to start without
   them. The token is held in memory from the environment; do not commit it.

3. **Start the node.**

   ```
   docker compose -f docker-compose.edge.yml up -d
   ```

   or `helm install my-edge deploy/helm/dependably-edge --set edge.masterUrl=… --set
   edge.existingSecret=… ` (see the chart's `values.yaml`).

## Inbound client auth — anonymous vs pre-shared token

By default an edge accepts **anonymous** reads and logs the startup warning:

> edge node accepting anonymous clients — intended for trusted networks only

Anonymous mode is for **trusted LANs only** — anyone who can reach the edge can pull whatever the
edge's master token can see, including that org's private packages. Set `EDGE_ACCESS_TOKEN` to a
pre-shared token whenever the edge is reachable beyond a trusted network or the master token can
see private/hosted content. When set, the edge seeds it as a reader token in its own database,
disables anonymous pull, and requires clients to authenticate (`Authorization: Bearer <token>`,
or Basic for PyPI/NuGet). Rotating the value replaces the row on the next restart.

## Central revocation

The edge holds no authoritative data. To cut an edge off, revoke its `EDGE_MASTER_TOKEN` on the
master (Settings → Service Tokens → delete). The edge can still serve whatever is already warm in
its cache, but every cache miss to the master then fails auth — the edge goes **cold-only** until
re-enrolled with a fresh token. This is the blast-radius control: a compromised edge box never
holds anything durable and is revoked with one token operation on the master.

## Persistent cache volume (required)

The whole point of an edge — offloading the master and surviving a flaky link for warm content —
depends on the **cache tier surviving restarts**. An ephemeral per-job cache is all cold misses
and saves nothing. The compose file mounts a named `dependably-edge-cache` volume; the Helm chart
provisions a `PersistentVolumeClaim`. Keep it persistent, and size it against your working set
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
exactly one writing process, so **run one edge process per volume** — the Helm chart hard-codes
`replicas: 1` and uses the `Recreate` strategy for exactly this reason (do not raise it; scale out
with a second edge and its own volume, not replicas on one volume).

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
