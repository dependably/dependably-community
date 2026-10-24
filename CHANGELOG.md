# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.14.1] - 2026-10-23

Version 0.14.0 was not published. When upgrading from v0.13.3, read this section together with
the 0.14.0 section below.

**Upgrade notes**

- Startup now enforces the v0.13.3 upgrade floor. A database below it is refused before anything
  changes, and the error says why. A Postgres database created by 0.2.2 to 0.4.4 is recognized
  and upgrades directly, but a boot that has already failed partway on such a database leaves it
  unrecognizable; set `UPGRADE_FLOOR_OVERRIDE=true` for that boot and remove it afterwards. The
  override applies the schema to any below-floor database and logs an error. See
  [Supported upgrade path](OPERATIONS.md#supported-upgrade-path).
- Two new settings, neither of which needs changing: `THREAT_FEED_FETCH_TIMEOUT_SECONDS`
  (default `300`) caps each KEV and EPSS fetch, and `NPM_MANIFEST_RESCAN_SCHEDULE` (default
  `*/5 * * * *`) is how often `npm-manifest-rescan` runs until it has read every stored tarball.
- The schema gains the nullable column `oci_scan_jobs.first_deferred_at` and the table
  `oci_manifest_pushes`. Both are additive. On upgraded Postgres databases whose foreign keys
  drifted from the schema, the first boot replaces those keys once, inside the existing
  lock-bounded retrofit pass.
- The image scanner API refuses a scan result or rematch with more than 250,000 findings with
  `422` (`error.ociScan.findingsMax`). `POST /api/v1/oci-scan/{job}/heartbeat` and `/fail` now
  declare `200`, `409` and `422` in the OpenAPI document, and `/result` declares `204`, `409`,
  `422` and `503`.
- `GET /api/v1/lookup` with no `version` answers `422` with `reason: passthrough_off` for an
  organization with proxy passthrough off. Adding a reserved namespace that is already reserved
  answers `409` instead of `201`.
- Upgrade a master before its edge nodes. Until the master states each organization's scan
  enforcement setting, an upgraded edge treats every organization as unstated: it asks the master
  for manifests while the master is up, and never refuses a pull because of it.
- For contributors: `CredentialMintGateComplianceTests` requires every insert into a credential
  table (one with a `token_hash` and a tenant column) to run the tenant mint gate. Opt out with
  `// mint-ok: <reason>`.

### Security

- **OCI respects proxy passthrough off and the per-organization air-gap setting.** OCI checked
  only the instance-wide `AIR_GAPPED` setting. An organization with proxy passthrough off, or
  air-gapped in its settings, still had every image pull, tag list and tag
  revalidation sent to its upstream registries. With the default Docker Hub upstream, that sent
  the names of its private image repositories to Docker Hub. Such an organization now gets no
  upstream requests from OCI at all, including token exchanges and the image scanner's reads of
  images it does not hold. An image it does not hold returns `404` `MANIFEST_UNKNOWN` or
  `BLOB_UNKNOWN`, with a message naming the setting, and `tags/list` returns local tags only.
  An organization with no settings row keeps the default, passthrough on.

- The web frontend's `dompurify` dependency moves to 3.4.17, past the critical advisories
  GHSA-p98j-92pf-mc4p and its four related entries that affect 3.4.16 and earlier.

- **npm tarballs are scanned the way npm extracts them.** The scan behind the install-script gate,
  the licence extractor and the upload validator disagreed with npm's extractor in two ways, so a
  tarball could show the gates a clean manifest while npm installed one with a `postinstall` hook
  or a blocked licence. A backslash in an entry name is now read both the POSIX and the Windows
  way, and the stronger result wins, so `x\y/package.json` counts as a top-level manifest as it
  does for npm on Linux and macOS. A tar header npm would skip (a bad checksum, a link name on a
  regular file, a directory with a size) no longer hides the next header from the scan: the
  archive is read block by block as npm reads it, and any construct whose npm reading the scanner
  cannot reproduce exactly is unscannable. An unscannable tarball is refused on the proxy path
  and rejected at publish. Limits are unchanged.
- **The npm install-script detector fails closed on a read failure.** A tarball that could not be
  read, or a detector error on the proxy or publish path, recorded no install script. Each now
  records `npm:unscannable-manifest`. A proxied tarball whose staged copy disappears before the
  check (a concurrent refusal of the same bytes deleted it) answers `502` and records nothing.
  Other ecosystems keep their fail-soft detection.
- **An advisory the scan could not fetch no longer reads as clean.** When OSV's batch query named
  an advisory but fetching its record failed or ran past its timeout, the version was stamped as
  checked with no link. A version is now left unchecked and retried unless the instance already
  holds that advisory; the rest of the batch is stored. An OSV hydration timeout no longer fails
  the whole batch, so npm bulk audit answers `503` for an unreached source instead of `500`. Under
  `OSV_MODE=local`, a dump with no feed for an ecosystem no longer reads as checked: the lookup
  reports `unavailable` with `no_osv_coverage`, the scan leaves the artefact unchecked, and npm
  bulk audit answers `503`.
- **Rendered npm packuments and NuGet registration documents are cached per public URL.** Both
  embed the request's scheme and host in their links, and the cache key carried neither, so one
  request with a crafted `Host` (or `localhost`) could set the tarball and registration URLs every
  client received until the entry expired. Each base URL now gets its own entry, and an eviction
  retires them all.
- **The package lookup, NuGet symbol forwarding and Go module routes respect the organization's
  upstream settings.** With proxy passthrough off, `GET /api/v1/lookup` sent the name upstream
  with the stored credentials; it now sends nothing, answers a version-less lookup with `422`
  (`reason: passthrough_off`), and keeps the advisory and licence checks when a version is given.
  An SSQP symbol miss answers `404` without contacting a symbol server when passthrough is off,
  the organization is air-gapped, or the PDB name is a reserved NuGet name. Go module routes
  decode bang-encoded names strictly, so an invalid escape answers `404` and is never forwarded.
- **Redeeming an invite, a password-reset link or an email-change link honours a suspension.**
  Each consumed the link and wrote the user, password or address as separate steps, so a
  suspension landing between them could miss the redemption and the result survived the restore.
  Each is now one transaction that checks the tenant's status, and a suspended tenant's
  redemption answers `423` and consumes nothing. A forgot-password request for a known email on a
  replica that has not yet seen the suspension answers `202`, as an unknown email does, and sends
  nothing.
- **Password changes and operator resets remove remembered devices in the same transaction.**
  A changed or reset password committed before the user's remembered devices were deleted, so a
  failure between the two left a device that skipped the second factor.
  `POST /api/v1/users/me/password`, `POST /api/v1/system/me/password` and an operator's password
  reset now commit the password, the session invalidation and the device removal together.
- **An empty versions map from an upstream no longer clears deprecation marks.** An npm or PyPI
  answer whose `versions` or `releases` object was present but empty cleared every recorded
  deprecation for the package, so a hollow mirror answer let versions blocked under
  `block_deprecated=block_all` serve again. It is now treated as no answer, and the next upstream
  is asked.
- **OCI scan enforcement covers more of the pull path.** A manual block on an image index now
  reaches a platform manifest that was catalogued as its own image first. A `HEAD` on the blob
  route that misses the cache answers like a hit under enforcement when the blob is labelled or
  known as a manifest or is at most 4 MiB; a larger non-manifest blob keeps its headers-only
  answer.
- **An rpm lookup no longer reads clean for a name its release feed never lists.** As for apk,
  an rpm lookup now checks that the scoped release feed knows the name, and a name it
  never lists (a typo, an EPEL package under `Rocky Linux:9`, an AppStream package under a
  `::baseos` scope) answers `unavailable` with the new reason `name_unknown`.

### Fixed

- **A held OCI tag keeps serving when upstream fetching is off.** A proxied tag older than
  `Oci:ManifestTagTtl` is normally checked against the upstream before it is served. When upstream
  fetching is off, whether by the instance `AIR_GAPPED` setting or by the organization's
  settings, the held digest is now served as a cache hit. Before, it returned `404`, so an
  air-gapped instance stopped serving a pulled tag an hour after it was last checked.

- **A stalled upstream body no longer wedges a package until restart.** A shared upstream fetch
  runs once for every client waiting on the same index or artifact, and `HttpClient.Timeout`
  stops applying once the response headers arrive. An upstream that sent headers and then
  stalled held that fetch, and every later request for the package, open until the process was
  restarted. A metadata fetch now has a two-minute overall deadline, and an artifact body fails
  after sixty seconds with no progress, so a large artifact on a slow but live link still
  completes. Either expiry is reported as an upstream failure, so a cached copy is served stale
  where the organization allows it.
- **The Setup page's twine recipe uploads to the right route.** The generated `.pypirc` pointed
  `repository` at `/simple/`, the read-only index, so every `twine upload` answered `405`. It now
  points at `/pypi/legacy/`.

- **An edge node keeps serving an organization that does not gate OCI pulls through a master
  outage.** An edge trusted a master-stated `off` setting for five minutes and only in memory, so
  after that, or after a restart, every manifest bypassed the local cache, and during an outage
  digest manifests (every platform of a multi-arch pull) answered `502`. A newly upgraded edge
  refused every organization while the master was down. The `off` confirmation is now stored and
  survives a restart. During an outage only an organization last seen at `warn` or `block` is
  refused, with a `403` naming that setting; any other is answered from the local cache, digests
  and fresh tags first, then stale tags. The master states the setting for every organization,
  `off` included, and to anonymous callers, and an edge records nothing from a response without
  it.
- **Package lookups no longer give one advisory another CVE's KEV or EPSS.** A stored advisory
  covering several CVEs carries KEV if any of them is listed and the highest EPSS among them; the
  lookup applied that to any advisory sharing one alias, which could answer a false `blocked`. A
  stored row now enriches an advisory only when its id is one of the advisory's ids, or every CVE
  it names is. Advisory detail follows the same rule.
- **An OCI lookup under `block` answers with the pull's verdict.** With `oci_scan_enforcement=block`,
  `GET /api/v1/lookup` for an image now evaluates the same gate as the pull, without its side
  effects: an image with no result or a partial result reads `blocked` as `unscanned` unless that
  arm was approved, a finding over a tolerance reads `blocked` on its arm, and a manual block reads
  `manual`. Under `off` and `warn` the lookup answers `warn` as before.
- **Advisory fixes and ids are read from the right record.** A `fixedVersion` for an advisory
  covering several packages, none matching the queried name, is now `null` instead of the first
  package's fix. An advisory detail request by a CVE id that matches a GHSA record by alias
  returns the GHSA id, with the CVE listed once among its aliases.
- **Version actions on uploaded packages find the version by its ecosystem identity.** Delete,
  download, block and unblock compared version strings exactly on the uploaded side, so a PyPI
  `1.0.0-rc1` or a NuGet version in mixed case could act on the proxied copy and leave the
  uploaded release in place while answering `204`. The uploaded version now matches the way the
  proxied one does, and wins whenever both match. PEP 440's `1.0` and `1.0.0` stay distinct.
- **Saving proxy settings no longer fails on the OCI scan setting when the instance runs no
  scanner.** Every save on the Gates, Signatures and Proxy routing tabs sent the stored
  `ociScanEnforcement` back, and a stored `warn` or `block` was refused with `422` once
  `OCI_SCAN_ENABLED` was off. Sending the stored value is now accepted, and the page sends the
  field only from the Gates tab and only when it changed.
- **A parked OCI scan job no longer blocks its image for good.** A job that used up its attempts
  left the image `unscanned`, and unpullable under `block`, until someone intervened.
  `oci-scan-sweep` now queues a new job for it once it has been parked for
  `OCI_SCAN_RESCAN_AGE_HOURS`. A result stored with unverified advisories is queued again after
  the same window for every organization, as a `scan` where the scanner does not take rematch jobs.
- **The OSV outage window for an image scan starts at its first deferral.** It was measured from
  when the job was queued, so an image that waited a full window for its first claim got no
  deferral at all. The per-result advisory fetch budget is also at least the OSV client's timeout
  plus five seconds, so a hanging source is deferred rather than stored as a gap.
- **A digest-only push is queued for scanning.** A manifest pushed by digest alone was never
  catalogued, so under `block` it was refused as `unscanned` while the message said it was
  queued. It is now catalogued and queued at its first gated pull, under the repository it was
  pushed to; a platform manifest of a held index still takes the index's verdict.
- **A push probe no longer triggers a scan refusal.** A `HEAD` from a token that can publish but
  not pull, on an unscanned image, wrote an activity row, a quarantine entry and a webhook and
  answered `403`. It now skips the scan gate and answers on the licence check alone. Pull-capable
  requests stay gated.
- **The npm manifest rescan finishes in hours, not months, and checks each storage tier on its own.** It ran
  inside the daily licence backfill at 2,000 tarballs a day, so a large cache took months while
  already-cached ambiguous tarballs kept serving. It now runs as its own job on
  `NPM_MANIFEST_RESCAN_SCHEDULE` until it has read everything. An outage of the registry tier
  while the cache tier answered counted failed reads against uploaded versions and could flag
  healthy ones as unscannable; each tier now checks its own store. A tarball flagged as ambiguous
  or unscannable shows a "manifest needs review" badge instead of the install-script badge.
- **Threat-feed fetches have a deadline.** A KEV or EPSS mirror that sent headers and then
  trickled the body held the refresh indefinitely. Each fetch now stops at
  `THREAT_FEED_FETCH_TIMEOUT_SECONDS`, and one stalled EPSS batch fails alone. The marker that
  keeps advisories from being stamped from a half-applied EPSS file now uses the database clock,
  so replicas whose clocks differ by minutes no longer defeat it.
- **A webhook whose secret cannot be decrypted shows as failing.** It was skipped silently and
  looked healthy. It is now recorded as a delivery failure, without secret material, so it shows
  as failing and auto-disables on the usual thresholds. It is never sent unsigned.
- **A Postgres blue-green upgrade keeps the read-model views while data-only migrations run.**
  Startup dropped `artifact_inventory`, `artifact_license`, `org_storage_bytes` and
  `org_billable_storage_bytes` before any pending migration, so a v0.13.3 replica still serving
  failed publish, OCI manifest and inventory requests during a plain data update. Only migrations
  that restructure tables drop them now. The backfill of per-organization refresh stamps runs in
  committed batches that resume after a restart, so a large table no longer times out and
  crash-loops startup.
- **The Postgres constraint retrofit converges and says what it left.** A constraint that cannot
  validate is named in the warning with the table, column, the number of violating rows and up to
  five keys. Orphaned "created by" references are cleared, and two SBOM read-back flags with
  values outside their vocabulary are reset to their default, before validation; other columns
  are left for the operator. A foreign key with the expected name but a different definition is
  replaced. The alias reconcile and donor sweeps stop at the shared boot deadline and finish in the
  background.
- **Adding a namespace that is already reserved answers `409`.** It answered `201` with an id that
  named no stored row, and wrote an audit entry for a change that did not happen. Nothing is
  written now, and the response uses `error.list.reservedNamespaceDuplicate`.
- **OCI scan tables are indexed for deletes.** Deleting a cached artefact or a package version
  scanned `oci_scan_jobs`, `oci_scan_coverage` and `oci_component_vulns` in full. They now have
  plain indexes on their owner and organization columns, and `oci_scan_coverage.matched_at` uses
  the `C` collation on Postgres.

### Changed

- **Startup refuses a database below the upgrade floor.** A database whose migration history
  shows it was never upgraded to v0.13.3 stops startup with an error naming the floor and
  `UPGRADE_FLOOR_OVERRIDE`, before any schema change. See the upgrade notes above.
- **OCI scan findings are capped and written in batches.** One scan result or rematch may carry at
  most 250,000 findings; more is refused with `422`. Findings are inserted many rows per
  statement instead of one at a time.
- **OCI image scan enforcement can only be turned on once a scanner has connected.** Setting
  `oci_scan_enforcement` to `warn` or `block` is now refused (`422`,
  `error.settings.ociScannerNotSeen`) until the organization's scanner has called the scan API at
  least once, as well as while `OCI_SCAN_ENABLED` is unset. With no scanner every image is
  unscanned, so `block` would have refused every OCI pull, and the scanner image is not publicly
  distributed yet. `GET /api/v1/proxy-settings` gains `oci_scanner_last_seen_at`, and
  Settings → Gates keeps the control at Off with a note until a scanner has called. An
  organization already at `warn` or `block` keeps its setting, and a scanner that stops calling
  still fails closed.
- **The compose `oci-scanner` service defaults to scanner `0.2.0` instead of `latest`**
  (`OCI_SCANNER_TAG`), so a scanner upgrade is a deliberate change.

## [0.14.0] - 2026-10-16

**Upgrade notes**

- Upgrade to v0.13.3 first from anything older. A Postgres database created by 0.2.2 to 0.4.4
  is the one exception and upgrades straight to this release. See
  [Supported upgrade path](OPERATIONS.md#supported-upgrade-path).
- An unrecognized `DISABLE_BACKGROUND_JOBS` value now stops startup. Check the value before
  upgrading.
- On Linux, check the startup `Stored secret check:` warning once after upgrading and re-enter
  any secret it names.
- An OCI upstream whose token service runs on another port of the registry host needs its
  **Token endpoint** set in Settings → Proxy → Upstream registries.
- Suspending or deleting a tenant now revokes its API tokens for good, including an edge
  node's `EDGE_MASTER_TOKEN`. After a restore the tenant issues new tokens.
- Two API responses change. `GET /api/v1/lookup` with no `version` answers `422` with a `reason`
  (`name_reserved`, `upstream_not_configured`) instead of `503` for a reserved name or an
  ecosystem with no upstream. A PyPI file download for a blocklisted or non-allowlisted name that
  the upstream cannot resolve answers `403` instead of `404`. The lookup's `blockedReason` is now
  the snake_case wire token.

### Added

- **An OCI image's expanded version row shows its scan detail.** Expanding an image on its
  package page now lists, from your organization's own scan result, each scanned platform's
  coverage gaps (shown first, verbatim), the platforms scanned, and the components with findings:
  the layer and Dockerfile instruction that introduced each one, and each finding's advisory,
  severity and reachability verdict (`Reachable`, `Not observed`, or `Reachability unknown`; no
  verdict ever reads as not reachable). The full component inventory is one toggle away. An image
  with no result says why: not yet queued, queued (with its attempts), given up after N attempts,
  or no image scanner reporting. The data comes from the new
  `GET /api/v1/packages/oci/{name}/{digest}/scan` (`read:packages`), which pages one platform's
  components (`platform`, `affectedOnly`, `offset`, `limit` up to 500), lists at most 50 findings
  per component beside its full `findingCount`, and returns a scan job's state and attempts but
  never its error text. A hosted image with no result reads `unscanned` even when a proxied copy
  of the same digest has one, matching the version row's status badge. Each platform shows when its findings were last matched as well as when it was scanned, so a re-matched image never reads as only as current as its scan.

  The package list and the version page read the same scan results. Each OCI package in
  `GET /api/v1/packages` carries an `ociScan` object rolled up from the organization's results
  across the images it holds (the worst `state` wins, `findingCount` is the largest per-image
  count and `maxScore` the highest score), and each OCI version carries its own (`state` of
  `scanned`, `unscanned` or `no_feed`, plus `gapCount`, `findingCount` and `maxScore`). A
  vulnerable image shows its severity and finding count, `unscanned`, `no_feed` and partly
  scanned images each say so, and only an image scanned with no findings and no coverage gaps
  reads clean. Other ecosystems omit the field.

- **OCI image findings stay current as OSV moves.** Once an image's last OSV match is older than
  `OCI_SCAN_RESCAN_AGE_HOURS` (default 24), `oci-scan-sweep` queues a `rematch` job for it. The
  scanner reads the image's stored components from the new `GET /api/v1/oci-scan/{job}/inventory`
  and posts fresh findings to `POST /api/v1/oci-scan/{job}/matches`, without reading a manifest or
  layer: the server answers 404 to image reads for a rematch job. A new advisory raises the same
  alerts and webhook a first scan does, and one no longer found leaves the image's findings and
  version links; its alert stays, since one alert covers every digest of the repository. A stored
  scan from an older extractor is handed back with `POST /api/v1/oci-scan/{job}/reextract` and
  re-extracted. If OSV is unreachable the rematch fails and retries, and the previous result
  stays. Only an org whose scanner claims with `?kinds=scan,rematch` gets rematch jobs; the claim
  response now lists the server's `capabilities`, and a scan result may carry
  `platforms[].contentGaps` and `components[].verdict`. OCI versions and OCI lookups report the
  last match as `matchedAt`, and `dependably.oci.scan.oldest_match_age` reports the oldest across
  the instance.

- **Lookup and npm bulk audit advisories carry `aliases` and a fixed version, and the advisory
  detail endpoint serves upstream-only advisories.** Each scored and unscored advisory from
  `GET /api/v1/lookup` now has `aliases` (the other ids the same flaw is published under, never
  its own id) and `fixedVersion` (the fix for the affected range containing the queried version,
  `null` when none is published or the ecosystem has no version ordering). The npm bulk audit
  adds the same two fields to each advisory as `aliases` and `fixed_version`, matching that
  payload's snake_case; npm ignores them. `GET /api/v1/vulnerabilities/{osvId}` takes
  `ecosystem`, `name` and `version` together and, for an advisory not stored for the org, serves
  the public OSV record for that coordinate instead of a 404. A reserved name, an unreached
  OSV source, or an id the coordinate has no advisory for is still a 404.

- **`GET /api/v1/lookup` now answers for apk, rpm, oci and terraform.** The response gains an
  `advisorySource` object on every lookup, so a client can tell three cases apart that an empty
  advisory list cannot: `status: "checked"` (the source was consulted, so no advisories means none),
  `"unavailable"` (it could not be, with a `reason`), and `"not_applicable"`.
  - **apk and rpm** query OSV's release-scoped distro feeds (`Alpine:v3.20`, `Rocky Linux:9`,
    `AlmaLinux:9`, `Red Hat:enterprise_linux:9::baseos`) with the distro's own version ordering, from
    the remote API or an `OSV_MODE=local` dump. Pass the release as the new `distro` query
    parameter (`v3.20`, `Rocky Linux:9`). Without it, the release is taken from the org's
    upstream URLs only when they all name the same one; otherwise the lookup says
    `reason: "distro_required"` instead of reading as clean. A release OSV does not carry (an
    unlisted release, or a local dump with no feed for it) says `no_osv_coverage`. `version` must
    be a full build (`8.5.0-r0`, `1:3.0.7-24.el9`), and an apk name whose release feed has never
    listed it says `origin_unknown`, since Alpine advisories are filed under the origin package.
  - **oci** answers from the org's own scan result for the image digest (give the digest as
    `version`). An image with no result says `no_scan_result`; a partial scan says
    `scan_incomplete`, and keeps the advisories it did find.
  - **terraform** has no advisory source and returns `status: "not_applicable"`. That is not a
    failed check, so a terraform lookup that passes the other checks keeps the verdict `allowed`
    (it is not downgraded to `warn`).

- **OCI image scanning, off by default (`OCI_SCAN_ENABLED`).** With it on, every pushed image and
  every image a tenant pulls through the proxy is queued for that tenant's image scanner, an
  out-of-process service that reads the image's layers, inventories the OS and language packages
  inside them, and matches them against OSV. The scanner drives a new API under
  `/api/v1/oci-scan/` with a tenant token carrying the new `scan:oci` capability (the **OCI image
  scanner** token preset; admins and owners only). It claims queued images, reads only the
  manifests and blobs of the image it leased, and posts per-package results. Each org sees only
  its own scanner's results, including for a proxied image cached once for every tenant. An OCI
  version's status now comes from those results:
  - `no_feed` while no scanner is live;
  - `unscanned` until the image is scanned;
  - `vulnerable` or `clean` once scanned. A score above the org's tolerance reads
    `vulnerable`. While `oci_scan_enforcement` is `off` or `warn`, such an image still pulls and
    `GET /api/v1/lookup` for it answers `warn`; at `block` the pull refuses it (see the
    enforcement entry below);
  - `partial`, a new status, when the scan could not read or match part of the image and found
    no advisories in the rest.

  For a pushed image, the advisories also reach the existing alerts, KEV alerts and webhooks.
  Advisory records are shared by every organization, so Dependably never stores the advisory
  records a scanner posts. An advisory already stored is linked as stored. Any other advisory is
  fetched by id from Dependably's own OSV source (OSV.dev, or the sideloaded dumps under
  `OSV_MODE=local`) and stored from that record. One result fetches at most
  `OCI_SCAN_ADVISORY_FETCH_MAX` (default 200) such ids, within a third of the lease and never
  more than two minutes. An id the source does not know, one past the cap or the time budget, and
  one the source could not answer for is not stored or linked. It is recorded as a coverage gap on
  the platforms that named it, so the image reads `partial` or `vulnerable`, never `clean`, and the
  next match asks again. Records fetched before another fetch fails are kept. An id the source
  reported unknown is not asked about again for six hours. If the source answers none of the ids,
  the result is refused with 503 and the job is queued again after a backoff of at most 15 minutes.
  These refusals do not count against `OCI_SCAN_MAX_ATTEMPTS`, so an outage never parks a first
  scan. After `OCI_SCAN_RESCAN_AGE_HOURS` the result is stored with the gap instead. An OSV
  request that runs past its HTTP timeout counts as an unreached source, so it defers the result
  like any other outage; a source that answers some ids and times out on others still stores the
  partial result. The `oci-scan-sweep` job queues images catalogued before scanning was turned
  on.

  The claim response's `attempt` must come back as `?attempt=` on
  `POST /api/v1/oci-scan/{job}/heartbeat`, `/result` and `/fail`. A call without it, or with a
  value below 1, is answered 422, and a call naming a superseded attempt is answered 409, so a
  scanner whose lease lapsed cannot extend, fail or close a job a second scanner has re-claimed.

- **The OCI image scanner runs beside Dependably under the compose profile `oci-scan`.**
  `docker-compose.yml` gains an `oci-scanner` service (the `dependably/oci-scanner` image) that
  starts only with `--profile oci-scan`; without the profile nothing changes. It shares
  Dependably's network namespace and calls `http://localhost:8080`, reads its token from the
  `OCI_SCANNER_TOKEN` compose secret, runs read-only with all capabilities dropped, and waits for
  Dependably to be healthy. `OCI_SCAN_ENABLED` passes through to Dependably, default `false`. In
  multi-tenant mode the scanner needs the tenant's own `https://<slug>.<domain>` URL. Use scanner
  0.2.0 or later: 0.1.0 does not send the claim's `attempt` and cannot complete a job. See
  [OPERATIONS.md](OPERATIONS.md#oci-image-scanning).

- **`TENANT_DOMAIN` decouples the tenant parent domain from the apex host.** In
  `DEPLOYMENT_MODE=multi` the system administrator can now run at `master.mydomain.com`
  (`APEX_HOST`) while tenants resolve at `acme.mydomain.com` instead of
  `acme.master.mydomain.com`. Unset, tenants stay subdomains of the apex and nothing changes. The
  bootstrap response gains `tenantDomain`, the apex host never resolves as a tenant, and its label
  below the tenant domain is reserved as a slug.

- **OCI pulls can be gated on your organization's own image scan results.** A new per-org setting,
  `oci_scan_enforcement` (Settings → Gates → OCI image scan enforcement, or
  `PUT /api/v1/proxy-settings`), is `off` by default. At `off` no pull is refused or recorded for
  its scan; gated OCI responses carry an `X-Dependably-Oci-Scan-Enforcement` header naming the
  organization's setting, which edge nodes read. At `block`, every path that returns an image
  manifest (cache hit, upstream miss by `GET` or `HEAD`, stale tag, and manifest bytes on the blob
  route) applies your existing malicious, KEV, KEV
  ransomware, SSVC, EPSS, EPSS percentile and CVSS-ceiling gates to your organization's scan of
  the image, and refuses an image with no complete result as the new `unscanned` arm (403,
  `X-Dependably-Block-Reason: unscanned`, a `blocked_unscanned` activity row whose detail says
  `absent`, `partial` or `no_scanner`, a quarantine entry and a `package.blocked` webhook). A first
  pull is refused but still caches, catalogues and queues the image, a `HEAD` included, so a retry
  after the scan is answered from it. Approving an `unscanned` entry waives only that arm; a later
  advisory refuses the image and reopens the entry. A moving tag keeps serving its last passing
  digest until the new one's scan passes, shown on the version page and in the
  `dependably.oci.tag_pending_hold_age` gauge. `warn` serves everything and records what `block`
  would have refused. Each organization's verdict comes from its own scan only. An edge node
  answers manifests of an organization its master gates through the master, and refuses rather
  than stale-serves while the master is unreachable. Moving off `off` needs `OCI_SCAN_ENABLED`.

### Security

- **An npm package whose `package.json` repeats a key can no longer slip past the install-script gate.** Node keeps the last of two equal keys, so a manifest with `"scripts":{}` followed by `"scripts":{"postinstall":"..."}` runs its hook on install, but the scanner read the first and reported no script. A manifest with a duplicate key (or a detector failure on an npm tarball) is now refused on the proxy path and rejected at publish, and is recorded as `npm:unscannable-manifest` wherever it reaches the install-script check. A proxied tarball refused for an unreadable or ambiguous manifest also has its staged blob deleted when no other cache row references it, instead of leaving it behind.

- **A token or invite minted while a tenant is being suspended no longer survives the suspension.**
  A personal access token, service token, invite, password-reset link, email-change link or
  remembered device whose request was admitted just before the tenant was suspended could commit
  after the suspension had revoked the tenant's credentials, and then work again when the tenant
  was restored. Each now re-reads the tenant's status inside its own transaction (locking the
  organization row on Postgres) and is refused with the same 423 a locked-out tenant gets.

- **.NET cryptography packages moved to 10.0.13 for five denial-of-service advisories.**
  `System.Security.Cryptography.Pkcs` (CVE-2026-84008, CVE-2026-70162) and
  `System.Security.Cryptography.Xml` (CVE-2026-96958, CVE-2026-96959, CVE-2026-96960) were at
  10.0.10. The other Microsoft 10.0.x packages move to 10.0.13 with them. `Microsoft.AspNetCore.OpenApi`
  10.0.13 already requires a patched `Microsoft.OpenApi` (2.12.2), so its explicit 2.7.5 pin is
  removed.

- **The shipped images now bundle the 10.0.13 ASP.NET Core runtime.** `System.Security.Cryptography.Xml`
  (CVE-2026-96958, CVE-2026-96959, CVE-2026-96960) is not a NuGet dependency of any project: a
  `--self-contained` publish takes it from the ASP.NET Core runtime pack that the build SDK image
  carries, and the SDK image pin predated 10.0.13, so the community and edge images still shipped the
  10.0.7 copy. Both Dockerfiles and the CI multi-arch build now pin the SDK image (10.0.402, runtime
  10.0.13) and the matching `runtime-deps` image by digest. A self-contained publish of `Dependably` and
  `Dependably.Edge` resolves `System.Security.Cryptography.Xml.dll` from
  `runtimepack.Microsoft.AspNetCore.App.Runtime.linux-musl-x64/10.0.13`.

- **A refused PyPI file download no longer asks the upstream about the package.** On a cache miss,
  a download for a file of a reserved-namespace name, a `local_only`-claimed name, a blocklisted
  or non-allowlisted name, or any name while proxy passthrough is off, first fetched the
  upstream's simple index for that name, with the upstream credential, and only then refused with
  its 404 or 403. The request was refused, but the name of an internal package had already been
  sent to every configured PyPI upstream, which is the disclosure the dependency-confusion guard
  exists to prevent. The refusals now run first, and nothing is sent upstream for a refused
  request. One visible change: a blocklisted or non-allowlisted name whose file the upstream
  cannot resolve (or with no PyPI upstream configured) now answers 403 and records a `blocked`
  activity row, where it answered 404 before. Allowed fetches and the reserved, `local_only` and
  passthrough refusals are unchanged.
- **A reserved name is never sent to a package registry, on any lookup path or ecosystem.** The
  dependency-confusion guard promises that a name an organization has reserved never reaches a
  public registry, but several paths asked anyway. Each now checks the reservation first and
  makes no upstream request:
  - Maven `maven-metadata.xml` for a reserved group, and for a path whose group-level reading
    (`g/a/` as group `g.a`) is reserved. Hosted and cached versions of the name still serve,
    local-only.
  - The latest-version lookup at first fetch, the package lookup and the daily deprecation
    refresh, for npm, PyPI, NuGet, Maven, Cargo, Hex and Go (a Go name with an invalid escape
    counts as reserved). A reserved name records nothing for the organization and marks nothing
    deprecated or revoked, and a package shared with another organization is not touched for it.
  - `GET /pypi/{name}/json` and `/pypi/{name}/{version}/json`, which proxied a reserved name that
    the simple index and the downloads already refused. Locally known versions still serve.
  - `GET /hex/docs/{name}-{version}.tar.gz` for a name reserved after its package tarball was
    cached; docs already held for it still serve.

  Adding or removing a reservation also evicts the organization's already-rendered Maven metadata
  and package-lookup outcomes at once, instead of serving the earlier document for up to five
  minutes (lookups: two).

  Advisory queries are not registry requests: a lookup with an explicit version, and the
  vulnerability scan of a hosted version, still ask the advisory source about a reserved name.
  Under `OSV_MODE=remote` that is OSV.dev; under `OSV_MODE=local` the name stays on the instance.

- **An npm tarball with more than one top-level `package.json` can no longer hide an install
  script or a blocked licence.** npm extracts with last-write-wins, so it installs the last of
  several top-level manifests, while Dependably's checks read the first. A tarball whose first
  manifest was clean and whose later one declared a `postinstall` hook or a blocked licence
  passed the install-script and licence gates. One shared scan now selects the manifest for the
  validator, the install-script detector and the licence extractor, and counts every top-level
  manifest at the root or in any single wrapper directory, including names that differ only by
  case, and it reads entry names the way npm's extraction does, so `package/./package.json`,
  `package//package.json`, `..` paths and Windows drive prefixes such as
  `package/C:package.json` count too, and a name with backslash separators counts under each of
  the readings npm's extractor can give it. An archive that carries bytes after a lone end-of-archive
  block is treated as unreadable, because npm keeps extracting there. Publish, import and
  upload reject such a tarball as invalid content. A proxied tarball that is ambiguous, has no
  top-level manifest, has more than 100,000 entries, or cannot be read to the end is refused with
  a 502 on first fetch, before anything is cached or served, whatever the install-script and
  licence settings. Nothing is re-checked on download. Artefacts stored before this change are
  rescanned once in the background, in bounded slices that resume after a restart: any whose
  manifest is ambiguous or unreadable is flagged as having an install script (kind
  `npm:ambiguous-manifest` or `npm:unscannable-manifest`) and has its tarball-derived licences
  deleted (those recorded at publish, import or proxy fetch; a licence set any other way is kept),
  so the install-script and licence gates see it with an unknown licence. The rescan reads only
  local blobs and the database, so it runs under `AIR_GAPPED=true` and
  `DISABLE_BACKGROUND_JOBS=true` too, as the job `npm-manifest-rescan`; name that job in
  `DISABLE_BACKGROUND_JOBS` to stop it. A blob that cannot be read is retried on later runs and flagged as unreadable after three failed attempts, but only while the blob store is answering for other blobs: a tick in which nothing can be read counts no attempts and stops. With both
  gates at their default of `off`, an already-cached or already-published ambiguous tarball still
  serves until an operator enables them. The install-script
  detector now fails closed too, reporting a script for an ambiguous, over-long or unreadable
  archive, and the licence extractor reports the licence as unknown. Single-manifest tarballs,
  including DefinitelyTyped wrapper directories, are unaffected.

- **A stale cached upstream answer no longer clears a deprecation mark.** With the metadata cache
  on (the default on edge nodes: a 120-second TTL and a 24-hour serve-stale window), an upstream
  outage during a deprecation refresh made the cache serve the last answer it held, and the refresh
  read that answer as current. If the cached answer predated a deprecation, yank, NuGet unlisting
  or Hex retirement, the refresh cleared the mark, so under `block_deprecated=block_all` the
  version became servable for as long as the outage lasted. It could also revoke an npm or PyPI
  version cached after that answer, and record an out-of-date latest version and versions-behind
  count. The refresh now treats an answer served stale as no answer from that upstream: it asks the
  next configured upstream, and when none answers live it records nothing for the package and
  moves on. This covers npm, PyPI, NuGet (the latest version and the registration index, including
  each externalized page), Maven and Hex, and the latest version the first fetch of a package
  seeds. Proxy requests still get the stale answer during an
  outage, as before. Standard instances leave the metadata cache off unless
  `Proxy__MetadataCacheTtlSeconds` is set, so only edge nodes and instances that enable it were
  affected.

- **An upstream credential now goes only to the scheme and port you configured, not just the
  host.** When an upstream's own index named a follow-up URL, Dependably attached that upstream's
  credential whenever the host matched. So a hostile or compromised index could name `http://` on
  your `https://` host and the credential crossed the network in plaintext, or name another port
  on that host and hand the credential to a different service. Scheme, host and port must all
  match now. A default port counts as the same port, so `https://feed.example` and
  `https://feed.example:443` match. A NuGet registration page on another scheme or port is no
  longer fetched and is removed from the served index. A PyPI file link, Cargo download or RPM
  package location on another scheme or port is still downloaded and checksum-verified, but
  without the credential. Terraform already applied this rule.

- **Action for OCI operators whose token service runs on another port of the registry host.** The
  token-exchange realm in an upstream's `WWW-Authenticate` challenge must now be on the
  registry's own host *and* port. Before, any port on that host was accepted. A registry on one
  port with its token service on another, such as a self-hosted GitLab registry on `:5050` whose
  realm is on `:443`, now fails authentication. The log shows "challenge realm … is not HTTPS on
  the upstream's own host and port". To keep it working, set the upstream's **Token endpoint** to
  that realm URL in Settings → Proxy → Upstream registries.

- **Outbound HTTP clients no longer keep cookies.** Every outbound client, including the shared
  upstream and OCI clients, kept a cookie jar that every organization's requests shared. A session
  cookie an upstream set after one organization's authenticated request could then be sent with
  another organization's request to the same host. A cookie without the `Secure` flag could also
  follow an `http://` link on that host. Cookies are now off on every outbound client. Upstream
  credentials are sent only as the configured, origin-pinned header.

- **The Go checksum-database passthrough forwards only the paths the Go client uses.**
  `/go/sumdb/{name}/…` checked a reserved module name only on `lookup/` requests and forwarded
  every other path to the checksum database as written, so a request such as
  `/go/sumdb/sum.golang.org/lookupx/corp.example/internal/tool@v1.0.0` sent a reserved name
  upstream. Only `supported`, `latest`, `lookup/{module}@{version}` and tile paths in the exact
  form the Go transparency log writes them (`tile/{H}/{L|data}/…`) are now forwarded; anything
  else answers 404 without contacting upstream. Lookups are now case-sensitive and must name a
  `v`-prefixed semantic version, as the checksum database itself requires. Go clients are
  unaffected. The sumdb host was already limited to the configured `Go:SumDb`.

- **Action for Linux operators: check for stored secrets that can no longer be decrypted.**
  Every release from v0.2.2 until this one shared a single AES-GCM object across threads when
  encrypting and decrypting stored secrets. On Linux that object is not thread-safe, so a secret
  saved while another request was using it could be written with mismatched parts and never
  decrypt again (about 0.6% of overlapping saves in a stress test). Encryption and decryption are
  now serialized, so no new value can be written this way, but a value already damaged stays
  damaged until it is entered again. Damaged values do not leak: they decrypt to nothing, never to
  another organization's secret. They show up only when the feature that needs them runs, as
  Slack alerts that stop for an organization, a webhook that is skipped, upstream fetches that
  fail for an organization and ecosystem, authenticator codes that are always rejected, or SBOM
  and Hex signing that fails.

  To find them, every start now tries to decrypt each stored secret in the background once the
  server is listening and logs a `Stored secret check:` warning naming the table and rows of any
  that fail, never the values. Startup is not delayed or stopped. Set
  `SECRETS_VERIFY_ON_STARTUP=false` to skip it. For the full list, a system admin can call
  `POST /api/v1/system/secrets/verify`, or in single-tenant mode an organization admin or owner
  can call `POST /api/v1/instance/secrets/verify`; both are audited and report counts per kind
  plus each failing row's table, id, organization and reason. Values stored unencrypted are
  counted separately and are not failures, except TOTP keys, which are never stored unencrypted. If you ran a Linux build of an affected release,
  check once after upgrading and re-enter whatever is reported.
  [OPERATIONS.md, Verifying stored secrets](OPERATIONS.md#verifying-stored-secrets) lists what each
  kind breaks and how to replace it.

- **Locking or disabling a system admin now ends their sessions immediately.** Changing another
  operator's status with `PATCH /api/v1/system/admins/{id}/account-status` only updated the status:
  a session the admin already held kept full system access until it expired, up to eight hours
  later. Setting an admin to `locked` or `disabled` now invalidates every session they hold on its
  next request, and forgets their remembered devices in the same transaction as the status change,
  so they need their second factor again after re-activation. Re-activating an admin does not bring an old session back; they must sign in
  again. As a second safeguard, a system session is only accepted while its admin is `active`, so
  a status change that skipped the invalidation would still end the session. Deleting a disabled
  admin now also ends any session that was still being honoured from the token-version cache.
  A sign-in that passed the password step before the change can no longer finish its second
  step: it gets the same error as an invalid code, and no session or remembered device is
  created. Re-activation also forgets any remembered devices the admin still has. System API
  tokens already stopped working when their owner was locked or disabled; that is unchanged.
- **A tenant user's sessions and remembered devices are now bound to an active account.**
  Locking or disabling a user through `PATCH /api/v1/system/users/account-status` already ended
  their sessions, but it left their remembered devices in place, so after re-activation a device
  saved before or during the lock could skip the second factor. Every status change except active
  to active now forgets the user's remembered devices, and re-activation also invalidates any
  session issued before the lock, even if the lock itself was written without invalidating them.
  As a second safeguard, a tenant session is only accepted while its user is `active`, so a status
  change made any other way (for example, directly in the database) still ends the session within
  a minute. A sign-in that passed the password step before a lock, disable, re-activation or role
  change can no longer finish its second step: it gets the same error as an invalid code, nothing
  is created or recorded as a successful sign-in, and the attempt does not count towards lockout.
  For a tenant user or a system admin, such a refused second step is recorded as a
  `login.failure` audit entry with the reason `stale_challenge` and the realm, and is sent to the
  audit event stream, SIEM forwarding and webhooks like any other failed sign-in.
- **Restoring a suspended or deleted tenant no longer brings back its old sessions.** Suspending a
  tenant with `PATCH /api/v1/system/tenants/{slug}/status` refused its requests but left its
  users' sessions and remembered devices valid, so restoring the tenant within eight hours let
  them carry on with sessions issued before or during the suspension, and skip the second factor
  on devices remembered before it. Suspending a tenant, or deleting it with
  `DELETE /api/v1/system/tenants/{slug}`, now ends every session its users hold and forgets their
  remembered devices, so after the restore everyone signs in again. Restoring does the same again,
  which also covers a tenant locked out some other way. `read_only` is not a lockout: moving a
  tenant into or out of it leaves sessions alone, because its users keep signing in and managing
  the tenant.
- **Suspending or deleting a tenant now revokes its API tokens for good.** Suspension is how an
  operator contains an incident, but a tenant's personal access tokens and service tokens were only
  refused while it stayed suspended: restoring it brought back every token, including a leaked CI
  token that may have started the incident. Suspending a tenant with
  `PATCH /api/v1/system/tenants/{slug}/status`, or deleting it with
  `DELETE /api/v1/system/tenants/{slug}`, now deletes all of the tenant's personal access tokens
  and service tokens, its unused password-reset and email-change links, and its pending invites.
  Restoring the tenant does not bring any of them back, and does the same cleanup again for a
  tenant locked out some other way. `read_only` is still not a lockout and keeps every token.
  **After a restore, the tenant has to issue new tokens** for its CI pipelines, package-manager
  configuration, and any edge node that pulls from it: an edge's `EDGE_MASTER_TOKEN` is one of
  the revoked service tokens, so the edge serves only what it has already cached until it is
  given a new token. Members who had an invite or a reset link outstanding need a new one. The
  operator's `tenant.status_changed`, `tenant.deleted` and `tenant.restored` audit entries now
  record how many of each credential were revoked. Revoking a single service token now also takes
  effect on its next request, rather than up to a second later.

- **The daily deprecation and latest-version refresh respects proxy passthrough and fails closed.**
  An organization with passthrough off (or air-gapped) is no longer sent upstream requests, which
  carried its stored upstream credentials, and its deprecated, latest-version and Hex retirement
  facts are no longer rewritten from them. An npm or PyPI answer that is a 200 but carries no
  `versions` / `releases` object (a mirror's `{}` or error body) is now treated as no answer, so it
  can no longer clear a deprecation or yank and let a version blocked under `block_deprecated=block_all`
  serve again. Versions are also matched the way each ecosystem compares them: npm versions that
  differ only in case stay distinct, and a cached PyPI spelling such as `1.0.0.rc1` matches the
  upstream key `1.0.0rc1`, so a yank is no longer cleared and the release is no longer marked revoked.
- **Maven honours an organization's proxy passthrough setting.** With passthrough off (or the
  organization air-gapped), a Maven artefact miss answers 404, a cached SNAPSHOT is served without
  asking the upstream whether a newer build exists, and `maven-metadata.xml` lists only the
  versions the organization already holds. Before, all three still sent requests, carrying the
  upstream credential, to the configured Maven registries.
- **An apk request whose filename cannot be parsed is no longer fetched from upstream.** A
  `.apk` path that does not follow `{name}-{version}-r{release}.apk` has no package name to check
  against the reserved namespaces, and it used to skip that check and go upstream. It now answers
  404 unless the file is already in the store, so a reserved name is never asked of upstream by
  way of a malformed filename.
- **A TOTP key stored as plaintext is no longer accepted at sign-in.** Dependably has only ever
  stored these keys encrypted, so a plaintext one can only have been written to the database from
  outside, and it used to pass sign-in. It is now rejected, and the stored secret check reports it
  with the reason `unexpected_plaintext`. The user signs in with a recovery code and enrols again.

### Changed

- **`oci-scan-sweep` runs under `AIR_GAPPED=true`.** It makes no outbound call, and an air-gapped
  scanner re-matches against sideloaded OSV dumps. `DISABLE_BACKGROUND_JOBS=true`, a list naming
  it, and edge mode still stop it, and `disabled_reason` no longer reports `AIR_GAPPED=true` for it.
- **A hosted image's scan result now prunes and announces only what changed.** A re-extraction
  removes the image's advisory links its new inventory no longer supports, and the `package.vuln`
  webhook carries only advisories newly linked to the image instead of every advisory found.

- **Upgrading a Postgres database adds the schema's CHECK and foreign-key constraints on first
  boot, and that step can no longer hold up startup.** A database created by an older release lacks
  the column constraints a fresh install has. The first boot adds each one as `NOT VALID` (new
  writes are checked straight away) and then validates it against existing rows. The whole step
  shares a three-minute budget. Waiting for a table lock is bounded and retried; if another
  session, such as a long query on the old slot during a blue-green cutover, still holds the lock,
  that table (and, for a foreign key, the table it references) is skipped for the rest of the boot.
  Each validation scan is cut off after 60 seconds. Anything skipped, cancelled or past the budget
  is left absent or `NOT VALID`, logged in one warning that counts the deferred steps, and retried
  on the next boot. If existing rows break a constraint, the warning names it and the table and
  column; repair those rows and the next boot validates it. Until then that constraint is rescanned
  on every boot, and the 60-second cap bounds that cost. The step that drops the old unique key on
  `nuget_symbol_index` checks for the key first and, when it must drop it, waits only briefly for
  the table lock and retries on the next boot, so a previous-release instance holding the table
  cannot stall the new boot. SQLite is unaffected.

- **The vulnerability report, its total and the SIEM vulnerability summary stay fast at scale.** At
  about 100,000 vulnerability links, one report request took tens of seconds on both SQLite and
  Postgres, and the instance-wide summary a similar time, because each link evaluated its alias-donor
  lookups (the severity, score and summary a PYSEC or similar copy borrows from its GHSA twin) as
  correlated subqueries on every request, and several of those lookups could not use the partial
  indexes on `package_version_vulns` at all. The queries now filter on the link's owner kind so the
  indexes apply, the report total uses a count-specific query that drops the donor joins it never
  reads, and each link carries its resolved donor values (`alias_severity`, `alias_cvss_score`,
  `alias_summary`, `alias_resolved_at`) so the report, its sort and search, and the summary read columns
  instead of computing donors. The values are resolved when a link is written and again when an
  advisory's severity, score, summary or aliases change (a re-fetch that changes none of them
  changes nothing). A sweep re-resolves, in short batches, every owner that has a link never
  resolved or whose advisory's donor fields changed since the link was resolved; it runs at every
  boot and after every vulnerability scan tick, so links and advisories written by the previous
  release during a blue-green cutover, and two concurrent writers that each missed the other, are
  corrected within a tick (until then the query resolves a never-resolved link's donor itself). The
  sweep assumes the clocks of the replicas differ by less than two minutes; beyond that, a
  previous-release donor edit landing just after a resolve can be missed until the advisory next
  changes. Two advisory columns (`donor_basis`, `donor_changed_at`) record the donor fields and
  when they last changed. The resolve sweep and the advisory-basis sweep (the first fill of each
  advisory's recorded basis) size each batch from how long the previous statement held the write
  lock, aiming at 250 ms and staying between 10 and 500 owners, and pause for as long as the lock
  was held. A sweep that finds nothing to change takes no write lock.
  The first boot after the upgrade backfills existing links and takes about 4.5 seconds per 100,000
  links on Postgres. On the proxied (cache) plane the donor candidates are the advisories linked to
  any cached artefact of the same ecosystem, name and version (each artefact, such as a wheel and
  an sdist, is scanned and linked separately), whichever organization reaches them: an advisory's
  severity, score and summary are global facts, so the stored value never depends on who is
  looking, and report rows stay scoped to the organization's own artefacts. The accepted
  trade-off is that, in the window after an advisory publishes, an organization can observe that
  another file of the same version was fetched and scanned (through a borrowed severity). This replaces the earlier organization-scoped lookup on that plane. A donor is still
  never from the same advisory database, and severity and score still come from one donor.

- **The advisory detail fallback and the Alpine origin probe no longer query OSV on every call.**
  `GET /api/v1/vulnerabilities/{osvId}` with `ecosystem`, `name` and `version` reads OSV for an
  advisory that is not stored for the org, and a clean apk lookup probes the release feed to tell an
  unknown origin from a clean one. Both answers are public data, so they are now held in a bounded
  five-minute cache shared across orgs (capped by entry count and a 64 MiB byte budget; a single
  oversize answer is served but not stored), with concurrent identical queries collapsed into one OSV
  call. Only an answer from a reached source is kept, so an OSV outage is retried on the next call
  and never remembered as a clean result. The reserved-name check still runs on every request,
  outside the cache.

- **The deprecation refresh schedules each organization on its own stamp.** Organizations that
  proxy the same package share its cached rows, and the refresh used to decide what was due from a
  stamp on those shared rows. When one organization's refresh landed at the end of a pass, its stamp
  made another organization's refresh of the same package look fresh, so that organization's upstream
  facts (latest version, versions behind) waited a further full age window. Each organization's
  access to a cached package now carries its own refresh stamp (a new `tenant_artifact_access`
  column, seeded from the shared stamp on upgrade so the queue order is kept), and a refresh pass
  selects and stamps per organization. A failed upstream fetch or a reserved name now stamps only the
  organization it was processed for, so the shared `deprecation_checked_at` (exposed on the
  `artifact_inventory` view) records only the last upstream verdict. Packages never refreshed before
  are now selected ahead of stale ones on Postgres too. Organizations that share a package each fetch
  its upstream metadata once per age window, so `DEPRECATION_REFRESH_BATCH_SIZE`, which counts
  (organization, package) groups, may need raising on instances with many organizations.

- **Action required: upgrade to v0.13.3 before moving to this release from anything older.** The
  oldest release supported as an upgrade source is now v0.13.3. Databases created by an older
  release are no longer exercised against the current schema, and the upgrade tests start at
  v0.13.3. From an older install, upgrade to v0.13.3 first, let it start and finish its
  migrations, then upgrade to this release. The one exception is a Postgres database created by
  0.2.2 to 0.4.4, which upgrades straight to this release (see Fixed). See
  [Supported upgrade path](OPERATIONS.md#supported-upgrade-path).

- **Action required: an unrecognized `DISABLE_BACKGROUND_JOBS` value fails startup.** A token that
  is not a known job name used to log a warning, and startup continued with that job still
  running. The instance now refuses to start and the error names the token and lists the known job
  names. Check the value before upgrading: a typo such as `vulnscan` for `vuln-scan` was silently
  leaving the job on, and now stops the node. `true`, `1` and `all` (on their own) are accepted and
  disable every job except local housekeeping; see Fixed. `false` or `0` disables none, as an
  empty or unset value always has. A switch value mixed into a list (`true,vuln-scan`) also fails
  startup, because whether it means every job or is a mistyped name cannot be told from the value.
- **`GET /api/v1/instance/background-jobs` lists every background job.** It reported 10 of the 25
  jobs `DISABLE_BACKGROUND_JOBS` accepts; it now lists all of them, sorted by name. Each entry has
  the same fields as before.
- **Alias lookups for KEV and EPSS no longer scan the whole advisory table.** Resolving a
  package lookup's advisories through their CVE aliases matched each CVE against the
  `vulnerabilities.aliases` JSON text with a `LIKE`, so the cost grew with the instance's advisory
  history. A new `vulnerability_aliases` table holds one indexed `(alias, osv_id)` row per alias,
  written in the same transaction as the advisory, and the lookup resolves through it. The first
  start after the upgrade fills it for existing advisories, and every start (and each threat-feed
  pass) re-derives the rows of any advisory a previous release wrote without it, so a rolling
  deploy stays correct. Results are unchanged. The reconcile writes in batches sized from how long
  the previous one held the write lock and pauses for as long between them, and an advisory update
  linked from more than 50 package versions leaves re-resolving their alias-donor values to the
  sweep. A reconcile failure is logged, counted on `dependably.threat_feed.rejections` with reason
  `alias_reconcile_failed`, and recorded as a degraded run while the KEV and EPSS feeds continue.
  The reconcile locks advisory rows before their alias rows, as storing an advisory does, so the
  two cannot deadlock on Postgres.
- **The metadata-invalidation counters carry a `scope` attribute.** Every measurement on
  `dependably.metadata.invalidations_published` and `dependably.metadata.invalidations_received`
  has `scope="ecosystem"` (a message about one ecosystem's metadata, with `ecosystem` as
  before) or `scope="org"` (an organization-wide invalidation after a reserved-namespace,
  proxy-settings or licence-mode change, with no `ecosystem` attribute). `ecosystem` only ever
  holds an ecosystem id, so queries that group or filter by it keep working.
- **`GET /api/v1/lookup` now reports `blockedReason` as the wire token.** The field returned the
  internal arm name (`VulnScore`, `ReleaseAge`, `Malicious`, `Deprecated`); it now returns the
  same snake_case token the quarantine queue, response headers, and policy summary use
  (`vuln_score`, `release_age`, `malicious`, `deprecated`). Clients that match on the old
  spelling need to update.

### Fixed

- **Removing a member who created a licence policy entry or a package name grant no longer fails.**
  A member who had added a licence allowlist or blocklist entry, or granted another account a
  package name, could not be removed: the delete hit a foreign key on the entry's `created_by` and
  answered 500. Removal now clears that attribution (the entries stay, with no author), as it
  already did for reserved namespaces, quarantine decisions, dismissed alerts, claims and install
  script allowlist entries.

- **Licence copy no longer says an empty allowlist leaves only the blocklist in force.** Under
  `license_enforcement_mode=block` the serve gate refuses any licence that is not on the allowlist
  (allowed or conditional) as well as every blocklisted one, so an empty allowlist refuses
  everything. The allowlist empty state, the Block mode hint and the Policies page description
  now say so, in English and French. Off and Warn never refuse on the allowlist. Gate behaviour
  is unchanged.

- **A first fetch no longer erases a package version's "versions behind" count when upstream does not answer.**
  The count lives on a cache row shared by every organization; an unreachable upstream, a 404 or a stale
  metadata body used to overwrite it with nothing, and Cargo has no daily refresh to put it back.
  It is now written only when upstream returns a stable-version list to count against.

- **Postgres databases created by releases 0.2.2 to 0.4.4 start again.** Every release since 0.4.5
  failed at startup with `42703: column "cache_artifact_id" does not exist` (or `config_digest`)
  on a Postgres database created by 0.4.4 or earlier, including the 0.4.4 to 0.4.5 step.
  Four indexes in the base schema named columns that such a database only gets later in the
  upgrade. They are now created after those columns are added, on fresh installs as well as
  upgrades. Upgrade such a database straight to this release: v0.13.3 and every other release
  from 0.4.5 on fails to start on it, so it cannot take the usual route through v0.13.3. A database
  a newer release has already failed to start on upgrades the same way. See
  [Supported upgrade path](OPERATIONS.md#supported-upgrade-path).
- **A momentary catalogue-lock conflict no longer fails a Postgres upgrade boot.** Widening the
  numeric columns set `lock_timeout` for the whole session, so the 25 catalogue probes ran under
  it and, unlike the `ALTER` itself, were not retried on a lock timeout. Only the `ALTER` is now
  bounded, and retried; the probes wait as long as they need.
- **A Maven plugin-prefix document now proxies.** `maven-metadata.xml` at a plugin group (for
  example `org/apache/maven/plugins/`) answered 404, so Maven could not resolve short prefixes
  such as `help:` or `versions:`. When no version of the group's coordinate is hosted or cached
  and the upstream answers with a plugin-prefix document, it is served as the upstream sent it,
  unless the group is reserved. No version is named in it, and versions blocked by policy stay
  withheld from artefact metadata.
- **Maven metadata no longer serves a document rendered under an older policy.** Whether the
  upstream is merged in was decided before the cache entry was bound to the organization's
  current state, so a reservation or proxy-settings change made in that gap kept being served for
  up to five minutes. The decision is now part of the cache key, and npm, PyPI and Maven capture
  the organization's state before reading settings and reservations.
- **A package with many advisories no longer reads as clean when OSV pages the answer.** The
  purl query and the batch query ignored OSV's `next_page_token`, so advisories past the first
  page were dropped. Both now follow every page. A batch result that carries a page token is
  completed through the paged query, and a chain that cannot be finished (a failed page, or more
  than 50 pages) leaves the lookup unreached instead of serving a truncated list, so it is
  retried rather than recorded as clean.

- **Organization-wide cache invalidation reaches every replica.** Adding or removing a reserved
  namespace, saving proxy settings, or changing the licence mode used to clear caches only on the
  replica that took the change; the others kept serving the earlier policy until their TTLs
  expired. With `REDIS_CONNECTION_STRING` set, the change is now broadcast over the existing
  invalidation channel and every replica clears that organization's reservation list, settings
  and rendered metadata. A licence-mode change also clears cached lookup verdicts, which stayed
  stale for up to two minutes even on the replica that took it. During a rolling deploy, a
  replica on an older release ignores the message and converges when its TTLs expire. The
  broadcast is best effort; see
  [Metadata caches](OPERATIONS.md#metadata-caches-are-per-instance-invalidated-across-replicas-over-redis).
- **An advisory that affects several packages shows each package's own fix.** Storing an advisory
  overwrote its ecosystem, package name and affected versions with whichever package was scanned
  last, so `GET /api/v1/vulnerabilities/{osvId}` could show package A's fixed version while you
  were viewing package B. The first scan's ecosystem and package name are kept, and affected
  versions fill only when empty; the advisory's content still refreshes. The endpoint also takes
  an optional `ecosystem` and `name` (both or neither) for the package being viewed and resolves
  the fix for it. The Vulnerabilities page and the SBOM component panel pass them.

- **npm packages whose tarball does not use a `package/` root folder now report their licence.**
  The licence extractor only read `package/package.json`, so DefinitelyTyped tarballs
  (`@types/react` unpacks to `react v18.3/`, `@types/json5` to `json5/`) read as licence-unknown,
  which is a refusal under `license_enforcement_mode=block`. The extractor now selects the
  manifest the same way the upload validator does: the root or exactly one wrapper directory of any
  name. A nested manifest (a bundled dependency's
  `package/node_modules/x/package/package.json`) can no longer be mistaken for the package's own.
  On upgrade, the licence backfill re-reads each cached npm artefact that was recorded with no
  licence, once; it needs no schema change and no operator action.

- **A wrong sign-in code is counted once in the audit log.** A rejected TOTP or recovery code
  wrote its `login.failure` row (with `"reason":"mfa_invalid"`) and then a second, bare row named
  `auth.login.failure`, in both the tenant and the system realm, so every wrong code counted as
  two failed sign-ins on the audit page, in exports and in the SIEM pull feed. It now writes only
  the `login.failure` row. The `auth.login.failure` event that SIEM forwarding sends was already
  emitted once per failure and is unchanged. Audit rows written before this change under `auth.login.failure`
  stay as they are; leave them out when counting failures across the upgrade.
- **PyPI versions that PEP 440 treats as the same release now shadow each other and are blocked
  together.** An uploaded `1.0.0-rc1` and a proxied `1.0.0rc1` used to show as two rows and count
  as two versions, and a block, quarantine or by-version lookup on one spelling missed the other.
  Version identity now compares the PEP 440 canonical form, so separators, a leading `v`, implicit
  zeros in `a`/`b`/`rc`/`post`/`dev` segments and spelling variants (`alpha`, `beta`, `c`, `pre`,
  `preview`, `rev`, `-1`) all match. The uploaded copy shadows the proxied one in the version list
  and the count. Blocking a version, or denying its quarantine entry, from either spelling now
  blocks every spelling of it, uploaded and proxied, and resolves their pending quarantine entries
  as denied. Unblocking or approving does not spread the same way. On an uploaded version it
  allows that version and its other uploaded spellings, and lifts a block that spread to the
  proxied files without ever allowing them. On a proxied file it covers that file's exact spelling
  only. A proxied file flagged by an automatic gate (malicious, KEV, EPSS, release age, provenance
  or licence) therefore stays blocked, and its quarantine entry is left as it was, until someone
  approves that file itself; a clean one serves again. The shadowed proxied
  files stay in the simple index under their own names and stay subject to their block state. Two spellings within the same source (for example an sdist and a wheel that spell the
  version differently) still list as separate rows, and count that way. The stored version and the
  file names pip is served are unchanged. `1.0` and `1.0.0` stay distinct, as they are on the
  index.

- **A PyPI version published under a second spelling no longer becomes a second version.**
  `1.0.0rc1` and `1.0.0-rc1` are the same PEP 440 version, but the publish path compared version
  strings exactly, so both could be stored as separate rows and counted twice. A respelled upload
  now resolves to the version already stored: a new filename attaches to that release as another
  file, and a filename it already holds follows the version-overwrite policy. The stored spelling
  stays as published, and the package tile counts PEP 440-distinct versions. Deleting a version
  under a blocking overwrite policy also keeps every spelling of it spent, so it can no longer be
  republished with new bytes under a respelling. The match is read, then written, so two
  concurrent first publishes under different spellings can still both land; the package count folds
  them. Rows that were already published twice are left in place.

- **The deprecation refresh now keeps NuGet unlisting current.** A NuGet version unlisted upstream
  after this registry cached it stayed servable, because the daily refresh never read NuGet
  listing state, while the registration index already hid it: the index and the download
  disagreed. The refresh now reads each package's registration index once per pass and records
  each cached version's listing state, read the same way as on first fetch. A version unlisted
  upstream is marked "Unlisted upstream", so `block_deprecated=block_all` blocks it, and a version
  relisted upstream is unmarked and servable again without an operator allowing it or deleting the
  cached copy. When no upstream returns the registration index, or the page holding a version
  cannot be fetched, that version keeps what was recorded, so an outage cannot unblock it. NuGet's
  separate deprecation notice (reasons and an alternative package) is still not recorded.

- **A licence allowlist or blocklist edit now shows on the next package lookup.** Adding,
  editing or removing an allowlist or blocklist entry left the package lookup page showing the
  verdict it had cached under the old lists for up to two minutes, on the replica that made the
  edit and on its peers. Each committed edit now expires the organization's cached lookup
  verdicts on every replica, as a licence-mode change already did. An edit that is rejected, or
  that names an entry the organization does not have, changes nothing and expires nothing. The
  licence gate on package downloads always read the lists live, so no download was ever let
  through by the stale verdict.

- **Two system admins disabling each other at the same moment can no longer leave the instance
  with no active admin.** `PATCH /api/v1/system/admins/{id}/account-status` refuses to lock or
  disable the last active admin, but it counted the other active admins and wrote the new status
  in separate steps. When the last two active admins each disabled or locked the other at once,
  both requests could pass the count and both succeed, leaving nobody able to sign in. Because
  locking or disabling now ends sessions immediately, nobody was still signed in to undo it
  either. The count and the write now happen in one transaction that runs one at a time, on SQLite
  and on Postgres, so exactly one of the two requests succeeds and the other gets `409` with reason
  `last_active_admin`, as a lone request always has. Deleting an admin was not affected: only an
  admin who is already disabled can be deleted. If an instance has already lost its last active
  admin, [OPERATIONS.md, Recovering when no system admin is active](OPERATIONS.md#recovering-when-no-system-admin-is-active)
  gives the SQL to re-activate one.

- **A stored secret that cannot be decrypted now affects only its own record, and the log says
  which one.** An authenticator key that did not decrypt was handed to the code check as if the
  ciphertext were the key, so every code the user entered failed with a server error and nothing
  was logged. The code is now rejected as invalid, a warning names the user or system admin, and
  recovery codes still work. One webhook whose signing secret did not decrypt stopped every
  webhook of its organization for the events it was subscribed to; now only that subscription is
  skipped, with a warning naming it, and it is never sent unsigned. Upstream registries, Slack
  alerts, SBOM and Hex signing keys and instance settings still fail closed when their secret
  does not decrypt, but the error now names the table, row and organization, never the value.
  Upstreams stay all-or-nothing per ecosystem on purpose: skipping a private upstream would let
  the next one in the priority order, often a public registry, answer for its packages.

- **A new tenant's subdomain resolves as soon as it is created, and a usage-cap change from the
  hourly sweep applies at once.** In multi-tenant mode, a request to a subdomain just before its
  tenant was created cached "no such tenant", and that server kept answering 404 for up to five
  seconds after the create succeeded. The hourly usage sweep had a similar gap: when it moved an
  organization into or out of a capped posture (uploads refused, downloads throttled), the old
  posture kept applying for up to five seconds. Tenant creation and the sweep now clear the
  cached lookup once their change is saved. Other servers in a multi-server deployment still
  pick up the change within their own five-second cache lifetime.

- **A proxied version that differs from an uploaded one only in letter case is no longer hidden
  where versions are case-sensitive.** An uploaded `1.0.0-RC1` used to hide a proxied upstream
  `1.0.0-rc1` from the version list, and from its advisories on the package page, in every
  ecosystem. Only NuGet and PyPI treat those as one version; npm, Go, Cargo, Hex, Terraform and
  Maven keep them as two. One rule now decides this per ecosystem across the version list, the
  Packages tile's version count, the Cargo, Go and Maven merges, and the block, unblock and delete
  lookups by version, so the count always matches the rows listed and blocking `1.0.0-rc1` no longer
  also blocks `1.0.0-RC1`.

- **A proxy-settings change takes effect on the next metadata request, even under load.** A
  request that was reading an organization's settings when an admin saved new ones could put the
  old settings back in the one-second settings cache after the save had cleared it. The next npm,
  PyPI or Maven metadata request then rendered under the old policy (for example, still listing
  versions that `block_deprecated=block_all` now hides) and kept serving that document for the full
  rendered-metadata cache lifetime, five to ten minutes. A settings read that overlaps a change
  no longer caches what it read, so the next request reads the saved settings. This covers every
  settings save on the replica that made it (proxy, retention, licence policy, anonymous pull,
  allowlist mode, RPM upstream mode) and the organization-wide invalidation other replicas receive.
- **Concurrent cache misses for the same key no longer empty the cache.** When two requests
  missed the same cached record at once (an organization's reserved-namespace list, blocklist or
  install-script allowlist, a session or tenant lookup), the second one to finish could evict the
  first one's correct entry as it replaced it, leaving nothing cached. Under a burst of parallel
  requests, such as a CI `npm install`, that repeated on every miss and sent each request to the
  database. The surviving entry now stays cached.
- **A host with `REDIS_CONNECTION_STRING` set starts again.** From 0.4.3 through 0.13.3, a
  host configured with Redis, which every highly available deployment is, hung during startup and
  never began listening. It also ignored SIGTERM, so it had to be killed. The services that keep
  cached metadata in step across replicas depended on each other in a loop. Resolving them at
  startup recursed until the process deadlocked. The loop is broken: the Redis channel now looks up
  the component that applies peer messages when it subscribes, instead of when it is created.
  Delivery is unchanged: a replica still drops its own broadcasts, and a push on one replica still
  evicts the matching cached documents on the others. Hosts without
  `REDIS_CONNECTION_STRING`, and edge hosts, were never affected.
- **The daily deprecation refresh now covers Hex packages.** The 0.9.0 notes said the refresh
  read a proxied Hex package's retirements and latest release from the signed upstream resource,
  but the refresh never selected a Hex package. A release retired upstream after it was cached
  kept being served as not retired, and a newer upstream release and the "versions behind" count
  were never picked up. The refresh now covers Hex alongside npm, PyPI, NuGet and Maven,
  including packages whose proxied versions were evicted so only published versions remain. A
  retirement (or un-retirement) upstream now shows in the package's deprecated state and in the
  `/hex/packages/NAME` resource this registry serves, so Mix and Rebar3 print their retired-release
  warning. A Hex release retired upstream after it was cached now becomes blocked (and hidden
  from the index) under `block_deprecated=block_all` on the next refresh pass. The refresh reads
  only from a Hex upstream with a configured public key. When no upstream gives an answer that
  verifies, it leaves the recorded retirement and latest version as they were. A name the
  organization has reserved is never looked up.

- **An upstream outage no longer unblocks a deprecated npm or PyPI version.** When every
  configured npm or PyPI upstream answered a refresh with an error status (503, 429, or a 401/403
  after a credential rotation), the deprecation refresh treated the empty result as a verdict: it
  cleared every version's deprecation, erased the recorded latest version and versions-behind
  counts, and stamped the versions as checked. Under `block_deprecated=block_all`, one bad pass
  made a deprecated or yanked version servable again. The refresh now records nothing for a
  package when no upstream returns a successful answer, as it already did for a network error or
  an unverifiable Hex resource, and moves on to the next package. A package that every upstream
  reports as not found (404) is also left as recorded. NuGet and Maven now keep their recorded
  latest version and versions-behind counts the same way. A NuGet version marked unlisted
  upstream when it was first fetched now stays marked as deprecated: the refresh was clearing that
  mark on every pass. It now clears the mark only when the version is relisted upstream (see the
  NuGet unlisting entry above).

- **A package lookup no longer reports a reserved name or a missing upstream as an outage.**
  `GET /api/v1/lookup` with no `version` answered 503 "The upstream registry is temporarily
  unavailable. Try again shortly." both for a name the organization has reserved and for an
  ecosystem with no upstream registry configured. Neither is transient: both are settings an
  operator chose, so retrying never helped. Each now returns 422 on the `version` field with its
  own message and a machine-readable `reason`: `name_reserved` or `upstream_not_configured`. The
  503 now means only that a fetch from the upstream was attempted and failed. A lookup of a
  reserved name with a version still returns the advisory and licence verdict, and the response
  carries a new `reserved` field set to `true`; the lookup page shows a note saying the name is
  reserved and that upstream metadata was not checked. Clients that retried on the 503 should
  treat these two 422 reasons as final.
- **`DISABLE_BACKGROUND_JOBS=true` now disables every background job except local
  housekeeping.** The value was read as a list of job names, so `true` matched no job and every
  job kept running, including the OSV scans, the CISA KEV and EPSS refresh, the deprecation
  refresh and the healthcheck ping, each reaching the internet from an instance set up to be
  isolated. `true`, `1` and `all` (any case) now switch off the whole job set apart from three
  local jobs that make no outbound call: `cache-eviction` and `oci-staging-janitor`, which keep the
  proxy cache and staging volume bounded, and `npm-manifest-rescan`. `AIR_GAPPED=true` leaves the
  same three running, and `oci-scan-sweep` as well. On an edge node the
  switch also stops the size gauge and the healthcheck ping. A comma-separated list of job names
  works as before. Unlike `AIR_GAPPED=true`, this setting does not stop request-time upstream
  fetches. `GET /api/v1/instance/background-jobs` reports a job switched off this way with a
  `disabled_reason` of `DISABLE_BACKGROUND_JOBS=true`, a job named in a list with
  `DISABLE_BACKGROUND_JOBS`, and a job an edge node force-disables with
  `DEPLOYMENT_MODE=edge`.
- **Naming `cache-eviction` or `oci-staging-janitor` in `DISABLE_BACKGROUND_JOBS` now stops it.**
  Neither job checked the setting, so a named entry left it running while the background-jobs
  report and the system health report showed it as disabled. Both now skip their pass when named.
  Under `AIR_GAPPED=true` the two jobs keep running, as they always did, and the reports now say
  so instead of listing them as disabled.
- **A rejected threat feed now shows up as a degraded job run and a metric, and the first KEV
  fetch after an upgrade is guarded.** A KEV or EPSS fetch that failed, came back empty, or came
  back under half the stored size was dropped with only a log warning, and the `threat-feed` job
  still recorded a success, so a mirror pointed at a filtered copy produced a daily warning and
  nothing else. The run is now recorded with outcome `degraded` (the last-success time does not
  advance), the new `dependably.threat_feed.rejections` counter increments with a `reason` of
  `kev_fetch_failed`, `kev_empty`, `kev_shrunk`, `epss_fetch_failed`, `epss_empty` or
  `epss_shrunk`, and the system health report lists the job as `degraded` and the instance as
  degraded. An upgraded install starts with an empty stored KEV catalogue, so its first fetch had
  nothing to be compared with and a degenerate one (a single entry from a broken mirror) would
  have cleared every `is_kev` flag. While the stored catalogue is empty, the fetch is now
  compared against the number of distinct CVEs behind the advisories already flagged `is_kev`
  (one CVE often has several flagged rows) and rejected under half of it. Once a catalogue is
  stored, that count covers only CVEs the catalogue contains. A `degraded` run has its own label,
  colour and filter entry on the system Audit page's Background Jobs tab.
- **Package lookups now report EPSS for a CVE this instance has never stored.** `GET
  /api/v1/lookup` read EPSS only from stored advisory rows, so a candidate whose advisories the
  instance had never scanned (log4j-core 2.14.1, for example) came back with `epss: null` and
  `maxEpss: null`, and a missing score reads as "no signal" to the `epss` and `epss_percentile`
  block arms: the pre-adoption check could say `allowed` for a version the download path would
  later refuse. The threat-feed refresh now also keeps a local copy of FIRST.org's daily EPSS file
  (a new `epss_scores` table, about 380,000 rows, refreshed on each successful fetch;
  `EPSS_BULK_URL` overrides the source), and the lookup takes the highest score across
  every CVE among an advisory's id and aliases. The lookup now also evaluates the `epss_percentile`
  arm, which it previously ignored. The lookup makes no network call for this: with `AIR_GAPPED`
  or `DISABLE_BACKGROUND_JOBS` the table stays empty or holds the last copy fetched. A file that
  parses to no scores, or to fewer than half the stored count, is treated as a failed fetch and
  the stored scores stay as they were.

  The file loads into a staging table in short batches and is then applied to `epss_scores` in
  bounded committed batches by key range, removing CVEs the file dropped last. Every batch (the
  load, the apply and the advisory fill below) is sized from how long the previous one held the
  write lock, aiming at 250 ms, and followed by a pause as long as that hold, so publishes, scans
  and first-fetch records are not locked out on SQLite. During a refresh the table can hold a mix
  of the old and new files' scores, each one complete. On Postgres a row is rewritten only when its
  score or percentile changed. A store that fails keeps the last complete file and records the
  run as `degraded` with the reason `epss_replace_failed` on `dependably.threat_feed.rejections`.

  The download gate reads the score stamped on the stored advisory, so the file scores advisories
  too. Storing an advisory fills its score and percentile from the file, and after each successful
  refresh the threat-feed pass fills every advisory still unscored, in short batches; if that fill
  fails the run is `degraded` with the reason `epss_fill_failed` and the next pass retries. Both
  take the highest probability across the advisory's id and CVE aliases, with the percentile of
  that same CVE, and never overwrite a recorded score. A score and its percentile are only ever
  replaced together, so a per-CVE API answer with no score keeps the one the file supplied. An
  advisory saved while a refresh applies the file is left for the fill that follows, so a
  multi-CVE advisory cannot record a probability below both files' highest. That window is marked
  in `instance_settings`, and a marker left by a crashed run expires after 5 minutes.
- **`versionCount` no longer double-counts a proxied version shadowed by an uploaded one that
  differs only in letter case.** In NuGet and PyPI, an uploaded `1.0.0-RC1` beside a proxied
  `1.0.0-rc1` produced one row in `versions` but `versionCount: 2`, on both SQLite and Postgres and
  on both the package list and the detail view. The count now follows the version list's rule:
  exact version strings, except that in NuGet and PyPI a proxied version matching an uploaded one
  case-insensitively is not counted again, and NuGet proxy rows compare case-insensitively among
  themselves. Every other ecosystem counts a case-only variant as a separate version, on either
  plane, as the list shows it.
- **The package detail view no longer shows zero versions and zero downloads for a proxied
  package.** `GET /api/v1/packages/{ecosystem}/{name}` returned `versionCount: 0` and
  `totalDownloads: 0` beside a non-empty `versions` list, and the vulnerability counts and
  malicious/KEV flags were empty too, because the detail lookup carried none of the totals the
  packages list computes. It now reads the same totals as the list, so the two agree. Each
  proxied version row also carries the `packageId` of its package instead of an empty string.
- **The vulnerability report no longer shows a flaw's second identifier as an unknown-severity
  duplicate.** A flaw published under several ids (for example a GHSA and a PYSEC for the same
  Django release) appears once per id in `GET /api/v1/vuln-report`, and the PYSEC copy usually
  carries no severity, CVSS score, or summary because OSV's PYSEC records omit them. A row missing
  any of those now takes it from an alias advisory linked to the same version, in a different
  database (a GHSA never lends to another GHSA), and one that lists the other as an alias.
  Severity and score come from the same advisory. The substitution is made in the query, so
  sorting, `search`, and the SIEM severity counts agree with the values shown. A summary still
  missing after that falls back to the first prose line of the advisory's `details`; that line is
  display-only and is not matched by `search` or used for sorting. Each item also gains an
  `aliases` array (the advisory's other OSV ids, empty when none) so clients can group the rows
  for one flaw. Row counts, totals, and paging are unchanged.
- **Package lookups now report KEV and EPSS for advisories found only through a CVE alias.**
  `GET /api/v1/lookup` decided KEV membership and the EPSS score from a stored row whose id
  matched the live advisory exactly, so a GitHub advisory with no stored row of its own (Log4Shell,
  `GHSA-jfh8-c2jp-5v3q`, alias `CVE-2021-44228`) came back with `isKev: false` and no EPSS even
  though the CVE is in the CISA catalogue. The lookup now matches stored rows on the advisory's id
  and on its aliases, treats the advisory as KEV when any matching row is, and takes the highest
  EPSS across them. The block-KEV and EPSS verdict arms read the same corrected facts.

  The threat-feed refresh now also keeps a local copy of the CISA KEV catalogue (a new
  `kev_catalog` table, replaced in one transaction on each successful fetch and left untouched
  when a fetch fails), and the lookup checks every CVE among an advisory's id and aliases against
  it. An advisory whose CVE is in the catalogue reads as KEV even when this instance has never
  stored any advisory for it. The lookup makes no network call for this: on an air-gapped
  deployment, or with background jobs disabled, the table stays empty or holds the last copy
  fetched. A feed response that parses to no entries, or to fewer than half the stored count, is
  treated as a failed fetch: the catalogue and every KEV flag stay as they were. The lookup also
  reports an advisory id once when the advisory source returns it more than once.

  The download gate, the vulnerability report, the package list and the scan-time KEV alert read
  the `is_kev` flag on the stored advisory, which only the daily threat-feed pass used to set, so
  the lookup could report an advisory as KEV while the first proxy fetch of the same package was
  served. Storing an advisory now also sets `is_kev` (and the ransomware and date-added context the
  catalogue copy holds) when its id or any CVE among its aliases is in the stored catalogue, so all
  of those agree with the lookup from the first scan, including on an instance where no refresh
  pass ever runs. Storing an advisory never clears a flag; only the refresh pass does that, behind
  its guard. EPSS for a CVE the instance has never stored is covered by a separate entry.
- **Registry requests that name no organization now get `404` instead of `500`.** In
  `DEPLOYMENT_MODE=multi`, a package-manager request sent to the apex host (for example
  `http://localhost:8080/maven/.../maven-metadata.xml`) or to a subdomain that matches no
  organization reached the registry code with no organization and failed with a server error.
  Every registry surface (npm, PyPI, NuGet, Maven, RPM, Cargo, Go, OCI, APK, Terraform, Hex) now
  answers such a request with `404` problem+json, or the OCI error envelope with `NAME_UNKNOWN`
  under `/v2/`, whether or not it carries a token. A token never makes the request fall back to
  its own organization: the host decides which organization a request is for. The system admin
  console, login, and health endpoints on the apex are unchanged.

- **Banners can be created and edited on PostgreSQL.** Creating or updating an organization or
  system banner failed with a server error on PostgreSQL (`column "enabled" is of type integer but
  expression is of type boolean`); SQLite deployments were unaffected. The `enabled` flag is now
  stored as `1`/`0` on both databases.

## [0.13.3] - 2026-09-30

### Added

- **`DEFAULT_USAGE_CAPS` sets instance-wide default usage caps.** In `DEPLOYMENT_MODE=multi` or
  `header`, a comma-separated list of `meter=quantity` pairs over `egress_bytes`,
  `egress_metadata_bytes`, `storage_bytes` and `artifact_count` (for example
  `egress_bytes=500000000000,artifact_count=10000`) caps every tenant on each meter where it has no
  explicit cap. Clearing a tenant's explicit cap makes the meter fall back to the default. Unset
  or empty means no defaults, and the setting is ignored in single and edge mode. An unknown meter,
  a repeated meter, or a quantity that is not a positive whole number stops startup with an error
  naming the bad pair. It is read at startup, so a change takes a restart. The system API's
  `GET` and `PATCH /api/v1/system/tenants/{slug}/usage-limits` responses gain `defaultCaps` and
  `effectiveCaps` beside `caps`, and the hourly usage rollup measures a tenant against its
  effective caps. See [OPERATIONS.md](OPERATIONS.md#usage-caps).

### Fixed

- **An empty S3 bucket or prefix is read as zero objects.** The AWS SDK leaves the listing's
  object collection null rather than empty when the service returns none, so measuring the
  total size of, or enumerating, an empty bucket or prefix threw instead of reporting zero.
- **Back and Forward restore a list's scroll position on a slow page.** The restore gave up after
  about ten frames, so a page whose data arrived later landed at the top. It now keeps trying for
  up to three seconds, and stops as soon as you scroll or interact, or when another navigation
  places the viewport.

## [0.13.2] - 2026-09-29

### Fixed

- **A failing licence backfill no longer crashes the application on Postgres.** The first page of
  the backfill's query bound a null timestamp that Postgres rejected (`42P08`), and because the
  job ran at startup and stopped the whole host on a tick error, the failure became a crash loop
  on every boot. The query now binds the timestamp as text on both databases.
- **A background job that fails a pass no longer stops the application.** The threat-feed
  refresh, vulnerability scan, deprecation refresh and licence backfill were set to end the host
  on an unhandled error in a pass. Every background job now logs the failure and retries at its
  next scheduled run.

## [0.13.1] - 2026-09-28

### Added

- **An instance-wide proxy cache size alert.** An hourly check compares the shared proxy cache
  against `CACHE_SIZE_WARN_BYTES` (default 500 GB; `0` turns it off, and a system admin can change
  it from Settings → Instance). The first check over the threshold records a
  `system.cache_size_threshold_exceeded` audit event and notifies the operator Slack channel; it
  stays quiet while the cache remains over and re-arms once it drops back under. The last reading
  also appears in `/api/v1/system/health` and the operator dashboard. `CACHE_SIZE_ALERT_SCHEDULE`
  sets the check's cron schedule (default `0 * * * *`).

### Changed

- **Anonymous requests no longer spend a tenant's rate-limit budget.** `TENANT_RATE_LIMIT_PERMITS`
  (and the throttled budget) now counts only traffic the organization serves: every request while
  the org's anonymous pull is on, and otherwise only requests that carry one of the org's own
  credentials, in any form its clients send (Bearer, Basic, the bare token Cargo and Hex send, or
  `X-NuGet-ApiKey`). Before, anyone who could reach a tenant's host could use up its budget from
  many addresses and leave the org's own clients with `429`. Requests that are not charged to the
  tenant still count against the per-address limits.

### Fixed

- **Row-level security no longer turns on over a transaction-mode pooler.** When
  `DB_ROW_LEVEL_SECURITY` is unset on multi-tenant Postgres and the connection goes through a
  transaction-mode pooler such as PgBouncer `pool_mode=transaction`, startup now detects it and
  boots with row-level security off, logging a warning naming the pooler, instead of enforcing it
  over a pool that can run one tenant's statement on a backend bound to another. An explicit
  `enforce` refuses to boot there. Startup detects the pooler by holding several tenant connections
  open and checking that each keeps its database backend and its own tenant from one statement to
  the next. The 0.13.0 advice to set `DB_ROW_LEVEL_SECURITY=off` behind such a pooler still holds;
  it is no longer the only thing standing between the default and a wrong tenant.
- **Postgres read-model views keep `security_invoker` on every boot.** On Postgres 15 and later,
  `artifact_inventory`, `artifact_license`, `org_storage_bytes`, and `org_billable_storage_bytes`
  are now always created `security_invoker`, whatever `DB_ROW_LEVEL_SECURITY` says. The views are
  shared by every node on the database, so a node booting with row-level security off or fallen
  back, or the `migrate-to-postgres` command, recreated them without the option, and nodes enforcing
  row-level security then read them with owner rights, across tenants, until an enforcing node
  next booted. The application's `org_id` filter was unaffected. A role other than the connecting
  role that reads these views now needs `SELECT` on their base tables. During a blue-green cutover
  from 0.13.0, a restarted 0.13.0 node still recreates the views without the option until it drains.
- **The Postgres numeric-column upgrade no longer stalls other queries or dies at 30 seconds.**
  Widening a database's numeric columns on the first boot after 0.12.x now waits at most 5 seconds
  for each table's lock, retried with back-off for about three minutes per table, instead of
  queueing every later query on that table behind it. The rewrite itself is no longer cut off by the
  30-second command timeout, so a large table completes instead of failing startup. The
  maintenance-window guidance for this upgrade still applies. SQLite is unaffected.
- **Split storage tiers serve proxied artefacts from the cache tier.** With the cache and registry
  tiers on different stores (`_CACHE` / `_REGISTRY` overrides), proxied artefacts were written to
  the cache tier but several ecosystems (PyPI and Go among them) read, probed and measured them on
  the registry tier. Those reads missed, so the artefact was fetched from upstream on every request
  or failed, and its recorded size was 0. Every service now names the tier it reads, and a
  compliance test keeps it that way. Single-store deployments, the default, were unaffected.
- **apk index caching is per credential.** The cached `APKINDEX.tar.gz` and `DESCRIPTION` were
  keyed by upstream URL and path only. When two organizations configured the same apk upstream
  URL, one with credentials and one without, the second could be served the first one's cached
  index, or join its in-flight authenticated fetch. The cache and the in-flight fetch now include a
  hash of the credential.
- **System audit rows record the source address.** Every request-scoped system-admin audit event
  (instance settings, admin create, disable, password reset and delete, banners, observability,
  and the system token events) now records `source_ip`, and token create and revoke record the
  actor kind. A compliance test now covers system audit writes too.

## [0.13.0] - 2026-09-27

### Added

- **System API tokens.** In `DEPLOYMENT_MODE=multi`, a system admin can mint a `dpsys_` token at
  the apex (the Tokens page of the System console, or `POST /api/v1/system/tokens`) so CI, Terraform, or a
  provisioning script can create and manage tenants without an interactive session. The token's
  reach is fixed, not chosen at mint time: it authenticates only the tenant-management actions
  listed under [System API tokens](OPERATIONS.md#system-api-tokens) in OPERATIONS.md, and gets `401`
  everywhere else, including admin management, instance settings, audit, and minting another
  token. Every token needs an expiry at most 365 days out, and an instance holds at most 50
  unexpired tokens. A token stops working when its owner is disabled, locked, or deleted, or when
  another admin resets the owner's password. The owner's own password change leaves it alone. Any
  system admin can list or revoke any token. An action taken with a token is audited as a
  `service` actor under the token's name, with the owning admin's id in the event detail.
- **Presigned redirects for every ecosystem.** `STORAGE_PRESIGNED_READS` redirected only full,
  digest-addressed OCI blob downloads. It now applies to any ecosystem named in the new
  `STORAGE_PRESIGNED_READ_ECOSYSTEMS`: `apk`, `cargo`, `go`, `hex`, `maven`, `npm`, `nuget`, `oci`,
  `pypi`, `rpm`, and `terraform`. The default is `oci`, so an upgrade redirects nothing that did not
  redirect before. A redirect is issued after the same authorization, tenancy, and block-gate
  checks the streaming path runs, and only for immutable artefacts. Metadata, `HEAD`, ranged
  reads, and cache misses still stream. Downloads redirect with `307`, except apk, which gets `302`
  because apk-tools does not follow a `307`.
- **CloudFront signer for presigned redirects.** `STORAGE_PRESIGNED_READ_SIGNER=cloudfront` points
  redirects at a CloudFront distribution instead of the bucket, using signed URLs whose canned
  policy covers the one object until the URL expires. It needs `STORAGE_BACKEND=s3` with no
  `_CACHE` / `_REGISTRY` overrides, plus `CLOUDFRONT_URL_BASE`, `CLOUDFRONT_KEY_PAIR_ID`, and
  `CLOUDFRONT_PRIVATE_KEY`. Uploaded artefacts are private: they go through CloudFront only when
  `CLOUDFRONT_UNCACHED_PATH_PREFIX` is set, and are signed by the object store otherwise. A proxied
  artefact takes `CLOUDFRONT_CACHED_PATH_PREFIX`, where the edge may cache it, only when every
  upstream its org has configured for that ecosystem is credential-free. Otherwise it is treated
  like an uploaded one. The same applies when the org has no upstream left for the ecosystem,
  when the check fails, and on edge nodes. The check covers the whole ecosystem, so an org with
  one private OCI registry loses edge caching for all of its proxied image layers. It is also
  permanent: a credentialed upstream is recorded in the new `upstream_credential_history` table,
  and the org's proxied artefacts for that ecosystem stay off the cached prefix even after the
  upstream is deleted, because the artefacts it fetched are still in the cache. There is no way to
  clear the record short of deleting the org. Credentialed upstreams added before this release are
  recorded at startup if they still exist or their `upstream_registry_added` audit event is still
  in the audit log with its detail. One deleted before that retention window is not known, so
  operators who had one should delete the org's cached proxied artefacts for the ecosystem before
  enabling the CloudFront signer. See
  [Signing with CloudFront](OPERATIONS.md#signing-with-cloudfront) in OPERATIONS.md.
- **Read-only organizations.** `PATCH /api/v1/system/tenants/{slug}/status` accepts `read_only`
  alongside `active` and `suspended`. A read-only org keeps serving downloads, and its users can
  still sign in and use the web UI and management API, but every state-changing request to a
  package registry (publish, upload, delete, yank) gets `423`. Nothing is deleted. The check looks
  at which controller a request reaches rather than its path, so SAML sign-in and other
  management writes are unaffected. Other replicas of a multi-replica deployment pick up a status
  change within 5 seconds.
- **Postgres credentials as separate variables.** `DB_PASSWORD` and `DB_USERNAME` override any
  `Password=` or `Username=` in `DB_CONNECTION_STRING`, so an orchestrator that injects secrets as
  separate variables (ECS task-definition `secrets`, a rotated RDS or Aurora managed credential)
  can supply them without splicing them into the string. They apply to the app and to the default
  target of `migrate-to-postgres` and `verify-postgres-migration`. An explicit `--target` is used
  as given.
- **Per-tenant rate limit.** `TENANT_RATE_LIMIT_PERMITS` bounds one tenant's protocol-plane
  requests per second across all of its tokens and addresses. It is off unless set.

### Changed

- **Action required: Postgres row-level security is on by default for multi-tenant
  deployments.** With `DB_PROVIDER=postgres` and `DEPLOYMENT_MODE` set to `multi` or `header`,
  `DB_ROW_LEVEL_SECURITY` now defaults to `enforce`. Row-level security backs the application's
  `org_id` filter: tenant connections switch to the non-login role `DB_ROW_LEVEL_SECURITY_ROLE`
  (default `dependably_rls`) and can read or write only their own tenant's rows. Startup creates
  that role, so the connecting role needs `CREATEROLE`, or the role must be created beforehand
  (`NOLOGIN NOBYPASSRLS`, granted to the connecting role, with `SET` on Postgres 16 and later). The
  default never blocks startup. If the connecting role lacks `CREATEROLE`, the server is older than
  Postgres 15, or `DB_CONNECTION_STRING` sets `Multiplexing=true`, the node boots with it off, logs
  a warning naming the reason, and reports `dependably.db.rls_enforced=0`. An explicit `enforce`
  refuses to boot in those cases instead, and an explicit `off` is honoured with a warning.
  Transaction-mode poolers (PgBouncer `pool_mode=transaction`) are not supported with it on. Set
  `DB_ROW_LEVEL_SECURITY=off` if yours uses one. RDS Proxy is fine. SQLite and single-tenant
  deployments are unaffected.
- **Action required: an unknown `DB_PROVIDER` fails startup.** Any value other than `sqlite` or
  `postgres` (ignoring case and surrounding whitespace) used to fall back to SQLite without saying
  so. A deployment with `DB_PROVIDER=postgresql` or `pg` was running on SQLite. It now refuses to
  start. Set `DB_PROVIDER=postgres` to keep using Postgres. If you want to keep the SQLite
  database such a deployment has been writing to, set `DB_PROVIDER=sqlite` instead.
- **Upgrading a Postgres database rewrites several large tables.** The first boot of this release
  widens integer and floating-point columns on `package_versions`, `vulnerabilities`, `oci_blobs`,
  `maven_version_files`, `rpm_metadata`, `project_documents`, `org_settings`, and others to 64-bit
  types. Each change rewrites the table and rebuilds its indexes while holding an exclusive lock,
  and the read-model views are unavailable until the migration finishes. On a large database,
  plan the upgrade as a maintenance window rather than a blue-green cutover with the previous
  release still serving. SQLite databases are unaffected.

### Fixed

- **Cargo downloads work when anonymous pull is off.** `/cargo/config.json` did not declare
  `"auth-required": true`, so Cargo sent its token to the index but not to the crate download,
  which answered `401`. The registry configuration now declares it whenever the org's anonymous
  pull is off, and leaves it out when anonymous pull is on. Cargo 1.74 or later is required for
  an authenticated registry.
- **Proxied PyPI files record their size on S3 and Azure.** On an object-store backend a proxied
  PyPI file was recorded with a size of 0, because the store's response stream cannot report its
  length, so those files never took a presigned redirect. The first fetch now reads the size from
  a listing of the stored object when the stream cannot give it. Files fetched before this
  release keep their 0 until they are evicted and fetched again.
- **Proxied OCI blob pulls work on S3 storage.** With `STORAGE_BACKEND=s3`, every OCI blob that
  had to be fetched from the upstream registry failed with `500` and `AmazonS3Exception: Could
  not determine content length`. Blobs already in the cache were served normally. The proxy
  streams a blob into the store while it checks the digest, and that stream cannot report its
  length, which the AWS SDK requires before it sends a single upload request. This happened on
  AWS S3 and S3-compatible services (MinIO, R2) alike. The S3 store now uploads a stream of unknown
  length in 8 MiB parts, holding at most one part in memory, and a blob smaller than one part
  still goes up as a single request. A failed upload is aborted so its parts do not stay in the
  bucket. The IAM policy for the bucket needs `s3:AbortMultipartUpload`; see
  [Blob storage backends](OPERATIONS.md#blob-storage-backends) in OPERATIONS.md.
- **Presigned redirects keep an `http://` S3 endpoint's scheme.** With `S3_ENDPOINT` set to an
  `http://` address (a common MinIO setup), presigned redirects named `https://` on the same
  host and port, where nothing listens for TLS, so every redirected download failed. The URL now
  uses the endpoint's own scheme. AWS S3 and `https://` endpoints are unaffected.
- **Transparent intercept reaches the ecosystem again.** With `HOST_ROUTING` set, a request to a
  mapped host (for example `registry.npmjs.org=npm`) had its path rewritten to the ecosystem
  prefix only after the endpoint had already been chosen from the original path, so it never
  reached the ecosystem's controller. Routing now runs after the rewrite, in both the full and the
  edge images.

## [0.12.2] - 2026-09-23

### Added

- **Policies page.** A new sidebar page, visible to every role that can browse packages, shows the
  organization's policies read-only. The **Licences** tab lists the licence enforcement mode and
  the allowed, conditional, and blocked licences. The **Controls** tab lists each control that
  can refuse a download (malicious packages, known-exploited and actively exploited
  vulnerabilities, CVSS and EPSS thresholds, deprecation, revocation, release age, install
  scripts, signature and provenance, licence) with its current setting. Each control's hover tip
  names the `X-Dependably-Block-Reason` value a refused request carries, so a developer who hits
  a 403 can find the control that refused it. Backed by `GET /api/v1/policies`, which requires
  `read:packages`. It is a narrower projection than the settings endpoints and carries no upstream
  URLs, credentials, trust-anchor material, or allowlist patterns.

### Changed

- **`APEX_HOST` sets the apex hostname again, as an optional override.** The apex (the host that
  serves the system administrator in `DEPLOYMENT_MODE=multi`, whose subdomains are the tenants,
  and which host-header filtering admits) is still the host portion of `BASE_URL` by default, and
  a deployment that sets only `BASE_URL` sees no change. When `APEX_HOST` is set to a non-blank
  value it takes precedence, for tenant resolution, the `AllowedHosts` allowlist, and the apex
  reported by the bootstrap endpoint alike. It was previously read, warned about as deprecated,
  and ignored; that startup warning is gone. A blank value falls back to `BASE_URL`. Setting it to
  a loopback name (`localhost`) is taken literally and leaves no usable apex, which fails host
  filtering closed to loopback the same way an unset `BASE_URL` does.

### Fixed

- **Action required — three controls were not enforced on a proxy first fetch.** `kev_ransomware`,
  `ssvc_exploitation`, and `epss_percentile` were enforced when a cached version was served, but
  not when a version was fetched from upstream for the first time, so the first download of a
  version those controls should refuse went through. All three are now enforced on first fetch
  as well. An organization with any of them enabled may see downloads refused
  that previously succeeded; the refusals carry the matching `X-Dependably-Block-Reason`.
- **Info tips inside tables showed nothing.** The hover bubble was drawn inside its table cell,
  which clips overflow, so a tip in a table row was cut off. The bubble is now positioned against
  the viewport, flips below the icon when there is no room above, and stays inside the window.

## [0.12.1] - 2026-09-21

### Fixed

- **The OCI blob proxy was store-and-forward, so a large layer could never be pulled through a
  reverse proxy.** A cache-miss blob `GET` downloaded the entire layer, verified it and promoted
  it into the cache before writing the first byte to the client — time-to-first-byte scaled with
  layer size while every reverse proxy in front of the registry enforces a fixed read timeout
  (nginx defaults to 60 s). Past roughly a minute's worth of transfer the pull could not complete
  at any size of blob, however healthy that blob was upstream: the proxy hung up, the request's
  cancellation surfaced as an unhandled `TaskCanceledException` — **`500`, with a stack trace at
  Error level** — and the client read that as a broken server and retried from byte zero into the
  same wall. A 5.8 GiB layer needing about twenty minutes against a sixty-second budget failed
  identically on every attempt, which read as one poisoned object in the cache rather than as a
  structural limit; the same wall was being hit and survived by luck on layers a tenth the size,
  where a retry happened to land after the background fetch had finished.

  The blob proxy now **streams through**: upstream bytes are mirrored to the client by the same
  pass that hashes and caches them, so time-to-first-byte is the upstream's own regardless of
  layer size. Verify-then-commit is unchanged — the content-addressed key is still written only
  after the digest is confirmed. A client that hangs up mid-layer no longer aborts the fetch: the
  caching pass runs to completion, which is what makes that client's retry a cache hit. A caller
  that joins a fetch already in flight cannot be mirrored and is served from the cache as before.

  Two refusals interact with this, and they are treated differently because only one of them has
  to. **An over-cap body is never streamed into a reset**: a response arriving with no declared
  `Content-Length` can only have its cap checked mid-transfer, so that one case deliberately does
  not stream at all and keeps answering `502 blob_too_large` with nothing yet sent. It costs
  nothing in practice — a registry serving a layer declares its length — and it means the size
  refusal introduced in the previous release keeps its status contract intact. **A digest
  mismatch on a streamed blob can only be a reset**, because a whole-layer digest is not knowable
  until the last byte, by which time the response is committed; the connection is reset so a
  truncated transfer rather than a clean `200` is what the client acts on, and nothing is written
  to the cache, so a retry is not served the bad bytes either. On the non-streamed path the
  mismatch still answers `502 blob_digest_mismatch` in full.

- **A caller disconnecting mid-pull was reported as a server fault.** An `OperationCanceledException`
  raised by the caller's own request token now answers **`504 UNAVAILABLE`** and logs one line
  without a stack trace, instead of a `500` that told the puller this registry had broken and
  filled the log with traces for the most ordinary event a long transfer has. Where the response
  has already started, the connection is reset rather than a status invented for bytes already
  sent.

- **The OCI blob proxy leaked its staging entry on any failure after the staged write.** Cleanup
  ran only on the two refusals that were named explicitly (over-cap, digest mismatch), so a
  promote that failed — a full cache volume, the likeliest cause when writing a multi-gigabyte
  layer twice — stranded the staged bytes permanently. Nothing else reclaims them: the OCI
  staging janitor sweeps the `PROXY_STAGING_PATH` filesystem for a different filename shape, and
  cache eviction is row-driven while a staging entry never had a row, so a retrying client minted
  a fresh orphan per attempt on the volume whose exhaustion caused the failure. The delete is now
  unconditional and runs on `CancellationToken.None`, and the staged stream is disposed before
  the slot is unlinked — leaving it open held a file handle on an unlinked multi-gigabyte inode
  until a finalizer ran, so the space the delete appeared to reclaim was still spent.

- **The OCI blob proxy refused any layer over a hard-coded 600 MB and reported the refusal as
  `404 BLOB_UNKNOWN`** — "this blob does not exist" — for content the upstream was in the middle
  of handing over. The cap was `UpstreamClient.MaxUpstreamResponseBytes`, a constant shared with
  every other ecosystem's metadata and tarball fetches and never sized for an image layer, so
  `docker pull` of any ML/CUDA image failed deterministically on the same layer every time. Being
  deterministic and reported as absence, it read as a corrupted cache entry rather than as a
  configured limit, and sent operators looking in the wrong place.

  The blob path now has its own bound, `Oci__MaxBlobProxyBytes`, defaulting to 10 GiB — a disk
  bound on the cache tier, not a memory one, since blobs stream through without being buffered.
  Sized per-ecosystem rather than by raising the shared constant, which would have widened every
  other ecosystem's fetch at the same time. Values below 1 MiB are refused at startup.

  Both refusals that used to collapse into that 404 are now **502 `UNAVAILABLE`**, matching the
  posture this controller already takes for an upstream it cannot reach, and they are
  distinguishable from each other: `blob_too_large` is a number the operator chose,
  `blob_digest_mismatch` is an integrity event worth alerting on. The upstream host, the fault,
  and the setting to change are disclosed only to a caller holding a token for the org — a
  `/v2/` blob read is anonymously reachable under `anonymous_pull`, and an org's upstream list is
  supply-chain topology. The status itself is unconditional. Blob `HEAD` applies the same cap as
  `GET`, so a client is refused before it starts a pull rather than part-way through one.

## [0.12.0] - 2026-09-20

### Added

- **`GET /api/v1/ecosystems`** publishes the server's ecosystem vocabulary and per-plane support
  matrix (`registry`, `lookup`, `setup`), read from the same three source-of-truth constants the
  server itself enforces (`UpstreamRegistryRepository.SupportedEcosystems`,
  `PackageLookupService.SupportedEcosystems`, `SetupRecipeCatalog.Ecosystems`) rather than a
  hand-maintained copy. Lets a client — the MCP server, the web UI, a future integration — ask the
  server which ecosystems it supports instead of hardcoding a list that can drift from it.
  Authorized on `read:packages`, org-guarded like the rest of the read-only inventory surfaces.

### Fixed

- **A signed and an unsigned export of identical data published under the same `serialNumber`
  and `version`**, so a consumer caching an SBOM/VDR/VEX export by that pair never re-fetched the
  newly-signed document, and two recipients holding "revision 1" disagreed about whether the
  author signed. The revision fingerprint now covers the org's signing posture (whether it has an
  active signing key at all — never the per-replica rendered `signed`/`unsigned-*` state, which a
  mixed fleet can answer two different ways for identical data) and the `dependably:signature-state`
  metadata property; the signature itself (`value`, `keyId`, `algorithm`, `publicKey`) stays out
  of the fingerprint, so rotating a signing key does not move the revision. Two narrower gaps in
  the same fingerprint closed alongside it: a component's asserted hashes and additional
  identifiers were fingerprinted from the raw stored column rather than the filtered, ordered set
  the export actually renders, so a future ingest change or a reordered stored array could bump
  `version` with nothing rendered differently, or (for a purl-less component carrying an
  unrecognised identifier kind) miss a real change to the `dependably:identifier-status` property.

  **Action required:** the fingerprint's inputs changed, so the FIRST export of every
  already-persisted document after upgrading to this release bumps its `version` by exactly one —
  `serialNumber` and `metadata.timestamp` are unchanged, and no document content is different; it
  is the one-time cost of computing revision identity correctly. During a blue-green cutover, a
  replica still running the previous build computes the OLD fingerprint and one running this
  release computes the NEW one, so an export alternating between the two bumps `version` on every
  request that lands on a different replica than the last — it settles back to one bump per
  document once every replica runs this release.

## [0.11.0] - 2026-09-13

### Added

- **The SIEM auth feed can reach every audit action, and now says which ones exist.** Its
  `action=` filter appended the family separator unconditionally, so every pattern was
  `<value>.%` — an action name with no dot in it could not be matched by any value a caller was
  able to send. 60 of the 138 action names this instance writes are flat, and 25 of those are
  security-relevant: `checksum_failure`, `ssrf_blocked`, `provenance_verification_failed`,
  `upstream_source_pin_violation`, `token_created`/`token_revoked`,
  `service_token_created`/`service_token_revoked`, `member_role_changed`, `member_removed`,
  `trust_anchor_added`/`trust_anchor_removed`, `quarantine_decision`, `allowlist_blocked`,
  `conflict_resolved` and `invite_accept_blocked` among them.
  None of them could reach a collector, and nothing surfaced it: the query ran, the
  endpoint returned 200, and the events were simply absent. A filter value now matches the action
  of exactly that name **plus** every action in its dotted family, so `action=checksum_failure`
  works and `action=login.` keeps meaning what it meant.
- **`GET /api/v1/siem/actions`** returns the declared action vocabulary — every name, which of them
  the no-filter feed serves, the dotted families the vocabulary implies (`family_prefixes`), and the
  two per-request filter limits (`max_action_filters`, `max_family_filters`). A collector previously
  had to hardcode the vocabulary from the source, and could not tell what it was *not* receiving; a
  distinct-values query over the rows cannot answer that either, since an event family nobody
  subscribed to leaves no row to find. Same auth as the feeds.
- **Naming declared actions on the auth feed is free, and the filter limit that remains is measured.**
  A filter naming a declared action now binds only an equality term; the family `LIKE` is emitted
  just for filters that name a dotted family or an action the release does not declare, since no
  declared action sits under another and the term could only ever match outside the vocabulary. So
  pinning the exact action set a collector understands — instead of inheriting the default set and
  letting it widen on upgrade — costs what the default feed costs. The single chosen cap of 100 is
  replaced by two derived ones: `max_action_filters` (every declared action plus a full complement
  of families) and `max_family_filters` (the families the vocabulary implies). **Action required (SIEM collectors only):**
  a request naming more than `max_family_filters` unrecognized-or-family values is now a `400`
  naming the limit, where it previously succeeded; the limits are published by the catalogue
  endpoint above so a collector can check its subscription against them.
- **Auth-feed events name their tenant.** `orgSlug` is projected beside `orgId` (and rendered as
  `cs4Label=OrgSlug` in CEF), so an alert reads as a customer rather than as a 32-hex id — a
  read:audit credential has no tenant-lookup route to resolve one with. `actorEmail` remains
  intentionally null for user actors; CONTRIBUTING.md now documents that as the deliberate GDPR
  decision it is, rather than leaving it to read as a bug.

### Changed

- **The auth feed's default action set no longer advertises coverage it does not have.** It was
  `login.` `lockout.` `token.` `rbac.` `auth.` `ratelimit.`, of which `token.` and `rbac.` matched
  nothing whatsoever — no writer has ever emitted a dotted `token.*` or `rbac.*` action, so a
  collector trusting the default believed it had credential and RBAC coverage and had neither. The
  default is now the declared security vocabulary by exact name: everything the old prefixes really
  matched, plus the credential, privilege, identity-provider-trust, refusal and supply-chain
  integrity events the two dead prefixes implied. Configuration changes (allowlists, licence
  policy, retention, proxy and webhook settings, preferences) are deliberately not in it and are
  one `action=` value away. No collector loses an event it receives today.
- **One name per event.** `POST /api/v1/sbom` wrote `project.create` for the project creation that
  `ProjectsController` writes as `project.created`, so a consumer filtering either spelling
  silently missed the other's rows. Both surfaces now write `project.created`. Rows written before
  this release keep the old spelling; query it explicitly to read that history.
- **The CEF name/severity table matches what writers emit.** It mapped `token.created`,
  `token.revoked`, `rbac.role_changed`, `rbac.member_added` and `rbac.member_removed` — five names
  nothing has ever written — so the real events fell through to the raw action string and the
  lowest severity. The table now names the emitted actions and covers the supply-chain integrity
  failures and refusals, which rank above authentication noise.
- **Audit action names are a declared vocabulary** (`AuditActions`), enforced by the new
  `Category=Compliance` gate `AuditActionVocabularyComplianceTests`: a writer naming an undeclared
  action fails the build, as does a declared name no writer emits, a CEF mapping for a name nothing
  writes, and a default-set entry that is not a declared action. A call site whose action is not a
  literal or a constant carries an `// audit-action-ok: <reason>` marker, bare markers rejected.

- **Block-gate refusals can now reach a SIEM.** `GET /api/v1/siem/events/activity` serves the
  `activity` plane over an allowlist — the whole `blocked*` block-gate family by default, matched
  as a range so an arm added later is carried without a config change. Until now the only pull feed
  was `/api/v1/siem/events/auth`, which reads `audit_log`; the two planes are disjoint and never
  dual-written, so a refusal reached no collector at all. Same auth tier as its sibling: a token or
  tenant-session caller is pinned to its own tenant and `?org=` is inert for it, and the query takes
  a non-nullable org id, so a platform admin reads one named tenant per poll rather than every
  tenant at once. `download` is available behind `SIEM_ACTIVITY_DOWNLOAD_EVENTS` (default off); a
  collector that asks for it while it is off gets a 400 naming the variable instead of a response
  that is quietly short. The feed never serves past `now − SIEM_ACTIVITY_LAG_SECONDS` (default 30)
  and reports the window it served on the last page of a read, because activity rows are
  timestamped when they are enqueued and inserted later — reading up to "now" would permanently
  skip every row whose INSERT landed after the poll that already moved the watermark past its
  timestamp, and advancing on a truncated newest-first page would skip the older rows still behind
  the cursor. JSON, NDJSON, and CEF as before, and
  a new `idx_activity_org_event` index serves the event-type-scoped read.

## [0.10.0] - 2026-09-07

### Security

- **SSO-only is now enforced by the server, not only by the sign-in page.** Switching a tenant to
  SSO-only (`forms_login_enabled=false`) hid the password form, but `POST /api/v1/auth/login` never
  read the setting: a correct local password kept minting sessions, bypassing every control the IdP
  enforces (its MFA, conditional access, deprovisioning). The 0.9.0 entry below that revokes
  password-backed sessions on the flip assumed the grant itself was already closed; it was not.
  The login endpoint now refuses password logins on an SSO-only tenant with the same generic 401
  as a wrong password, and records the refusal (audit `login.failure` with
  `reason=forms_login_disabled`, activity, SIEM event) against the same lockout budget, answering
  429 once that budget locks — so a spray against an SSO-only tenant is as visible as one against a
  password-backed one. `POST /api/v1/invites/accept`, which stores a local password and mints a
  session on its own, refuses on an SSO-only tenant with 409 (audited as `invite_accept_blocked`)
  without consuming the invite, so it works again if forms login is re-enabled. "SSO-only" means
  what the ACS callback means by "configured": IdP entity id, SSO URL, and a signing certificate
  from metadata **or** an admin-pinned override — a tenant with `forms_login_enabled=false` but no
  usable IdP still accepts passwords, so a stray config row cannot lock every user out. The admin
  guard that lets a tenant switch to SSO-only reads the same predicate, and IdP metadata whose
  `SingleSignOnService` location is not an absolute http(s) URL is rejected at upload instead of
  being stored as a config no SAML login could ever complete.

### Added

- **Applications and releases can be retired.** A project and a project version each carry an
  `is_active` flag, editable from the project edit modal and the release list
  (`PATCH /api/v1/projects/{projectId}/versions/{versionId}`). Retiring a release is the
  statement "we no longer run this", which drops it out of the blast radius, out of the
  nightly policy re-evaluation, and out of the exported VEX — the number an operator reads as
  "N applications ship this component" now counts what the tenant actually ships rather than
  everything it has ever uploaded. Retirement is independent of "latest": a release still
  running after a partial rollout stays counted while a newer one leads. Nothing is derived
  from activity — every existing project and version is active, so the flag changes no counts
  until an operator sets one. One predicate (`ProjectLifecycle.InServiceFilter`) governs the
  blast radius, the nightly re-evaluation, retention's version cap and the VEX export, and a
  new compliance gate fails if those four drift apart — a narrower filter in retention would
  silently delete a counted version, and a narrower one in the re-evaluation would present a
  frozen count beside current ones.
- **Curated skills are readable before you install one.** A skill's name on the Setup page is
  now a link that opens the document in place, rendered rather than raw, with buttons to copy
  the Markdown or download the `SKILL.md`. Installing a skill writes it straight into an AI
  assistant's directory, so this is the one moment a reader would want to see what they are
  about to run. It applies to both surfaces that list a skill — the Skills tab and the
  configure-with-an-assistant alternative in step 3.
- **Install or download the whole set at once.** The Skills tab carries one command that
  installs every skill where the selected assistant looks for it, and a `Download all (.zip)`
  button backed by `GET /api/v1/skills/bundle` (optionally `?family=config|remediation`). The
  archive is laid out as `<id>/SKILL.md`, so unpacking it into `~/.claude/skills/` lands every
  file where it belongs, and its entry timestamps are pinned so the same corpus always produces
  the same bytes.


- **The Setup page serves the skills this instance ships.** Setup is now two tabs: the
  package-manager wizard, and a Skills tab listing the nine curated remediation skills with a
  per-assistant install one-liner (Claude Code / OpenAI Codex / GitHub Copilot), which were
  previously reachable only from an advisory that happened to map to one. Step 3 of the wizard
  additionally offers the client-config skill covering the selected package manager and scope,
  as an alternative to copying the configuration by hand.
- **`GET /api/v1/skills` and `/api/v1/skills/{id}`** serve every curated skill anonymously,
  each tagged with its family (and, for the client-config family, its ecosystem and scope).
  The 17 client-config skills are now embedded in the binary, so an air-gapped install can
  hand them out without reaching the source repository — previously only the nine remediation
  skills were. The existing `/api/v1/remediation/skills` routes are unchanged and still return
  exactly the nine, so install one-liners already copied out of a running instance keep working.
- **Client-config skills for RPM, Alpine apk, Terraform and Hex.** Those four ecosystems had
  Setup recipes with no skill behind them. A new gate asserts the skill set and the Setup
  recipe matrix cover exactly the same (ecosystem, scope) cells, in both directions.

### Changed

- **The Setup wizard asks what you are doing before it mints a token.** The "I want to"
  choice moves into step 1 beside the token, because it is the only axis that selects the
  token's capability preset; "Applies to" and "Tool" move into step 3 beside the configuration
  they reshape. Step 2 is the package-manager choice alone. The auto-generated token
  description now names the operation rather than the package manager, which is chosen below it.

### Fixed

- **Auditors can open the Audit page in the web console.** The `auditor` role holds
  `read:audit`, which is all `GET /api/v1/audit` and `/activity` gate on, but the console hid
  the Audit link behind an admin/owner check and bounced the role off the `/audit` URL. Page
  access is now a per-page allowed-roles map (`RESTRICTED_PAGES` in `routes.js`) shared by the
  sidebar, the route guards, and the dashboard's blocked-pull drill-downs; `audit` admits
  `auditor`, the other restricted pages stay admin/owner-only. The unused `audit.forbidden`
  string is removed.
- **OSV advisory timestamps are stored in the canonical precise shape.** OSV serves `published`
  and `modified` with nanosecond precision, which the schema's timestamp `CHECK` does not admit;
  they are now normalized on the way in, so an advisory whose upstream record carries sub-second
  precision stores its dates instead of dropping them.
- **Layout fixes at laptop widths.** A visual pass at narrower viewports fixed overlap and
  spacing across the console, added the column floors that keep a table readable once its
  horizontal scroll engages, gave the upload outcome table fixed column widths so `Detail` wraps
  inside its card rather than past it, bulleted the blast-radius application list, and
  interpolated the `{threshold}` placeholder that was rendering literally in the Risk page intro.

## [0.9.0] - 2026-09-03

### Added

- **Hex joins the upstream-metadata surfaces.** The daily deprecation refresh reads a Hex
  package's retirements and latest release from the signed upstream resource (so
  "versions behind" and the deprecated arm work for proxied Hex packages), the licence backfill
  reads `metadata.config` licences out of cached tarballs, and the Lookup page accepts `hex`.
  One shared verified fetcher applies the same trust rules everywhere: an upstream without a
  known public key is never consulted, and a resource that fails verification is a fault.

- **Hex (Elixir / Erlang) ecosystem, read plane and proxy.** `/hex/` serves the Hex repository
  protocol Mix and Rebar3 resolve from: `names`, `versions`, `packages/NAME` and the new
  per-org `public_key`, plus package and documentation tarballs. Every registry resource is
  rebuilt from what the org holds and a signature-verified upstream answer, then signed with
  the org's own RSA key under the repository name `dependably`, because a Hex client checks both
  the signature and the repository name embedded in each resource and a relabelled upstream
  byte stream can satisfy neither. Tarballs are verified against the outer checksum the
  upstream's signed index vouched for, recorded on the cache plane, scanned and gated before
  a byte is served. The block gate's release-age and deprecation arms decide upstream-only
  releases at index time from the publish timestamp and retirement state the Hex index
  carries; the advisories this registry knows about are projected into the index's native
  `SecurityAdvisory` entries. Requires `DEPENDABLY_MASTER_KEY`, which protects the org's
  signing key at rest. Per-org upload cap `max_upload_bytes_hex`; upstream rows carry a
  `public_key_pem`, pre-filled for hex.pm.

- **Hex API plane, operator surfaces and policy.** `/hex/api/` is what `mix hex.publish`,
  `rebar3 hex publish` and `mix hex.retire` talk to: publish a tarball (its `metadata.config`
  must name the addressed package; the release then appears in the signed index and serves
  from the hosted plane), retire and unretire (recorded on the index entry and, as a
  deprecation, on the version so the deprecated block arm applies), upload and remove
  documentation, revert a release, and `users/me`. Replies are Erlang terms when the client
  asks for them — hex_core has no JSON decoder. Settings → Signatures shows the org's Hex
  signing key with its fingerprint and a rotate action; a Hex upstream row accepts the
  repository's PEM public key. `/hex/repos/dependably/policies/dependably` projects the org's
  block-gate posture — advisory severity ceiling, retirement reasons, release-age cooldown
  and a `DENY` override per blocklisted held package — as a signed Hex policy that opted-in
  clients enforce before resolution. New capabilities `publish:hex` and `yank:hex`.

- **CycloneDX 1.7 on ingest and export.** Uploaded documents are accepted across CycloneDX
  1.4–1.7, and the two fields 1.7 adds are recorded and displayed: `components[].versionRange`,
  which 1.7 admits in place of a concrete version, and `components[].isExternal`. Both are
  nullable — NULL means the document did not say, which every document below 1.7 is, and absence
  is a weaker claim than a declared `false`. A document declaring a version outside 1.4–1.7 is
  refused with a validation error naming the version it declared.

- **Dev-dependency scope seeded from a CycloneDX manifest.** A component the manifest marks as a
  dev dependency (the CycloneDX property taxonomy's dev-declaration) now seeds
  `dependency_scope`, so a dev dependency is classified as one before any reachability scan has
  run. It is a fill, not an override: once the reachability scanner has asserted `dev` or
  `runtime`, the manifest declaration no longer touches the column.

### Fixed

- **A Cargo publish whose `.crate` disagrees with the frame is refused.** The archive's embedded
  `Cargo.toml` is cross-checked against the publish frame on `name`, `version` and the archive's
  root directory — the way npm cross-checks `package.json` and PyPI cross-checks `METADATA`.
  The frame's name and version are what this registry records, scans and builds SBOMs from,
  while the archive is what `cargo build` actually compiles; a mismatch between them is now a
  `422` instead of a stored crate whose recorded identity is not the one it compiles as. (#642)

- **Both Risk tables are sortable.** The licence table's sortable columns now match the keys the
  endpoint accepts, as do the analysis table's. (#653)

- **SBOM ingest fixes.** A batch's VEX and SARIF are skipped when its SBOM was rejected rather
  than applied to a document that never landed; SARIF retraction no longer wipes the manifest
  `dependency_scope` fill; the project picker presets correctly for a project inside a folder;
  and the upload modal no longer overflows its outcome table.

- **Setup copy** says explicitly that the Basic-auth username is ignored.

## [0.8.1] - 2026-08-30

### Added

- **Copyable install commands on the package surfaces.** Every package and version row renders the
  command a developer actually needs — `npm install`, `pip install`, `dotnet add package`, the Maven
  coordinate block, `go get`, `cargo add`, `docker pull` — already pointed at this instance rather
  than at the public registry, with the org's host substituted in. One click copies it.

- **Component metadata from uploaded SBOMs is captured and displayed.** Author, publisher,
  description, and supplier were already carried in the CycloneDX documents both planes ingest and
  were being discarded on parse. They are now extracted with an explicit precedence order, stored,
  and shown on the component panel beside the advisory and licence facts.

- **`background_job_runs` is bounded by a retention sweep.** Nothing previously deleted from that
  table while its loudest writer ran on a 60-second timer. `JOB_RUN_RETENTION_DAYS` (default `14`)
  bounds successful runs and `JOB_RUN_FAILURE_RETENTION_DAYS` (default `90`) bounds everything else
  — longer on purpose, because a failed or cancelled run is the forensic record an operator goes
  looking for and there are few of them. The latest run per job, and the latest success per job, are
  kept regardless of age so `/health` can always report a job's last outcome. There is no value that
  disables the sweep.

### Changed

- **Setup is a guided connect flow.** The page walks through choosing an ecosystem, minting a token,
  and pointing a client at the instance, instead of presenting the whole surface at once. The
  explanatory prose was cut and the step badges now match the rest of the design system.

- **The dashboard leads with what it prevented.** The panel order was reworked and the prevention
  gates now render unconditionally — previously a gate with nothing to report was hidden, which made
  an inactive gate and an unconfigured one look identical.

### Removed

- **The package-note feature is retired**, in full: the `/api/v1` endpoints, the notes section on
  the package page, and the `package_note` table, which is dropped on boot from every database that
  still carries one.

  **Action required:** if you called the package-note endpoints, they are gone as of this release and
  any content stored in them is deleted by the drop. Export anything you need before upgrading. The
  drop carries a `backcompat-ok` waiver and runs on every boot rather than once, because the
  preceding release still declares the table additively and a one-shot drop would read as done while
  the live schema silently diverged.

### Fixed

- **The backend SBOM shipped a `0.0.0` root component version** instead of the version actually
  built, so every published SBOM described an artefact that matched no release.

- **A schema migration verified `CHECK` rewrites with a full-database integrity scan**, which turned
  a cheap sanity check into minutes of boot time on a large database while the boot path held no
  lock. The verification is now scoped to the rewritten table.

## [0.8.0] - 2026-08-26

### Added

- **A projects plane: SBOM, VEX and SARIF ingest, organized in folders.** Dependably now holds
  the inventory of what your own software is built from, beside the registry that serves the
  artefacts. Upload a CycloneDX SBOM, an OpenVEX document, or a SARIF report (`cyclonedx-json`,
  `openvex-json`, `sarif-json`) against a project; organize projects into folders that roll up their
  whole subtree; relocate rows, navigate by breadcrumb, and export one SBOM for an entire folder.

  Components are cross-linked with the registry plane sitting beside them, so a component in an
  uploaded SBOM resolves to the package version this instance already knows about — its advisories,
  its licence, its block state — rather than being a name in a document. Uploaded documents are
  retained under an explicit project retention policy, and superseded document blobs are reclaimed
  by a bounded nightly sweep.

- **An instance-level connection to a vulnerability tracker, with enrichment overlay.** Configured
  once per deployment from Settings, the connection enriches scanned advisories with signals OSV
  does not carry: SSVC exploitation state, an NVD score fallback, CISA ransomware-campaign use,
  EPSS percentile, and dependency-graph reach. Requests are deduplicated before they leave, batched,
  and the client **cannot report an outage as clean** — an unreachable tracker defers, it does not
  record a negative.

  Operators can test the connection instead of waiting for a scan, and connection health renders
  next to the config editor. Tenants see their own enrichment coverage; instance-wide coverage
  lives on the apex dashboard.

- **Two new block-gate arms, both default off.** `block_ssvc_exploitation` gates on SSVC
  exploitation state; ransomware-campaign use and EPSS percentile each gate independently of the
  CVSS band. The NVD score deliberately gets **no** arm of its own — it feeds the existing
  `max_osv_score_tolerance` ceiling as a fallback, closing a fail-open where an OSV advisory
  carrying no severity passed the ceiling silently whatever the tenant had set.

- **An enrichment staleness horizon.** Enrichment older than the horizon refuses under `block`;
  never-enriched is inert. Those are two different facts, not two degrees of one.

- **A subscribable gate-refusal webhook event**, with per-`(org, purl, arm)` burst coalescing so a
  CI job retrying a blocked dependency produces one notification, not hundreds.

- **Append-only daily org stats history**, with bounded retention and trend rendering on the
  dashboard.

- **A durable first-seen timestamp for findings** on both the registry and projects planes, so
  "how long has this been here" is answerable after a rescan.

- **KEV surfacing throughout the UI** — a KEV-blocked stat tile on the dashboard, KEV status on the
  Packages list, a KEV chip on the Projects list, KEV/EPSS on the version-drilldown rows, and a
  distinct badge for KEV advisories tied to a ransomware campaign. Advisories link out to OSV.dev
  and NVD, and to this instance's own assessment; vulnerabilities are searchable globally.

- **Risk-ordering in the UI** surfaces coverage, prevention, override age, and KEV/EPSS-first
  ordering.

### Fixed

- **RPM artefacts were stamped scanned-clean without ever being screened — on both advisory-source
  paths.** `pkg:rpm` purls carried no distro namespace, so an OSV query for them was structurally
  unresolvable: OSV.dev answers it empty, and a sideloaded local dump (whose RPM advisories are
  filed under `Rocky Linux` / `AlmaLinux` / `Red Hat`) matches nothing. Because RPM is not in the
  no-feed set, that empty result was not reported as `no_feed` — the artefact was stamped
  `vuln_checked_at` and rendered as *scanned, nothing found*.

  `vuln_checked_at` is the flag that **enables** the malicious, KEV, EPSS and CVSS block arms, so
  every RPM package in the catalogue armed all four over a structurally empty advisory set. Remote
  purls now carry a distro namespace and **fail closed when none resolves**; local mode reports
  no-feed instead of stamping.

  **Action required:** every RPM artefact scanned on 0.7.1 or earlier carries a
  `vuln_checked_at` stamp that means nothing. Clear it and rescan — until you do, those artefacts
  read as screened when they were not.

- **CVSS v4.0 vectors were unparsed, so the score-driven block arm was inert for them** — 21% of
  npm and 19% of crates.io advisories carry a v4-only vector. `OsvScoring` accepted `CVSS:3.` and
  returned null for everything else, which left `max_osv_score_tolerance` with nothing to compare.
  v4.0 base scores now parse, and where an advisory carries several severity entries the
  best-parseable one is selected.

  **Action required:** advisories that scored as unscored on 0.7.1 may now exceed your configured
  `max_osv_score_tolerance` and start refusing. Review the ceiling before upgrading if you set it
  tightly.

- **A vulnerability alert is no longer gated on the CVSS band**, so a KEV-listed advisory with no
  parseable score raises one. Expect more alerts on the same catalogue.

- **`warn` mode recorded nothing.** The block gate's `warn` disposition now records the
  would-have-blocked decision, which is the entire point of running it before `block`.

- **`kev_ransomware` and `epss_percentile` refused artefacts invisibly** — neither had a case in the
  gate's side-effect handling, so a refusal produced no activity row. A compliance gate now pins
  that every arm has one.

- **Security hardening across the request surface.** Control characters are rejected in package
  coordinates; `?` and `#` are rejected in an upstream proxy path segment; ZIP entry count and
  central-directory span are bounded; `LIKE` metacharacters are escaped in every parameterized
  search; a duplicated tenant header is refused rather than resolved to the first value; an absent
  `tid` claim is refused in `RouteScopeFilter`; the two remaining `X-Dependably-PURL` header writes
  are sanitized; security headers are preserved across every refusal response; and every
  SSRF-guarded HTTP handler bypasses the ambient proxy.

- **Tenant suspension is a full lockout**, enforced at one seam rather than per-surface, and
  background jobs stop for a non-active tenant. The subdomain resolver is registered Singleton so
  invalidation can cancel a racing cache fill.

- **`NOT IN @list` failed on Postgres** with a `42601` syntax error — array-binding after `IN` is
  not valid Npgsql. Those sites now expand through `DapperInClause`.

- **The PyPI simple-index cache key had no proxy/local discriminator**, so the two planes could
  serve each other's index.

- **Alert `email_status` is reconciled from the authoritative outbox row** rather than drifting from
  it, and a SQLite `PRAGMA` command's lifetime is bound to its scope.

- **Cache generations are retired on throw**, closing an async post-eviction race.

- Malicious advisories escalate to Act priority on the SBOM plane; legacy duplicate analysis rows
  are reconciled; `vuln_key` case is folded in every analysis conflict target; unscannable
  components are surfaced rather than silently omitted; and two zero-latest holes are closed.

### Changed

- **English defaults to en-CA**, and fr-CA typography is enforced. `licence` is the noun in UI
  prose; the CISA Known Exploited Vulnerabilities Catalog is named properly.

- **The vulnerability facts vocabulary and priority taxonomy are unified across both planes**, so
  the answer to "which finding is worse" no longer depends on which plane you ask. The two
  evaluators stay deliberately separate — the gate returns the first arm that fires because it must
  produce one verdict, the inventory evaluator returns every arm that fires because the point is
  review.

- **The `docs/` tree is retired** and every reference repointed. Operator documentation now lives in
  the dedicated docs repository.

- **Token presets grant `read:packages` on the pull and both presets**, and the raw capability list
  is hidden for tokens whose capabilities match a preset exactly.

- Every export producer emits full signal coverage plus coverage/freshness metadata, so an export
  states what it could and could not see.

- The SBOM component table's identity columns are restructured; the Upload action moves right-most
  on the version-detail toolbar; empty Trends and Prevention render as status lines rather than
  placeholders; and enrichment coverage moves from the org dashboard to apex.

- RPM repodata SQL pre-filters the two unconditional gate arms.

- The Docker image reads its version from MSBuild rather than a drift-prone `VERSION` build-arg.

## [0.7.1] - 2026-08-19

### Fixed

- **`maven-metadata.xml` returned 404 for any artifactId containing a digit.** `commons-lang3`,
  `log4j-core`, `slf4j-api`, `h2`, `junit-jupiter-api` and every other artifactId carrying a
  version-ish suffix were affected. The path parser classified any segment containing a digit as a
  *version*, so `org/apache/commons/commons-lang3/maven-metadata.xml` resolved to a coordinate that
  does not exist.

  This is the document Maven resolves version **ranges** and the `LATEST`/`RELEASE` markers
  through, so those dependencies could not be resolved at all — while pinned exact versions kept
  downloading, which made the failure look coordinate-specific rather than systematic. The
  `.sha1`/`.md5` sidecars resolved through the same parse and were equally unreachable.

  **No action required.** Upgrading fixes affected coordinates immediately; nothing to reconfigure.

- **Version listings no longer advertise versions the download path refuses.** Every listing
  surface — the PyPI simple index, npm packument, NuGet registration, `maven-metadata.xml`, RPM
  repodata, the Cargo sparse index, Go `@v/list` and `@latest`, and the Terraform version index —
  now applies the same block gate the artifact route does.

  Previously a blocked, revoked, malicious or too-new version was listed and then refused with a
  bare 403. Package managers do not backtrack on an HTTP error once they have resolved to a
  version, so a hold meant to keep developers on the last known-good release instead broke the
  build. A cooldown (`min_release_age_hours`) is now invisible to a developer, which is what it was
  always meant to be.

  Where a listing genuinely cannot decide — an upstream version nobody has fetched, Alpine `apk`'s
  signature-verified index, OCI's mutable tag list — enforcement remains at first fetch, and each
  exception is recorded and enforced by a compliance gate.

- **A manual block on a Go module version was accepted and never enforced.** The `.zip` download
  gate read only the global cache plane and allowed anything with no row there, so a block written
  to `package_versions` — the plane the management API uses whenever such a row exists — was shown
  as applied while the artifact kept being served.

  **Action:** if you blocked a Go module version on 0.7.0 or earlier, re-check that it is actually
  refused now.

- **`cargo search` reported a `max_version` the download refuses**, and Go's `@latest` named blocked
  versions. Both now skip withheld versions; `@latest` falls back to the newest servable one.

- **RPM repodata caches ignored proxy-settings changes.** Neither repodata cache was bound to the
  org policy epoch, so a policy change did not evict them. They now expire like every other
  ecosystem's rendered metadata.

- **npm bulk audit refused large dependency trees** instead of chunking the upstream request.

- **The retention settings page misreported what governs retention.**

- **Generated token secrets are now alphanumeric**, so they can be stored as masked CI variables.

### Added

- **A refusal now says which policy arm produced it.** Policy denials carry an
  `X-Dependably-Block-Reason` response header naming the arm (`release_age`, `malicious`, `manual`,
  …). A 403 **without** the header is not a policy decision — it is an authentication or
  authorization failure, so the two are now distinguishable without reading the activity feed.

  Only the arm name is disclosed; configured thresholds and advisory ids stay out of the response,
  because an error body travels further than the request did. New operator guide:
  `docs/diagnosing-a-blocked-package.md`.

- **A conditional disposition for licence policy**, with policy and package notes.

### Changed

- **Proxy-cache eviction is now opt-in.** `CacheEvictionService` previously applied an implicit
  30-day age cap when none of `CACHE_MAX_AGE_DAYS` / `CACHE_MAX_SIZE_BYTES` /
  `CACHE_MAX_ARTIFACTS` was set, so a default installation expired proxy artefacts on a schedule
  its operator never chose — overriding a per-org `keep_versions` retention decision made somewhere
  that never mentions caching.

  **Action required if you relied on the implicit cap.** Eviction now does nothing unless one of
  those three variables is set; set one explicitly to keep the previous behaviour. A one-shot
  `delete_empty_package_rows` pass clears the "0 versions" package rows the old default left behind.

### Removed

- **The retired per-org SMTP transport columns on `alert_settings` are dropped**

  (`email_inherit_instance`, `email_smtp_host`, `email_smtp_port`, `email_smtp_security`,
  `email_smtp_username`, `email_smtp_password`, `email_smtp_from`). SMTP is an instance-level
  transport; an org owns whether alert mail is sent and to whom, never how it is carried. Their
  readers were removed in 0.6.0 and their values scrubbed in 0.7.0; this is the contract step. The
  drop runs on every boot rather than once, so a database an older slot re-populated converges back
  on the next start.

  No action is needed upgrading from 0.6.x or 0.7.x — neither reads these columns. An operator
  running a **blue-green cutover directly from 0.5.x or earlier** should stop the old slot first:
  left serving, its alert-settings read fails until it restarts (the Alerts page and alert-email
  delivery; it self-repairs on restart, and no data is lost). Upgrading via 0.6.x or 0.7.x avoids
  this entirely.

  The stored credential was already cleared in 0.7.0, so nothing readable remains. Note the drop
  reclaims no pages on either provider: ciphertext written before 0.7.0 can survive in SQLite
  freelist pages or Postgres dead tuples until that space is reused. `VACUUM` reclaims it. If a
  per-org SMTP credential was ever configured on this database and may have been exposed, rotate it
  at the relay provider — that, not the drop, is the step that matters.

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
