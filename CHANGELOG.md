# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Go module proxy** — GOPROXY protocol surface at `/go/`. Implements `@v/list`, `.info`, `.mod`, `.zip`, and `@latest` routes with bang-encoding decode at the route boundary and re-encode on upstream URL construction. All requests go through the proxy cache-miss path; `.zip` fetches record a `package_versions` row in the catalogue. Proxy-only in this release (no hosted push path).
- **Cargo sparse registry** — sparse index protocol at `/cargo/`. Serves `config.json`, sparse index files (per-name path layout), and crate downloads at `api/v1/crates/{name}/{version}/download`. Local versions shadow upstream on collision; crate downloads are cached in the blob store on first fetch. OSV vulnerability scanning and PURL normalization (`pkg:cargo/{name}@{version}`) are included.
- **Staging-disk guardrails** — `StagingDiskMonitor` samples staging volume free space every 60 s and emits OTel gauges and a Serilog `Warning` when free space falls below `STAGING_DISK_WARN_THRESHOLD_PERCENT` (default 10 %). Proxy fetches are rejected with 507 Insufficient Storage when available bytes fall below `STAGING_DISK_FLOOR_BYTES` (default 512 MiB); when `Content-Length` is present the effective floor is `max(STAGING_DISK_FLOOR_BYTES, 2 × Content-Length)`.
