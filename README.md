# Dependably

Self-hosted private artifact repository for **npm**, **PyPI**, **NuGet**, **Maven**, **RPM**, **OCI** images, **Go** modules, **Cargo** crates, **Alpine (apk)** packages, and **Terraform** providers.

Every package your team pulls from the internet is a supply chain risk. Dependably sits between your developers and the public registries, caching what they pull, verifying checksums, blocking packages that don't belong, and giving you a full audit trail — without requiring a cloud account or a per-seat licence.

---

## Features

- **Proxy cache** — pull-through cache for npm, PyPI, NuGet, Maven, RPM, OCI, Go, Cargo, Alpine apk, and Terraform providers; verified by SHA-256 before storage, served locally on every subsequent request. Go, apk, and Terraform are proxy-only (no hosted push).
- **NuGet symbol server** — `.snupkg` symbol packages are indexed by debug-id and served over SSQP, so Visual Studio and `dotnet-symbol` resolve PDBs straight from your registry. A distinct capability from storing `.snupkg` files: Portable PDBs only, and source files are not served.
- **Supply chain tracking** — first-fetch detection, per-version checksum verification, CycloneDX 1.6 SBOM generation
- **Allowlisting** — per-org PURL pattern allowlists to restrict which packages can be fetched or pushed
- **Multitenancy** — multiple orgs, scoped tokens, role-based access, full org isolation
- **Retention policies** — configurable keep-versions and keep-days per org
- **Single binary** — self-contained Alpine Docker image; SQLite metadata; local, S3, or Azure blob storage

---

## Quick start

```bash
docker run -d \
  --name dependably \
  -p 8080:8080 \
  -v dependably-data:/data \
  -e BASE_URL=http://localhost:8080 \
  ghcr.io/dependably/dependably:latest
```

On first boot, Dependably prints the admin credentials to stdout:

```
============================================================
  DEPENDABLY FIRST BOOT — SAVE THESE CREDENTIALS
============================================================
  Email   : admin@dependably.local
  Password: <generated>
============================================================
```

Log in at `http://localhost:8080` to change the password and create your first org.

---

## docker-compose

```yaml
services:
  dependably:
    image: ghcr.io/dependably/dependably:latest
    ports:
      - "8080:8080"
    volumes:
      - dependably-data:/data
    environment:
      BASE_URL: https://dependably.example.com
      DEFAULT_ORG_SLUG: default

volumes:
  dependably-data:
```

---

## Configuring package managers

Tenancy is host-resolved, not path-resolved. The registry URL shape depends on your deployment mode:

- **Single-tenant** (`DEPLOYMENT_MODE=single`, the default): the bare host serves the one org.
  `https://dependably.example.com/simple/`, `/npm/`, `/nuget/v3/index.json`, etc.
- **Multi-tenant** (`DEPLOYMENT_MODE=multi`): each org is a subdomain of the apex host.
  `https://my-org.dependably.example.com/simple/`, `/npm/`, `/nuget/v3/index.json`, etc.

The examples below use the single-tenant form. For multi-tenant, replace `dependably.example.com`
with `my-org.dependably.example.com` (the ecosystem path stays the same).

Generate a service token or user token from the web UI, then point your tools at Dependably.

> **More setup recipes:** see [`skills/`](skills/README.md) for copy-pasteable
> project-level *and* global config recipes for npm, PyPI (pip / Poetry / uv),
> and NuGet — including the gotchas for plain-HTTP self-hosted deployments.

### pip / pip.conf

```ini
[global]
index-url = https://user:<token>@dependably.example.com/simple/
```

Publishing with twine:

```bash
twine upload \
  --repository-url https://dependably.example.com/pypi/legacy/ \
  -u user -p <token> \
  dist/*
```

### npm / .npmrc

```ini
registry=https://dependably.example.com/npm/
//dependably.example.com/npm/:_authToken=<token>
```

```bash
npm publish --registry https://dependably.example.com/npm/
```

Verify connectivity and credentials before installing anything:

```bash
npm ping     # exits 0 when Dependably is reachable
npm whoami   # prints the token owner's email (or `service:<name>` for service tokens)
```

### NuGet / nuget.config

```xml
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <add key="dependably" value="https://dependably.example.com/nuget/v3/index.json" />
  </packageSources>
  <packageSourceCredentials>
    <dependably>
      <add key="Username" value="user" />
      <add key="ClearTextPassword" value="<token>" />
    </dependably>
  </packageSourceCredentials>
</configuration>
```

```bash
dotnet nuget push MyPackage.1.0.0.nupkg \
  --source https://dependably.example.com/nuget/v3/index.json \
  --api-key <token>
```

A `.snupkg` pushed alongside a package (`dotnet nuget push MyPackage.1.0.0.snupkg ...`, same
source/API key) is indexed automatically: every Portable PDB it contains becomes fetchable by
debug-id over the [Simple Symbol Query Protocol](https://github.com/dotnet/symstore/blob/main/docs/specs/Simple_Symbol_Query_Protocol.md)
at `https://dependably.example.com/nuget/symbols`. Add that URL as a symbol source in Visual
Studio (**Options → Debugging → Symbols → Symbol file (.pdb) locations**) or point
[`dotnet-symbol`](https://github.com/dotnet/symstore) at it to download PDBs for a built assembly:

```bash
dotnet symbol --symbols --microsoft-symbol-server \
  --server-path https://dependably.example.com/nuget/symbols \
  MyApp.dll
```

Symbol reads follow the same auth posture as every other NuGet read: a token is required unless
the org has AnonymousPull enabled, and a version you have blocked or revoked serves no symbols.

**Uploading instead of pushing.** A `.snupkg` can also be added from the admin **Upload** page
(drag-and-drop) or by posting it to `/api/v1/admin/upload`, alongside its `.nupkg` or on its own —
useful for backfilling symbols from an artifact archive. Its Portable PDBs are indexed exactly as on
push, and the two files land as siblings of one version, each listed and downloadable separately.

Keep the **`.snupkg` extension**: it is what identifies the archive as a symbol package. Renamed to
`.nupkg` it is validated as a regular package and rejected, because a symbol manifest omits fields
(`authors`, `description`) that a package manifest must declare.

**Scope limits.** These match what nuget.org's own symbol server supports, so a package that
resolves there resolves here:

- **Portable PDBs only.** A `.snupkg` containing native/Windows PDBs is accepted and stays
  downloadable, but those PDBs are skipped by the indexer and never resolve by debug-id. The push
  still returns 201 — check the indexed-PDB count on the version to confirm what was indexed.
- **`.snupkg` only.** The legacy `.symbols.nupkg` format is not accepted as a symbol package.
- **No source-file serving.** SSQP also defines source retrieval; only the PDB path is
  implemented, so stepping into code requires your debugger to resolve sources another way
  (Source Link against your own source host, for example).

---

## Health probes

```
GET /health             → 200 OK (process is running)
GET /ready              → 200 OK while every required dependency is reachable, 503 otherwise
GET /ready?strict=true  → 200 OK only when every dependency is reachable
GET /api/v1/licenses    → third-party attribution data (CycloneDX subset)
```

`/ready` is the load-balancer check: it fails only on a *required* dependency (the metadata
store; also the blob store on an edge node) so a failure of a dependency shared by the whole
fleet is reported as degradation rather than deregistering every replica at once. It also turns
503 during graceful shutdown, so it carries the drain signal `/health` does not. The strict view
demands everything green and is what deployment gating and alerting should poll. Classification
is configurable — see
[CONTRIBUTING.md → Health probes](CONTRIBUTING.md#health-probes-health-ready).

---

## Architecture

- [DESIGN.md](DESIGN.md) — product and UI design system, layout, and visual language
- [CLAUDE.md](CLAUDE.md) — project structure, key architectural rules and invariants, tech stack
- [CONTRIBUTING.md](CONTRIBUTING.md) — build instructions, environment variable reference, security model

## API

Both API surfaces are documented as live OpenAPI documents served by the running instance:

- `/docs/` — protocol surfaces (PyPI `/simple/`, npm, NuGet v3, Maven, RPM, OCI `/v2/`, Go `/go/`, Cargo `/cargo/`, apk `/apk/`, Terraform `/terraform/`); spec at `/openapi/protocol.json`
- `/api/v1/docs/` — management API; spec at `/openapi/management.json`

The full route surface is contract-tested against [`tests/Contracts/openapi.contract.json`](tests/Contracts/openapi.contract.json) — any route change fails CI until the contract is regenerated.

Per-ecosystem client guides, where a protocol's behaviour differs from the public registry it
mirrors:

- [docs/terraform.md](docs/terraform.md) — Terraform provider mirror: `.terraformrc` setup, why it
  is a network mirror rather than a registry, and what it does not cover (modules)
- [docs/cargo.md](docs/cargo.md) — Cargo sparse registry: config, publish, yank, and why crate
  ownership is org membership rather than `cargo owner`

For the developer-facing remediation walkthrough — reading the vulnerability report (CVSS/EPSS/KEV), the OWASP Top 10 mapping, and the curated fix skills for Claude Code / OpenAI Codex / GitHub Copilot — see [docs/fixing-vulnerabilities.md](docs/fixing-vulnerabilities.md).

Operator runbooks:

- [docs/edge-node.md](docs/edge-node.md) — enrolling and running a cache-only edge node
- [docs/sqlite-to-postgres-migration.md](docs/sqlite-to-postgres-migration.md) — moving an existing
  standalone (SQLite) install onto Postgres for high availability, with verification and rollback
- [docs/postgres-collate-migration.md](docs/postgres-collate-migration.md) — opting an existing
  Postgres database into `COLLATE "C"` on its indexed temporal columns, for byte-exact ordering and
  immunity to glibc collation-version drift

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for build instructions, environment variable reference, architecture notes, and the security model.

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

---

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
