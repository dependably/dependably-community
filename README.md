# Dependably

Self-hosted private artifact repository for **npm**, **PyPI**, **NuGet**, **Maven**, **RPM**, and **OCI** images.

Every package your team pulls from the internet is a supply chain risk. Dependably sits between your developers and the public registries, caching what they pull, verifying checksums, blocking packages that don't belong, and giving you a full audit trail — without requiring a cloud account or a per-seat licence.

---

## Features

- **Proxy cache** — pull-through cache for npm, PyPI, NuGet, Maven, RPM, and OCI; verified by SHA-256 before storage, served locally on every subsequent request
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

---

## Health probes

```
GET /health             → 200 OK (process is running)
GET /ready              → 200 OK when database is reachable, 503 otherwise
GET /api/v1/licenses    → third-party attribution data (CycloneDX subset)
```

---

## Architecture

- [DESIGN.md](DESIGN.md) — product and UI design system, layout, and visual language
- [CLAUDE.md](CLAUDE.md) — project structure, key architectural rules and invariants, tech stack
- [CONTRIBUTING.md](CONTRIBUTING.md) — build instructions, environment variable reference, security model

## API

Both API surfaces are documented as live OpenAPI documents served by the running instance:

- `/docs/` — protocol surfaces (PyPI `/simple/`, npm, NuGet v3, Maven, RPM, OCI `/v2/`); spec at `/openapi/protocol.json`
- `/api/v1/docs/` — management API; spec at `/openapi/management.json`

The full route surface is contract-tested against [`tests/Contracts/openapi.contract.json`](tests/Contracts/openapi.contract.json) — any route change fails CI until the contract is regenerated.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for build instructions, environment variable reference, architecture notes, and the security model.

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

---

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
