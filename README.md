# Dependably

Self-hosted private artifact repository for **npm**, **PyPI**, and **NuGet**.

Every package your team pulls from the internet is a supply chain risk. Dependably sits between your developers and the public registries, caching what they pull, verifying checksums, blocking packages that don't belong, and giving you a full audit trail — without requiring a cloud account or a per-seat licence.

---

## Features

- **Proxy cache** — pull-through cache for npm, PyPI, and NuGet; verified by SHA-256 before storage, served locally on every subsequent request
- **Supply chain tracking** — first-fetch detection, per-version checksum verification, CycloneDX 1.5 SBOM generation
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

All registry URLs follow the pattern `/o/{org-slug}/{ecosystem}/`. The short aliases `/simple/`, `/npm/`, and `/nuget/` redirect to the default org.

Generate a CI/CD token or user token from the web UI, then point your tools at Dependably.

> **More setup recipes:** see [`skills/`](skills/README.md) for copy-pasteable
> project-level *and* global config recipes for npm, PyPI (pip / Poetry / uv),
> and NuGet — including the gotchas for plain-HTTP self-hosted deployments.

### pip / pip.conf

```ini
[global]
index-url = https://user:<token>@dependably.example.com/o/my-org/simple/
```

Publishing with twine:

```bash
twine upload \
  --repository-url https://dependably.example.com/o/my-org/pypi/legacy/ \
  -u user -p <token> \
  dist/*
```

### npm / .npmrc

```ini
registry=https://dependably.example.com/o/my-org/npm/
//dependably.example.com/o/my-org/npm/:_authToken=<token>
```

```bash
npm publish --registry https://dependably.example.com/o/my-org/npm/
```

### NuGet / nuget.config

```xml
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <add key="dependably" value="https://dependably.example.com/o/my-org/nuget/v3/index.json" />
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
  --source https://dependably.example.com/o/my-org/nuget/v3/index.json \
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

- [Architecture overview](docs/architecture/overview.md) — multitenant storage, database, request routing, deployment shapes
- [Cross-cutting decisions](docs/architecture/cross-cutting-decisions.md) — async hygiene, isolation strategy, retention, schema conventions, audit invariants

## API

- [API surface](docs/api-surface.md) — full listing of every HTTP route, generated from controller route attributes (CI-guarded)

## Deployment

- [High-availability](docs/deployment/ha.md) — multi-replica topologies, SQLite vs Postgres trade-offs, per-write-path leader requirements
- [Transparent intercept](docs/deployment/transparent-intercept.md) — pretending to be `registry.npmjs.org`/`pypi.org`/`api.nuget.org` so stock clients pass through Dependably without config changes

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for build instructions, environment variable reference, architecture notes, and the security model.

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

---

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
