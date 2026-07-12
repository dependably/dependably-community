# Dependably client-config skills

Copy-pasteable recipes that point a package manager at a self-hosted dependably
instance. Pick the cell in the table that matches your ecosystem and scope.

| Ecosystem | Project-level (checked into the repo) | Global / user-level (per-machine)             |
|-----------|----------------------------------------|------------------------------------------------|
| **npm**   | [npm-configure-project](./npm-configure-project/SKILL.md)   | [npm-configure-global](./npm-configure-global/SKILL.md)   |
| **PyPI**  | [pypi-configure-project](./pypi-configure-project/SKILL.md) | [pypi-configure-global](./pypi-configure-global/SKILL.md) |
| **NuGet** | [nuget-configure-project](./nuget-configure-project/SKILL.md) | [nuget-configure-global](./nuget-configure-global/SKILL.md) |
| **Maven** | [maven-configure-project](./maven-configure-project/SKILL.md) | [maven-configure-global](./maven-configure-global/SKILL.md) |
| **Go**    | [go-configure-project](./go-configure-project/SKILL.md)     | [go-configure-global](./go-configure-global/SKILL.md)     |
| **Cargo** | [cargo-configure-project](./cargo-configure-project/SKILL.md) | [cargo-configure-global](./cargo-configure-global/SKILL.md) |
| **Docker / OCI** | — (host-level login, no project scope) | [docker-configure-global](./docker-configure-global/SKILL.md) |

Each skill prompts for two inputs, in order:

1. **Dependably base URL** — the base URL of your dependably org, e.g.
   `https://repo.example.com` or `http://192.168.1.50:8080`. Registry paths are
   ecosystem-only (`/npm/`, `/simple/`, `/nuget/v3/index.json`); the org is
   resolved from the host, not a URL path segment. Single-tenant deployments use
   the bare host; multi-tenant deployments put the org in the subdomain
   (`https://acme.repo.example.com`).
2. **Token** — created in the dependably web UI under **Tokens** (user token) or
   **Settings → Service tokens** (long-lived non-personal token).

> **Plain HTTP gotcha.** Self-hosted dependably is commonly served over plain
> HTTP on a LAN. Most package managers refuse plaintext registries by default.
> Each skill calls out the per-tool flag (`strict-ssl=false`, `trusted-host`,
> `allowInsecureConnections`) needed to make this work.

> **Never commit tokens.** Project-level files are checked into source control.
> Each skill shows how to reference an environment variable instead of pasting
> the literal value. The variable name differs by ecosystem on purpose: the npm
> skills use `${NPM_TOKEN}` (npm's own convention); the PyPI and NuGet skills
> use `${DEPENDABLY_TOKEN}`.

## See also

- [Configuring package managers](../README.md#configuring-package-managers) in the top-level README.
- The in-app **Setup** page generates the same snippets pre-filled for the
  current org. Skills are useful when you want a deeper recipe (Poetry, uv,
  global config, etc.) than the one-snippet Setup page covers.

## Remediation skills

`skills/remediation/` is a separate set: curated recipes for **fixing** a
vulnerability the dependably vuln report surfaced, not for configuring a
client. The Vulnerabilities detail panel links each finding to the
applicable skill(s) below and gives a one-liner to install one into
`~/.claude/skills/`; they are also served directly from a running instance
at `GET /api/v1/remediation/skills/{id}` (anonymous, so the install
one-liner works air-gapped, without a token).

| Skill | Covers |
|-------|--------|
| [fix-vulnerable-dependency](./remediation/fix-vulnerable-dependency/SKILL.md) | Upgrading a vulnerable npm/PyPI/NuGet/Maven/Go/Cargo/RPM/OCI dependency to its fixed version, lockfile-aware, with transitive-override recipes. Applies to any advisory with a fixed version. |
| [fix-injection](./remediation/fix-injection/SKILL.md) | SQL, OS command, LDAP, XPath, and code/template injection (CWE-20/77/78/89/90/91/94/95/... — OWASP A05:2025 Injection). |
| [fix-xss](./remediation/fix-xss/SKILL.md) | Cross-Site Scripting (CWE-79/80/83/86 — OWASP A05:2025 Injection). |
| [fix-path-traversal](./remediation/fix-path-traversal/SKILL.md) | Path/directory traversal and symlink following (CWE-22/23/36/59/61/65/73 — OWASP A01:2025 Broken Access Control). |
| [fix-unsafe-deserialization](./remediation/fix-unsafe-deserialization/SKILL.md) | Unsafe deserialization and mass assignment (CWE-502/915 — OWASP A08:2025 Software or Data Integrity Failures). |
| [fix-ssrf](./remediation/fix-ssrf/SKILL.md) | Server-Side Request Forgery (CWE-918/441 — OWASP A01:2025 Broken Access Control). |
