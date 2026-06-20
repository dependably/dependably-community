# Dependably client-config skills

Copy-pasteable recipes that point a package manager at a self-hosted dependably
instance. Pick the cell in the table that matches your ecosystem and scope.

| Ecosystem | Project-level (checked into the repo) | Global / user-level (per-machine)             |
|-----------|----------------------------------------|------------------------------------------------|
| **npm**   | [npm-configure-project](./npm-configure-project/SKILL.md)   | [npm-configure-global](./npm-configure-global/SKILL.md)   |
| **PyPI**  | [pypi-configure-project](./pypi-configure-project/SKILL.md) | [pypi-configure-global](./pypi-configure-global/SKILL.md) |
| **NuGet** | [nuget-configure-project](./nuget-configure-project/SKILL.md) | [nuget-configure-global](./nuget-configure-global/SKILL.md) |

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
