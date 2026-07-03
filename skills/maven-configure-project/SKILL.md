---
name: maven-configure-project
description: Point Maven at a dependably org for a single project via pom.xml
ecosystem: maven
scope: project
inputs:
  - DEPENDABLY_BASE_URL
  - DEPENDABLY_TOKEN
---

## When to use this

You want a specific Maven project to resolve and deploy through your dependably
instance, so anyone who clones it inherits the repository without editing global
settings. Maven has **no project-level credential store**, so the repository URL
goes in the committed `pom.xml` while the token stays in each developer's
`~/.m2/settings.xml`.

## Inputs

Ask the user for:

1. **DEPENDABLY_BASE_URL** — the base URL of your dependably org, e.g.
   `https://repo.example.com` or `http://192.168.1.50:8080`. Single-tenant uses
   the bare host; multi-tenant puts the org in the subdomain.
2. **DEPENDABLY_TOKEN** — created under **Tokens**. Never commit it: it lives in
   `~/.m2/settings.xml` (see below), not in `pom.xml`.

## File to write

Add to the project's `pom.xml`:

```xml
<repositories>
  <repository>
    <id>dependably</id>
    <url>https://repo.example.com/maven/</url>
  </repository>
</repositories>

<!-- Only if this project publishes with `mvn deploy`: -->
<distributionManagement>
  <repository>
    <id>dependably</id>
    <url>https://repo.example.com/maven/</url>
  </repository>
</distributionManagement>
```

Then each developer adds the matching credentials to `~/.m2/settings.xml`
(this file is NOT committed):

```xml
<settings>
  <servers>
    <server>
      <id>dependably</id>
      <username>your-username</username>
      <password>your-token</password>
    </server>
  </servers>
</settings>
```

Substitutions:
- Replace `https://repo.example.com` with `DEPENDABLY_BASE_URL` (keep `/maven/`).
- The `<repository>` `<id>` in `pom.xml` MUST match the `<server>` `<id>` in
  `settings.xml` (`dependably`) — that is how Maven attaches credentials.

> **HTTP gotcha.** Maven 3.8.1+ blocks plaintext `http://` repositories. Serve
> dependably over HTTPS, or add the `<mirror>` with `<blocked>false</blocked>`
> shown in the `maven-configure-global` skill.

## Verify it works

```bash
mvn -q dependency:resolve      # pulls declared deps through dependably
mvn deploy                     # if <distributionManagement> is set
```

The first resolve records a `first_fetch` entry on the dependably **Activity**
page — check there to confirm the proxy is being hit.

## Never commit the token

`pom.xml` only holds the repository URL, so it is safe to commit. The token lives
in `~/.m2/settings.xml`. If a project needs CI to authenticate, inject the token
into a generated `settings.xml` at build time (e.g. GitHub Actions'
`actions/setup-java` `server-password`) rather than committing it.

## Reverting

Remove the `<repositories>` / `<distributionManagement>` blocks from `pom.xml`.
