---
name: maven-configure-global
description: Point your machine-wide Maven at a dependably org via ~/.m2/settings.xml
ecosystem: maven
scope: global
inputs:
  - DEPENDABLY_BASE_URL
  - DEPENDABLY_TOKEN
---

## When to use this

You want every Maven build on your machine to resolve (and optionally deploy)
artifacts through your dependably instance, without editing each project's
`pom.xml`. Credentials live in your home directory only — Maven has no
project-level credential store, so the token always goes here.

## Inputs

Ask the user for:

1. **DEPENDABLY_BASE_URL** — the base URL of your dependably org, e.g.
   `https://repo.example.com`. Tenancy is host-resolved: single-tenant
   deployments use the bare host; multi-tenant deployments put the org in the
   subdomain (`https://my-org.repo.example.com`). Trailing slash is stripped.
2. **DEPENDABLY_TOKEN** — created in dependably under **Tokens**. Any username
   is accepted; the token is the password (dependably resolves the org from the
   host, not the username).

## File to write

Linux / macOS: `~/.m2/settings.xml`
Windows: `%USERPROFILE%\.m2\settings.xml`

```xml
<settings>
  <servers>
    <server>
      <id>dependably</id>
      <username>your-username</username>
      <password>your-token</password>
    </server>
  </servers>
  <profiles>
    <profile>
      <id>dependably</id>
      <repositories>
        <repository>
          <id>dependably</id>
          <url>https://repo.example.com/maven/</url>
        </repository>
      </repositories>
    </profile>
  </profiles>
  <activeProfiles><activeProfile>dependably</activeProfile></activeProfiles>
</settings>
```

Substitutions:
- Replace `https://repo.example.com` with `DEPENDABLY_BASE_URL` (keep the
  trailing `/maven/`).
- Put the token in `<password>`; `<username>` can be anything.
- The `<server>` `<id>` MUST match the `<repository>` `<id>` (`dependably`) —
  that is how Maven attaches the credentials to the repository.

> **HTTP gotcha.** If `DEPENDABLY_BASE_URL` is `http://` (no `s`), Maven 3.8.1+
> blocks plaintext repositories by default. Either serve dependably over HTTPS,
> or add a mirror override that unblocks it:
> ```xml
> <mirrors><mirror><id>dependably</id><mirrorOf>dependably</mirrorOf>
>   <url>http://repo.example.com/maven/</url><blocked>false</blocked>
> </mirror></mirrors>
> ```

## Verify it works

```bash
# Resolve a dependency through dependably (any artifact your org proxies/hosts):
mvn dependency:get -Dartifact=org.apache.commons:commons-lang3:3.14.0

# Publish, if the project declares a matching <distributionManagement> (see the
# maven-configure-project skill):
mvn deploy
```

A `401`/`403` means the `<server>` `<id>` doesn't match the repository `<id>`,
or the token is wrong. A `501`/`blocked` message is the HTTP-plaintext block
above.

## Reverting

Delete `~/.m2/settings.xml` (or remove the `dependably` `<server>`, `<profile>`,
and `<activeProfile>` entries). Maven falls back to Maven Central.
