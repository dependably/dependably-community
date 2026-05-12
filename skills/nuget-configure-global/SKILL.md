---
name: nuget-configure-global
description: Point machine-wide dotnet / nuget at a dependably org via the user-level NuGet.Config
ecosystem: nuget
scope: global
inputs:
  - DEPENDABLY_BASE_URL
  - ORG_SLUG
  - DEPENDABLY_TOKEN
---

## When to use this

You want every .NET project on your machine to pull packages from dependably by
default, without a per-solution `NuGet.config`.

## Inputs

Ask the user for:

1. **DEPENDABLY_BASE_URL** — e.g. `https://repo.example.com`.
2. **ORG_SLUG** — e.g. `default`.
3. **DEPENDABLY_TOKEN** — from dependably **Tokens**.

## File to write

The user-level NuGet config path depends on the OS:

- Linux / macOS: `~/.config/NuGet/NuGet.Config`
- Windows: `%APPDATA%\NuGet\NuGet.Config`

The `dotnet nuget` CLI can edit this file safely:

```bash
dotnet nuget add source https://repo.example.com/o/default/nuget/v3/index.json \
  --name dependably \
  --username user \
  --password $DEPENDABLY_TOKEN \
  --store-password-in-clear-text
```

For HTTP-only deployments (no TLS), append `--allow-insecure-connections`.

To make dependably the *only* source (preventing fall-through to public
nuget.org), remove the default source:

```bash
dotnet nuget remove source nuget.org
```

If you prefer to edit the file directly, the resulting XML looks identical to
the [project-level recipe](../nuget-configure-project/SKILL.md) — except the
`ClearTextPassword` element holds the literal token instead of an env var
reference, since this file is not under source control.

> Tighten permissions on the global config:
> ```bash
> chmod 600 ~/.config/NuGet/NuGet.Config
> ```

## Verify it works

```bash
dotnet nuget list source                 # should show "dependably" enabled
dotnet new console -n smoke && cd smoke
dotnet add package Newtonsoft.Json
```

## Reverting

```bash
dotnet nuget remove source dependably
```
