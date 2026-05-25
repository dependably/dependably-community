---
name: nuget-configure-project
description: Point dotnet / nuget.exe at a dependably org for a single solution via NuGet.config
ecosystem: nuget
scope: project
inputs:
  - DEPENDABLY_BASE_URL
  - ORG_SLUG
  - DEPENDABLY_TOKEN
---

## When to use this

You have a .NET solution and want every contributor to restore packages from
your dependably instance. The token is referenced via `clear` + environment
variable so it does not get committed.

## Inputs

Ask the user for:

1. **DEPENDABLY_BASE_URL** — e.g. `https://repo.example.com`.
2. **ORG_SLUG** — e.g. `default`.
3. **DEPENDABLY_TOKEN** — created in dependably under **Tokens** or
   **Service tokens**. NuGet uses HTTP Basic with `user` as the username.

## File to write

Create `NuGet.config` in the solution / repo root (same directory as the
`.sln`). The `dotnet` and `nuget` CLIs walk up the directory tree looking
for this file.

```xml
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <clear />
    <add key="dependably" value="https://repo.example.com/o/default/nuget/v3/index.json" />
  </packageSources>
  <packageSourceCredentials>
    <dependably>
      <add key="Username" value="user" />
      <!-- ClearTextPassword reads the env var at restore time -->
      <add key="ClearTextPassword" value="%DEPENDABLY_TOKEN%" />
    </dependably>
  </packageSourceCredentials>
  <!-- Required if dependably is served over plain HTTP -->
  <packageSourceMapping>
    <packageSource key="dependably">
      <package pattern="*" />
    </packageSource>
  </packageSourceMapping>
</configuration>
```

> **HTTP gotcha.** Modern `dotnet` refuses HTTP feeds by default. Add this
> attribute to the `<add key="dependably" ...>` element:
> ```xml
> <add key="dependably"
>      value="http://repo.example.com/o/default/nuget/v3/index.json"
>      allowInsecureConnections="true" />
> ```

## Verify it works

```bash
export DEPENDABLY_TOKEN=<paste the token here>
dotnet restore
dotnet add package Newtonsoft.Json
```

Then check the dependably **Activity** page for a `first_fetch` entry.

## .gitignore

The `NuGet.config` shown above is safe to commit. The token is referenced via
`%DEPENDABLY_TOKEN%`, so the literal value never ends up in source control.
Add `*.user` and any `.env` file you use to load the token to `.gitignore`.
