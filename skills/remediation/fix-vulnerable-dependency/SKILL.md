---
name: fix-vulnerable-dependency
description: Upgrade a vulnerable npm, PyPI, NuGet, Maven, Go, or Cargo dependency to its fixed version — lockfile-aware, with transitive-override recipes — then verify. RPM and OCI notes cover the rebuild/republish path.
category: remediation
inputs:
  - OSV_ID
  - PACKAGE_PURL
  - INSTALLED_VERSION
  - FIXED_VERSION
---

## When to use this

An OSV/GHSA advisory names a package you depend on, an installed version, and a fixed version.
This applies whether the package is a **direct** dependency (in your manifest) or a
**transitive** one (pulled in by something else) — the recipe differs, and getting it wrong
(bumping the wrong manifest entry, or forgetting to regenerate the lockfile) leaves the
vulnerable version resolved at install time even though the manifest looks fixed.

## Inputs

Ask the user for, or read from the advisory the user pasted:

1. **OSV_ID** — the advisory id (`GHSA-...`, `CVE-...`, `PYSEC-...`, etc.), for context in commit
   messages and PR descriptions.
2. **PACKAGE_PURL** — the affected package as a purl (`pkg:npm/lodash@4.17.15`) or plain
   `ecosystem/name`. Determines which section below applies.
3. **INSTALLED_VERSION** — the version currently resolved in the lockfile.
4. **FIXED_VERSION** — the first version where the advisory no longer applies. If the advisory
   gives a range instead of one version, pick the lowest version that is `>= ` every `fixed`
   event and satisfies your other constraints.

## General procedure

1. Determine whether `PACKAGE_PURL` is a **direct** dependency (listed in your manifest) or
   **transitive** (only in the lockfile). Each ecosystem section below has a lookup command for
   this.
2. Apply the direct-bump or transitive-override recipe for your ecosystem.
3. Regenerate the lockfile (most package managers do this automatically on install; a few need
   an explicit `update`/`lock` step — called out per ecosystem). If the repo also commits a
   **generated file derived from the lockfile** — an exported requirements file, a vendored
   directory, a rendered manifest — regenerating the lockfile is only half the job. Whatever CI
   installs from is the file that decides which version actually ships; see
   [Exact pins and exported lockfiles](#exact-pins-and-exported-lockfiles).
4. Run the project's test suite. A transitive override changes what code actually runs even when
   your own source is untouched — treat it like any other dependency bump.
5. Confirm the fix landed: re-run the ecosystem's own audit command, or re-scan through
   dependably (`POST /api/v1/packages/{eco}/{name}/{version}/rescan` from the UI's rescan button)
   once the new lockfile is committed and the project is reinstalled from your dependably org.

## npm

**Direct dependency** — bump in `package.json` and reinstall:

```bash
npm ls PACKAGE_NAME                 # confirms direct vs transitive, and who requires it
npm install PACKAGE_NAME@FIXED_VERSION
```

**Transitive dependency** — npm 8.3+ supports `overrides` in `package.json`. A blanket override
forces every resolution of the package to the fixed version, regardless of which direct
dependency pulled it in:

```json
{
  "overrides": {
    "PACKAGE_NAME": "FIXED_VERSION"
  }
}
```

If only one dependency's copy needs pinning (rare — usually the blanket form above is correct),
nest the override under that dependency instead:

```json
{
  "overrides": {
    "direct-dep-name": {
      "PACKAGE_NAME": "FIXED_VERSION"
    }
  }
}
```

Then `npm install` to regenerate `package-lock.json`, and `npm audit` to confirm the advisory
clears.

## PyPI

**Direct dependency** (`requirements.txt` / `pyproject.toml`):

```bash
pip show PACKAGE_NAME                       # Required-by: shows if something else pulls it in
# requirements.txt
PACKAGE_NAME==FIXED_VERSION
# pyproject.toml (PEP 621 / Poetry)
PACKAGE_NAME = ">=FIXED_VERSION"
```

**Match the manifest's existing style.** The `>=` above is the common case, where the manifest
holds floors and a lockfile holds the resolved versions. If the entry you are editing is already
an exact `==` pin, replace the pinned version in place — do not relax it to `>=`. Swapping a pin
for a floor is a silent policy change: it re-opens the manifest to whatever the resolver picks
next, and in a repo that pins deliberately it will also trip that repo's own lint (e.g. pycheck's
`pinned-versions` / `PP_UNPINNED`).

**Transitive dependency:**

- **pip-tools**: add a constraint to `requirements.in` even though you don't import the package
  directly, then `pip-compile` to regenerate `requirements.txt` with the pin applied through the
  whole tree.
- **Poetry**: add the same explicit version constraint under `[tool.poetry.dependencies]`; Poetry's
  resolver treats it as a hard constraint on every resolution of that package, then
  `poetry lock --no-update` to refresh `poetry.lock` without re-resolving unrelated packages.
- **uv**: use `override-dependencies` in `pyproject.toml`:

  ```toml
  [tool.uv]
  override-dependencies = ["PACKAGE_NAME==FIXED_VERSION"]
  ```

  then `uv lock` — and re-run the repo's `uv export` commands too if it commits exported
  requirements files, per the next section.

Verify with `pip install --dry-run -r requirements.txt` (or the Poetry/uv equivalent) and confirm
the resolved version.

### Exact pins and exported lockfiles

Some repos stack three layers: exact `==` pins in `pyproject.toml`, a resolver lockfile
(`uv.lock` / `poetry.lock`), and one or more **exported requirements files committed for CI**,
generated with hashes — `uv export --frozen`, or `pip-compile --generate-hashes`. CI then installs
with `pip install --require-hashes -r <export>`.

In that layout, **`uv lock` alone fixes nothing that CI sees.** The export carries its own pinned
versions and `--hash=` lines. Until it is regenerated, `--require-hashes` keeps installing the
vulnerable version — and the integrity check *passes*, because the recorded hashes still match the
vulnerable artifact it is pinned to. The manifest looks fixed, the lockfile looks fixed, and the
build still ships the vulnerability.

Full sequence with uv:

```bash
# 1. Bump the pin in pyproject.toml -> PACKAGE_NAME==FIXED_VERSION
# 2. Re-resolve the lockfile
uv lock
# 3. Regenerate EVERY committed export (see below for the exact commands)
uv export --frozen --no-emit-project --extra dev -o requirements/dev.lock.txt
uv export --frozen --no-emit-project -o requirements/prod.lock.txt
```

**Do not guess the export flags.** Each generated file records the command that produced it in a
header comment — re-run it verbatim, because a different flag set silently changes which extras
and markers land in the file:

```
# This file was autogenerated by uv via the following command:
#    uv export --frozen --no-emit-project --extra dev -o requirements/dev.lock.txt
```

`pip-compile` writes the same style of header. Poetry needs the export plugin
(`poetry export -f requirements.txt -o requirements.txt`) and only emits hashes when the source
lock has them.

**Check for more than one export.** Repos commonly commit a dev and a prod/runtime file.
Regenerating one and forgetting the other leaves the vulnerable version on the path you missed —
often the runtime image, which is the one that ships.

Verify:

```bash
grep -A3 '^PACKAGE_NAME==' requirements/prod.lock.txt   # version bumped AND --hash= lines changed
uv lock --check                                         # lock still agrees with the manifest
pip install --require-hashes --dry-run -r requirements/prod.lock.txt
```

A bumped version line whose `--hash=` values did not change means the file was hand-edited instead
of regenerated; that install will fail its integrity check rather than silently succeed. Treat a
passing `--require-hashes` dry run against the regenerated export — not a green `uv lock` — as the
evidence the fix actually reaches CI.

## NuGet

**Direct dependency:**

```bash
dotnet add package PACKAGE_NAME --version FIXED_VERSION
```

**Transitive dependency** — NuGet's "nearest wins" resolution means an explicit
`PackageReference` for a transitive package overrides the version your direct dependencies would
otherwise pull, even though you don't call it directly:

```xml
<ItemGroup>
  <PackageReference Include="PACKAGE_NAME" Version="FIXED_VERSION" />
</ItemGroup>
```

If the repo uses Central Package Management (`Directory.Packages.props` with
`ManagePackageVersionsCentrally=true`), the pin goes there instead, as a `PackageVersion` entry,
plus a bare `<PackageReference Include="PACKAGE_NAME" />` in the consuming project if one doesn't
already exist.

Run `dotnet restore` and `dotnet list package --vulnerable --include-transitive` to confirm the
advisory clears. If a `packages.lock.json` is committed, `dotnet restore --force-evaluate` to
regenerate it.

## Maven

**Direct dependency** — bump the `<version>` in the `<dependency>` block.

**Transitive dependency** — pin it in `<dependencyManagement>`, which applies to every module in
the reactor without changing who declares the dependency:

```xml
<dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>...</groupId>
      <artifactId>PACKAGE_NAME</artifactId>
      <version>FIXED_VERSION</version>
    </dependency>
  </dependencies>
</dependencyManagement>
```

Confirm with `mvn dependency:tree -Dincludes=groupId:PACKAGE_NAME` — the resolved version should
now be `FIXED_VERSION` wherever it appears in the tree.

## Go

```bash
go get PACKAGE_NAME@FIXED_VERSION   # bumps go.mod's minimum version requirement
go mod tidy                         # regenerates go.sum
```

Go's minimal version selection means bumping the `require` directive (directly, via `go get`, or
by hand for a package you don't import) is itself the transitive-override mechanism — no separate
override syntax is needed. If a specific replacement source is required (a fork, a local patch),
use `go mod edit -replace PACKAGE_NAME=PACKAGE_NAME@FIXED_VERSION` instead.

Confirm with `go list -m all | grep PACKAGE_NAME`.

## Cargo

**Direct dependency:**

```bash
cargo update -p PACKAGE_NAME --precise FIXED_VERSION
```

**Transitive dependency** — same command works if the package appears anywhere in the
dependency graph; Cargo resolves it as long as `FIXED_VERSION` satisfies every dependent's
version requirement. If a dependent's requirement is too narrow to allow the fix, patch the
graph in the workspace root `Cargo.toml` instead:

```toml
[patch.crates-io]
PACKAGE_NAME = { version = "FIXED_VERSION" }
```

Confirm with `cargo tree -i PACKAGE_NAME` (shows every path to the package and the version
resolved on each).

## RPM

RPM packages are OS-level, not app-level — there is no per-project manifest to bump. Two paths:

1. **Upstream already shipped the fix**: pull the patched RPM from the distro's security/updates
   repo and republish it to your dependably RPM channel (`PUT /rpm/upload`), or let
   `Rpm:UpstreamMode=merged` serve the upstream fix directly if proxy passthrough is enabled for
   that repo.
2. **No upstream fix yet, or you carry a local patch**: rebuild the SRPM with the patch applied
   (`rpmbuild --rebuild`), bump the release tag so NEVRA comparison picks the new build over the
   vulnerable one, and publish the rebuilt RPM to your dependably channel.

Either way, confirm the fix by checking the resolved package version in the repodata your clients
actually consume (`repoquery --info PACKAGE_NAME` against your dependably RPM repo), not just the
upstream advisory.

## OCI

Base-image and layer vulnerabilities are fixed by rebuilding, not patching in place:

1. Check whether a newer tag of the same base image already contains the fix
   (`docker pull` the candidate tag, re-scan). If so, bump the `FROM` line and rebuild.
2. If the vulnerable package is installed inside your own Dockerfile (not the base image), bump
   its version the same way you would for that ecosystem's package manager inside the `RUN`
   step, and rebuild.
3. Push the rebuilt image to your dependably OCI registry under a new tag; do not overwrite the
   vulnerable tag in place — consumers pinned to a digest need a new digest to pick up the fix.

Confirm with a fresh pull and re-scan of the new tag/digest, not the old one.
