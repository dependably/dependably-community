/**
 * Builds the copyable "how do I get this artefact" command shown in each expanded version
 * row and in the packages-list row menu.
 *
 * Pure and synchronous — `origin` is a parameter rather than a read of `window.location`,
 * so every ecosystem is unit-testable without a Svelte render harness (the same shape as
 * `sbom/curlSnippet.js` and `remediation.js`'s `skillInstallCommand`).
 *
 * This is an INVOCATION — one line per artefact, rendered many times per page. It is a
 * different artefact from the CONFIGURATION documents (.npmrc, pip.conf, nuget.config,
 * settings.xml, ~/.terraformrc) that `OrgController.GetSetup` renders on the Setup page,
 * and the two are deliberately not merged. They do share the registry base paths below —
 * see BASE_PATHS.
 */
/**
 * Client-facing route prefix per ecosystem. These are protocol constants fixed by each
 * ecosystem's own specification (PEP 503 mandates /simple/, the OCI Distribution Spec
 * mandates /v2/, npm and NuGet clients hardcode theirs), so they cannot change without
 * breaking every client.
 *
 * Co-owned with the snippet generators in OrgController.GetSetup — a change here needs a
 * matching change there. `installCommand.test.js` asserts this map covers ECOSYSTEMS
 * exactly, so a newly added ecosystem fails loudly rather than silently rendering nothing.
 *
 * OCI is absent by design: the Distribution Spec puts the registry host in the image
 * reference itself, so an OCI pull names the bare host and never a path prefix.
 */
const BASE_PATHS = Object.freeze({
  npm: '/npm/',
  pypi: '/simple/',
  nuget: '/nuget/v3/index.json',
  maven: '/maven/',
  rpm: '/rpm/',
  golang: '/go',
  cargo: '/cargo/',
  apk: '/apk',
  terraform: '/terraform/',
})

/** @typedef {{ command: string, labelKey: 'install'|'pull', caveatKey: string|null }} InstallCommand */

/** Caveat identifiers. The module stays locale-free; Svelte maps these to $t(...). */
export const CAVEATS = Object.freeze({
  /** The command is correct but only resolves once the Setup snippet has been applied. */
  requiresSetup: 'requiresSetup',
  /** Terraform rejects an http:// mirror URL at config-parse time. */
  httpMirror: 'httpMirror',
  /** Installs this exact artefact; its dependencies still come from configured repos. */
  dependenciesFromConfiguredRepos: 'dependenciesFromConfiguredRepos',
  /** Docker needs an insecure-registries entry to talk to a plain-HTTP registry. */
  insecureRegistry: 'insecureRegistry',
})

/**
 * The registry base URL to embed in a copied command.
 *
 * Mirrors `IPublicUrlBuilder.BaseUrl` (scheme from BASE_URL when the operator set one,
 * host always from the request). The one case where `window.location.origin` disagrees
 * with the server is an operator who declared an HTTPS deployment while this browser
 * reached the SPA over plain HTTP; `bootstrap.insecureHttp` is false exactly then, and a
 * command gets pasted into a Dockerfile or a colleague's terminal where the browser-local
 * http:// would be wrong.
 *
 * @param {{ insecureHttp?: boolean } | null | undefined} bootstrap the bootstrapInfo store value
 * @param {{ origin: string, protocol: string }} loc window.location (or a stub in tests)
 * @returns {string} origin with no trailing slash
 */
export function registryOrigin(bootstrap, loc) {
  const origin = (loc?.origin ?? '').replace(/\/+$/, '')
  if (bootstrap?.insecureHttp === false && loc?.protocol === 'http:') {
    return origin.replace(/^http:/, 'https:')
  }
  return origin
}

/** Hostname without the port — what pip's --trusted-host matches on. */
function hostnameOf(origin) {
  try { return new URL(origin).hostname } catch { return '' }
}

/** Host including any non-default port — what an OCI image reference needs. */
function hostOf(origin) {
  try { return new URL(origin).host } catch { return '' }
}

function isHttp(origin) {
  return /^http:\/\//i.test(origin)
}

/**
 * Single-quote an argument unless it is made only of characters every shell treats
 * literally. Package names and versions originate from proxied upstream metadata, so they
 * are never interpolated into the command unquoted on trust. PyPI epoch versions ("1!2.0")
 * are the common real case — a bare `!` history-expands in an interactive bash.
 *
 * `=` is in the safe set because every value here is an argument, never the first word of
 * the command, so it can not be read as a shell assignment — and pip's `name==version`
 * and apk's `name=version` pins would otherwise be quoted on every single row.
 */
function shellArg(value) {
  const s = String(value ?? '')
  if (s !== '' && /^[A-Za-z0-9._@/:+=-]+$/.test(s)) return s
  return `'${s.replaceAll("'", `'\\''`)}'`
}

/** Maven stores "{groupId}:{artifactId}". Split on the FIRST colon — a groupId never has one. */
function mavenCoords(name) {
  const idx = String(name ?? '').indexOf(':')
  if (idx <= 0 || idx === name.length - 1) return null
  return { group: name.slice(0, idx), artifact: name.slice(idx + 1) }
}

/**
 * The reference an OCI pull should use. A tag is friendlier, but only a tag that actually
 * exists: an untagged digest (a proxied multi-arch child, or a by-digest push) falls back
 * to the digest form. Synthesizing ":latest" for an untagged digest would 404.
 */
function ociReference(version, tags) {
  const list = Array.isArray(tags) ? tags.filter(Boolean) : []
  if (list.includes('latest')) return ':latest'
  if (list.length > 0) return `:${[...list].sort()[0]}`
  return version ? `@${version}` : null
}

/**
 * @param {string} command
 * @param {'install' | 'pull'} labelKey
 * @param {string | null} [caveatKey]
 * @returns {InstallCommand}
 */
function result(command, labelKey, caveatKey = null) {
  return { command, labelKey, caveatKey }
}

/**
 * Per-ecosystem builders. `pkg` is the unpinned "give me the current release" form shown
 * in the packages list; `version` is the pinned form shown in an expanded row. Kept
 * adjacent per ecosystem so the two forms cannot drift apart.
 *
 * Each receives { name, version, filename, tags, origin, http } and returns an
 * InstallCommand or null. Returning null renders nothing at all — an absent affordance is
 * quieter than a placeholder, and honest when no correct command exists.
 */
const BUILDERS = Object.freeze({
  npm: {
    pkg: ({ name, origin }) =>
      result(`npm install ${shellArg(name)} --registry ${origin}${BASE_PATHS.npm}`, 'install'),
    version: ({ name, version, origin }) =>
      result(`npm install ${shellArg(`${name}@${version}`)} --registry ${origin}${BASE_PATHS.npm}`, 'install'),
  },

  // pip normalizes names itself, so the stored PEP 503 form resolves either way.
  // --trusted-host is what makes a plain-HTTP index usable, matching GeneratePyPiSnippet.
  pypi: {
    pkg: ({ name, origin, http }) =>
      result(`pip install ${shellArg(name)} --index-url ${origin}${BASE_PATHS.pypi}${trustedHost(origin, http)}`, 'install'),
    version: ({ name, version, origin, http }) =>
      result(`pip install ${shellArg(`${name}==${version}`)} --index-url ${origin}${BASE_PATHS.pypi}${trustedHost(origin, http)}`, 'install'),
  },

  // NuGet ids are case-insensitive, so the lowercased stored name resolves fine.
  nuget: {
    pkg: ({ name, origin }) =>
      result(`dotnet add package ${shellArg(name)} --source ${origin}${BASE_PATHS.nuget}`, 'install'),
    version: ({ name, version, origin }) =>
      result(`dotnet add package ${shellArg(name)} --version ${shellArg(version)} --source ${origin}${BASE_PATHS.nuget}`, 'install'),
  },

  // No CLI flag adds a resolution repository to a normal mvn/gradle build, so the honest
  // answer is the manifest fragment plus a pointer at Setup.
  maven: {
    pkg: (ctx) => BUILDERS.maven.version(ctx),
    version: ({ name, version }) => {
      const c = mavenCoords(name)
      if (!c || !version) return null
      return result(
        [
          '<dependency>',
          `  <groupId>${c.group}</groupId>`,
          `  <artifactId>${c.artifact}</artifactId>`,
          `  <version>${version}</version>`,
          '</dependency>',
        ].join('\n'),
        'install',
        CAVEATS.requiresSetup,
      )
    },
  },

  // /rpm/packages/{file} serves hosted and proxied RPMs alike, so the URL form is exact
  // and needs no repo file. The unpinned form has no filename, so it falls back to the
  // configured-repo command.
  rpm: {
    pkg: ({ name }) =>
      name ? result(`sudo dnf install ${shellArg(name)}`, 'install', CAVEATS.requiresSetup) : null,
    version: ({ name, version, filename, origin }) => {
      if (filename) {
        return result(
          `sudo dnf install ${shellArg(`${origin}${BASE_PATHS.rpm}packages/${filename}`)}`,
          'install',
          CAVEATS.dependenciesFromConfiguredRepos,
        )
      }
      // version is already "{ver}-{rel}", which is a valid NVR spec.
      if (!name || !version) return null
      return result(`sudo dnf install ${shellArg(`${name}-${version}`)}`, 'install', CAVEATS.requiresSetup)
    },
  },

  // The registry host IS the image reference prefix, so an OCI pull is self-contained.
  // Plain HTTP additionally needs insecure-registries in daemon.json, which cannot be
  // expressed in the pull command itself — say so beside it, as GenerateOciSnippet does.
  oci: {
    pkg: (ctx) => BUILDERS.oci.version(ctx),
    version: ({ name, version, tags, origin, http }) => {
      const ref = ociReference(version, tags)
      if (!name || !ref) return null
      return result(
        `docker pull ${shellArg(`${hostOf(origin)}/${name}${ref}`)}`,
        'pull',
        http ? CAVEATS.insecureRegistry : null,
      )
    },
  },

  // The proxy passes sumdb through, so no GOPRIVATE/GONOSUMDB is needed. The VAR=x prefix
  // is POSIX-shell only; `go get` must also run inside a module (Go >= 1.16).
  golang: {
    pkg: (ctx) => goGet(ctx, 'latest'),
    version: (ctx) => (ctx.version ? goGet(ctx, ctx.version) : null),
  },

  // cargo's --registry names an entry in config.toml, not a URL — there is no
  // resolution-time URL flag, so this form depends on the Setup snippet.
  cargo: {
    pkg: ({ name }) =>
      name ? result(`cargo add ${shellArg(name)} --registry dependably`, 'install', CAVEATS.requiresSetup) : null,
    version: ({ name, version }) =>
      name && version
        ? result(`cargo add ${shellArg(`${name}@${version}`)} --registry dependably`, 'install', CAVEATS.requiresSetup)
        : null,
  },

  // The self-contained `apk add -X {origin}/apk/{release}/{repo}` form cannot be built:
  // the release segment (v3.22, edge) lives only inside the blob key, and BlobKey is
  // deliberately stripped from the API payload. Ship the configured-repo form only.
  apk: {
    pkg: ({ name }) =>
      name ? result(`apk add ${shellArg(name)}`, 'install', CAVEATS.requiresSetup) : null,
    version: ({ name, version }) =>
      // version is already "{pkgver}-r{pkgrel}", which is exactly apk's pin syntax.
      name && version
        ? result(`apk add ${shellArg(`${name}=${version}`)}`, 'install', CAVEATS.requiresSetup)
        : null,
  },

  // Provider installation is configured globally in the CLI config, by design — there is
  // no per-project file and no command. name is already "{hostname}/{namespace}/{type}".
  terraform: {
    pkg: (ctx) => BUILDERS.terraform.version(ctx),
    version: ({ name, version, http }) => {
      if (!name || !version) return null
      const localName = String(name).split('/').pop()
      return result(
        [
          'terraform {',
          '  required_providers {',
          `    ${localName} = {`,
          `      source  = "${name}"`,
          `      version = "${version}"`,
          '    }',
          '  }',
          '}',
        ].join('\n'),
        'install',
        http ? CAVEATS.httpMirror : CAVEATS.requiresSetup,
      )
    },
  },
})

function trustedHost(origin, http) {
  return http ? ` --trusted-host ${hostnameOf(origin)}` : ''
}

function goGet({ name, origin }, ref) {
  if (!name) return null
  return result(
    `GOPROXY=${origin}${BASE_PATHS.golang} go get ${shellArg(`${name}@${ref}`)}`,
    'install',
    null,
  )
}

function build(which, opts) {
  const { ecosystem, name, origin } = opts ?? {}
  if (!ecosystem || !name || !origin) return null
  const builder = BUILDERS[ecosystem]
  if (!builder) return null
  return builder[which]({
    name,
    origin: origin.replace(/\/+$/, ''),
    version: opts.version ?? null,
    filename: opts.filename ?? null,
    tags: opts.tags ?? null,
    http: isHttp(origin),
  })
}

/**
 * The unpinned "give me the current release" form — the packages-list row menu.
 *
 * Nine ecosystems express this without naming a version, which is both more honest (latest
 * on a live registry is whatever it resolves to) and what lets a list row offer a command
 * without resolving one. Maven, Terraform and OCI cannot: pass `version` (and `tags` for
 * OCI) where the caller has resolved one, and accept null where it has not.
 *
 * Every field is optional because the function is total: it guards each input and returns
 * null rather than throwing, so a caller that has not resolved a name or an origin yet can
 * call it unconditionally on every render.
 *
 * @param {{ ecosystem?: string, name?: string, origin?: string,
 *           version?: string|null, tags?: string[]|null } | null} [opts]
 * @returns {InstallCommand|null} null when no correct command can be built — render nothing.
 */
export function packageInstallCommand(opts) {
  return build('pkg', opts)
}

/**
 * The version-pinned form — one expanded version row.
 *
 * Total in the same way as {@link packageInstallCommand} — see that note.
 *
 * @param {{ ecosystem?: string, name?: string, origin?: string, version?: string|null,
 *           filename?: string|null, tags?: string[]|null } | null} [opts]
 * @returns {InstallCommand|null}
 */
export function versionInstallCommand(opts) {
  return build('version', opts)
}

/** Exported for the coverage test that pins this map against ECOSYSTEMS. */
export const SUPPORTED_ECOSYSTEMS = Object.freeze(Object.keys(BUILDERS))
