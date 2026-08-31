import { describe, expect, it } from 'vitest'
import { ECOSYSTEMS } from './ecosystems.js'
import {
  CAVEATS,
  SUPPORTED_ECOSYSTEMS,
  packageInstallCommand,
  registryOrigin,
  versionInstallCommand,
} from './installCommand.js'

const HTTPS = 'https://reg.example.ca'
const HTTP = 'http://reg.example.ca:8080'

// `pkg`/`ver` narrow away the null return so each assertion below reads as one line.
// A builder that unexpectedly declines fails here, naming the ecosystem, rather than
// surfacing as "cannot read property 'command' of null" ten lines later. The tests that
// assert a DECLINED command call the imported functions directly.
/** @param {Parameters<typeof packageInstallCommand>[0]} o */
const pkg = (o) => {
  const r = packageInstallCommand(o)
  if (!r) throw new Error(`expected a package command for ${o?.ecosystem}`)
  return r
}
/** @param {Parameters<typeof versionInstallCommand>[0]} o */
const ver = (o) => {
  const r = versionInstallCommand(o)
  if (!r) throw new Error(`expected a version command for ${o?.ecosystem}`)
  return r
}

describe('coverage against the ecosystem vocabulary', () => {
  // The guard that matters: a newly added ecosystem must fail here rather than silently
  // rendering no install command anywhere in the UI.
  it('builds a command for exactly the ecosystems the app knows about', () => {
    expect([...SUPPORTED_ECOSYSTEMS].sort()).toEqual([...ECOSYSTEMS].sort())
  })
})

describe('registryOrigin', () => {
  it('upgrades to https when the operator declared an HTTPS deployment', () => {
    const loc = { origin: 'http://reg.example.ca', protocol: 'http:' }
    expect(registryOrigin({ insecureHttp: false }, loc)).toBe('https://reg.example.ca')
  })

  it('leaves a genuinely plain-HTTP deployment alone', () => {
    const loc = { origin: 'http://reg.example.ca', protocol: 'http:' }
    expect(registryOrigin({ insecureHttp: true }, loc)).toBe('http://reg.example.ca')
  })

  it('leaves an https location alone regardless of the flag', () => {
    const loc = { origin: 'https://reg.example.ca', protocol: 'https:' }
    expect(registryOrigin({ insecureHttp: false }, loc)).toBe('https://reg.example.ca')
    expect(registryOrigin({ insecureHttp: true }, loc)).toBe('https://reg.example.ca')
  })

  it('falls back to the browser origin before bootstrap resolves', () => {
    const loc = { origin: 'http://reg.example.ca', protocol: 'http:' }
    expect(registryOrigin(null, loc)).toBe('http://reg.example.ca')
    expect(registryOrigin(undefined, loc)).toBe('http://reg.example.ca')
  })

  it('strips a trailing slash and preserves a non-default port', () => {
    expect(registryOrigin(null, { origin: 'https://reg.example.ca:8443/', protocol: 'https:' }))
      .toBe('https://reg.example.ca:8443')
  })
})

describe('npm', () => {
  const base = { ecosystem: 'npm', name: 'lodash', origin: HTTPS }

  it('unpinned', () => {
    expect(pkg(base).command).toBe('npm install lodash --registry https://reg.example.ca/npm/')
  })

  it('version-pinned', () => {
    expect(ver({ ...base, version: '4.17.21' }).command)
      .toBe('npm install lodash@4.17.21 --registry https://reg.example.ca/npm/')
  })

  it('scoped names need no encoding — @scope/pkg@1.2.3 is the literal CLI form', () => {
    expect(ver({ ...base, name: '@types/node', version: '20.1.0' }).command)
      .toBe('npm install @types/node@20.1.0 --registry https://reg.example.ca/npm/')
  })

  it('carries no caveat — the registry URL is inline', () => {
    expect(ver({ ...base, version: '4.17.21' }).caveatKey).toBeNull()
  })
})

describe('pypi', () => {
  const base = { ecosystem: 'pypi', name: 'requests', origin: HTTPS }

  it('unpinned', () => {
    expect(pkg(base).command).toBe('pip install requests --index-url https://reg.example.ca/simple/')
  })

  it('version-pinned', () => {
    expect(ver({ ...base, version: '2.32.3' }).command)
      .toBe('pip install requests==2.32.3 --index-url https://reg.example.ca/simple/')
  })

  it('adds --trusted-host on a plain-HTTP index, without the port', () => {
    expect(ver({ ...base, version: '2.32.3', origin: HTTP }).command)
      .toBe('pip install requests==2.32.3 --index-url http://reg.example.ca:8080/simple/'
        + ' --trusted-host reg.example.ca')
  })

  it('quotes an epoch version so bash does not history-expand the !', () => {
    expect(ver({ ...base, version: '1!2.0' }).command)
      .toBe("pip install 'requests==1!2.0' --index-url https://reg.example.ca/simple/")
  })
})

describe('nuget', () => {
  const base = { ecosystem: 'nuget', name: 'newtonsoft.json', origin: HTTPS }

  it('unpinned', () => {
    expect(pkg(base).command)
      .toBe('dotnet add package newtonsoft.json --source https://reg.example.ca/nuget/v3/index.json')
  })

  it('version-pinned', () => {
    expect(ver({ ...base, version: '13.0.3' }).command)
      .toBe('dotnet add package newtonsoft.json --version 13.0.3'
        + ' --source https://reg.example.ca/nuget/v3/index.json')
  })
})

describe('maven', () => {
  const base = { ecosystem: 'maven', name: 'com.google.guava:guava', origin: HTTPS }

  it('emits the dependency fragment, splitting on the first colon', () => {
    expect(ver({ ...base, version: '33.2.0-jre' }).command).toBe(
      '<dependency>\n'
      + '  <groupId>com.google.guava</groupId>\n'
      + '  <artifactId>guava</artifactId>\n'
      + '  <version>33.2.0-jre</version>\n'
      + '</dependency>')
  })

  it('is config-dependent — there is no resolution-time URL flag for mvn', () => {
    expect(ver({ ...base, version: '33.2.0-jre' }).caveatKey).toBe(CAVEATS.requiresSetup)
  })

  it('renders nothing without a version (the packages list has none)', () => {
    expect(packageInstallCommand(base)).toBeNull()
  })

  it('renders nothing for a name carrying no coordinate separator', () => {
    expect(versionInstallCommand({ ...base, name: 'guava', version: '1.0' })).toBeNull()
  })
})

describe('rpm', () => {
  const base = { ecosystem: 'rpm', name: 'nginx', origin: HTTPS }

  it('prefers the exact artefact URL, which needs no repo file', () => {
    const r = ver({ ...base, version: '1.24.0-1.el9', filename: 'nginx-1.24.0-1.el9.x86_64.rpm' })
    expect(r.command)
      .toBe('sudo dnf install https://reg.example.ca/rpm/packages/nginx-1.24.0-1.el9.x86_64.rpm')
    expect(r.caveatKey).toBe(CAVEATS.dependenciesFromConfiguredRepos)
  })

  it('falls back to the NVR spec when no filename is known', () => {
    const r = ver({ ...base, version: '1.24.0-1.el9' })
    expect(r.command).toBe('sudo dnf install nginx-1.24.0-1.el9')
    expect(r.caveatKey).toBe(CAVEATS.requiresSetup)
  })

  it('unpinned needs the repo configured', () => {
    expect(pkg(base).command).toBe('sudo dnf install nginx')
    expect(pkg(base).caveatKey).toBe(CAVEATS.requiresSetup)
  })
})

describe('oci', () => {
  const digest = 'sha256:3c51bc18d60e201e00f01aea2ffa114f677613222cedec4967c9363599cd695d'
  const base = { ecosystem: 'oci', name: 'library/ubuntu', origin: HTTPS }

  it('prefers the latest tag when the digest carries one', () => {
    expect(ver({ ...base, version: digest, tags: ['24.04', 'latest'] }).command)
      .toBe('docker pull reg.example.ca/library/ubuntu:latest')
  })

  it('uses a stable tag choice when latest is absent', () => {
    expect(ver({ ...base, version: digest, tags: ['noble', '24.04'] }).command)
      .toBe('docker pull reg.example.ca/library/ubuntu:24.04')
  })

  it('falls back to the digest for an untagged version — :latest would 404', () => {
    expect(ver({ ...base, version: digest, tags: [] }).command)
      .toBe(`docker pull reg.example.ca/library/ubuntu@${digest}`)
    expect(ver({ ...base, version: digest, tags: null }).command)
      .toBe(`docker pull reg.example.ca/library/ubuntu@${digest}`)
  })

  it('labels itself a pull, not an install', () => {
    expect(ver({ ...base, version: digest, tags: ['latest'] }).labelKey).toBe('pull')
  })

  it('keeps a non-default port in the image reference and flags plain HTTP', () => {
    const r = ver({ ...base, version: digest, tags: ['latest'], origin: HTTP })
    expect(r.command).toBe('docker pull reg.example.ca:8080/library/ubuntu:latest')
    expect(r.caveatKey).toBe(CAVEATS.insecureRegistry)
  })

  it('renders nothing with neither tag nor digest', () => {
    expect(versionInstallCommand({ ...base, version: null, tags: [] })).toBeNull()
  })
})

describe('golang', () => {
  const base = { ecosystem: 'golang', name: 'github.com/gorilla/Mux', origin: HTTPS }

  it('unpinned resolves @latest through the proxy', () => {
    expect(pkg(base).command)
      .toBe('GOPROXY=https://reg.example.ca/go go get github.com/gorilla/Mux@latest')
  })

  it('version-pinned uses the module path verbatim — bang-encoding is a wire concern', () => {
    expect(ver({ ...base, version: 'v1.8.1' }).command)
      .toBe('GOPROXY=https://reg.example.ca/go go get github.com/gorilla/Mux@v1.8.1')
  })

  it('is self-contained — the proxy passes sumdb through', () => {
    expect(ver({ ...base, version: 'v1.8.1' }).caveatKey).toBeNull()
  })
})

describe('cargo', () => {
  const base = { ecosystem: 'cargo', name: 'serde', origin: HTTPS }

  it('unpinned', () => {
    expect(pkg(base).command).toBe('cargo add serde --registry dependably')
  })

  it('version-pinned', () => {
    expect(ver({ ...base, version: '1.0.203' }).command)
      .toBe('cargo add serde@1.0.203 --registry dependably')
  })

  it('is config-dependent — --registry names a config.toml entry, not a URL', () => {
    expect(ver({ ...base, version: '1.0.203' }).caveatKey).toBe(CAVEATS.requiresSetup)
  })
})

describe('apk', () => {
  const base = { ecosystem: 'apk', name: 'curl', origin: HTTPS }

  it('unpinned', () => {
    expect(pkg(base).command).toBe('apk add curl')
  })

  it('pins with apk = syntax; the stored version already carries the -r release', () => {
    expect(ver({ ...base, version: '8.5.0-r0' }).command).toBe('apk add curl=8.5.0-r0')
  })

  it('is config-dependent — the release segment is not recoverable for a -X form', () => {
    expect(ver({ ...base, version: '8.5.0-r0' }).caveatKey).toBe(CAVEATS.requiresSetup)
  })
})

describe('terraform', () => {
  const base = { ecosystem: 'terraform', name: 'registry.terraform.io/hashicorp/aws', origin: HTTPS }

  it('emits required_providers keyed by the provider type', () => {
    expect(ver({ ...base, version: '5.52.0' }).command).toBe(
      'terraform {\n'
      + '  required_providers {\n'
      + '    aws = {\n'
      + '      source  = "registry.terraform.io/hashicorp/aws"\n'
      + '      version = "5.52.0"\n'
      + '    }\n'
      + '  }\n'
      + '}')
  })

  it('warns that terraform rejects an http mirror at config-parse time', () => {
    expect(ver({ ...base, version: '5.52.0', origin: HTTP }).caveatKey).toBe(CAVEATS.httpMirror)
  })

  it('otherwise points at Setup — the mirror lives in the CLI config', () => {
    expect(ver({ ...base, version: '5.52.0' }).caveatKey).toBe(CAVEATS.requiresSetup)
  })

  it('renders nothing without a version', () => {
    expect(packageInstallCommand(base)).toBeNull()
  })
})

describe('degenerate input', () => {
  it.each([
    ['unknown ecosystem', { ecosystem: 'cocoapods', name: 'x', origin: HTTPS }],
    ['missing ecosystem', { name: 'x', origin: HTTPS }],
    ['empty name', { ecosystem: 'npm', name: '', origin: HTTPS }],
    ['missing origin', { ecosystem: 'npm', name: 'x' }],
    ['no opts', undefined],
  ])('returns null rather than throwing for %s', (_label, opts) => {
    expect(packageInstallCommand(opts)).toBeNull()
    expect(versionInstallCommand(opts)).toBeNull()
  })

  it('returns null for a pinned command with no version', () => {
    expect(versionInstallCommand({ ecosystem: 'cargo', name: 'serde', origin: HTTPS })).toBeNull()
    expect(versionInstallCommand({ ecosystem: 'apk', name: 'curl', origin: HTTPS })).toBeNull()
    expect(versionInstallCommand({ ecosystem: 'golang', name: 'example.com/m', origin: HTTPS })).toBeNull()
  })

  it('tolerates an origin with a trailing slash', () => {
    expect(pkg({ ecosystem: 'npm', name: 'lodash', origin: 'https://reg.example.ca/' }).command)
      .toBe('npm install lodash --registry https://reg.example.ca/npm/')
  })

  it('quotes a name carrying shell metacharacters', () => {
    expect(pkg({ ecosystem: 'npm', name: 'a;rm -rf /', origin: HTTPS }).command)
      .toBe("npm install 'a;rm -rf /' --registry https://reg.example.ca/npm/")
  })
})
