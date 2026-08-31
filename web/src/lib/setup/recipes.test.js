import { describe, it, expect } from 'vitest'
import {
  availableOperations,
  availableScopes,
  availableVariants,
  selectRecipe,
  reconcileSelection,
  tokenCommand,
  fileBody,
} from './recipes.js'

/**
 * @param {string} variant
 * @param {string} operation
 * @param {string} scope
 * @returns {import('./recipes.js').SetupRecipe}
 */
const recipe = (variant, operation, scope, extra = {}) => ({
  variant,
  operation,
  scope,
  capabilityPreset: operation === 'publish' ? 'push' : 'pull',
  files: [],
  tokenDelivery: { kind: 'literal', envVar: null, command: null },
  verify: null,
  caveats: [],
  ...extra,
})

// Shaped like the npm payload: one variant, both operations, both scopes.
/** @type {import('./recipes.js').SetupPayload} */
const npm = {
  ecosystem: 'npm',
  variants: [{ id: 'npm', label: 'npm' }],
  recipes: [
    recipe('npm', 'install', 'project'),
    recipe('npm', 'install', 'global'),
    recipe('npm', 'publish', 'project'),
    recipe('npm', 'publish', 'global'),
  ],
}

// Go is proxy-only: install in both scopes, no publish path at all.
/** @type {import('./recipes.js').SetupPayload} */
const golang = {
  ecosystem: 'golang',
  variants: [{ id: 'go', label: 'Go' }],
  recipes: [recipe('go', 'install', 'project'), recipe('go', 'install', 'global')],
}

// Docker has no project scope — the host lives in the image reference.
/** @type {import('./recipes.js').SetupPayload} */
const oci = {
  ecosystem: 'oci',
  variants: [{ id: 'docker', label: 'Docker' }],
  recipes: [recipe('docker', 'install', 'global'), recipe('docker', 'publish', 'global')],
}

// Maven's variants are uneven: Gradle publishes only at project scope.
/** @type {import('./recipes.js').SetupPayload} */
const maven = {
  ecosystem: 'maven',
  variants: [
    { id: 'maven', label: 'Maven' },
    { id: 'gradle-groovy', label: 'Gradle (Groovy)' },
    { id: 'gradle-kotlin', label: 'Gradle (Kotlin)' },
  ],
  recipes: [
    recipe('maven', 'install', 'project'),
    recipe('maven', 'install', 'global'),
    recipe('maven', 'publish', 'project'),
    recipe('gradle-groovy', 'install', 'project'),
    recipe('gradle-groovy', 'publish', 'project'),
    recipe('gradle-kotlin', 'install', 'project'),
  ],
}

describe('availableOperations', () => {
  it('returns both operations in a fixed order regardless of recipe order', () => {
    expect(availableOperations(npm)).toEqual(['install', 'publish'])
  })

  it('omits publish for a proxy-only ecosystem', () => {
    expect(availableOperations(golang)).toEqual(['install'])
  })

  it('is empty for a missing or malformed payload rather than throwing', () => {
    expect(availableOperations(null)).toEqual([])
    expect(availableOperations(/** @type {any} */ ({}))).toEqual([])
    expect(availableOperations(/** @type {any} */ ({ recipes: 'nope' }))).toEqual([])
  })
})

describe('availableScopes', () => {
  it('returns project before global', () => {
    expect(availableScopes(npm, 'install')).toEqual(['project', 'global'])
  })

  it('omits project scope where the ecosystem has none', () => {
    expect(availableScopes(oci, 'install')).toEqual(['global'])
  })

  it('is scoped to the operation asked about', () => {
    expect(availableScopes(maven, 'publish')).toEqual(['project'])
    expect(availableScopes(maven, 'install')).toEqual(['project', 'global'])
  })
})

describe('availableVariants', () => {
  it('keeps the server-declared display order', () => {
    expect(availableVariants(maven, 'install', 'project').map((v) => v.id)).toEqual([
      'maven',
      'gradle-groovy',
      'gradle-kotlin',
    ])
  })

  it('drops variants that have no recipe in this cell', () => {
    // Only Maven itself publishes at global scope, and only Maven/Gradle-Groovy publish at all.
    expect(availableVariants(maven, 'publish', 'project').map((v) => v.id)).toEqual([
      'maven',
      'gradle-groovy',
    ])
    expect(availableVariants(maven, 'install', 'global').map((v) => v.id)).toEqual(['maven'])
  })
})

describe('selectRecipe', () => {
  it('finds the exact cell', () => {
    const found = selectRecipe(npm, 'publish', 'global', 'npm')
    expect(found?.operation).toBe('publish')
    expect(found?.scope).toBe('global')
  })

  it('returns null for a cell that does not exist', () => {
    expect(selectRecipe(golang, 'publish', 'project', 'go')).toBeNull()
    expect(selectRecipe(npm, 'install', 'project', 'pnpm')).toBeNull()
  })
})

describe('reconcileSelection', () => {
  it('leaves a valid selection untouched', () => {
    expect(reconcileSelection(npm, { operation: 'publish', scope: 'global', variant: 'npm' })).toEqual({
      operation: 'publish',
      scope: 'global',
      variant: 'npm',
    })
  })

  it('falls back to install when the ecosystem cannot publish', () => {
    expect(
      reconcileSelection(golang, { operation: 'publish', scope: 'project', variant: 'go' }),
    ).toEqual({ operation: 'install', scope: 'project', variant: 'go' })
  })

  it('falls back to global when the ecosystem has no project scope', () => {
    expect(
      reconcileSelection(oci, { operation: 'install', scope: 'project', variant: 'docker' }),
    ).toEqual({ operation: 'install', scope: 'global', variant: 'docker' })
  })

  it('falls back to the first variant when the carried one has no recipe here', () => {
    // Gradle Kotlin installs but does not publish, so switching to publish has to move off it.
    expect(
      reconcileSelection(maven, { operation: 'publish', scope: 'project', variant: 'gradle-kotlin' }),
    ).toEqual({ operation: 'publish', scope: 'project', variant: 'maven' })
  })

  it('reconciles every axis at once when switching ecosystem', () => {
    // A selection carried over from Maven lands on Docker, which shares none of its axes.
    expect(
      reconcileSelection(oci, { operation: 'publish', scope: 'project', variant: 'gradle-kotlin' }),
    ).toEqual({ operation: 'publish', scope: 'global', variant: 'docker' })
  })

  it('returns the selection unchanged when there is nothing to reconcile against', () => {
    const selection = { operation: 'install', scope: 'project', variant: 'npm' }
    expect(reconcileSelection(null, selection)).toBe(selection)
  })
})

describe('tokenCommand', () => {
  it('builds an export line for an envVar recipe', () => {
    expect(tokenCommand({ kind: 'envVar', envVar: 'NPM_TOKEN', command: null }, 'abc123')).toBe(
      'export NPM_TOKEN=abc123',
    )
  })

  it('substitutes into a command recipe, including every occurrence', () => {
    expect(
      tokenCommand(
        { kind: 'command', envVar: null, command: 'export A=<token>\nexport B=<token>' },
        'abc123',
      ),
    ).toBe('export A=abc123\nexport B=abc123')
  })

  it('keeps the placeholder visible when no token has been minted', () => {
    expect(tokenCommand({ kind: 'envVar', envVar: 'NPM_TOKEN', command: null }, null)).toBe(
      'export NPM_TOKEN=<token>',
    )
  })

  it('has no command for a literal recipe, whose token lives in the file', () => {
    expect(tokenCommand({ kind: 'literal', envVar: null, command: null }, 'abc123')).toBeNull()
    expect(tokenCommand(null, 'abc123')).toBeNull()
  })
})

describe('fileBody', () => {
  const secret = { path: '~/.npmrc', locationHint: 'homeDir', language: 'ini', body: 'a=<token>\nb=<token>', secretBearing: true }
  const plain = { path: '.npmrc', locationHint: 'repoRoot', language: 'ini', body: 'a=${NPM_TOKEN}', secretBearing: false }

  it('substitutes every occurrence into a secret-bearing file', () => {
    expect(fileBody(secret, 'abc123')).toBe('a=abc123\nb=abc123')
  })

  it('leaves the placeholder in place when no token has been minted', () => {
    // An empty substitution would render as a syntactically valid but silently broken config.
    expect(fileBody(secret, null)).toBe('a=<token>\nb=<token>')
  })

  it('never touches a committable file, even when a token is available', () => {
    expect(fileBody(plain, 'abc123')).toBe('a=${NPM_TOKEN}')
  })
})
