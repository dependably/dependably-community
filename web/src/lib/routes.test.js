import { describe, it, expect, beforeEach } from 'vitest'
import { useRouter, pathFor, routeFor, routesEqual } from './routes.js'

describe('routes — tenant table', () => {
  beforeEach(() => useRouter('tenant'))

  it('pathFor returns the canonical path for a tenant page', () => {
    expect(pathFor('dashboard')).toBe('/')
    expect(pathFor('packages')).toBe('/packages')
    expect(pathFor('users')).toBe('/users')
  })

  it('pathFor builds the version-detail path with URL-encoded params', () => {
    const url = pathFor('version-detail', { ecosystem: 'npm', name: '@scope/pkg' })
    expect(url).toBe('/package/npm/%40scope/pkg')
  })

  it('pathFor falls back to "/" for unknown pages', () => {
    expect(pathFor('does-not-exist')).toBe('/')
  })

  it('pathFor("version-detail") with no params yields empty segments via nullish coalescing', () => {
    // Exercises the `params.ecosystem ?? ''` and `params.name ?? ''` branches.
    expect(pathFor('version-detail')).toBe('/package//')
  })

  it('pathFor("version-detail") with explicit nullish param values still falls back to empty string', () => {
    expect(pathFor('version-detail', { ecosystem: null, name: undefined })).toBe('/package//')
  })

  it('routeFor parses static paths back to (page, params)', () => {
    expect(routeFor('/packages')).toEqual({ page: 'packages', params: {} })
    expect(routeFor('/packages/')).toEqual({ page: 'packages', params: {} }) // trailing slash normalised
  })

  it('routeFor("/") returns dashboard without stripping the trailing slash', () => {
    // Hits the `path.length > 1` short-circuit (false) in the trailing-slash normaliser.
    expect(routeFor('/')).toEqual({ page: 'dashboard', params: {} })
  })

  it('routeFor parses version-detail paths and decodes the params', () => {
    expect(routeFor('/package/npm/%40scope/pkg')).toEqual({
      page: 'version-detail',
      params: { ecosystem: 'npm', name: '@scope/pkg' },
    })
  })

  it('routeFor returns null for unknown paths or non-strings', () => {
    expect(routeFor('/totally-bogus')).toBeNull()
    expect(routeFor(undefined)).toBeNull()
  })
})

describe('routes — system table', () => {
  beforeEach(() => useRouter('system'))

  it('pathFor and routeFor use the system page set when active', () => {
    // Canonical home is the operator dashboard; system-tenants lives at /tenants.
    expect(pathFor('system-dashboard')).toBe('/')
    expect(pathFor('system-tenants')).toBe('/tenants')
    expect(routeFor('/')).toEqual({ page: 'system-dashboard', params: {} })
    expect(routeFor('/tenants')).toEqual({ page: 'system-tenants', params: {} })
    expect(routeFor('/users')).toEqual({ page: 'system-users', params: {} })
  })

  it('pathFor("version-detail") in system mode does not match the tenant-only branch', () => {
    // Hits the `activeTable === 'tenant'` short-circuit (false) in pathFor; falls through to
    // the static lookup and ultimately the '/' fallback since version-detail isn't a system page.
    expect(pathFor('version-detail', { ecosystem: 'npm', name: 'foo' })).toBe('/')
  })

  it('routeFor("/package/...") in system mode falls through to static lookup', () => {
    // Exercises the `activeTable === 'tenant'` guard around the version-detail regex.
    expect(routeFor('/package/npm/foo')).toBeNull()
  })
})

describe('routes — useRouter', () => {
  it('rejects unknown router names', () => {
    expect(() => useRouter('marketing')).toThrow(/unknown router/)
  })
})

describe('routesEqual', () => {
  it('treats nullish routes as not-equal', () => {
    expect(routesEqual(null, { page: 'x' })).toBe(false)
    expect(routesEqual({ page: 'x' }, undefined)).toBe(false)
    expect(routesEqual(null, null)).toBe(false)
  })

  it('compares pages and parameter shapes structurally', () => {
    const a = { page: 'version-detail', params: { ecosystem: 'npm', name: 'foo' } }
    const b = { page: 'version-detail', params: { ecosystem: 'npm', name: 'foo' } }
    const c = { page: 'version-detail', params: { ecosystem: 'pypi', name: 'foo' } }
    expect(routesEqual(a, b)).toBe(true)
    expect(routesEqual(a, c)).toBe(false)
  })

  it('returns false when param key sets differ in size', () => {
    const a = { page: 'p', params: { x: 1 } }
    const b = { page: 'p', params: { x: 1, y: 2 } }
    expect(routesEqual(a, b)).toBe(false)
  })

  it('treats missing params as an empty object (nullish coalescing branch)', () => {
    // Hits the `a.params ?? {}` and `b.params ?? {}` branches when params is absent.
    expect(routesEqual({ page: 'p' }, { page: 'p' })).toBe(true)
    expect(routesEqual({ page: 'p' }, { page: 'p', params: { x: 1 } })).toBe(false)
  })

  it('returns false when pages match but a param value differs at the same key', () => {
    const a = { page: 'p', params: { x: 1 } }
    const b = { page: 'p', params: { x: 2 } }
    expect(routesEqual(a, b)).toBe(false)
  })
})
