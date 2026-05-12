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

  it('routeFor parses static paths back to (page, params)', () => {
    expect(routeFor('/packages')).toEqual({ page: 'packages', params: {} })
    expect(routeFor('/packages/')).toEqual({ page: 'packages', params: {} }) // trailing slash normalised
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
    expect(pathFor('system-tenants')).toBe('/')
    expect(routeFor('/users')).toEqual({ page: 'system-users', params: {} })
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
})
