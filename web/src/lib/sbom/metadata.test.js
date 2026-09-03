import { describe, it, expect } from 'vitest'
import { componentLinksOf, hasComponentMetadata } from './metadata.js'

describe('componentLinksOf', () => {
  it('returns links in a fixed order, skipping the kinds the document omitted', () => {
    const links = componentLinksOf({
      distributionUrl: 'https://example.com/dist.tgz',
      websiteUrl: 'https://example.com/home',
    })
    // Order is the module's, not the payload's, so two components never render their links in
    // different orders just because their producers serialized them differently.
    expect(links).toEqual([
      { key: 'website', url: 'https://example.com/home' },
      { key: 'distribution', url: 'https://example.com/dist.tgz' },
    ])
  })

  it('drops non-string and empty values rather than rendering a broken link', () => {
    expect(componentLinksOf({ websiteUrl: '', vcsUrl: null, issueTrackerUrl: 42 })).toEqual([])
  })

  it('tolerates a missing item', () => {
    expect(componentLinksOf(undefined)).toEqual([])
    expect(componentLinksOf(null)).toEqual([])
  })
})

describe('hasComponentMetadata', () => {
  it('is false for a row that carries none of it', () => {
    // The case that matters most: every row written before ingest captured these fields. The
    // panel must show no section at all, not a heading with nothing under it.
    expect(hasComponentMetadata({ name: 'x', version: '1.0.0', purl: 'pkg:npm/x@1.0.0' })).toBe(false)
    expect(hasComponentMetadata(null)).toBe(false)
  })

  it.each([
    ['description', { description: 'a library' }],
    ['author', { author: 'Ada' }],
    ['copyright', { copyright: '(c) 2016' }],
    ['group', { group: '@scoped' }],
    ['a link', { vcsUrl: 'https://example.com/repo' }],
    ['hashes alone', { hashes: [{ alg: 'SHA-256', content: 'abc' }] }],
    ['a version range', { versionRange: 'vers:npm/>=1.6.0|<2.0.0' }],
    ['a declared isExternal', { isExternal: true }],
  ])('is true when the row carries %s', (_label, item) => {
    expect(hasComponentMetadata(item)).toBe(true)
  })

  it('is false for an empty hashes array', () => {
    expect(hasComponentMetadata({ hashes: [] })).toBe(false)
  })

  it.each([
    ['null', null],
    ['undefined', undefined],
    ['a declared false', false],
  ])('is false when isExternal is %s', (_label, isExternal) => {
    // Every document below CycloneDX 1.7 leaves this unset, so treating absence as a fact to
    // render would open the section on essentially every row in an existing inventory. A
    // declared false is not worth a section either: it is the specification's own default.
    expect(hasComponentMetadata({ isExternal })).toBe(false)
  })
})
