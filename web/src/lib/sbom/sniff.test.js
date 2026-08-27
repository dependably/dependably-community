import { describe, it, expect } from 'vitest'
import { detectDocumentKind, sniffDocumentText, DOCUMENT_KIND_ENDPOINT } from './sniff.js'

describe('detectDocumentKind', () => {
  it('classifies a SARIF log by runs[]', () => {
    expect(detectDocumentKind({ version: '2.1.0', runs: [] })).toBe('sarif')
    expect(detectDocumentKind({ runs: [{ tool: {} }] })).toBe('sarif')
  })

  it('classifies an OpenVEX document by @context', () => {
    expect(detectDocumentKind({ '@context': 'https://openvex.dev/ns/v0.2.0', statements: [] })).toBe('vex')
    // Case-insensitive — some producers emit the host in a different case.
    expect(detectDocumentKind({ '@context': 'https://OpenVEX.dev/ns' })).toBe('vex')
  })

  it('classifies a CycloneDX document with components as sbom', () => {
    expect(detectDocumentKind({
      bomFormat: 'CycloneDX', specVersion: '1.6',
      components: [{ name: 'left-pad', type: 'library' }],
    })).toBe('sbom')
  })

  it('classifies a CycloneDX document with components AND vulnerabilities as sbom (VDR)', () => {
    expect(detectDocumentKind({
      bomFormat: 'CycloneDX', specVersion: '1.6',
      components: [{ name: 'left-pad' }],
      vulnerabilities: [{ id: 'CVE-2024-0001' }],
    })).toBe('sbom')
  })

  it('classifies a CycloneDX document with vulnerabilities but no components as vex', () => {
    expect(detectDocumentKind({
      bomFormat: 'CycloneDX', specVersion: '1.6',
      vulnerabilities: [{ id: 'CVE-2024-0001', analysis: { state: 'not_affected' } }],
    })).toBe('vex')
  })

  it('classifies a CycloneDX document with neither components nor vulnerabilities as sbom (empty inventory)', () => {
    expect(detectDocumentKind({ bomFormat: 'CycloneDX', specVersion: '1.6' })).toBe('sbom')
  })

  it('returns unknown for unrecognised shapes, null, and non-objects', () => {
    expect(detectDocumentKind({ foo: 'bar' })).toBe('unknown')
    expect(detectDocumentKind(null)).toBe('unknown')
    expect(detectDocumentKind(undefined)).toBe('unknown')
    expect(detectDocumentKind('not an object')).toBe('unknown')
    expect(detectDocumentKind(42)).toBe('unknown')
  })
})

describe('sniffDocumentText', () => {
  it('parses valid JSON and classifies it', () => {
    const result = sniffDocumentText(JSON.stringify({ runs: [] }))
    expect(result.kind).toBe('sarif')
    expect(result.parseError).toBeNull()
    expect(result.parsed).toEqual({ runs: [] })
  })

  it('reports a parse error and kind unknown for invalid JSON, without throwing', () => {
    const result = sniffDocumentText('{ not valid json')
    expect(result.kind).toBe('unknown')
    expect(result.parsed).toBeNull()
    expect(typeof result.parseError).toBe('string')
    expect(result.parseError?.length).toBeGreaterThan(0)
  })
})

describe('DOCUMENT_KIND_ENDPOINT', () => {
  it('maps every recognised kind to its own endpoint, and unknown to sbom as a safe default', () => {
    expect(DOCUMENT_KIND_ENDPOINT.sbom).toBe('sbom')
    expect(DOCUMENT_KIND_ENDPOINT.vex).toBe('vex')
    expect(DOCUMENT_KIND_ENDPOINT.sarif).toBe('sarif')
    expect(DOCUMENT_KIND_ENDPOINT.unknown).toBe('sbom')
  })
})
