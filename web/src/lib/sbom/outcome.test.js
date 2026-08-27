import { describe, it, expect } from 'vitest'
import { orderStagedFiles, describeSuccess, describeFailure } from './outcome.js'

describe('orderStagedFiles', () => {
  it('sorts sbom files before vex/sarif files', () => {
    const staged = [
      { kind: 'sarif', file: 'results.sarif.json' },
      { kind: 'vex', file: 'vex.json' },
      { kind: 'sbom', file: 'sbom.json' },
    ]
    const ordered = orderStagedFiles(staged)
    expect(ordered[0].kind).toBe('sbom')
    expect(ordered.map(f => f.kind).slice(1).sort()).toEqual(['sarif', 'vex'])
  })

  it('is stable for two files of the same kind — original staged order survives', () => {
    const staged = [
      { kind: 'vex', file: 'vex-b.json' },
      { kind: 'sbom', file: 'sbom.json' },
      { kind: 'vex', file: 'vex-a.json' },
    ]
    expect(orderStagedFiles(staged).map(f => f.file)).toEqual(['sbom.json', 'vex-b.json', 'vex-a.json'])
  })

  it('does not mutate the input array', () => {
    const staged = [{ kind: 'sarif' }, { kind: 'sbom' }]
    const copy = [...staged]
    orderStagedFiles(staged)
    expect(staged).toEqual(copy)
  })

  it('treats an unrecognised kind like vex/sarif priority (after sbom)', () => {
    const staged = [{ kind: 'weird' }, { kind: 'sbom' }]
    expect(orderStagedFiles(staged).map(f => f.kind)).toEqual(['sbom', 'weird'])
  })
})

describe('describeSuccess', () => {
  it('describes a normal SBOM ingest with added/removed/unchanged counts', () => {
    const d = describeSuccess('sbom', { components: { total: 120, added: 118, removed: 0, unchanged: 2 } })
    expect(d).toEqual({ key: 'sbomUpload.outcome.detail.sbom', values: { added: 118, removed: 0, unchanged: 2, total: 120 } })
  })

  it('describes an idempotent byte-identical re-upload as the noop variant', () => {
    const d = describeSuccess('sbom', { components: { total: 120, added: 0, removed: 0, unchanged: 120 } })
    expect(d.key).toBe('sbomUpload.outcome.detail.sbomNoop')
    expect(d.values).toEqual({ total: 120 })
  })

  it('describes a VEX upload with applied/unmatched statement counts', () => {
    const d = describeSuccess('vex', { statements: { total: 5, applied: 4, unmatched: 1 } })
    expect(d).toEqual({ key: 'sbomUpload.outcome.detail.vex', values: { applied: 4, total: 5, unmatched: 1 } })
  })

  it('describes a SARIF upload with applied/unmatched result counts', () => {
    const d = describeSuccess('sarif', { results: { total: 10, applied: 10, unmatched: 0 } })
    expect(d).toEqual({ key: 'sbomUpload.outcome.detail.sarif', values: { applied: 10, total: 10, unmatched: 0 } })
  })

  it('falls back to zeroed counts when the response omits the expected section', () => {
    expect(describeSuccess('sbom', {})).toEqual({ key: 'sbomUpload.outcome.detail.sbomNoop', values: { total: 0 } })
    expect(describeSuccess('vex', {})).toEqual({ key: 'sbomUpload.outcome.detail.vex', values: { applied: 0, total: 0, unmatched: 0 } })
  })

  it('returns a generic descriptor for an unrecognised kind', () => {
    expect(describeSuccess('unknown', {})).toEqual({ key: 'sbomUpload.outcome.detail.generic', values: {} })
  })
})

describe('describeFailure', () => {
  it('prefers the server problem-detail text over the generic ApiError message', () => {
    const err = { status: 422, message: 'Unprocessable Entity', body: { detail: 'Unsupported CycloneDX spec version 0.9' } }
    expect(describeFailure(err)).toEqual({ text: 'Unsupported CycloneDX spec version 0.9', key: null, values: {} })
  })

  it('falls back to the ApiError message when the body has no detail field', () => {
    const err = { status: 500, message: 'Internal Server Error', body: null }
    expect(describeFailure(err)).toEqual({ text: 'Internal Server Error', key: null, values: {} })
  })

  it('surfaces a 422 kind-mismatch verbatim — the server verdict overrides a wrong client sniff', () => {
    // The client sniffed this file as sbom (chose /api/v1/sbom), but the server determined the
    // body was actually an OpenVEX document and rejected it — describeFailure must render the
    // server's rejection, not silently agree with the client's guess.
    const err = { status: 422, message: 'Unprocessable Entity', body: { detail: 'Document does not match a CycloneDX SBOM (bomFormat missing)' } }
    const d = describeFailure(err)
    expect(d.text).toBe('Document does not match a CycloneDX SBOM (bomFormat missing)')
  })

  it('falls back to a generic i18n key for a transport failure with no status/body (network error)', () => {
    const err = new TypeError('Failed to fetch')
    const d = describeFailure(err)
    expect(d.text).toBeNull()
    expect(d.key).toBe('sbomUpload.outcome.detail.error')
    expect(d.values.message).toBe('Failed to fetch')
  })
})

describe('mixed partial-failure batch (SBOM + SARIF + VEX, one deliberate failure)', () => {
  it('orders and independently describes a batch with one deliberate failure among successes', () => {
    const staged = [
      { kind: 'sarif', file: 'results.sarif.json' },
      { kind: 'sbom', file: 'sbom.json' },
      { kind: 'vex', file: 'vex.json' },
    ]
    const ordered = orderStagedFiles(staged)
    expect(ordered.map(f => f.file)).toEqual(['sbom.json', 'results.sarif.json', 'vex.json'])

    // Simulate the sequential submit loop's per-item outcome mapping. The SARIF file is the
    // deliberate failure (malformed reachability payload); the other two succeed — a batch must
    // not abort or coalesce this into one summary, each file gets its own independent outcome.
    const responses = {
      'sbom.json': { ok: true, kind: 'sbom', body: { components: { total: 3, added: 3, removed: 0, unchanged: 0 } } },
      'results.sarif.json': { ok: false, error: { status: 422, message: 'Unprocessable Entity', body: { detail: 'runs[0].results[0] missing partialFingerprints' } } },
      'vex.json': { ok: true, kind: 'vex', body: { statements: { total: 2, applied: 2, unmatched: 0 } } },
    }
    const outcomes = ordered.map(item => {
      const r = responses[item.file]
      return r.ok ? { file: item.file, status: 'accepted', ...describeSuccess(r.kind, r.body) }
                   : { file: item.file, status: 'rejected', ...describeFailure(r.error) }
    })

    expect(outcomes).toEqual([
      { file: 'sbom.json', status: 'accepted', key: 'sbomUpload.outcome.detail.sbom', values: { added: 3, removed: 0, unchanged: 0, total: 3 } },
      { file: 'results.sarif.json', status: 'rejected', text: 'runs[0].results[0] missing partialFingerprints', key: null, values: {} },
      { file: 'vex.json', status: 'accepted', key: 'sbomUpload.outcome.detail.vex', values: { applied: 2, total: 2, unmatched: 0 } },
    ])
    expect(outcomes.filter(o => o.status === 'accepted')).toHaveLength(2)
    expect(outcomes.filter(o => o.status === 'rejected')).toHaveLength(1)
  })
})
