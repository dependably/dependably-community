import { describe, it, expect } from 'vitest'
import { ECOSYSTEMS, ECO_LABEL } from './ecosystems.js'

describe('ecosystems vocabulary', () => {
  it('exposes the six supported ecosystem keys in priority order', () => {
    expect(ECOSYSTEMS).toEqual(['pypi', 'npm', 'nuget', 'maven', 'rpm', 'oci'])
  })

  it('has a display label for every ecosystem key', () => {
    for (const key of ECOSYSTEMS) {
      expect(ECO_LABEL[key]).toBeTruthy()
    }
    expect(Object.keys(ECO_LABEL).sort()).toEqual([...ECOSYSTEMS].sort())
  })

  it('renders oci as Docker (the only key/label divergence)', () => {
    expect(ECO_LABEL.oci).toBe('Docker')
    expect(ECO_LABEL.pypi).toBe('PyPI')
  })
})
