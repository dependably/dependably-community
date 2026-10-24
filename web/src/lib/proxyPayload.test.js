import { describe, it, expect } from 'vitest'
import { buildProxyPayload } from './proxyPayload.js'

const base = {
  proxy_passthrough_enabled: true,
  max_osv_score_tolerance: '7.0',
  min_release_age_value: '2',
  min_release_age_unit: 'days',
  max_epss_tolerance: '',
  max_epss_percentile_tolerance: '',
  oci_scan_enforcement: 'block',
}

describe('buildProxyPayload', () => {
  it('omits ociScanEnforcement unless the caller is the Gates save', () => {
    const p = buildProxyPayload(base)
    expect('ociScanEnforcement' in p).toBe(false)
  })

  it('omits ociScanEnforcement from the Gates save when it is unchanged', () => {
    const p = buildProxyPayload(base, { includeOciScan: true, storedOciScan: 'block' })
    expect('ociScanEnforcement' in p).toBe(false)
  })

  it('sends ociScanEnforcement from the Gates save when it changed', () => {
    const p = buildProxyPayload({ ...base, oci_scan_enforcement: 'off' }, { includeOciScan: true, storedOciScan: 'block' })
    expect(p.ociScanEnforcement).toBe('off')
  })

  it('does not send a changed value from a non-Gates save', () => {
    const p = buildProxyPayload({ ...base, oci_scan_enforcement: 'warn' }, { storedOciScan: 'off' })
    expect('ociScanEnforcement' in p).toBe(false)
  })

  it('converts the age pair to hours and clears empty EPSS fields to null', () => {
    const p = buildProxyPayload(base)
    expect(p.minReleaseAgeHours).toBe(48)
    expect(p.maxEpssTolerance).toBeNull()
    expect(p.maxEpssPercentileTolerance).toBeNull()
  })
})
