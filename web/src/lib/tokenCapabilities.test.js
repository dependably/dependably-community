import { describe, it, expect } from 'vitest'
import { PACKAGE_PRESETS, PRIVILEGED_PRESETS, presetToCapabilities, capabilitiesToLabel, capabilitiesToText } from './tokenCapabilities.js'

describe('presetToCapabilities', () => {
  it('pull → read-only capabilities', () => {
    expect(presetToCapabilities('pull')).toEqual(['read:metadata', 'read:artifact', 'read:packages'])
  })

  it('push → publish-only (no read)', () => {
    expect(presetToCapabilities('push')).toEqual(['publish:*'])
  })

  it('both → read + publish wildcard', () => {
    expect(presetToCapabilities('both')).toEqual(['read:metadata', 'read:artifact', 'read:packages', 'publish:*'])
  })

  it('sbom → sbom:upload only, nothing else', () => {
    expect(presetToCapabilities('sbom')).toEqual(['sbom:upload'])
  })

  it('sbom is a privileged preset, distinct from push, which does not silently grant it', () => {
    // sbom:upload is in AdminCaps — only an admin/owner token may carry it — so it sits with
    // the privileged presets, never the package ones a member sees. It is also deliberately its
    // own preset rather than folded into `push`: doing so would widen every existing push/both
    // token's meaning. This is what a mutant that adds 'sbom:upload' to PRESET_CAPS.push
    // (instead of giving it its own key) would break: `push` would start reporting a capability
    // list containing the SBOM grant, and `sbom` would drop off the privileged-preset list if it
    // were removed in favour of that shortcut.
    expect(presetToCapabilities('push')).not.toContain('sbom:upload')
    expect(presetToCapabilities('both')).not.toContain('sbom:upload')
    expect(PRIVILEGED_PRESETS).toContain('sbom')
    expect(PACKAGE_PRESETS).not.toContain('sbom')
  })

  it('admin → tenant configure + read tenant', () => {
    expect(presetToCapabilities('admin')).toEqual(['tenant:configure', 'read:tenant'])
  })

  it('audit → audit-log read only', () => {
    expect(presetToCapabilities('audit')).toEqual(['read:audit'])
  })

  it('unknown preset falls back to pull (conservative default)', () => {
    expect(presetToCapabilities('something-else')).toEqual(['read:metadata', 'read:artifact', 'read:packages'])
    expect(presetToCapabilities(undefined)).toEqual(['read:metadata', 'read:artifact', 'read:packages'])
  })
})

describe('capabilitiesToLabel', () => {
  it('null/missing → em-dash', () => {
    expect(capabilitiesToLabel(null)).toBe('—')
    expect(capabilitiesToLabel(undefined)).toBe('—')
    expect(capabilitiesToLabel('')).toBe('—')
  })

  it('unparseable JSON → em-dash', () => {
    expect(capabilitiesToLabel('not-json')).toBe('—')
  })

  it('empty array → em-dash', () => {
    expect(capabilitiesToLabel('[]')).toBe('—')
  })

  it('non-array JSON → em-dash', () => {
    expect(capabilitiesToLabel('{"foo":1}')).toBe('—')
  })

  it('read-only → pull', () => {
    expect(capabilitiesToLabel('["read:metadata","read:artifact","read:packages"]')).toBe('pull')
  })

  it('read + publish → both', () => {
    expect(capabilitiesToLabel('["read:metadata","read:artifact","read:packages","publish:*"]')).toBe('both')
  })

  it('publish without read → push', () => {
    expect(capabilitiesToLabel('["publish:*"]')).toBe('push')
  })

  it('tenant:configure → admin', () => {
    expect(capabilitiesToLabel('["tenant:configure","read:tenant"]')).toBe('admin')
  })

  it('read:audit alone → audit', () => {
    expect(capabilitiesToLabel('["read:audit"]')).toBe('audit')
  })

  it('sbom:upload alone → sbom, distinct from push', () => {
    expect(capabilitiesToLabel('["sbom:upload"]')).toBe('sbom')
    expect(capabilitiesToLabel('["publish:*","sbom:upload"]')).toBe('custom')
  })

  it('order does not matter — the set does', () => {
    expect(capabilitiesToLabel('["read:artifact","read:metadata","read:packages"]')).toBe('pull')
    expect(capabilitiesToLabel('["publish:*","read:artifact","read:metadata","read:packages"]')).toBe('both')
  })

  it('anything that is not exactly a preset is custom, never an approximation', () => {
    // Inferring a preset from the presence of any publish: entry would make these two
    // indistinguishable in the UI, and only publish:* can push an OCI image.
    expect(capabilitiesToLabel('["publish:nuget"]')).toBe('custom')
    expect(capabilitiesToLabel('["publish:oci","publish:nuget"]')).toBe('custom')
    expect(capabilitiesToLabel('["read:metadata","publish:npm"]')).toBe('custom')
    // A superset of a preset is not that preset: this one can also delete.
    expect(capabilitiesToLabel('["publish:*","yank:*"]')).toBe('custom')
    // tenant:configure no longer swallows the label and hides publish rights.
    expect(capabilitiesToLabel('["tenant:configure","publish:*"]')).toBe('custom')
  })

  it('a value the server reads as deny-all shows as em-dash, not a label', () => {
    // TokenRecord.CapabilitySet deserializes to string[], so one non-string element throws and
    // the whole token grants nothing (pinned server-side by
    // CapabilitiesTests.CapabilitySet_MalformedOrMixedTypeValue_GrantsNothing). A partial render
    // would claim a grant the credential does not have, so a malformed array voids the display.
    expect(capabilitiesToLabel('[1,2,3]')).toBe('—')
    expect(capabilitiesToLabel('["read:metadata",1]')).toBe('—')
    expect(capabilitiesToText('["read:metadata",1]')).toBe('—')
  })

  it('a blank entry is dropped without voiding the rest, as the server does', () => {
    expect(capabilitiesToLabel('["read:metadata","read:artifact","read:packages","  "]')).toBe('pull')
    expect(capabilitiesToText('["read:metadata","  "]')).toBe('read:metadata')
  })
})

describe('capabilitiesToText', () => {
  it('renders the stored grant, sorted', () => {
    expect(capabilitiesToText('["publish:*","read:metadata"]')).toBe('publish:*, read:metadata')
    expect(capabilitiesToText('["publish:nuget"]')).toBe('publish:nuget')
  })

  it('distinguishes the two tokens the badge cannot', () => {
    expect(capabilitiesToText('["publish:*"]')).not.toBe(capabilitiesToText('["publish:nuget"]'))
  })

  it('missing, unparseable, empty, and non-array all read as em-dash', () => {
    expect(capabilitiesToText(null)).toBe('—')
    expect(capabilitiesToText('')).toBe('—')
    expect(capabilitiesToText('not-json')).toBe('—')
    expect(capabilitiesToText('[]')).toBe('—')
    expect(capabilitiesToText('{"foo":1}')).toBe('—')
    expect(capabilitiesToText('[1,2,3]')).toBe('—')
  })
})
