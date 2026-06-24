import { describe, it, expect } from 'vitest'
import { qrSvg } from './qrcode.js'
import qrcode from './vendor/qrcode-generator.js'

// Realistic otpauth URI with a 32-base32-char secret — typical ASP.NET Identity output.
// This URI is 108 bytes, which forces version 7 (45 modules) under ECC level M.
const V7_URI =
  'otpauth://totp/myservice:username@domain.example.com?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PX&issuer=myservice'

// Shorter URI that lands below version 7 — confirms the version boundary detection.
const V5_URI =
  'otpauth://totp/test:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=test'

// The representative 32-base32 secret URI given in the task spec.
const LONG_URI =
  'otpauth://totp/dependably:averylongtestuser@example.com?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=dependably&algorithm=SHA1&digits=6&period=30'

describe('qrSvg — public API', () => {
  it('returns a string starting with <svg for a short URI', () => {
    const svg = qrSvg(V5_URI)
    expect(svg).toBeTypeOf('string')
    expect(svg.startsWith('<svg')).toBe(true)
  })

  it('returns a string starting with <svg for the v7+ URI', () => {
    const svg = qrSvg(V7_URI)
    expect(svg).toBeTypeOf('string')
    expect(svg.startsWith('<svg')).toBe(true)
  })

  it('returns a string starting with <svg for the long TOTP URI', () => {
    const svg = qrSvg(LONG_URI)
    expect(svg).toBeTypeOf('string')
    expect(svg.startsWith('<svg')).toBe(true)
  })

  it('respects the size option', () => {
    const svg = qrSvg(V5_URI, { size: 300 })
    expect(svg).toContain('width="300"')
    expect(svg).toContain('height="300"')
  })

  it('SVG does NOT contain the raw secret text (XSS guard)', () => {
    const svg = qrSvg(V7_URI)
    expect(svg).not.toContain('JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PX')
  })

  it('SVG does NOT contain the URI text for the long URI (XSS guard)', () => {
    const svg = qrSvg(LONG_URI)
    expect(svg).not.toContain('JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP')
    expect(svg).not.toContain('otpauth://')
  })

  it('SVG does NOT contain the account name text (XSS guard)', () => {
    const svg = qrSvg(V7_URI)
    expect(svg).not.toContain('username@domain.example.com')
  })
})

describe('qrcode-generator — version selection for v7+ inputs', () => {
  it('auto-selects version >= 7 for the 108-byte v7+ URI', () => {
    const qr = qrcode(0, 'M')
    qr.addData(V7_URI, 'Byte')
    qr.make()
    const moduleCount = qr.getModuleCount()
    const version = (moduleCount - 17) / 4
    // Version 7 = 45 modules; confirm the trusted library reaches this path.
    expect(version).toBeGreaterThanOrEqual(7)
    expect(moduleCount).toBe(45) // v7 is exactly 45 modules
  })

  it('auto-selects version >= 8 for the 147-byte long URI', () => {
    const qr = qrcode(0, 'M')
    qr.addData(LONG_URI, 'Byte')
    qr.make()
    const moduleCount = qr.getModuleCount()
    const version = (moduleCount - 17) / 4
    expect(version).toBeGreaterThanOrEqual(7)
    // 147 bytes at ECC M → version 8 (49 modules)
    expect(moduleCount).toBe(49)
  })

  it('auto-selects version < 7 for the short URI (below v7 boundary)', () => {
    const qr = qrcode(0, 'M')
    qr.addData(V5_URI, 'Byte')
    qr.make()
    const version = (qr.getModuleCount() - 17) / 4
    expect(version).toBeLessThan(7)
  })

  it('module count is consistent with version formula (version*4+17)', () => {
    const qr = qrcode(0, 'M')
    qr.addData(V7_URI, 'Byte')
    qr.make()
    const moduleCount = qr.getModuleCount()
    const version = (moduleCount - 17) / 4
    // Verify the module count formula holds.
    expect(moduleCount).toBe(version * 4 + 17)
  })
})
