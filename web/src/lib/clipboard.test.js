import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { copyToClipboard } from './clipboard.js'

describe('copyToClipboard', () => {
  beforeEach(() => {
    // jsdom doesn't define isSecureContext; default the global to false so each
    // test starts in the legacy-fallback path unless it opts into the secure path.
    Object.defineProperty(window, 'isSecureContext', { value: false, configurable: true })
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('returns false for null/undefined without touching the DOM', async () => {
    expect(await copyToClipboard(null)).toBe(false)
    expect(await copyToClipboard(undefined)).toBe(false)
  })

  it('uses navigator.clipboard.writeText in a secure context', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined)
    Object.defineProperty(window, 'isSecureContext', { value: true, configurable: true })
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true })

    const ok = await copyToClipboard('hello')

    expect(ok).toBe(true)
    expect(writeText).toHaveBeenCalledWith('hello')
  })

  it('falls back to the legacy textarea path on insecure contexts', async () => {
    document.execCommand = vi.fn().mockReturnValue(true)

    const ok = await copyToClipboard('plain http payload')

    expect(ok).toBe(true)
    expect(document.execCommand).toHaveBeenCalledWith('copy')
    // textarea should be removed after the copy attempt
    expect(document.querySelectorAll('textarea').length).toBe(0)
  })

  it('coerces non-string values to strings before writing', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined)
    Object.defineProperty(window, 'isSecureContext', { value: true, configurable: true })
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true })

    await copyToClipboard(42)

    expect(writeText).toHaveBeenCalledWith('42')
  })
})
