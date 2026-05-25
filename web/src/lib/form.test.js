import { describe, it, expect, vi } from 'vitest'
import { extractErrorMessage, submitForm } from './form.js'

describe('extractErrorMessage', () => {
  it('returns empty string for null', () => {
    expect(extractErrorMessage(null)).toBe('')
  })

  it('returns empty string for undefined', () => {
    expect(extractErrorMessage(undefined)).toBe('')
  })

  it('prefers body.detail when present (ApiError raw-body fallback)', () => {
    const e = { body: { detail: 'from body' }, message: 'msg', detail: 'top' }
    expect(extractErrorMessage(e)).toBe('from body')
  })

  it('falls back to message when body.detail is missing', () => {
    const e = new Error('boom')
    expect(extractErrorMessage(e)).toBe('boom')
  })

  it('falls back to message when body exists but has no detail', () => {
    const e = { body: {}, message: 'fallback msg' }
    expect(extractErrorMessage(e)).toBe('fallback msg')
  })

  it('falls back to top-level detail when message is absent', () => {
    const e = { detail: 'top-level detail' }
    expect(extractErrorMessage(e)).toBe('top-level detail')
  })

  it('stringifies an arbitrary object when no message/detail keys exist', () => {
    const e = { foo: 'bar' }
    expect(extractErrorMessage(e)).toBe('[object Object]')
  })

  it('stringifies a plain string thrown value', () => {
    // Strings have no .body/.message/.detail → fall through to String(e)
    expect(extractErrorMessage('raw string error')).toBe('raw string error')
  })

  it('handles a number-like throw via String()', () => {
    expect(extractErrorMessage(42)).toBe('42')
  })

  it('does not blow up when body is itself nullish', () => {
    const e = { body: null, message: 'ok' }
    expect(extractErrorMessage(e)).toBe('ok')
  })
})

describe('submitForm — happy path', () => {
  it('returns true and runs onSuccess with fn result', async () => {
    const fn = vi.fn().mockResolvedValue({ id: 1 })
    const setSaving = vi.fn()
    const setError = vi.fn()
    const onSuccess = vi.fn()

    const ok = await submitForm(fn, { setSaving, setError, onSuccess })

    expect(ok).toBe(true)
    expect(fn).toHaveBeenCalledOnce()
    expect(onSuccess).toHaveBeenCalledWith({ id: 1 })
    // State machine: error cleared, saving toggled on then off.
    expect(setError).toHaveBeenCalledWith('')
    expect(setSaving).toHaveBeenNthCalledWith(1, true)
    expect(setSaving).toHaveBeenLastCalledWith(false)
  })

  it('works when called with no opts at all (all callbacks optional)', async () => {
    const fn = vi.fn().mockResolvedValue('ok')
    const ok = await submitForm(fn)
    expect(ok).toBe(true)
    expect(fn).toHaveBeenCalledOnce()
  })

  it('works when opts is provided but onSuccess is omitted', async () => {
    const fn = vi.fn().mockResolvedValue('ok')
    const setSaving = vi.fn()
    const ok = await submitForm(fn, { setSaving })
    expect(ok).toBe(true)
    expect(setSaving).toHaveBeenCalledWith(true)
    expect(setSaving).toHaveBeenLastCalledWith(false)
  })
})

describe('submitForm — error path', () => {
  it('returns false and reports error message via setError', async () => {
    const fn = vi.fn().mockRejectedValue(new Error('validation failed'))
    const setSaving = vi.fn()
    const setError = vi.fn()
    const onSuccess = vi.fn()

    const ok = await submitForm(fn, { setSaving, setError, onSuccess })

    expect(ok).toBe(false)
    expect(onSuccess).not.toHaveBeenCalled()
    // setError was called twice: '' on entry, then the extracted message on failure.
    expect(setError).toHaveBeenNthCalledWith(1, '')
    expect(setError).toHaveBeenNthCalledWith(2, 'validation failed')
    // Saving still toggles off in the finally block.
    expect(setSaving).toHaveBeenNthCalledWith(1, true)
    expect(setSaving).toHaveBeenLastCalledWith(false)
  })

  it('uses body.detail when fn throws an ApiError-shaped object', async () => {
    const apiErr = { body: { detail: 'slow down' }, message: 'Too Many Requests' }
    const fn = vi.fn().mockRejectedValue(apiErr)
    const setError = vi.fn()
    const ok = await submitForm(fn, { setError })
    expect(ok).toBe(false)
    expect(setError).toHaveBeenLastCalledWith('slow down')
  })

  it('still returns false when no callbacks are provided on failure', async () => {
    const fn = vi.fn().mockRejectedValue(new Error('network'))
    const ok = await submitForm(fn)
    expect(ok).toBe(false)
  })

  it('catches onSuccess throws as failures (onSuccess is inside the try block)', async () => {
    // Documents current behavior: onSuccess throwing is treated like fn throwing — caught,
    // reported via setError, returns false. The finally still toggles saving off.
    const fn = vi.fn().mockResolvedValue('ok')
    const setSaving = vi.fn()
    const onSuccess = vi.fn(() => { throw new Error('post-success boom') })
    const setError = vi.fn()

    const ok = await submitForm(fn, { setSaving, setError, onSuccess })

    expect(ok).toBe(false)
    expect(setError).toHaveBeenLastCalledWith('post-success boom')
    expect(setSaving).toHaveBeenNthCalledWith(1, true)
    expect(setSaving).toHaveBeenLastCalledWith(false)
  })
})

describe('submitForm — state machine progression', () => {
  it('order: setError("") → setSaving(true) → fn → onSuccess → setSaving(false)', async () => {
    const calls = []
    const fn = vi.fn(async () => { calls.push('fn'); return 'r' })
    const setSaving = vi.fn(v => calls.push(`saving:${v}`))
    const setError = vi.fn(v => calls.push(`error:${JSON.stringify(v)}`))
    const onSuccess = vi.fn(() => calls.push('onSuccess'))

    await submitForm(fn, { setSaving, setError, onSuccess })

    expect(calls).toEqual([
      'error:""',
      'saving:true',
      'fn',
      'onSuccess',
      'saving:false',
    ])
  })

  it('error order: setError("") → setSaving(true) → fn-throws → setError(msg) → setSaving(false)', async () => {
    const calls = []
    const fn = vi.fn(async () => { calls.push('fn'); throw new Error('nope') })
    const setSaving = vi.fn(v => calls.push(`saving:${v}`))
    const setError = vi.fn(v => calls.push(`error:${JSON.stringify(v)}`))

    await submitForm(fn, { setSaving, setError })

    expect(calls).toEqual([
      'error:""',
      'saving:true',
      'fn',
      'error:"nope"',
      'saving:false',
    ])
  })
})
