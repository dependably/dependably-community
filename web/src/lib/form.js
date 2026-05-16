/**
 * Extract a human-readable message from a thrown value.
 *
 * ApiError (web/src/lib/api.js) already sets `message = body.detail || body.title || statusText`,
 * so for normal API failures `e.message` is the right answer. This helper also handles the
 * raw-body fallback (`e.body?.detail`) and stringifies anything non-Error so call sites
 * don't have to do their own defensive checks.
 */
export function extractErrorMessage(e) {
  if (!e) return ''
  return e?.body?.detail || e?.message || e?.detail || String(e)
}

/**
 * Wrap an async submit operation: manages a saving flag, an error string, and runs an
 * onSuccess callback when the operation resolves. Returns true on success, false on failure.
 *
 * Use the setters to bind to local component state:
 *
 *   await submitForm(() => api.updateThing(payload), {
 *     setSaving: v => saving = v,
 *     setError:  v => error  = v,
 *     onSuccess: r => { success = 'Saved.'; reload() },
 *   })
 *
 * Use this in modals/forms with a single submit; for pages with many independent submits,
 * extractErrorMessage alone is usually enough.
 */
/**
 * @template T
 * @param {() => Promise<T>} fn
 * @param {{ setSaving?: (v: boolean) => void, setError?: (v: string) => void, onSuccess?: (result: T) => void }} [opts]
 * @returns {Promise<boolean>}
 */
export async function submitForm(fn, opts = {}) {
  const { setSaving, setError, onSuccess } = opts
  setError?.('')
  setSaving?.(true)
  try {
    const result = await fn()
    onSuccess?.(result)
    return true
  } catch (e) {
    setError?.(extractErrorMessage(e))
    return false
  } finally {
    setSaving?.(false)
  }
}
