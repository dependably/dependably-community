import { describe, it, expect, beforeEach, vi } from 'vitest'

vi.mock('./store.js', () => ({
  claimTransition: vi.fn(),
  settleTransition: vi.fn(),
}))

import { reportPageLoad } from './pageLoad.js'
import { claimTransition, settleTransition } from './store.js'

beforeEach(() => vi.clearAllMocks())

describe('reportPageLoad', () => {
  it('claims the transition while the page is still fetching', () => {
    reportPageLoad(7, true)

    expect(claimTransition).toHaveBeenCalledWith(7)
    expect(settleTransition).not.toHaveBeenCalled()
  })

  it('settles it once the data has landed', () => {
    reportPageLoad(7, false)

    expect(settleTransition).toHaveBeenCalledWith(7)
    expect(claimTransition).not.toHaveBeenCalled()
  })

  it('reports nothing without a token', () => {
    // A page rendered outside a RouteView — a test, a modal — has no transition to report to,
    // and reporting against one would commit a page the user never navigated to.
    /** @type {Array<number | null>} */
    const absentTokens = [null, /** @type {any} */ (undefined)]
    for (const token of absentTokens) {
      reportPageLoad(token, true)
      reportPageLoad(token, false)
    }

    expect(claimTransition).not.toHaveBeenCalled()
    expect(settleTransition).not.toHaveBeenCalled()
  })

  it('treats token 0 as a real token', () => {
    // Guarded on null/undefined rather than falsiness on purpose: the first transition of a
    // session is token 0, and a truthiness check would silently never commit it.
    reportPageLoad(0, true)

    expect(claimTransition).toHaveBeenCalledWith(0)
  })

  it('claims then settles across the load, which is how a page drives one transition', () => {
    reportPageLoad(3, true)
    reportPageLoad(3, false)

    expect(claimTransition).toHaveBeenCalledExactlyOnceWith(3)
    expect(settleTransition).toHaveBeenCalledExactlyOnceWith(3)
  })
})
