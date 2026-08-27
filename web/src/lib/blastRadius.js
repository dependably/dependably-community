/**
 * Presentation decisions for the blast-radius counts — "which of my applications ship this?" —
 * shared by the quarantine queue, the vulnerability report and the package detail page.
 *
 * These live here rather than inside the three pages because both decisions are the same one:
 * a count on a security surface must never read as safer than reality. There is no Svelte
 * component-render harness in this repo, so logic left inline in a page is logic no test can
 * reach — and these two are the ones most worth pinning.
 */

/**
 * What a blast-radius cell should render for one key.
 *
 * Three states, deliberately, because two of them look identical if they are collapsed:
 *
 * - `unavailable` — the count could not be fetched. NOT zero. On the quarantine queue, whose own
 *   help text says denying a package affects the applications shipping it, an outage rendered as
 *   a blank cell says "affects nobody" and invites exactly the wrong decision.
 * - `none` — the query answered and found nothing. A real zero.
 * - `count` — the query answered with a number.
 *
 * @param {Record<string, number>|null|undefined} counts keyed map from the counts endpoint
 * @param {string} key the row's key, or '' when the row carries no coordinate to ask about
 * @param {boolean} failed whether the fetch for this page failed
 * @returns {{ state: 'unavailable'|'none'|'count', count: number }}
 */
export function blastRadiusCell(counts, key, failed) {
  if (failed) return { state: 'unavailable', count: 0 }
  const count = (key && counts?.[key]) || 0
  return count > 0 ? { state: 'count', count } : { state: 'none', count: 0 }
}

/**
 * How many results a capped list is not showing. Every blast-radius list is fetched with a limit,
 * and rendering the capped rows without saying so presents part of the answer as all of it.
 *
 * Returns 0 — render nothing — when the list is complete, and clamps a total that is somehow
 * smaller than the rows in hand rather than reporting a negative overflow.
 *
 * @param {number|null|undefined} total server-reported total for the whole result
 * @param {number} shown rows actually rendered
 * @returns {number}
 */
export function overflowCount(total, shown) {
  return Math.max(0, (total ?? 0) - shown)
}
