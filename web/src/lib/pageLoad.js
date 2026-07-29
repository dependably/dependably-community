import { claimTransition, settleTransition } from './store.js'

/**
 * Reports a page's initial-load state to the route transition that mounted it.
 *
 * A deferred navigation keeps the outgoing page on screen while the incoming one mounts detached
 * and fetches; this is how the incoming page says "still loading" and then "ready", which is what
 * lets the swap happen in one paint with real content instead of through a shimmer.
 *
 * Mirror the page's own loading flag from a reactive statement:
 *
 *   export let pageToken = null
 *   $: reportPageLoad(pageToken, loading)
 *
 * The first run happens during component init, ahead of the auto-commit frame, so declaring the
 * load is what keeps the transition open. Pages with no initial fetch call nothing at all and are
 * committed on that frame.
 *
 * The token is what scopes the report to the right transition. It arrives as a prop from
 * RouteView rather than through context because slot content is initialised in the component that
 * *declares* it — the shell — so a context published by the host would never reach the page. A
 * page rendered outside a RouteView (a test, a modal) gets null and reports nothing; so does the
 * page the user is leaving, whose own later loads must not commit the page they are arriving at.
 *
 * @param {number | null} token the transition this page instance was mounted for
 * @param {boolean} loading whether its initial data is still in flight
 */
export function reportPageLoad(token, loading) {
  if (token === null || token === undefined) return
  if (loading) claimTransition(token)
  else settleTransition(token)
}
