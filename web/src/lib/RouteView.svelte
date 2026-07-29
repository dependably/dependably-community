<!--
  Renders the app's pages for a deferred route commit: the visible route always, plus the
  incoming route mounted (parked off-screen by RouteHost) while its data is in flight.

  The shell supplies the page markup once, through the default slot, and receives the route to
  render as slot props — so the same {#if page === …} chain serves both hosts:

    <RouteView let:page let:params let:token>
      {#if page === 'packages'}<Packages pageToken={token} />
      {:else if page === 'version-detail'}<VersionDetail {params} pageToken={token} />
      …
    </RouteView>

  Pages read their params from the slot prop rather than the `route` store, because during a
  transition the store still names the visible page and a parked host asking it would render the
  outgoing page's params. `token` is what a page reports its initial load against; it is a prop
  rather than a context because slot content is initialised in the component that declares it —
  the shell — where a context published down here would never be visible.

  Hosts are keyed by route identity, so the incoming host is the same component instance before
  and after the commit: it keeps the data it already fetched and the swap costs one paint. The
  outgoing host is destroyed by the same keyed-each update.
-->
<script>
  import { route, incomingRoute, currentTransitionToken } from './store.js'
  import RouteHost from './RouteHost.svelte'

  const identity = (r) => `${r.page}|${JSON.stringify(r.params ?? {})}`

  // Captured when the incoming route appears, not read at render time: by the time the host
  // mounts a later transition may already have replaced this one.
  let incomingToken = null
  let incomingKey = null
  $: if ($incomingRoute) {
    const key = identity($incomingRoute)
    if (key !== incomingKey) {
      incomingKey = key
      incomingToken = currentTransitionToken()
    }
  } else {
    incomingKey = null
    incomingToken = null
  }

  // The incoming host drops out the moment the visible route matches it — the commit sets `route`
  // first, so this is the frame where the held page becomes the visible one. Keying both hosts
  // the same way is what preserves that instance across the swap; excluding the duplicate is
  // what keeps the keyed each from seeing the same key twice while both stores settle.
  $: visibleKey = identity($route)
  $: hosts = [
    { key: visibleKey, route: $route, token: null, incoming: false },
    ...($incomingRoute && incomingKey !== visibleKey
      ? [{ key: incomingKey, route: $incomingRoute, token: incomingToken, incoming: true }]
      : []),
  ]
</script>

<div class="route-view">
  {#each hosts as host (host.key)}
    <RouteHost token={host.token} incoming={host.incoming}>
      <slot page={host.route.page} params={host.route.params ?? {}} token={host.token} />
    </RouteHost>
  {/each}
</div>
