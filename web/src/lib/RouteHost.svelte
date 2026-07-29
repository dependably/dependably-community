<!--
  One mounted page inside RouteView.

  While a host is the incoming one its element is parked in a detached container, and at the
  commit it is moved back into the route view. Moving the element does not touch the component:
  Svelte drives it from node references, not parentage, so the page keeps its state and the data
  it has already fetched, and its fetch runs the whole time it is parked.

  Props:
    token     the transition this host was mounted for; null for the visible host
    incoming  true while this host is the held page waiting to be committed
-->
<script>
  import { onMount } from 'svelte'
  import { settleIfUnclaimed } from './store.js'

  export let token = null
  export let incoming = false

  /**
   * Where a held page waits: a container that is never attached to the document.
   *
   * Detached rather than hidden-in-place. A hidden copy still answers document.querySelector,
   * still collides on element ids, and still doubles every "the heading is X" match for as long
   * as the two overlap; a detached one is not in the document at all, so nothing outside this
   * component can see it. The component itself runs exactly the same either way — Svelte drives
   * it from node references, and its fetch does not care where its DOM lives.
   *
   * Nothing in the page tree measures itself on mount (the two getBoundingClientRect calls are
   * both click handlers, and a parked page takes no clicks), so having no layout while parked
   * costs nothing; the page is laid out for the first time when the commit attaches it.
   *
   * One per host, created on first use — a host that is never parked never makes one.
   */
  let pen = null
  function holdingPen() {
    if (typeof document === 'undefined') return null
    pen ??= document.createElement('div')
    return pen
  }

  /**
   * Keeps the host element in the right place: the holding pen while it is the incoming page,
   * back where it was rendered once it is committed. An action rather than a reactive statement,
   * because the action is handed the node itself and its `update` runs when `incoming` flips —
   * exactly the two moments that matter.
   */
  function park(node, params) {
    let current = params
    /** Where the route view rendered this host, captured before the first move. */
    let origin = null

    const apply = () => {
      origin ??= node.parentNode
      const parent = current.incoming ? holdingPen() : origin
      if (parent && node.parentNode !== parent) parent.appendChild(node)
    }

    // Deferred by one microtask: Svelte runs an element's actions before it inserts the element,
    // so parking synchronously would be undone by that insert — and would also capture a null
    // origin, leaving the committed page nowhere to move back to.
    queueMicrotask(apply)
    return {
      update: (next) => {
        current = next
        apply()
      },
    }
  }

  onMount(() => {
    if (token === null) return
    // A page with no initial fetch never claims the transition, and holding it for the full
    // budget would make a static page the slowest thing in the app. By the next frame the page's
    // reactive statements have run, so silence here means there is nothing to wait for.
    if (typeof requestAnimationFrame === 'function') requestAnimationFrame(() => settleIfUnclaimed(token))
    else settleIfUnclaimed(token)
  })
</script>

<div class="route-host" use:park={{ incoming }}>
  <slot />
</div>

<style>
  /* The host must not exist as far as layout is concerned: the page inside it lays out as a
     direct child of the content column, so wrapping it changes nothing on screen. */
  .route-host { display: contents; }
</style>
