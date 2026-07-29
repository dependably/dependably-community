<!--
  Sortable table shell. Owns sort state + header rendering; the parent owns the row
  markup via the default slot (one <tr> per visible row).

  Props:
    columns      array of { key, label, sortable?, defaultDir?, width?, align? } (width applied via
                 colgroup; align: 'right' | 'center' right/center-aligns the header to match a
                 right/center-aligned value column — anything else defaults to left)
    rows         the source array
    comparators  optional map of { [key]: (a, b) => number }; missing keys fall back to
                 string compare on row[key] (or just-render — keys without comparators
                 are still clickable to toggle direction but won't change order; pass
                 sortable:false to suppress).
    initialSort  optional { key, dir } to seed state
    emptyText    string rendered when sorted.length === 0
    tableClass   extra class applied to the <table>

  Slot props (default slot):
    row          the current row (already sorted)
    i            its index

  Two-way `sortCol` / `sortDir` are not bound — sort state lives inside. Use
  `on:sortchange={e => ...}` to react if you also need to drive other UI.
-->
<script>
  import { createEventDispatcher } from 'svelte'
  import { sortIndicator } from './sortIndicator.js'
  import { rememberedRowCount, rememberRowCount } from './tableSize.js'

  /** @type {Array<{ key: string, label: string, sortable?: boolean, defaultDir?: string, width?: string, align?: string }>} */
  export let columns = []
  /** @type {any[]} */
  export let rows = []
  /** @type {Record<string, (a: any, b: any) => number>} */
  export let comparators = {}
  /** @type {{ key: string, dir: string } | null} */
  export let initialSort = null
  export let emptyText = ''
  export let tableClass = 'table-auto'
  export let loading = false
  /**
   * Placeholder rows drawn while `loading` and the table has nothing to show yet. Paged callers
   * pass their page size as the first-visit estimate; once this table has rendered real rows the
   * remembered count takes over, because a page size overstates every table that holds fewer rows
   * than its limit. Unpaged callers keep the small default.
   */
  export let loadingRows = 5
  /**
   * Height of one placeholder row, matching a loaded row of this table. The default suits a
   * single-line row; tables whose cells stack two lines (a badge over a package name) pass their
   * own, otherwise the reserved height is short by a third.
   */
  export let loadingRowHeight = '34px'
  /**
   * Stable identifier under which this table's real row count is remembered for the session, so a
   * later load reserves the height it is actually going to need. Omit to opt out.
   */
  export let memoryKey = ''

  // Reserving past the fold buys nothing: rows arriving below the viewport grow the document
  // without moving anything the reader can see. Capping keeps a `limit=200` page from drawing a
  // screen-and-a-half of shimmer, and keeps the overshoot bounded on a registry too sparse to
  // fill the page it asked for.
  const MAX_PLACEHOLDER_ROWS = 30
  // What this table held last time, which beats the page size as an estimate — reserving fifty
  // rows for a table that turns out to hold four moves everything below it further than
  // reserving nothing would have.
  const remembered = rememberedRowCount(memoryKey)
  $: placeholderRows = Math.max(1, Math.min(remembered ?? loadingRows, MAX_PLACEHOLDER_ROWS))
  $: if (!loading) rememberRowCount(memoryKey, rows.length)

  // A table that already has rows keeps showing them while the next load is in flight: replacing
  // a rendered page with shimmer and back again is the same flicker as a route change committing
  // early, and paging, sorting, and filtering all take this path. The placeholder is for a table
  // with nothing to show yet.
  $: showPlaceholder = loading && rows.length === 0

  let sortCol = initialSort?.key ?? columns.find(c => c.sortable)?.key ?? ''
  let sortDir = initialSort?.dir ?? columns.find(c => c.key === sortCol)?.defaultDir ?? 'asc'

  const dispatch = createEventDispatcher()

  function toggleSort(col) {
    const def = columns.find(c => c.key === col)
    if (!def?.sortable) return
    if (sortCol === col) sortDir = sortDir === 'asc' ? 'desc' : 'asc'
    else {
      sortCol = col
      sortDir = def.defaultDir ?? 'asc'
    }
    dispatch('sortchange', { col: sortCol, dir: sortDir })
  }

  function defaultCmp(a, b) {
    if (a === b) return 0
    if (a === null || a === undefined) return -1
    if (b === null || b === undefined) return 1
    if (typeof a === 'number' && typeof b === 'number') return a - b
    return String(a).localeCompare(String(b))
  }

  $: cmp = comparators[sortCol] ?? ((a, b) => defaultCmp(a?.[sortCol], b?.[sortCol]))
  $: sorted = [...rows].sort((a, b) => {
    const r = cmp(a, b)
    return sortDir === 'asc' ? r : -r
  })
</script>

<table class={tableClass} aria-busy={loading || undefined}>
  {#if columns.some(c => c.width)}
    <colgroup>
      {#each columns as c (c.key)}
        <col style:width={c.width ?? ''} />
      {/each}
    </colgroup>
  {/if}
  <thead>
    <tr>
      {#each columns as c (c.key)}
        {#if c.sortable}
          <th class="sortable" class:text-right={c.align === 'right'} class:text-center={c.align === 'center'} on:click={() => toggleSort(c.key)}>
            {c.label}{sortIndicator(c.key, sortCol, sortDir)}
          </th>
        {:else}
          <th class:text-right={c.align === 'right'} class:text-center={c.align === 'center'}>{c.label}</th>
        {/if}
      {/each}
    </tr>
  </thead>
  {#if showPlaceholder}
    <tbody aria-hidden="true">
      {#each [...Array(placeholderRows).keys()] as i (i)}
        <tr class="skeleton-row" style:height={loadingRowHeight}>
          <td colspan={columns.length}><span class="skeleton"></span></td>
        </tr>
      {/each}
    </tbody>
  {:else}
    <tbody>
      {#each sorted as row, i (row.id ?? i)}
        <slot {row} {i} />
      {/each}
      {#if sorted.length === 0 && emptyText}
        <tr><td colspan={columns.length} class="text-center text-muted">{emptyText}</td></tr>
      {/if}
    </tbody>
  {/if}
</table>

<style>
  /* The row height is the reserved height, so pin it on the cell too: a <tr> height is advisory
     in table layout, while a <td> height acts as the row's minimum. */
  .skeleton-row td { height: inherit; }
</style>
