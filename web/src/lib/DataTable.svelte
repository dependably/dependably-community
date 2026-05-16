<!--
  Sortable table shell. Owns sort state + header rendering; the parent owns the row
  markup via the default slot (one <tr> per visible row).

  Props:
    columns      array of { key, label, sortable?, defaultDir?, width? } (width applied via colgroup)
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

  /** @type {Array<{ key: string, label: string, sortable?: boolean, defaultDir?: string, width?: string }>} */
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
  export let loadingRows = 5

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

<table class={tableClass}>
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
          <th class="sortable" on:click={() => toggleSort(c.key)}>
            {c.label}{sortIndicator(c.key, sortCol, sortDir)}
          </th>
        {:else}
          <th>{c.label}</th>
        {/if}
      {/each}
    </tr>
  </thead>
  {#if loading}
    <tbody>
      {#each [...Array(loadingRows).keys()] as i (i)}
        <tr><td colspan={columns.length}><span class="skeleton"></span></td></tr>
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
