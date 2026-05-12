<script>
  import { t } from 'svelte-i18n'
  import { createEventDispatcher } from 'svelte'

  export let total = 0
  export let page = 1
  export let limit = 50

  const dispatch = createEventDispatcher()
  const PAGE_SIZES = [20, 50, 100, 200]
  const MAX_VISIBLE = 7

  $: totalPages = Math.max(1, Math.ceil(total / limit))
  $: from = total === 0 ? 0 : (page - 1) * limit + 1
  $: to   = Math.min(page * limit, total)
  $: pages = buildPageList(page, totalPages)

  function buildPageList(current, total) {
    if (total <= MAX_VISIBLE) return Array.from({ length: total }, (_, i) => i + 1)
    const set = new Set(
      [1, total, current - 2, current - 1, current, current + 1, current + 2]
        .filter(p => p >= 1 && p <= total)
    )
    const sorted = [...set].sort((a, b) => a - b)
    const result = []
    for (let i = 0; i < sorted.length; i++) {
      if (i > 0 && sorted[i] - sorted[i - 1] > 1) result.push('ellipsis')
      result.push(sorted[i])
    }
    return result
  }

  function goTo(p) {
    if (p < 1 || p > totalPages || p === page) return
    dispatch('pagechange', { page: p })
  }

  function onLimitChange(e) {
    dispatch('limitchange', { limit: parseInt(e.target.value, 10) })
  }
</script>

{#if total > 0}
<div class="pagination">
  <div class="pagination-summary">
    {$t('common.pagination.summary', { values: { from, to, total } })}
  </div>

  <div class="pagination-controls">
    <button
      class="page-btn"
      disabled={page === 1}
      on:click={() => goTo(page - 1)}
      aria-label={$t('common.pagination.prev')}
    >‹</button>

    {#each pages as p, i (i)}
      {#if p === 'ellipsis'}
        <span class="page-ellipsis">…</span>
      {:else}
        <button
          class="page-btn"
          class:active={p === page}
          on:click={() => goTo(p)}
          aria-current={p === page ? 'page' : undefined}
        >{p}</button>
      {/if}
    {/each}

    <button
      class="page-btn"
      disabled={page === totalPages}
      on:click={() => goTo(page + 1)}
      aria-label={$t('common.pagination.next')}
    >›</button>
  </div>

  <div class="pagination-size">
    <label for="page-size-{limit}">{$t('common.pagination.perPage')}</label>
    <select id="page-size-{limit}" value={limit} on:change={onLimitChange} class="size-select">
      {#each PAGE_SIZES as s (s)}
        <option value={s}>{s}</option>
      {/each}
    </select>
  </div>
</div>
{/if}

<style>
  .pagination {
    display: flex;
    align-items: center;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 8px;
    margin-top: 16px;
    padding-top: 12px;
    border-top: 1px solid var(--border);
    font-size: 13px;
    color: var(--text2);
  }

  .pagination-controls {
    display: flex;
    align-items: center;
    gap: 2px;
  }

  .page-btn {
    min-width: 32px;
    height: 32px;
    padding: 0 6px;
    font-size: 13px;
    border: 1px solid var(--border);
    background: var(--bg2);
    color: var(--text);
    border-radius: var(--radius);
    cursor: pointer;
    transition: background 0.1s;
  }
  .page-btn:hover:not(:disabled) { background: var(--bg3); }
  .page-btn.active {
    background: var(--accent);
    border-color: var(--accent);
    color: var(--on-accent);
    font-weight: 600;
  }
  .page-btn:disabled { opacity: 0.4; cursor: not-allowed; }

  .page-ellipsis {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 28px;
    color: var(--text2);
  }

  .pagination-size {
    display: flex;
    align-items: center;
    gap: 6px;
  }
  .pagination-size label { white-space: nowrap; }
  .pagination-size .size-select { width: auto; }
</style>
