<script>
  import { createEventDispatcher, onDestroy } from 'svelte'
  import { api } from './api.js'

  export let placeholder = 'Search SPDX identifier or name…'
  export let includeDeprecated = false
  // Optional set (array or Set) of identifiers to grey-out as "already added" — the picker
  // still emits them on select; the parent decides whether to ignore.
  export let exclude = []

  const dispatch = createEventDispatcher()

  let query = ''
  let results = []
  let open = false
  let highlight = -1
  let loading = false
  let error = ''
  let debounceTimer = null

  $: excludeSet = new Set(Array.isArray(exclude) ? exclude : [...exclude])

  function scheduleSearch() {
    if (debounceTimer) clearTimeout(debounceTimer)
    debounceTimer = setTimeout(runSearch, 150)
  }

  async function runSearch() {
    loading = true
    error = ''
    try {
      results = await api.searchSpdx(query.trim(), includeDeprecated, 50)
      highlight = results.length > 0 ? 0 : -1
      open = true
    } catch (e) {
      error = e.message ?? 'lookup failed'
    } finally {
      loading = false
    }
  }

  function onFocus() {
    if (!results.length && !query) runSearch()
    else open = true
  }

  function onInput(e) {
    query = e.target.value
    scheduleSearch()
  }

  function onKeydown(e) {
    if (!open && (e.key === 'ArrowDown' || e.key === 'Enter')) { open = true; return }
    if (!open) return
    if (e.key === 'ArrowDown') {
      e.preventDefault()
      highlight = Math.min(results.length - 1, highlight + 1)
    } else if (e.key === 'ArrowUp') {
      e.preventDefault()
      highlight = Math.max(0, highlight - 1)
    } else if (e.key === 'Enter') {
      e.preventDefault()
      if (highlight >= 0 && highlight < results.length) pick(results[highlight])
    } else if (e.key === 'Escape') {
      open = false
    }
  }

  function pick(row) {
    dispatch('select', row)
    query = ''
    results = []
    open = false
    highlight = -1
  }

  function copyleftLabel(c) {
    return c === 'unclassified' ? '—' : c.replace('-copyleft', ' copyleft')
  }

  onDestroy(() => { if (debounceTimer) clearTimeout(debounceTimer) })
</script>

<div class="spdx-picker">
  <input
    type="text"
    autocomplete="off"
    spellcheck="false"
    role="combobox"
    aria-expanded={open}
    aria-controls="spdx-listbox"
    aria-activedescendant={highlight >= 0 ? `spdx-opt-${highlight}` : undefined}
    aria-haspopup="listbox"
    aria-autocomplete="list"
    {placeholder}
    bind:value={query}
    on:input={onInput}
    on:focus={onFocus}
    on:keydown={onKeydown}
    on:blur={() => setTimeout(() => open = false, 150)}
  />
  {#if open}
    <div class="dropdown" role="listbox" id="spdx-listbox">
      {#if loading}
        <div class="hint">Searching…</div>
      {:else if error}
        <div class="hint err">{error}</div>
      {:else if results.length === 0}
        <div class="hint">No matches.</div>
      {:else}
        {#each results as r, i (r.identifier)}
          <button
            type="button"
            class="row"
            class:highlight={i === highlight}
            class:dim={excludeSet.has(r.identifier)}
            class:deprecated={r.isDeprecated}
            on:mousedown|preventDefault={() => pick(r)}
            on:mouseenter={() => highlight = i}
            role="option"
            id={`spdx-opt-${i}`}
            aria-selected={i === highlight}
          >
            <span class="ident">{r.identifier}</span>
            <span class="name">{r.name}</span>
            <span class="badges">
              {#if r.isOsiApproved}<span class="badge osi" title="OSI Approved">OSI</span>{/if}
              {#if r.isFsfLibre}<span class="badge fsf" title="FSF Free/Libre">FSF</span>{/if}
              {#if r.copyleft !== 'unclassified'}<span class="badge cl cl-{r.copyleft}">{copyleftLabel(r.copyleft)}</span>{/if}
              {#if r.isDeprecated}<span class="badge dep" title="Deprecated SPDX identifier">deprecated</span>{/if}
              {#if excludeSet.has(r.identifier)}<span class="badge already" title="Already on a list">added</span>{/if}
            </span>
          </button>
        {/each}
      {/if}
    </div>
  {/if}
</div>

<style>
  .spdx-picker { position: relative; }
  input {
    width: 100%;
    padding: 6px 8px;
    border: 1px solid var(--border);
    border-radius: 4px;
    background: var(--bg);
    color: var(--text);
    font-family: var(--font-mono, monospace);
    font-size: 13px;
  }
  .dropdown {
    position: absolute;
    top: calc(100% + 2px);
    left: 0;
    right: 0;
    max-height: 320px;
    overflow-y: auto;
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 4px;
    box-shadow: var(--shadow);
    z-index: 20;
  }
  .hint {
    padding: 8px 10px;
    color: var(--text2);
    font-size: 12px;
  }
  .hint.err { color: var(--danger); }
  .row {
    display: grid;
    grid-template-columns: minmax(140px, 220px) 1fr auto;
    align-items: center;
    gap: 8px;
    width: 100%;
    padding: 6px 10px;
    background: transparent;
    border: 0;
    border-bottom: 1px solid var(--border-faint, var(--border));
    text-align: left;
    cursor: pointer;
    color: var(--text);
    font-size: 13px;
  }
  .row:last-child { border-bottom: 0; }
  .row.highlight { background: var(--bg-hover, rgba(127,127,127,0.08)); }
  .row.dim { opacity: 0.55; }
  .row.deprecated .ident { text-decoration: line-through; }
  .ident { font-family: var(--font-mono, monospace); font-weight: 600; }
  .name { color: var(--text2); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .badges { display: flex; gap: 4px; flex-wrap: nowrap; }
  .badge {
    font-size: 10px;
    padding: 1px 6px;
    border-radius: 9px;
    line-height: 1.6;
    white-space: nowrap;
  }
  .badge.osi { background: var(--badge-sky-bg);    color: var(--badge-sky-text); }
  .badge.fsf { background: var(--badge-hosted-bg); color: var(--badge-hosted-text); }
  .badge.dep { background: var(--badge-red-bg);    color: var(--badge-red-text); }
  .badge.already { background: var(--bg3); color: var(--text2); }
  .badge.cl-permissive       { background: var(--success-soft);     color: var(--success); }
  .badge.cl-weak-copyleft    { background: var(--badge-warning-bg); color: var(--badge-warning-text); }
  .badge.cl-strong-copyleft  { background: var(--warning-soft);     color: var(--warning); }
  .badge.cl-network-copyleft { background: var(--danger-soft);      color: var(--danger); }
  .badge.cl-public-domain    { background: var(--badge-purple-bg);  color: var(--badge-purple-text); }
</style>
