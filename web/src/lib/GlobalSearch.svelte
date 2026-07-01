<script>
  import { onMount } from 'svelte'
  import { t } from 'svelte-i18n'
  import { api } from './api.js'
  import { navigate } from './store.js'

  let inputEl
  let query = ''
  let groups = []
  let loading = false
  let open = false
  let activeIndex = -1
  let seq = 0 // request sequence — ignore stale responses
  let debounceTimer

  // Flat, ordered list of selectable results (for keyboard nav + group headers).
  $: flat = groups.flatMap((g) => g.results.map((r) => ({ ...r, kind: g.kind })))

  async function run(q) {
    const mine = ++seq
    loading = true
    try {
      const data = await api.search(q)
      if (mine !== seq) return
      groups = (data.groups || []).filter((g) => g.results?.length)
      open = true
      activeIndex = -1
    } catch {
      if (mine !== seq) return
      groups = []
      open = true
    } finally {
      if (mine === seq) loading = false
    }
  }

  function onInput() {
    clearTimeout(debounceTimer)
    const q = query.trim()
    if (q.length < 2) {
      seq++ // cancel any in-flight response
      groups = []
      open = false
      loading = false
      return
    }
    debounceTimer = setTimeout(() => run(q), 180)
  }

  function close() {
    open = false
    activeIndex = -1
  }

  function select(r) {
    close()
    query = ''
    groups = []
    if (r.kind === 'packages') {
      navigate('version-detail', { ecosystem: r.ecosystem, name: r.purlName ?? r.name })
    }
  }

  function onKeydown(e) {
    if (e.key === 'Escape') {
      if (open) { close(); e.stopPropagation() }
      else { query = ''; inputEl?.blur() }
      return
    }
    if (!open || !flat.length) return
    if (e.key === 'ArrowDown') {
      e.preventDefault()
      activeIndex = (activeIndex + 1) % flat.length
    } else if (e.key === 'ArrowUp') {
      e.preventDefault()
      activeIndex = (activeIndex - 1 + flat.length) % flat.length
    } else if (e.key === 'Enter' && activeIndex >= 0) {
      e.preventDefault()
      select(flat[activeIndex])
    }
  }

  // Global "/" focuses search, unless the user is already typing somewhere.
  function onWindowKeydown(e) {
    const tag = (e.target?.tagName || '').toLowerCase()
    const typing = tag === 'input' || tag === 'textarea' || e.target?.isContentEditable
    if (e.key === '/' && !typing) {
      e.preventDefault()
      inputEl?.focus()
    }
  }

  onMount(() => {
    window.addEventListener('keydown', onWindowKeydown)
    return () => window.removeEventListener('keydown', onWindowKeydown)
  })

  // Delay close so a result click (mousedown) lands before blur hides the overlay.
  function onBlur() {
    setTimeout(close, 120)
  }
</script>

<div class="gs">
  <svg class="gs-icon" width="16" height="16" aria-hidden="true"><use href="/icons.svg#icon-search"/></svg>
  <input
    bind:this={inputEl}
    bind:value={query}
    on:input={onInput}
    on:keydown={onKeydown}
    on:focus={() => { if (flat.length) open = true }}
    on:blur={onBlur}
    type="search"
    class="gs-input"
    placeholder={$t('globalSearch.placeholder')}
    aria-label={$t('globalSearch.placeholder')}
    role="combobox"
    aria-expanded={open}
    aria-controls="gs-results"
    autocomplete="off"
  />
  <kbd class="gs-kbd" aria-hidden="true">/</kbd>

  {#if open}
    <div id="gs-results" class="gs-overlay" role="listbox">
      {#if loading && !flat.length}
        <div class="gs-status">{$t('globalSearch.loading')}</div>
      {:else if !flat.length}
        <div class="gs-status">{$t('globalSearch.empty')}</div>
      {:else}
        {#each flat as r, i (r.kind + ':' + r.ecosystem + '/' + (r.purlName ?? r.name))}
          {#if i === 0 || flat[i - 1].kind !== r.kind}
            <div class="gs-group">{$t(`globalSearch.groups.${r.kind}`)}</div>
          {/if}
          <button
            class="gs-result"
            class:active={i === activeIndex}
            on:mousedown|preventDefault={() => select(r)}
            on:mousemove={() => (activeIndex = i)}
            role="option"
            aria-selected={i === activeIndex}
          >
            <svg class="gs-result-icon" width="16" height="16" aria-hidden="true"><use href="/icons.svg#icon-package"/></svg>
            <span class="badge {r.ecosystem} gs-eco">{r.ecosystem}</span>
            <span class="mono gs-name" title={r.name}>{r.name}</span>
            {#if r.version}<span class="gs-ver mono">{r.version}</span>{/if}
          </button>
        {/each}
      {/if}
    </div>
  {/if}
</div>

<style>
  .gs { position: relative; width: 100%; }
  .gs-icon {
    position: absolute;
    left: 10px;
    top: 50%;
    transform: translateY(-50%);
    color: var(--text2);
    pointer-events: none;
  }
  .gs-input {
    width: 100%;
    height: 32px;
    padding: 0 34px 0 32px;
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    color: var(--text);
    font-size: 13px;
  }
  .gs-input:focus { outline: none; border-color: var(--accent); }
  .gs-kbd {
    position: absolute;
    right: 8px;
    top: 50%;
    transform: translateY(-50%);
    font-size: 11px;
    color: var(--text2);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 0 5px;
    font-family: var(--font-mono, monospace);
    pointer-events: none;
  }

  .gs-overlay {
    position: absolute;
    top: 38px;
    left: 0;
    right: 0;
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    box-shadow: 0 8px 24px rgb(0 0 0 / 18%);
    z-index: 60;
    max-height: 340px;
    overflow-y: auto;
    padding: 4px;
  }
  .gs-status { padding: 12px; font-size: 13px; color: var(--text2); }
  .gs-group {
    padding: 8px 8px 3px;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    color: var(--text2);
  }
  .gs-result {
    display: flex;
    align-items: center;
    gap: 8px;
    width: 100%;
    border: none;
    background: none;
    padding: 7px 8px;
    border-radius: var(--radius);
    cursor: pointer;
    text-align: left;
    color: var(--text);
  }
  .gs-result.active { background: var(--bg3); }
  .gs-result-icon { color: var(--text2); flex: none; }
  .gs-eco { flex: none; }
  .gs-name { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; flex: 1; min-width: 0; }
  .gs-ver { color: var(--text2); font-size: 12px; flex: none; }
</style>
