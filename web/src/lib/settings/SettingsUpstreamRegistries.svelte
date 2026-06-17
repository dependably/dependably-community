<!--
  Upstream proxy registries — one priority-ordered list per ecosystem. The top entry is tried
  first; the proxy falls through to the next on a miss/unreachable. An ecosystem with no entries
  has proxying disabled (surfaced as the empty-state line). Drag a row by its handle to reorder;
  the new order is persisted immediately. Self-contained: mounts only when the Proxy tab is active,
  so it loads its own data on mount rather than threading state through the parent.
-->
<script>
  import { onMount } from 'svelte'
  import { t } from 'svelte-i18n'
  import { api } from '../api.js'
  import { ECOSYSTEMS as ECO_VOCAB, ECO_LABEL } from '../ecosystems.js'
  import ErrorBanner from '../ErrorBanner.svelte'
  import InfoTip from '../InfoTip.svelte'

  // The subset of the shared ecosystem vocabulary whose upstreams are configurable through the
  // per-org `upstream_registry` table — mirrors UpstreamRegistryRepository.SupportedEcosystems so
  // the two can't silently drift. OCI is excluded on purpose: its upstreams are config-file-driven
  // (`Oci:Upstreams` via OciUpstreamRegistryOptions), not this DB table.
  const DB_UPSTREAM_ECOSYSTEMS = new Set(['pypi', 'npm', 'nuget', 'maven', 'rpm', 'cargo', 'golang'])
  const ECOSYSTEMS = ECO_VOCAB
    .filter(key => DB_UPSTREAM_ECOSYSTEMS.has(key))
    .map(key => ({ key, label: ECO_LABEL[key] }))

  /** @type {Record<string, any[]>} */
  let byEco = Object.fromEntries(ECOSYSTEMS.map(e => [e.key, []]))
  let loaded = false
  let error = ''

  // Add modal
  let showAdd = false, addEco = 'pypi', newUrl = '', newName = '', adding = false

  // Drag state
  let dragEco = null, dragFrom = -1

  onMount(load)

  async function load() {
    try {
      const entries = await api.getUpstreamRegistries()
      /** @type {Record<string, any[]>} */
      const grouped = Object.fromEntries(ECOSYSTEMS.map(e => [e.key, []]))
      for (const e of entries) {
        if (grouped[e.ecosystem]) grouped[e.ecosystem].push(e)
      }
      for (const k of Object.keys(grouped)) grouped[k].sort((a, b) => a.position - b.position)
      byEco = grouped
      loaded = true
    } catch (e) { error = extract(e) }
  }

  function openAdd(eco) {
    addEco = eco; newUrl = ''; newName = ''; error = ''; showAdd = true
  }

  async function add() {
    adding = true; error = ''
    try {
      const entry = await api.addUpstreamRegistry(addEco, newUrl.trim(), newName.trim() || null)
      byEco[addEco] = [...byEco[addEco], entry]
      byEco = byEco
      showAdd = false
    } catch (e) { error = extract(e) }
    finally { adding = false }
  }

  async function remove(eco, id) {
    if (!confirm($t('settings.proxy.upstreamRegistries.removeConfirm'))) return
    error = ''
    try {
      await api.deleteUpstreamRegistry(id)
      byEco[eco] = byEco[eco].filter(e => e.id !== id)
      byEco = byEco
    } catch (e) { error = extract(e) }
  }

  function onDragStart(eco, i) { dragEco = eco; dragFrom = i }

  function onDrop(eco, to) {
    if (dragEco !== eco || dragFrom < 0 || dragFrom === to) { resetDrag(); return }
    const list = [...byEco[eco]]
    const [moved] = list.splice(dragFrom, 1)
    list.splice(to, 0, moved)
    byEco[eco] = list
    byEco = byEco
    resetDrag()
    persistOrder(eco)
  }

  function resetDrag() { dragEco = null; dragFrom = -1 }

  async function persistOrder(eco) {
    error = ''
    try {
      await api.reorderUpstreamRegistries(eco, byEco[eco].map(e => e.id))
    } catch (e) { error = extract(e); await load() }
  }

  function extract(e) { return e?.body?.detail || e?.message || e?.detail || String(e) }
</script>

<div class="page-header list-header mt-4">
  <h3 class="section-h">
    {$t('settings.proxy.upstreamRegistries.section')}
    <InfoTip text={$t('settings.proxy.upstreamRegistries.hint')} />
  </h3>
</div>

<ErrorBanner message={error} />

{#each ECOSYSTEMS as eco (eco.key)}
  <div class="card eco-card">
    <div class="eco-head">
      <span class="eco-label">{eco.label}</span>
      <button class="btn-sm" on:click={() => openAdd(eco.key)}>
        {$t('settings.proxy.upstreamRegistries.add')}
      </button>
    </div>

    {#if loaded && byEco[eco.key].length === 0}
      <p class="text-muted empty">
        {$t('settings.proxy.upstreamRegistries.emptyDisabled', { values: { ecosystem: eco.label } })}
      </p>
    {:else}
      <ul class="reg-list">
        {#each byEco[eco.key] as entry, i (entry.id)}
          <li
            class="reg-row"
            class:dragging={dragEco === eco.key && dragFrom === i}
            draggable="true"
            on:dragstart={() => onDragStart(eco.key, i)}
            on:dragover|preventDefault
            on:drop|preventDefault={() => onDrop(eco.key, i)}
            on:dragend={resetDrag}>
            <span class="drag-handle" aria-hidden="true" title={$t('settings.proxy.upstreamRegistries.dragHint')}>⠿</span>
            <span class="priority">{i + 1}</span>
            <span class="reg-main">
              <span class="reg-url">{entry.url}</span>
              {#if entry.name}<span class="reg-name">{entry.name}</span>{/if}
            </span>
            <div class="row-actions">
              <button class="btn-sm danger" on:click={() => remove(eco.key, entry.id)}>
                {$t('common.actions.remove')}
              </button>
            </div>
          </li>
        {/each}
      </ul>
    {/if}
  </div>
{/each}

{#if showAdd}
  <div class="modal-backdrop">
    <div class="modal">
      <h3>{$t('settings.proxy.upstreamRegistries.modal.title')}</h3>
      <div class="form-row">
        <label for="ur-eco">{$t('settings.proxy.upstreamRegistries.modal.ecosystem')}</label>
        <select id="ur-eco" bind:value={addEco}>
          {#each ECOSYSTEMS as e (e.key)}<option value={e.key}>{e.label}</option>{/each}
        </select>
      </div>
      <div class="form-row">
        <label for="ur-url">{$t('settings.proxy.upstreamRegistries.modal.url')}</label>
        <input id="ur-url" bind:value={newUrl} placeholder="https://registry.example.com" />
        <div class="form-hint">{$t('settings.proxy.upstreamRegistries.modal.urlHint')}</div>
      </div>
      <div class="form-row">
        <label for="ur-name">{$t('settings.proxy.upstreamRegistries.modal.name')}</label>
        <input id="ur-name" bind:value={newName} placeholder={$t('settings.proxy.upstreamRegistries.modal.namePlaceholder')} />
      </div>
      <div class="modal-actions">
        <button on:click={() => showAdd = false}>{$t('common.actions.cancel')}</button>
        <button class="primary" on:click={add} disabled={adding || !newUrl.trim()}>
          {adding ? $t('common.actions.saving') : $t('common.actions.add')}
        </button>
      </div>
    </div>
  </div>
{/if}

<style>
  .eco-card { margin-bottom: 12px; }
  .eco-head { display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px; }
  .eco-label { font-weight: 600; }
  .empty { margin: 4px 0 0; font-size: 13px; }
  .reg-list { list-style: none; margin: 0; padding: 0; }
  .reg-row {
    display: flex; align-items: center; gap: 10px;
    padding: 6px 4px; border-bottom: 1px solid var(--border);
  }
  .reg-row:last-child { border-bottom: none; }
  .reg-row.dragging { opacity: 0.5; }
  .drag-handle { cursor: grab; color: var(--text2); user-select: none; }
  .priority {
    flex: 0 0 auto; min-width: 18px; text-align: center;
    font-size: 12px; color: var(--text2);
  }
  .reg-main { flex: 1 1 auto; display: flex; flex-direction: column; min-width: 0; }
  .reg-url { font-family: var(--mono); font-size: 13px; word-break: break-all; }
  .reg-name { font-size: 12px; color: var(--text2); }
  /* Row actions belong in their own flex wrapper — never on a flex cell directly. */
  .row-actions { display: flex; gap: 6px; align-items: center; flex: 0 0 auto; }
</style>
