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
  // per-org `upstream_registry` table — mirrors UpstreamRegistryRepository.SupportedEcosystems.
  const DB_UPSTREAM_ECOSYSTEMS = new Set(['pypi', 'npm', 'nuget', 'maven', 'rpm', 'cargo', 'golang', 'oci'])
  const ECOSYSTEMS = ECO_VOCAB
    .filter(key => DB_UPSTREAM_ECOSYSTEMS.has(key))
    .map(key => ({ key, label: ECO_LABEL[key] }))

  /** @type {Record<string, any[]>} */
  let byEco = Object.fromEntries(ECOSYSTEMS.map(e => [e.key, []]))
  let loaded = false
  let error = ''

  // Add modal — shared fields
  let showAdd = false, addEco = 'pypi', newUrl = '', newName = '', adding = false

  // OCI-specific modal fields
  let ociAuthType = 'anonymous'
  let ociUsername = ''
  let ociSecret = ''
  let ociTokenEndpoint = ''
  let ociPrefixesRaw = '' // comma/newline-separated input

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
    addEco = eco
    newUrl = ''
    newName = ''
    ociAuthType = 'anonymous'
    ociUsername = ''
    ociSecret = ''
    ociTokenEndpoint = ''
    ociPrefixesRaw = ''
    error = ''
    showAdd = true
  }

  /**
   * Parse prefixes from the textarea — splits on newline/comma, trims, deduplicates.
   * An empty line (blank) is the catch-all prefix and is kept if present.
   */
  function parseOciPrefixes(raw) {
    const parts = raw.split(/[\n,]/).map(s => s.trim())
    /** @type {string[]} */
    const seen = []
    const result = []
    for (const p of parts) {
      if (!seen.includes(p)) {
        seen.push(p)
        result.push(p)
      }
    }
    // Keep only one empty string (catch-all) at most
    return result.filter((p, i) => p !== '' || i === result.indexOf(''))
  }

  async function add() {
    adding = true; error = ''
    try {
      let entry
      if (addEco === 'oci') {
        const prefixes = parseOciPrefixes(ociPrefixesRaw)
        entry = await api.addOciUpstreamRegistry({
          url: newUrl.trim(),
          name: newName.trim() || null,
          authType: ociAuthType,
          username: (ociAuthType !== 'anonymous' && ociUsername.trim()) ? ociUsername.trim() : null,
          secret: (ociAuthType !== 'anonymous' && ociSecret) ? ociSecret : null,
          tokenEndpoint: (ociAuthType === 'dockerhub_token_exchange' && ociTokenEndpoint.trim()) ? ociTokenEndpoint.trim() : null,
          prefixes,
        })
      } else {
        entry = await api.addUpstreamRegistry(addEco, newUrl.trim(), newName.trim() || null)
      }
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

  /**
   * For an OCI ecosystem list, find the index of the first entry whose prefixes
   * include the empty-string catch-all. Returns -1 if none.
   */
  function catchAllIndex(list) {
    return list.findIndex(entry => Array.isArray(entry.prefixes) && entry.prefixes.includes(''))
  }

  /** Summarise the prefixes array for display in the list row. */
  function prefixSummary(prefixes) {
    if (!Array.isArray(prefixes) || prefixes.length === 0) return ''
    const display = prefixes.map(p => p === '' ? $t('settings.proxy.upstreamRegistries.oci.catchAllLabel') : p)
    if (display.length <= 3) return display.join(', ')
    return display.slice(0, 3).join(', ') + ` +${display.length - 3}`
  }

  /** Whether the OCI add-modal submit button should be disabled. */
  $: ociAddDisabled = adding
    || !newUrl.trim()
    || parseOciPrefixes(ociPrefixesRaw).length === 0
    || (ociAuthType === 'basic' && (!ociUsername.trim() || !ociSecret))
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
          {@const catchIdx = eco.key === 'oci' ? catchAllIndex(byEco[eco.key]) : -1}
          {@const showCatchAllWarn = eco.key === 'oci' && catchIdx >= 0 && catchIdx < byEco[eco.key].length - 1 && i === catchIdx}
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
              {#if eco.key === 'oci'}
                <span class="reg-url">{entry.url}</span>
                <span class="reg-meta">
                  {#if entry.prefixes && entry.prefixes.length > 0}
                    <span class="reg-prefixes">{prefixSummary(entry.prefixes)}</span>
                  {/if}
                  <span class="auth-badge auth-badge--{entry.authType}">{$t('settings.proxy.upstreamRegistries.oci.authType.' + entry.authType)}</span>
                  {#if entry.hasSecret}
                    <span class="cred-badge">{$t('settings.proxy.upstreamRegistries.oci.credentialSet')}</span>
                  {/if}
                </span>
                {#if showCatchAllWarn}
                  <span class="catch-all-warn">{$t('settings.proxy.upstreamRegistries.oci.catchAllWarn')}</span>
                {/if}
              {:else}
                <span class="reg-url">{entry.url}</span>
                {#if entry.name}<span class="reg-name">{entry.name}</span>{/if}
              {/if}
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

      {#if addEco === 'oci'}
        <!-- OCI-specific form fields -->
        <div class="form-row">
          <label for="ur-oci-host">{$t('settings.proxy.upstreamRegistries.oci.host')}</label>
          <input id="ur-oci-host" bind:value={newUrl} placeholder="registry-1.docker.io" />
          <div class="form-hint">{$t('settings.proxy.upstreamRegistries.oci.hostHint')}</div>
        </div>
        <div class="form-row">
          <label for="ur-oci-prefixes">{$t('settings.proxy.upstreamRegistries.oci.prefixes')}</label>
          <textarea id="ur-oci-prefixes" bind:value={ociPrefixesRaw} rows="3" placeholder={$t('settings.proxy.upstreamRegistries.oci.prefixesPlaceholder')}></textarea>
          <div class="form-hint">{$t('settings.proxy.upstreamRegistries.oci.prefixesHint')}</div>
        </div>
        <div class="form-row">
          <label for="ur-oci-auth">{$t('settings.proxy.upstreamRegistries.oci.authTypeLabel')}</label>
          <select id="ur-oci-auth" bind:value={ociAuthType}>
            <option value="anonymous">{$t('settings.proxy.upstreamRegistries.oci.authType.anonymous')}</option>
            <option value="basic">{$t('settings.proxy.upstreamRegistries.oci.authType.basic')}</option>
            <option value="dockerhub_token_exchange">{$t('settings.proxy.upstreamRegistries.oci.authType.dockerhub_token_exchange')}</option>
          </select>
        </div>
        {#if ociAuthType === 'basic' || ociAuthType === 'dockerhub_token_exchange'}
          <div class="form-row">
            <label for="ur-oci-user">{$t('settings.proxy.upstreamRegistries.oci.username')}</label>
            <input id="ur-oci-user" bind:value={ociUsername} autocomplete="off" />
          </div>
          <div class="form-row">
            <label for="ur-oci-secret">{$t('settings.proxy.upstreamRegistries.oci.secret')}</label>
            <input id="ur-oci-secret" type="password" bind:value={ociSecret} autocomplete="new-password" />
            <div class="form-hint">{$t('settings.proxy.upstreamRegistries.oci.secretHint')}</div>
          </div>
        {/if}
        {#if ociAuthType === 'dockerhub_token_exchange'}
          <div class="form-row">
            <label for="ur-oci-token-endpoint">{$t('settings.proxy.upstreamRegistries.oci.tokenEndpoint')}</label>
            <input id="ur-oci-token-endpoint" bind:value={ociTokenEndpoint} placeholder="https://auth.docker.io/token" />
            <div class="form-hint">{$t('settings.proxy.upstreamRegistries.oci.tokenEndpointHint')}</div>
          </div>
        {/if}
        <div class="form-row">
          <label for="ur-oci-name">{$t('settings.proxy.upstreamRegistries.modal.name')}</label>
          <input id="ur-oci-name" bind:value={newName} placeholder={$t('settings.proxy.upstreamRegistries.modal.namePlaceholder')} />
        </div>
        <div class="modal-actions">
          <button on:click={() => showAdd = false}>{$t('common.actions.cancel')}</button>
          <button class="primary" on:click={add} disabled={ociAddDisabled}>
            {adding ? $t('common.actions.saving') : $t('common.actions.add')}
          </button>
        </div>
      {:else}
        <!-- Standard non-OCI form fields -->
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
      {/if}
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
  .reg-meta { display: flex; flex-wrap: wrap; align-items: center; gap: 6px; margin-top: 2px; }
  .reg-prefixes { font-size: 12px; color: var(--text2); font-family: var(--mono); }
  .auth-badge {
    font-size: 11px; padding: 1px 6px; border-radius: 3px;
    background: var(--surface2); color: var(--text2);
  }
  .auth-badge--basic { background: var(--badge-nuget-bg); color: var(--badge-nuget-text); }
  .auth-badge--dockerhub_token_exchange { background: var(--badge-oci-bg); color: var(--badge-oci-text); }
  .cred-badge {
    font-size: 11px; padding: 1px 6px; border-radius: 3px;
    background: var(--badge-hosted-bg); color: var(--badge-hosted-text);
  }
  .catch-all-warn {
    font-size: 12px; color: var(--badge-warning-text);
    background: var(--badge-warning-bg); padding: 2px 6px; border-radius: 3px;
    margin-top: 2px;
  }
  /* Row actions belong in their own flex wrapper — never on a flex cell directly. */
  .row-actions { display: flex; gap: 6px; align-items: center; flex: 0 0 auto; }
  textarea { width: 100%; resize: vertical; min-height: 56px; }
</style>
