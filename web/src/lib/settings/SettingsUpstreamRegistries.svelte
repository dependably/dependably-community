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
  const DB_UPSTREAM_ECOSYSTEMS = new Set([
    'pypi', 'npm', 'nuget', 'maven', 'rpm', 'cargo', 'golang', 'oci', 'apk', 'terraform',
  ])
  const ECOSYSTEMS = ECO_VOCAB
    .filter(key => DB_UPSTREAM_ECOSYSTEMS.has(key))
    .map(key => ({ key, label: ECO_LABEL[key] }))

  /** @type {Record<string, any[]>} */
  let byEco = Object.fromEntries(ECOSYSTEMS.map(e => [e.key, []]))
  let loaded = false
  let error = ''

  // Per-tenant RPM hosted-publishing posture override, loaded from the org settings payload and
  // saved through its own targeted endpoint so it never clobbers other settings. '' is the UI
  // sentinel for "inherit the instance default" (sent to the API as null); an explicit
  // 'passthrough' | 'merged' overrides the instance default in either direction. The resolved
  // effective mode is shown alongside so the card never misreports what's actually enforced.
  let rpmUpstreamMode = ''
  let rpmUpstreamModeEffective = 'passthrough'
  let rpmUpstreamModeInstanceDefault = 'passthrough'
  let savingRpmMode = false

  // Add modal — shared fields
  let showAdd = false, addEco = 'pypi', newUrl = '', newName = '', adding = false

  // OCI-specific modal fields
  let ociAuthType = 'anonymous'
  let ociUsername = ''
  let ociSecret = ''
  let ociTokenEndpoint = ''
  let ociPrefixesRaw = '' // comma/newline-separated input

  // Non-OCI auth modal fields (not shown for rpm — public distro mirrors are anonymous-only)
  let nonOciAuthType = 'anonymous'
  let nonOciUsername = ''
  let nonOciSecret = ''

  // Terraform-only: which server-side protocol the upstream speaks. '' is the UI sentinel for
  // the default (Provider Registry Protocol, sent as null); 'mirror' selects the Provider
  // Network Mirror Protocol. No other ecosystem reads this field.
  let terraformProtocol = ''

  // Drag state
  let dragEco = null, dragFrom = -1

  onMount(load)

  async function load() {
    try {
      const [entries, settings] = await Promise.all([
        api.getUpstreamRegistries(),
        api.getOrgSettings(),
      ])
      /** @type {Record<string, any[]>} */
      const grouped = Object.fromEntries(ECOSYSTEMS.map(e => [e.key, []]))
      for (const e of entries) {
        if (grouped[e.ecosystem]) grouped[e.ecosystem].push(e)
      }
      for (const k of Object.keys(grouped)) grouped[k].sort((a, b) => a.position - b.position)
      byEco = grouped
      // null override → '' sentinel (renders as "Inherit" in the select).
      rpmUpstreamMode = settings?.rpmUpstreamMode === 'merged' || settings?.rpmUpstreamMode === 'passthrough'
        ? settings.rpmUpstreamMode : ''
      rpmUpstreamModeEffective = settings?.rpmUpstreamModeEffective === 'merged' ? 'merged' : 'passthrough'
      rpmUpstreamModeInstanceDefault = settings?.rpmUpstreamModeInstanceDefault === 'merged' ? 'merged' : 'passthrough'
      loaded = true
    } catch (e) { error = extract(e) }
  }

  async function saveRpmMode() {
    savingRpmMode = true; error = ''
    try {
      // '' sentinel (inherit) sends null so the API clears the override rather than storing it.
      // The endpoint returns 204, so the resolved effective mode is derived locally rather than
      // from a response body: an explicit override wins outright, '' falls back to the instance
      // default already loaded from GET /api/v1/settings.
      await api.updateRpmUpstreamMode(rpmUpstreamMode || null)
      rpmUpstreamModeEffective = rpmUpstreamMode || rpmUpstreamModeInstanceDefault
    } catch (e) { error = extract(e); await load() }
    finally { savingRpmMode = false }
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
    nonOciAuthType = 'anonymous'
    nonOciUsername = ''
    nonOciSecret = ''
    terraformProtocol = ''
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
        const authType = (addEco !== 'rpm' && nonOciAuthType !== 'anonymous') ? nonOciAuthType : undefined
        const username = (addEco !== 'rpm' && nonOciAuthType === 'basic' && nonOciUsername.trim()) ? nonOciUsername.trim() : undefined
        const secret = (addEco !== 'rpm' && nonOciAuthType !== 'anonymous' && nonOciSecret) ? nonOciSecret : undefined
        const protocol = (addEco === 'terraform' && terraformProtocol) ? terraformProtocol : undefined
        entry = await api.addUpstreamRegistry(addEco, newUrl.trim(), newName.trim() || null, authType, username, secret, protocol)
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

  // NuGet symbol server: id of the row whose editor is open, plus its draft value. Editing is
  // per-row and opt-in so the common case (a nuget.org upstream, seeded automatically) needs no
  // interaction at all.
  let symbolEditId = null
  let symbolDraft = ''
  let symbolSaving = false

  function openSymbolEditor(entry) {
    symbolEditId = entry.id
    symbolDraft = entry.symbolServerUrl || ''
  }

  function cancelSymbolEditor() { symbolEditId = null; symbolDraft = '' }

  async function saveSymbolServer(eco, entry) {
    error = ''
    symbolSaving = true
    try {
      // Empty CLEARS, which turns symbol proxying off for this upstream. Send null rather than ''
      // so the intent is unambiguous on the wire.
      const value = symbolDraft.trim() || null
      await api.setUpstreamSymbolServer(entry.id, value)
      byEco[eco] = byEco[eco].map(e => e.id === entry.id ? { ...e, symbolServerUrl: value } : e)
      byEco = byEco
      cancelSymbolEditor()
    } catch (e) {
      error = extract(e)
    } finally {
      symbolSaving = false
    }
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

    {#if eco.key === 'rpm'}
      <div class="rpm-mode">
        <label class="rpm-mode-label" for="rpm-upstream-mode">
          {$t('settings.proxy.upstreamRegistries.rpmMode.label')}
          <InfoTip text={$t('settings.proxy.upstreamRegistries.rpmMode.hint')} />
        </label>
        <select
          id="rpm-upstream-mode"
          bind:value={rpmUpstreamMode}
          on:change={saveRpmMode}
          disabled={savingRpmMode}>
          <option value="">
            {$t('settings.proxy.upstreamRegistries.rpmMode.inherit', { values: { mode: rpmUpstreamModeInstanceDefault } })}
          </option>
          <option value="passthrough">{$t('settings.proxy.upstreamRegistries.rpmMode.passthrough')}</option>
          <option value="merged">{$t('settings.proxy.upstreamRegistries.rpmMode.merged')}</option>
        </select>
        <span class="rpm-mode-effective">
          {$t('settings.proxy.upstreamRegistries.rpmMode.effective', { values: { mode: rpmUpstreamModeEffective } })}
        </span>
      </div>
    {/if}

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
                <span class="reg-meta">
                  {#if entry.name}<span class="reg-name">{entry.name}</span>{/if}
                  {#if entry.authType && entry.authType !== 'anonymous'}
                    <span class="auth-badge auth-badge--{entry.authType}">{$t('settings.proxy.upstreamRegistries.auth.authType.' + entry.authType)}</span>
                  {/if}
                  {#if entry.hasSecret}
                    <span class="cred-badge">{$t('settings.proxy.upstreamRegistries.auth.credentialSet')}</span>
                  {/if}
                  {#if eco.key === 'terraform'}
                    <!-- Only terraform reads upstream_protocol (ADR 0003) — no other ecosystem
                         card shows this badge. -->
                    <span class="protocol-badge">
                      {entry.protocol === 'mirror'
                        ? $t('settings.proxy.upstreamRegistries.terraform.protocol.mirror')
                        : $t('settings.proxy.upstreamRegistries.terraform.protocol.registry')}
                    </span>
                  {/if}
                </span>
                {#if eco.key === 'nuget'}
                  <!-- Symbol server (SSQP). A separate field because a symbol server is a
                       different host from the v3 index and cannot be derived from it. Empty
                       means no symbol proxying for this upstream — the fail-closed default. -->
                  <span class="symbol-row">
                    {#if symbolEditId === entry.id}
                      <input
                        class="symbol-input"
                        bind:value={symbolDraft}
                        placeholder="https://symbols.nuget.org/download/symbols"
                        aria-label={$t('settings.proxy.upstreamRegistries.symbolServer.label')} />
                      <button class="btn-sm" disabled={symbolSaving} on:click={() => saveSymbolServer(eco.key, entry)}>
                        {symbolSaving ? $t('common.actions.saving') : $t('common.actions.save')}
                      </button>
                      <button class="btn-sm" disabled={symbolSaving} on:click={cancelSymbolEditor}>
                        {$t('common.actions.cancel')}
                      </button>
                    {:else}
                      <span class="symbol-label">{$t('settings.proxy.upstreamRegistries.symbolServer.label')}</span>
                      {#if entry.symbolServerUrl}
                        <span class="symbol-value">{entry.symbolServerUrl}</span>
                      {:else}
                        <span class="symbol-off">{$t('settings.proxy.upstreamRegistries.symbolServer.disabled')}</span>
                      {/if}
                      <button class="btn-sm" on:click={() => openSymbolEditor(entry)}>
                        {$t('common.actions.edit')}
                      </button>
                    {/if}
                  </span>
                  {#if symbolEditId === entry.id}
                    <span class="symbol-hint">{$t('settings.proxy.upstreamRegistries.symbolServer.hint')}</span>
                  {/if}
                {/if}
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
        {#if addEco === 'terraform'}
          <div class="form-row">
            <label for="ur-tf-protocol">{$t('settings.proxy.upstreamRegistries.terraform.protocolLabel')}</label>
            <select id="ur-tf-protocol" bind:value={terraformProtocol}>
              <option value="">{$t('settings.proxy.upstreamRegistries.terraform.protocol.registry')}</option>
              <option value="mirror">{$t('settings.proxy.upstreamRegistries.terraform.protocol.mirror')}</option>
            </select>
            <div class="form-hint">{$t('settings.proxy.upstreamRegistries.terraform.protocolHint')}</div>
          </div>
        {/if}
        {#if addEco !== 'rpm'}
          <div class="form-row">
            <label for="ur-auth">{$t('settings.proxy.upstreamRegistries.auth.authTypeLabel')}</label>
            <select id="ur-auth" bind:value={nonOciAuthType}>
              <option value="anonymous">{$t('settings.proxy.upstreamRegistries.auth.authType.anonymous')}</option>
              <option value="bearer">{$t('settings.proxy.upstreamRegistries.auth.authType.bearer')}</option>
              <option value="basic">{$t('settings.proxy.upstreamRegistries.auth.authType.basic')}</option>
            </select>
          </div>
          {#if nonOciAuthType === 'basic'}
            <div class="form-row">
              <label for="ur-username">{$t('settings.proxy.upstreamRegistries.auth.username')}</label>
              <input id="ur-username" bind:value={nonOciUsername} autocomplete="off" />
            </div>
          {/if}
          {#if nonOciAuthType === 'bearer' || nonOciAuthType === 'basic'}
            <div class="form-row">
              <label for="ur-secret">{$t('settings.proxy.upstreamRegistries.auth.secret')}</label>
              <input id="ur-secret" type="password" bind:value={nonOciSecret} autocomplete="new-password" />
              <div class="form-hint">{$t('settings.proxy.upstreamRegistries.auth.secretHint')}</div>
            </div>
          {/if}
        {/if}
        <div class="modal-actions">
          <button on:click={() => { showAdd = false; nonOciAuthType = 'anonymous'; nonOciUsername = ''; nonOciSecret = '' }}>{$t('common.actions.cancel')}</button>
          <button class="primary" on:click={add} disabled={adding || !newUrl.trim() || (addEco !== 'rpm' && nonOciAuthType === 'basic' && (!nonOciUsername.trim() || !nonOciSecret)) || (addEco !== 'rpm' && nonOciAuthType === 'bearer' && !nonOciSecret)}>
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
  /* Symbol server (NuGet only). Sits under the URL as a secondary line so it reads as a
     property of the upstream rather than another upstream. */
  .symbol-row { display: flex; flex-wrap: wrap; align-items: center; gap: 6px; margin-top: 4px; }
  .symbol-label { font-size: 12px; color: var(--text2); }
  .symbol-value { font-size: 12px; font-family: var(--mono); color: var(--text2); word-break: break-all; }
  .symbol-off { font-size: 12px; color: var(--text2); font-style: italic; }
  .symbol-input { font-size: 12px; font-family: var(--mono); min-width: 280px; flex: 1; }
  .symbol-hint { display: block; font-size: 12px; color: var(--text2); margin-top: 4px; }
  .reg-prefixes { font-size: 12px; color: var(--text2); font-family: var(--mono); }
  .auth-badge {
    font-size: 11px; padding: 1px 6px; border-radius: 3px;
    background: var(--surface2); color: var(--text2);
  }
  .auth-badge--basic { background: var(--badge-nuget-bg); color: var(--badge-nuget-text); }
  .auth-badge--bearer { background: var(--badge-purple-bg); color: var(--badge-purple-text); }
  .auth-badge--dockerhub_token_exchange { background: var(--badge-oci-bg); color: var(--badge-oci-text); }
  .cred-badge {
    font-size: 11px; padding: 1px 6px; border-radius: 3px;
    background: var(--badge-hosted-bg); color: var(--badge-hosted-text);
  }
  .protocol-badge {
    font-size: 11px; padding: 1px 6px; border-radius: 3px;
    background: var(--surface2); color: var(--text2);
  }
  .catch-all-warn {
    font-size: 12px; color: var(--badge-warning-text);
    background: var(--badge-warning-bg); padding: 2px 6px; border-radius: 3px;
    margin-top: 2px;
  }
  /* Row actions belong in their own flex wrapper — never on a flex cell directly. */
  .row-actions { display: flex; gap: 6px; align-items: center; flex: 0 0 auto; }
  textarea { width: 100%; resize: vertical; min-height: 56px; }
  .rpm-mode {
    display: flex; align-items: center; gap: 10px; flex-wrap: wrap;
    padding: 6px 4px 8px; border-bottom: 1px solid var(--border);
  }
  .rpm-mode-label { font-size: 13px; color: var(--text2); }
  .rpm-mode select { max-width: 320px; }
  .rpm-mode-effective { font-size: 12px; color: var(--text2); }
</style>
