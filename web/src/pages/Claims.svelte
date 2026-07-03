<script>
  import { onMount } from 'svelte'
  import { t } from 'svelte-i18n'
  import { api } from '../lib/api.js'
  import { submitForm, extractErrorMessage } from '../lib/form.js'
  import ErrorBanner from '../lib/ErrorBanner.svelte'
  import SearchInput from '../lib/SearchInput.svelte'
  import DataTable from '../lib/DataTable.svelte'
  import { ECOSYSTEMS, ECO_LABEL } from '../lib/ecosystems.js'
  import { readQuery, writeQuery } from '../lib/tableState.js'

  // Ecosystem column width matches the Reserved-namespaces table above so the
  // ecosystem badges line up column-for-column across both sections.
  $: columns = [
    { key: 'ecosystem', label: $t('claims.ecosystem'), sortable: true,  width: '110px' },
    { key: 'name',      label: $t('claims.name'),      sortable: true },
    { key: 'state',     label: $t('claims.state'),     sortable: true,  width: '130px' },
    { key: 'reason',    label: $t('claims.reason'),    sortable: false },
    { key: 'actions',   label: $t('claims.actions'),   sortable: false, width: '200px' },
  ]
  const comparators = {
    ecosystem: (a, b) => (a.ecosystem ?? '').localeCompare(b.ecosystem ?? ''),
    name:      (a, b) => (a.name ?? '').localeCompare(b.name ?? ''),
    state:     (a, b) => (a.state ?? '').localeCompare(b.state ?? ''),
  }

  // Filter state lives in the URL query string so it survives route changes,
  // reloads, and copied links.
  const DEFAULTS = { q: '', eco: '', state: '' }
  const init = readQuery(DEFAULTS)

  let claims = []
  let loading = true
  let error = ''
  let filterEco = init.eco, filterState = init.state, search = init.q

  function sync() {
    writeQuery({ q: search, eco: filterEco, state: filterState }, DEFAULTS)
  }

  // Modal state.
  // mode: null | 'create' | 'transition' | 'release'
  let modal = null
  let mEco = 'npm', mName = '', mState = 'local_only', mReason = '', mAck = false
  let mError = '', mSubmitting = false
  // currentClaim is set for transition / release; used to derive ecosystem + name in those flows.
  let currentClaim = null

  async function load() {
    loading = true
    error = ''
    try {
      const params = {}
      if (filterEco) params.ecosystem = filterEco
      if (filterState) params.state = filterState
      if (search) params.search = search
      const data = await api.listClaims(params)
      claims = data.items ?? []
    } catch (e) {
      error = $t('claims.loadFailed', { values: { message: extractErrorMessage(e) } })
    } finally {
      loading = false
    }
  }

  onMount(load)

  function onSearch() { sync(); load() }
  function onFilterChange() { sync(); load() }

  function openCreate() {
    modal = 'create'
    mEco = 'npm'; mName = ''; mState = 'local_only'; mReason = ''; mAck = false; mError = ''
    currentClaim = null
  }
  function openTransition(c) {
    modal = 'transition'
    currentClaim = c
    mState = c.state === 'local_only' ? 'mixed' : 'local_only'
    mReason = ''; mAck = false; mError = ''
  }
  function openRelease(c) {
    modal = 'release'
    currentClaim = c
    mReason = ''; mError = ''
  }
  function closeModal() {
    modal = null
    mError = ''
  }

  async function submitModal() {
    if (mSubmitting) return
    mError = ''
    if (!mReason.trim()) { mError = 'Reason is required.'; return }
    if ((mState === 'mixed' || (modal === 'transition' && mState === 'mixed')) && !mAck) {
      mError = $t('claims.modal.mixedWarning'); return
    }
    await submitForm(async () => {
      if (modal === 'create') {
        await api.createClaim({ ecosystem: mEco, name: mName.trim(), state: mState, reason: mReason.trim() })
      } else if (modal === 'transition') {
        await api.transitionClaim(currentClaim.ecosystem, currentClaim.name,
          { state: mState, reason: mReason.trim() })
      } else if (modal === 'release') {
        await api.releaseClaim(currentClaim.ecosystem, currentClaim.name, mReason.trim())
      }
    }, {
      setSaving: v => mSubmitting = v,
      setError:  v => mError      = v,
      onSuccess: async () => { closeModal(); await load() },
    })
  }
</script>

<div class="page-header list-header">
  <h3 class="section-h">{$t('claims.title')}</h3>
  <button class="primary" on:click={openCreate}>{$t('claims.newClaim')}</button>
</div>

<p class="form-hint">{$t('claims.description')}</p>

<div class="page-toolbar">
  <SearchInput
    placeholder={$t('claims.filters.search')}
    bind:value={search}
    on:search={onSearch}
    class="toolbar-search"
  />
  <select bind:value={filterEco} on:change={onFilterChange} class="eco-select">
    <option value="">{$t('claims.filters.ecosystem')}</option>
    {#each ECOSYSTEMS as eco (eco)}
      <option value={eco}>{ECO_LABEL[eco]}</option>
    {/each}
  </select>
  <select bind:value={filterState} on:change={onFilterChange} class="state-select">
    <option value="">{$t('claims.filters.state')}</option>
    <option value="local_only">{$t('claims.states.local_only')}</option>
    <option value="mixed">{$t('claims.states.mixed')}</option>
  </select>
</div>

<ErrorBanner message={error} />

<DataTable
  {columns}
  rows={claims}
  {comparators}
  {loading}
  initialSort={{ key: 'name', dir: 'asc' }}
  emptyText={$t('claims.empty')}
  tableClass="list-table"
  let:row={c}
>
  <tr>
    <td><span class="badge {c.ecosystem}">{ECO_LABEL[c.ecosystem] ?? c.ecosystem}</span></td>
    <td class="mono">{c.name}</td>
    <td><span class="badge state-{c.state}">{$t(`claims.states.${c.state}`)}</span></td>
    <td class="reason-cell text-muted" title={c.reason}>{c.reason}</td>
    <td class="actions-col">
      <button class="action-btn" on:click={() => openTransition(c)}>{$t('claims.transition')}</button>
      <button class="action-btn" on:click={() => openRelease(c)}>{$t('claims.release')}</button>
    </td>
  </tr>
</DataTable>

{#if modal}
  <div
    class="modal-backdrop"
    role="dialog"
    aria-modal="true"
    tabindex="-1"
    on:click|self={closeModal}
    on:keydown={(e) => { if (e.key === 'Escape') closeModal() }}
  >
    <div class="modal scrollable modal-flex">
      {#if modal === 'create'}
        <h2>{$t('claims.modal.createTitle')}</h2>
        <label>
          {$t('claims.modal.ecosystem')}
          <select bind:value={mEco}>
            {#each ECOSYSTEMS as eco (eco)}
              <option value={eco}>{ECO_LABEL[eco]}</option>
            {/each}
          </select>
        </label>
        <label>
          {$t('claims.modal.name')}
          <input bind:value={mName} required />
        </label>
        <label>
          {$t('claims.modal.state')}
          <select bind:value={mState}>
            <option value="local_only">{$t('claims.states.local_only')}</option>
            <option value="mixed">{$t('claims.states.mixed')}</option>
          </select>
        </label>
        {#if mState === 'mixed'}
          <div class="warning-card">
            <p>{$t('claims.modal.mixedWarning')}</p>
            <label class="ack"><input type="checkbox" bind:checked={mAck} /> {$t('claims.modal.mixedAck')}</label>
          </div>
        {/if}
        {#if mState === 'local_only'}
          <div class="info-card"><p>{$t('claims.modal.purgeWarning')}</p></div>
        {/if}
      {:else if modal === 'transition'}
        <h2>{$t('claims.modal.transitionTitle')}</h2>
        <p class="text-muted">{currentClaim.ecosystem} / <span class="mono">{currentClaim.name}</span></p>
        <label>
          {$t('claims.modal.newState')}
          <select bind:value={mState}>
            <option value="local_only" disabled={currentClaim.state === 'local_only'}>{$t('claims.states.local_only')}</option>
            <option value="mixed" disabled={currentClaim.state === 'mixed'}>{$t('claims.states.mixed')}</option>
          </select>
        </label>
        {#if mState === 'mixed'}
          <div class="warning-card">
            <p>{$t('claims.modal.mixedWarning')}</p>
            <label class="ack"><input type="checkbox" bind:checked={mAck} /> {$t('claims.modal.mixedAck')}</label>
          </div>
        {/if}
        {#if mState === 'local_only'}
          <div class="info-card"><p>{$t('claims.modal.purgeWarning')}</p></div>
        {/if}
      {:else if modal === 'release'}
        <h2>{$t('claims.modal.releaseTitle')}</h2>
        <p class="text-muted">{currentClaim.ecosystem} / <span class="mono">{currentClaim.name}</span></p>
      {/if}

      <label>
        {$t('claims.modal.reason')}
        <textarea
          bind:value={mReason}
          placeholder={$t('claims.modal.reasonPlaceholder')}
          rows="3"
          required
        ></textarea>
      </label>

      {#if mError}<div class="error-msg">{mError}</div>{/if}

      <div class="modal-actions">
        <button on:click={closeModal} disabled={mSubmitting}>{$t('claims.modal.cancel')}</button>
        <button class="primary" on:click={submitModal} disabled={mSubmitting}>
          {#if modal === 'create'}{$t('claims.modal.create')}
          {:else if modal === 'transition'}{$t('claims.modal.save')}
          {:else}{$t('claims.modal.confirmRelease')}
          {/if}
        </button>
      </div>
    </div>
  </div>
{/if}

<style>
  .state-select { width: auto; }
  /* Column widths come from the DataTable colgroup (fixed layout); the cell
     just clips overflow to its column. */
  .reason-cell { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .actions-col { white-space: nowrap; }
  .action-btn { padding: 3px 8px; font-size: 12px; min-height: 28px; margin-right: 4px; }

  /* .modal-flex, .warning-card, .info-card are global — see app.css */
  .ack { flex-direction: row !important; align-items: center; gap: 6px !important; cursor: pointer; }
  .ack input { width: auto; margin: 0; }
  .mono { font-family: var(--mono, monospace); }
</style>
