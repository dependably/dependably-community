<script>
  import { onMount } from 'svelte'
  import { t } from 'svelte-i18n'
  import { api } from '../lib/api.js'
  import { submitForm, extractErrorMessage } from '../lib/form.js'
  import ErrorBanner from '../lib/ErrorBanner.svelte'
  import { ECOSYSTEMS, ECO_LABEL } from '../lib/ecosystems.js'

  let claims = []
  let loading = true
  let error = ''
  let filterEco = '', filterState = '', search = ''

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

  let searchTimeout
  function onSearchInput() {
    clearTimeout(searchTimeout)
    searchTimeout = setTimeout(load, 300)
  }

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
    <span></span>
    <button class="primary" on:click={openCreate}>{$t('claims.newClaim')}</button>
  </div>

  <p class="text-muted desc">{$t('claims.description')}</p>

  <div class="search-bar">
    <select bind:value={filterEco} on:change={load} class="eco-select">
      <option value="">{$t('claims.filters.ecosystem')}</option>
      {#each ECOSYSTEMS as eco (eco)}
        <option value={eco}>{ECO_LABEL[eco]}</option>
      {/each}
    </select>
    <select bind:value={filterState} on:change={load} class="state-select">
      <option value="">{$t('claims.filters.state')}</option>
      <option value="local_only">{$t('claims.states.local_only')}</option>
      <option value="mixed">{$t('claims.states.mixed')}</option>
    </select>
    <input
      type="text"
      placeholder={$t('claims.filters.search')}
      bind:value={search}
      on:input={onSearchInput}
      class="search-input"
    />
  </div>

  <ErrorBanner message={error} />

  {#if loading}
    <span class="spinner"></span>
  {:else}
    <table class="table-auto">
      <thead>
        <tr>
          <th>{$t('claims.ecosystem')}</th>
          <th>{$t('claims.name')}</th>
          <th>{$t('claims.state')}</th>
          <th>{$t('claims.reason')}</th>
          <th class="actions-col">{$t('claims.actions')}</th>
        </tr>
      </thead>
      <tbody>
        {#each claims as c (c.id)}
          <tr>
            <td><span class="badge {c.ecosystem}">{ECO_LABEL[c.ecosystem] ?? c.ecosystem}</span></td>
            <td class="mono">{c.name}</td>
            <td><span class="state-badge state-{c.state}">{$t(`claims.states.${c.state}`)}</span></td>
            <td class="reason-cell text-muted" title={c.reason}>{c.reason}</td>
            <td class="actions-col">
              <button class="action-btn" on:click={() => openTransition(c)}>{$t('claims.transition')}</button>
              <button class="action-btn" on:click={() => openRelease(c)}>{$t('claims.release')}</button>
            </td>
          </tr>
        {/each}
        {#if claims.length === 0}
          <tr><td colspan="5" class="text-center text-muted">{$t('claims.empty')}</td></tr>
        {/if}
      </tbody>
    </table>
  {/if}

{#if modal}
  <div
    class="modal-backdrop"
    role="dialog"
    aria-modal="true"
    tabindex="-1"
    on:click|self={closeModal}
    on:keydown={(e) => { if (e.key === 'Escape') closeModal() }}
  >
    <div class="modal">
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
  .page-header { display: flex; align-items: center; justify-content: space-between; }
  .desc { max-width: 720px; }
  .search-bar { display: flex; gap: 8px; margin-bottom: 12px; }
  .search-input { flex: 1; max-width: 320px; }
  .eco-select, .state-select { width: auto; }
  .reason-cell { max-width: 280px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .actions-col { width: 200px; white-space: nowrap; }
  .action-btn { padding: 3px 8px; font-size: 12px; min-height: 28px; margin-right: 4px; }

  .state-badge {
    display: inline-block;
    padding: 1px 8px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
  }
  .state-unclaimed  { background: var(--bg2); color: var(--text2); border: 1px solid var(--border); }
  .state-local_only { background: var(--success-bg); color: var(--success); border: 1px solid var(--success-border); }
  .state-mixed      { background: var(--warning-bg); color: var(--warning-text); border: 1px solid var(--warning-border); }

  .modal-backdrop {
    position: fixed; inset: 0;
    background: var(--overlay-scrim);
    display: flex; align-items: center; justify-content: center;
    z-index: 1000;
  }
  .modal {
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 24px;
    width: min(520px, 90vw);
    max-height: 85vh;
    overflow-y: auto;
    display: flex; flex-direction: column; gap: 12px;
  }
  .modal h2 { margin: 0; font-size: 16px; }
  .modal label { display: flex; flex-direction: column; gap: 4px; font-size: 13px; }
  .modal-actions { display: flex; justify-content: flex-end; gap: 8px; margin-top: 8px; }

  .warning-card {
    background: var(--warning-bg);
    border: 1px solid var(--warning-border);
    border-radius: 4px;
    padding: 8px 12px;
    font-size: 12px;
  }
  .warning-card p { margin: 0 0 6px 0; }
  .ack { flex-direction: row !important; align-items: center; gap: 6px !important; cursor: pointer; }
  .ack input { width: auto; margin: 0; }

  .info-card {
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 8px 12px;
    font-size: 12px;
  }
  .info-card p { margin: 0; }
  .mono { font-family: var(--mono, monospace); }
</style>
