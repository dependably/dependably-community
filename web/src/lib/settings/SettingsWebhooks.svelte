<!--
  Outbound webhook subscriptions — per-org list with add, edit, remove, and test-ping
  actions. Secrets are write-only: the backend returns hasSecret (bool); the raw value
  is never echoed. Mounts only when the Webhooks tab is active and loads its own data.
-->
<script>
  import { onMount } from 'svelte'
  import { t } from 'svelte-i18n'
  import { api } from '../api.js'
  import ErrorBanner from '../ErrorBanner.svelte'
  import InfoTip from '../InfoTip.svelte'
  import Toggle from '../Toggle.svelte'

  const ALL_EVENT_TYPES = [
    'package.publish',
    'package.replace',
    'package.import',
    'package.unlist',
    'package.yank',
    'package.vulnerability',
  ]

  /** @type {any[]} */
  let webhooks = []
  let loaded = false
  let error = ''
  let testMsg = ''

  // Add/edit modal state
  let showModal = false
  /** @type {any|null} */
  let editTarget = null  // null = adding, non-null = editing
  let modalUrl = ''
  let modalEventTypes = /** @type {string[]} */ ([])
  let modalSecret = ''
  let modalDescription = ''
  let modalEnabled = true
  let saving = false

  onMount(load)

  async function load() {
    try {
      webhooks = await api.listWebhooks()
      loaded = true
    } catch (e) { error = extract(e) }
  }

  function openAdd() {
    editTarget = null
    modalUrl = ''
    modalEventTypes = []
    modalSecret = ''
    modalDescription = ''
    modalEnabled = true
    error = ''
    testMsg = ''
    showModal = true
  }

  function openEdit(sub) {
    editTarget = sub
    modalUrl = sub.url
    modalEventTypes = [...(sub.eventTypes ?? [])]
    modalSecret = ''  // never pre-fill — write-only
    modalDescription = sub.description ?? ''
    modalEnabled = sub.enabled
    error = ''
    testMsg = ''
    showModal = true
  }

  function toggleEventType(et) {
    if (modalEventTypes.includes(et)) {
      modalEventTypes = modalEventTypes.filter(e => e !== et)
    } else {
      modalEventTypes = [...modalEventTypes, et]
    }
  }

  async function save() {
    saving = true; error = ''
    try {
      if (editTarget) {
        const updated = await api.updateWebhook(
          editTarget.id,
          modalUrl.trim(),
          modalEventTypes,
          modalEnabled,
          modalSecret || null,
          modalDescription.trim() || null)
        webhooks = webhooks.map(w => w.id === updated.id ? updated : w)
      } else {
        const created = await api.addWebhook(
          modalUrl.trim(),
          modalEventTypes,
          modalSecret || null,
          modalDescription.trim() || null)
        webhooks = [...webhooks, created]
      }
      showModal = false
    } catch (e) { error = extract(e) }
    finally { saving = false }
  }

  async function remove(sub) {
    if (!confirm($t('settings.webhooks.removeConfirm'))) return
    error = ''
    try {
      await api.deleteWebhook(sub.id)
      webhooks = webhooks.filter(w => w.id !== sub.id)
    } catch (e) { error = extract(e) }
  }

  async function test(sub) {
    testMsg = ''; error = ''
    try {
      await api.testWebhook(sub.id)
      testMsg = $t('settings.webhooks.testOk')
    } catch (e) { testMsg = $t('settings.webhooks.testFail') + ' ' + extract(e) }
  }

  function extract(e) { return e?.body?.detail || e?.message || e?.detail || String(e) }

  $: saveDisabled = saving || !modalUrl.trim() || modalEventTypes.length === 0
</script>

<div class="page-header list-header mt-4">
  <h3 class="section-h">
    {$t('settings.webhooks.section')}
    <InfoTip text={$t('settings.webhooks.hint')} />
  </h3>
  <button class="primary" on:click={openAdd}>{$t('settings.webhooks.add')}</button>
</div>

<ErrorBanner message={error} />
{#if testMsg}<p class="test-msg">{testMsg}</p>{/if}

{#if loaded && webhooks.length === 0}
  <p class="text-muted empty-state">{$t('settings.webhooks.empty')}</p>
{:else}
  <table class="list-table">
    <colgroup>
      <col>
      <col class="col-events">
      <col class="col-status">
      <col class="col-last">
      <col class="col-actions">
    </colgroup>
    <thead>
      <tr>
        <th>{$t('settings.webhooks.columns.url')}</th>
        <th>{$t('settings.webhooks.columns.events')}</th>
        <th>{$t('settings.webhooks.columns.status')}</th>
        <th>{$t('settings.webhooks.columns.lastDelivery')}</th>
        <th></th>
      </tr>
    </thead>
    <tbody>
      {#each webhooks as sub (sub.id)}
        <tr>
          <td class="t-mono url-cell">
            {sub.url}
            {#if sub.description}<div class="sub-desc">{sub.description}</div>{/if}
            {#if !sub.hasSecret}
              <div class="no-secret-warn">{$t('settings.webhooks.noSecretWarning')}</div>
            {/if}
          </td>
          <td class="events-cell">
            {#each (sub.eventTypes ?? []) as et (et)}
              <span class="event-badge">{$t('settings.webhooks.eventTypes.' + et)}</span>
            {/each}
          </td>
          <td>
            {#if sub.enabled}
              <span class="status-badge status-enabled">{$t('settings.webhooks.enabled')}</span>
            {:else}
              <span class="status-badge status-disabled">{$t('settings.webhooks.disabled')}</span>
            {/if}
            {#if sub.lastStatus}<div class="last-status">{sub.lastStatus}</div>{/if}
          </td>
          <td class="text-muted">{sub.lastDeliveryAt ?? '—'}</td>
          <td>
            <div class="row-actions">
              <button class="btn-sm" on:click={() => test(sub)}>{$t('settings.webhooks.test')}</button>
              <button class="btn-sm" on:click={() => openEdit(sub)}>{$t('common.actions.edit')}</button>
              <button class="btn-sm danger" on:click={() => remove(sub)}>{$t('settings.webhooks.remove')}</button>
            </div>
          </td>
        </tr>
      {/each}
    </tbody>
  </table>
{/if}

{#if showModal}
  <div class="modal-backdrop">
    <div class="modal">
      <h3>{editTarget ? $t('settings.webhooks.modal.editTitle') : $t('settings.webhooks.modal.addTitle')}</h3>
      {#if error}<div class="error-msg">{error}</div>{/if}

      <div class="form-row">
        <label for="wh-url">{$t('settings.webhooks.modal.url')}</label>
        <input id="wh-url" type="url" bind:value={modalUrl} placeholder="https://example.com/webhook" />
        <div class="form-hint">{$t('settings.webhooks.modal.urlHint')}</div>
      </div>

      <div class="form-row">
        <label>{$t('settings.webhooks.modal.events')}</label>
        <div class="event-checks">
          {#each ALL_EVENT_TYPES as et (et)}
            <label class="check-label">
              <input type="checkbox"
                     checked={modalEventTypes.includes(et)}
                     on:change={() => toggleEventType(et)} />
              {$t('settings.webhooks.eventTypes.' + et)}
            </label>
          {/each}
        </div>
        <div class="form-hint">{$t('settings.webhooks.modal.eventsHint')}</div>
      </div>

      <div class="form-row">
        <label for="wh-secret">{$t('settings.webhooks.modal.secret')}</label>
        <input id="wh-secret" type="password" bind:value={modalSecret} autocomplete="new-password" />
        <div class="form-hint">
          {editTarget ? $t('settings.webhooks.modal.secretRotateHint') : $t('settings.webhooks.modal.secretHint')}
        </div>
      </div>

      {#if editTarget}
        <div class="form-row">
          <span class="check-label">
            <Toggle bind:checked={modalEnabled} ariaLabel={$t('settings.webhooks.modal.enabledLabel')} />
            {$t('settings.webhooks.modal.enabledLabel')}
          </span>
        </div>
      {/if}

      <div class="form-row">
        <label for="wh-desc">{$t('settings.webhooks.modal.description')}</label>
        <input id="wh-desc" bind:value={modalDescription} maxlength="255" />
      </div>

      <div class="modal-actions">
        <button on:click={() => showModal = false}>{$t('common.actions.cancel')}</button>
        <button class="primary" on:click={save} disabled={saveDisabled}>
          {saving ? $t('common.actions.saving') : $t('common.actions.save')}
        </button>
      </div>
    </div>
  </div>
{/if}

<style>
  .empty-state { margin: 8px 0; font-size: 13px; }
  .url-cell { font-size: 13px; word-break: break-all; }
  .sub-desc { font-size: 12px; color: var(--text2); margin-top: 2px; }
  .no-secret-warn {
    font-size: 11px; color: var(--badge-warning-text);
    background: var(--badge-warning-bg); padding: 1px 5px;
    border-radius: 3px; margin-top: 3px; display: inline-block;
  }
  .events-cell { vertical-align: top; padding-top: 10px; }
  .event-badge {
    display: inline-block; font-size: 11px; padding: 1px 5px;
    border-radius: 3px; background: var(--surface2); color: var(--text2);
    margin: 2px 2px 2px 0;
  }
  .status-badge {
    font-size: 11px; padding: 1px 5px; border-radius: 3px; font-weight: 500;
  }
  .status-enabled { background: var(--badge-hosted-bg); color: var(--badge-hosted-text); }
  .status-disabled { background: var(--surface2); color: var(--text2); }
  .last-status { font-size: 12px; color: var(--text2); margin-top: 2px; }
  .col-events  { width: 160px; }
  .col-status  { width: 90px; }
  .col-last    { width: 120px; }
  .col-actions { width: 200px; }
  .row-actions { display: flex; gap: 6px; align-items: center; flex: 0 0 auto; }
  .event-checks { display: flex; flex-wrap: wrap; gap: 4px 12px; margin: 4px 0; }
  .check-label {
    display: flex; align-items: center; gap: 6px;
    font-size: 13px; font-weight: 500; color: var(--text2); cursor: pointer;
  }
  .check-label input[type="checkbox"] {
    width: auto; min-height: 0; margin: 0; flex-shrink: 0;
  }
  .test-msg { font-size: 13px; color: var(--text2); margin: 6px 0; }
</style>
