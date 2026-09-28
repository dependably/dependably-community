<!--
  System API tokens (apex, multi-mode only). Mints dpsys_… tokens scoped to exactly the six
  tenant-lifecycle actions on SystemController — CI/Terraform provisioning, not an interactive
  session. Any system admin can see and revoke any token; ownership only decides whose account
  status/deletion tears a token down (server-side, not shown here).

  Modelled on lib/settings/SettingsServiceTokens.svelte (list + create modal + show-once secret)
  and the dialog conventions in SystemAdmins.svelte.
-->
<script>
  import { reportPageLoad } from '../lib/pageLoad.js'
  import { onMount } from 'svelte'
  import { t } from 'svelte-i18n'
  import { systemApi } from '../lib/api.js'
  import { formatDateShort } from '../lib/format.js'
  import { copyToClipboard } from '../lib/clipboard.js'
  import { extractErrorMessage } from '../lib/form.js'
  import DataTable from '../lib/DataTable.svelte'

  /** The route transition this page was mounted for, supplied by RouteView. @type {number | null} */
  export let pageToken = null
  $: reportPageLoad(pageToken, loading)

  let tokens = [], loading = true, error = ''

  const DEFAULT_EXPIRY_DAYS = 90

  let showCreate = false, newName = '', newExpiry = defaultExpiry(), newDescription = '', creating = false, createError = ''
  let newTokenValue = null
  let copyState = ''

  let revokeTarget = null, revokeBusy = false

  function defaultExpiry() {
    const now = new Date()
    // datetime-local input wants a naive local-time string without seconds/zone; computed via
    // arithmetic on a fresh Date rather than mutating one in place (no .setDate/.setMinutes).
    const local = new Date(now.getTime()
      + DEFAULT_EXPIRY_DAYS * 24 * 60 * 60 * 1000
      - now.getTimezoneOffset() * 60 * 1000)
    return local.toISOString().slice(0, 16)
  }

  async function copyToken() {
    const ok = await copyToClipboard(newTokenValue)
    copyState = ok ? 'copied' : 'failed'
    setTimeout(() => copyState = '', 2000)
  }

  onMount(load)

  async function load() {
    loading = true
    error = ''
    try {
      tokens = await systemApi.listSystemTokens()
    } catch (e) {
      error = extractErrorMessage(e)
    } finally {
      loading = false
    }
  }

  function openCreate() {
    newName = ''
    newDescription = ''
    newExpiry = defaultExpiry()
    createError = ''
    showCreate = true
  }

  async function create() {
    if (!newName.trim()) { createError = $t('systemTokens.modal.nameRequired'); return }
    if (!newExpiry) { createError = $t('systemTokens.modal.expiresAtRequired'); return }
    creating = true
    createError = ''
    try {
      const data = await systemApi.createSystemToken(
        newName.trim(),
        new Date(newExpiry).toISOString(),
        newDescription.trim() || null,
      )
      newTokenValue = data.token
      tokens = [data.record, ...tokens]
      showCreate = false
    } catch (e) {
      createError = extractErrorMessage(e)
    } finally {
      creating = false
    }
  }

  function openRevoke(row) {
    revokeTarget = row
  }

  async function confirmRevoke() {
    if (!revokeTarget) return
    revokeBusy = true
    try {
      await systemApi.deleteSystemToken(revokeTarget.id)
      tokens = tokens.filter(tok => tok.id !== revokeTarget.id)
      revokeTarget = null
    } catch (e) {
      error = extractErrorMessage(e)
    } finally {
      revokeBusy = false
    }
  }

  function expired(tok) { return tok.expiresAt && new Date(tok.expiresAt) < new Date() }

  $: columns = [
    { key: 'name',        label: $t('systemTokens.columns.name'),        sortable: true },
    { key: 'ownerEmail',  label: $t('systemTokens.columns.owner'),       sortable: true },
    { key: 'description', label: $t('systemTokens.columns.description'), sortable: true },
    { key: 'createdAt',   label: $t('systemTokens.columns.created'),     sortable: true, width: '110px' },
    { key: 'expiresAt',   label: $t('systemTokens.columns.expires'),     sortable: true, width: '130px' },
    { key: 'lastUsedAt',  label: $t('systemTokens.columns.lastUsed'),    sortable: true, width: '130px' },
    { key: 'actions',     label: '',                                     sortable: false, width: '90px' },
  ]
  const comparators = {
    description: (a, b) => (a.description || '').localeCompare(b.description || ''),
    ownerEmail: (a, b) => (a.ownerEmail || '').localeCompare(b.ownerEmail || ''),
  }
</script>

<h1>{$t('systemTokens.title')}</h1>
<p class="text-muted">{$t('systemTokens.reach')}</p>

<div class="settings-tab-actions">
  <button class="primary" on:click={openCreate}>{$t('systemTokens.newToken')}</button>
</div>

{#if newTokenValue}
  <div class="card success mb-4">
    <strong>{$t('systemTokens.tokenCreated')}</strong>
    <div class="copy-block mt-2">
      <span class="copy-block-text">{newTokenValue}</span>
      <button class="copy-btn" on:click={copyToken}>
        {copyState === 'copied' ? $t('common.actions.copied') : copyState === 'failed' ? $t('common.actions.copyFailed') : $t('common.actions.copy')}
      </button>
    </div>
    <button class="mt-2" on:click={() => newTokenValue = null}>{$t('common.actions.dismiss')}</button>
  </div>
{/if}

{#if error}<div class="error-msg">{error}</div>{/if}

<DataTable
  {columns}
  rows={tokens}
  {comparators}
  {loading}
  initialSort={{ key: 'createdAt', dir: 'desc' }}
  emptyText={$t('systemTokens.empty')}
  tableClass="system-tokens-table"
  let:row={tok}
>
  <tr>
    <td>{tok.name}</td>
    <td class="text-muted">{tok.ownerEmail || '—'}</td>
    <td class="t-sm" title={tok.description || ''}>{tok.description || '—'}</td>
    <td class="text-muted date-cell">{$formatDateShort(tok.createdAt)}</td>
    <td class="date-cell">
      {#if expired(tok)}<span class="badge expired">{$t('systemTokens.expired')}</span>
      {:else}{$formatDateShort(tok.expiresAt)}{/if}
    </td>
    <td class="text-muted date-cell">{tok.lastUsedAt ? $formatDateShort(tok.lastUsedAt) : $t('systemTokens.never')}</td>
    <td><button class="danger btn-sm" on:click={() => openRevoke(tok)}>{$t('common.actions.revoke')}</button></td>
  </tr>
</DataTable>

{#if showCreate}
  <div class="modal-backdrop">
    <div class="modal">
      <h3>{$t('systemTokens.modal.title')}</h3>
      {#if createError}<div class="error-msg">{createError}</div>{/if}
      <div class="form-row"><label>{$t('systemTokens.modal.name')}</label><input bind:value={newName} placeholder={$t('systemTokens.modal.namePlaceholder')} /></div>
      <div class="form-row"><label>{$t('systemTokens.modal.description')}</label><input type="text" maxlength="200" bind:value={newDescription} placeholder={$t('systemTokens.modal.descriptionPlaceholder')} /></div>
      <div class="form-row"><label>{$t('systemTokens.modal.expiresAt')}</label><input type="datetime-local" bind:value={newExpiry} /></div>
      <div class="modal-actions">
        <button on:click={() => showCreate = false}>{$t('common.actions.cancel')}</button>
        <button class="primary" on:click={create} disabled={creating}>{creating ? $t('common.actions.creating') : $t('common.actions.create')}</button>
      </div>
    </div>
  </div>
{/if}

{#if revokeTarget}
  <div class="modal-backdrop">
    <div class="modal">
      <h3>{$t('common.actions.revoke')}</h3>
      <p>{$t('systemTokens.revokeConfirm')}</p>
      <div class="modal-actions">
        <button on:click={() => revokeTarget = null}>{$t('common.actions.cancel')}</button>
        <button class="danger" on:click={confirmRevoke} disabled={revokeBusy}>{$t('common.actions.revoke')}</button>
      </div>
    </div>
  </div>
{/if}

<style>
  .date-cell { white-space: nowrap; }
</style>
