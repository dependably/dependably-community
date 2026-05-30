<script>
  import { t } from 'svelte-i18n'
  import { api } from '../lib/api.js'
  import ErrorBanner from '../lib/ErrorBanner.svelte'
  import { currentOrg } from '../lib/store.js'
  import { formatDateShort } from '../lib/format.js'
  import { copyToClipboard } from '../lib/clipboard.js'
  import DataTable from '../lib/DataTable.svelte'
  import { presetToCapabilities, capabilitiesToLabel } from '../lib/tokenCapabilities.js'

  let tokens = [], loading = true, error = ''
  let showCreate = false, newScope = 'pull', newExpiry = '', newDescription = '', creating = false
  let newTokenValue = null
  let copyState = ''

  async function copyToken() {
    const ok = await copyToClipboard(newTokenValue)
    copyState = ok ? 'copied' : 'failed'
    setTimeout(() => copyState = '', 2000)
  }

  $: org = $currentOrg
  $: if (org) load()

  async function load() {
    loading = true
    tokens = await api.listTokens().catch(e => { error = e.message; return [] })
    loading = false
  }

  async function create() {
    creating = true
    try {
      const data = await api.createToken(
        presetToCapabilities(newScope),
        newExpiry || null,
        newDescription.trim() || null,
      )
      newTokenValue = data.token
      tokens = [data.record, ...tokens]
      newDescription = ''
      showCreate = false
    } catch (e) { error = e.message }
    finally { creating = false }
  }

  async function revoke(id) {
    if (!confirm($t('tokens.title') + '?')) return
    await api.deleteToken( id)
    tokens = tokens.filter(t => t.id !== id)
  }

  function expired(t) { return t.expiresAt && new Date(t.expiresAt) < new Date() }

  // The "scope" column displays a label derived from capabilities, so sort by that
  // derived label when the user clicks the header. Other columns sort by the raw field.
  $: columns = [
    { key: 'id',          label: $t('tokens.columns.id'),          sortable: false, width: '100px' },
    { key: 'description', label: $t('tokens.columns.description'), sortable: true },
    { key: 'scope',       label: $t('tokens.columns.scope'),       sortable: true,  width: '80px' },
    { key: 'createdAt',   label: $t('tokens.columns.created'),     sortable: true,  width: '110px', defaultDir: 'desc' },
    { key: 'expiresAt',   label: $t('tokens.columns.expires'),     sortable: true,  width: '130px' },
    { key: 'lastUsedAt',  label: $t('tokens.columns.lastUsed'),    sortable: true,  width: '130px' },
    { key: 'actions',     label: '',                               sortable: false, width: '90px' },
  ]
  const comparators = {
    scope: (a, b) => capabilitiesToLabel(a.capabilities).localeCompare(capabilitiesToLabel(b.capabilities)),
    description: (a, b) => (a.description || '').localeCompare(b.description || ''),
  }
</script>

<div class="page">
  <div class="page-header">
    <h1 class="page-title">{$t('tokens.title')}</h1>
    <button class="primary" on:click={() => showCreate = true}>{$t('tokens.newToken')}</button>
  </div>

  {#if newTokenValue}
    <div class="card success mb-4">
      <strong>{$t('tokens.tokenCreated')}</strong>
      <div class="copy-block mt-2">
        <span class="copy-block-text">{newTokenValue}</span>
        <button class="copy-btn" on:click={copyToken}>
          {copyState === 'copied' ? $t('common.actions.copied') : copyState === 'failed' ? $t('common.actions.copyFailed') : $t('common.actions.copy')}
        </button>
      </div>
      <button class="mt-2" on:click={() => newTokenValue = null}>{$t('common.actions.dismiss')}</button>
    </div>
  {/if}

  <ErrorBanner message={error} />
  <DataTable
    {columns}
    rows={tokens}
    {comparators}
    {loading}
    initialSort={{ key: 'createdAt', dir: 'desc' }}
    emptyText={$t('tokens.empty')}
    tableClass="tokens-table"
    let:row={tok}
  >
    <tr>
      <td class="t-mono t-sm">{tok.id.slice(0,8)}…</td>
      <td class="t-sm" title={tok.description || ''}>{tok.description || '—'}</td>
      <td><span class="badge">{capabilitiesToLabel(tok.capabilities)}</span></td>
      <td class="text-muted">{$formatDateShort(tok.createdAt)}</td>
      <td>
        {#if expired(tok)}<span class="badge expired">{$t('tokens.expired')}</span>
        {:else}{tok.expiresAt ? $formatDateShort(tok.expiresAt) : '—'}{/if}
      </td>
      <td class="text-muted">{tok.lastUsedAt ? $formatDateShort(tok.lastUsedAt) : $t('tokens.never')}</td>
      <td><button class="danger btn-sm" on:click={() => revoke(tok.id)}>{$t('common.actions.revoke')}</button></td>
    </tr>
  </DataTable>
</div>


{#if showCreate}
  <div class="modal-backdrop">
    <div class="modal">
      <h3>{$t('tokens.modal.title')}</h3>
      <div class="form-row">
        <label>{$t('tokens.modal.description')}</label>
        <input type="text" maxlength="200" bind:value={newDescription} placeholder={$t('tokens.modal.descriptionPlaceholder')} />
      </div>
      <div class="form-row">
        <label>{$t('tokens.modal.scope')}</label>
        <select bind:value={newScope} class="w-auto">
          <option value="pull">pull</option>
          <option value="push">push</option>
          <option value="both">both</option>
        </select>
      </div>
      <div class="form-row">
        <label>{$t('tokens.modal.expiresAt')}</label>
        <input type="datetime-local" bind:value={newExpiry} />
      </div>
      <div class="modal-actions">
        <button on:click={() => showCreate = false}>{$t('common.actions.cancel')}</button>
        <button class="primary" on:click={create} disabled={creating}>{creating ? $t('common.actions.creating') : $t('common.actions.create')}</button>
      </div>
    </div>
  </div>
{/if}
