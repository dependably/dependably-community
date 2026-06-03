<!--
  Service tokens tab of OrgSettings (admin-only). Manages named, org-level automation
  identities used by CI pipelines and other service integrations. Distinct from
  user tokens (member self-service, in Tokens.svelte) — admin-issued, no user_id,
  capped at the caller's role grants.

  Self-contained: owns its own list, create-modal, and revoke state. Mounts on tab
  switch and remounts on revisit, mirroring SettingsAuth / SettingsRetention.
-->
<script>
  import { onMount } from 'svelte'
  import { t } from 'svelte-i18n'
  import { api } from '../api.js'
  import ErrorBanner from '../ErrorBanner.svelte'
  import { formatDateShort } from '../format.js'
  import { copyToClipboard } from '../clipboard.js'
  import DataTable from '../DataTable.svelte'
  import { presetToCapabilities, capabilitiesToLabel, PACKAGE_PRESETS, PRIVILEGED_PRESETS } from '../tokenCapabilities.js'

  // This tab is admin-only, so all presets — package and privileged — are offered.
  const scopeOptions = [...PACKAGE_PRESETS, ...PRIVILEGED_PRESETS]

  let tokens = [], loading = true, error = ''
  let showCreate = false, newName = '', newScope = 'pull', newExpiry = '', newDescription = '', creating = false
  let newTokenValue = null
  let copyState = ''

  async function copyToken() {
    const ok = await copyToClipboard(newTokenValue)
    copyState = ok ? 'copied' : 'failed'
    setTimeout(() => copyState = '', 2000)
  }

  onMount(load)

  async function load() {
    loading = true
    tokens = await api.listServiceTokens().catch(e => { error = e.message; return [] })
    loading = false
  }

  async function create() {
    if (!newName.trim()) { error = $t('serviceTokens.modal.nameRequired'); return }
    creating = true
    try {
      const data = await api.createServiceToken(
        newName,
        presetToCapabilities(newScope),
        newExpiry || null,
        newDescription.trim() || null,
      )
      newTokenValue = data.token
      tokens = [data.record, ...tokens]
      showCreate = false; newName = ''; newDescription = ''
    } catch (e) { error = e.message }
    finally { creating = false }
  }

  async function revoke(id) {
    if (!confirm($t('serviceTokens.revokeConfirm'))) return
    await api.deleteServiceToken(id)
    tokens = tokens.filter(t => t.id !== id)
  }

  function expired(t) { return t.expiresAt && new Date(t.expiresAt) < new Date() }

  $: columns = [
    { key: 'name',        label: $t('serviceTokens.columns.name'),        sortable: true },
    { key: 'description', label: $t('serviceTokens.columns.description'), sortable: true },
    { key: 'scope',       label: $t('serviceTokens.columns.scope'),       sortable: true, width: '80px' },
    { key: 'createdAt',   label: $t('serviceTokens.columns.created'),     sortable: true, width: '110px' },
    { key: 'expiresAt',   label: $t('serviceTokens.columns.expires'),     sortable: true, width: '130px' },
    { key: 'lastUsedAt',  label: $t('serviceTokens.columns.lastUsed'),    sortable: true, width: '130px' },
    { key: 'actions',     label: '',                                      sortable: false, width: '90px' },
  ]
  const comparators = {
    scope: (a, b) => capabilitiesToLabel(a.capabilities).localeCompare(capabilitiesToLabel(b.capabilities)),
    description: (a, b) => (a.description || '').localeCompare(b.description || ''),
  }
</script>

<div class="settings-tab-actions">
  <button class="primary" on:click={() => showCreate = true}>{$t('serviceTokens.newToken')}</button>
</div>

{#if newTokenValue}
  <div class="card success mb-4">
    <strong>{$t('serviceTokens.tokenCreated')}</strong>
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
  initialSort={{ key: 'name', dir: 'asc' }}
  emptyText={$t('serviceTokens.empty')}
  tableClass="service-tokens-table"
  let:row={tok}
>
  {@const label = capabilitiesToLabel(tok.capabilities)}
  <tr>
    <td>{tok.name}</td>
    <td class="t-sm" title={tok.description || ''}>{tok.description || '—'}</td>
    <td><span class="badge {label}">{label === '—' ? '—' : $t('tokenScopes.' + label)}</span></td>
    <td class="text-muted">{$formatDateShort(tok.createdAt)}</td>
    <td>
      {#if expired(tok)}<span class="badge expired">{$t('serviceTokens.expired')}</span>
      {:else if tok.expiresAt}{$formatDateShort(tok.expiresAt)}
      {:else}{$t('common.never')}{/if}
    </td>
    <td class="text-muted">{tok.lastUsedAt ? $formatDateShort(tok.lastUsedAt) : $t('serviceTokens.never')}</td>
    <td><button class="danger btn-sm" on:click={() => revoke(tok.id)}>{$t('common.actions.revoke')}</button></td>
  </tr>
</DataTable>

{#if showCreate}
  <div class="modal-backdrop">
    <div class="modal">
      <h3>{$t('serviceTokens.modal.title')}</h3>
      {#if error}<div class="error-msg">{error}</div>{/if}
      <div class="form-row"><label>{$t('serviceTokens.modal.name')}</label><input bind:value={newName} placeholder={$t('serviceTokens.modal.namePlaceholder')} /></div>
      <div class="form-row"><label>{$t('serviceTokens.modal.description')}</label><input type="text" maxlength="200" bind:value={newDescription} placeholder={$t('serviceTokens.modal.descriptionPlaceholder')} /></div>
      <div class="form-row">
        <label>{$t('serviceTokens.modal.scope')}</label>
        <select bind:value={newScope} class="w-auto">{#each scopeOptions as s (s)}<option value={s}>{$t('tokenScopes.' + s)}</option>{/each}</select>
      </div>
      <div class="form-row"><label>{$t('serviceTokens.modal.expiresAt')}</label><input type="datetime-local" bind:value={newExpiry} /></div>
      <div class="modal-actions">
        <button on:click={() => showCreate = false}>{$t('common.actions.cancel')}</button>
        <button class="primary" on:click={create} disabled={creating}>{creating ? $t('common.actions.creating') : $t('common.actions.create')}</button>
      </div>
    </div>
  </div>
{/if}
