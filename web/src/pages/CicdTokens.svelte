<script>
  import { t } from 'svelte-i18n'
  import { api } from '../lib/api.js'
  import { currentOrg } from '../lib/store.js'
  import { formatDateShort } from '../lib/format.js'
  import { copyToClipboard } from '../lib/clipboard.js'
  import { sortIndicator } from '../lib/sortIndicator.js'
  import { presetToCapabilities, capabilitiesToLabel } from '../lib/tokenCapabilities.js'

  let tokens = [], loading = true, error = ''
  let showCreate = false, newName = '', newScope = 'pull', newExpiry = '', creating = false
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
    tokens = await api.listCicdTokens().catch(e => { error = e.message; return [] })
    loading = false
  }

  async function create() {
    if (!newName.trim()) { error = $t('cicdTokens.modal.nameRequired'); return }
    creating = true
    try {
      const data = await api.createCicdToken(newName, presetToCapabilities(newScope), newExpiry || null)
      newTokenValue = data.token
      tokens = [data.record, ...tokens]
      showCreate = false; newName = ''
    } catch (e) { error = e.message }
    finally { creating = false }
  }

  async function revoke(id) {
    if (!confirm($t('cicdTokens.revokeConfirm'))) return
    await api.deleteCicdToken( id)
    tokens = tokens.filter(t => t.id !== id)
  }

  function expired(t) { return t.expiresAt && new Date(t.expiresAt) < new Date() }

  let sortCol = 'name', sortDir = 'asc'
  $: sorted = [...tokens].sort((a, b) => {
    const key = (row) => sortCol === 'scope' ? capabilitiesToLabel(row.capabilities) : row[sortCol] ?? ''
    const av = key(a), bv = key(b)
    if (av < bv) return sortDir === 'asc' ? -1 : 1
    if (av > bv) return sortDir === 'asc' ? 1 : -1
    return 0
  })
  function toggleSort(col) {
    if (sortCol === col) sortDir = sortDir === 'asc' ? 'desc' : 'asc'
    else { sortCol = col; sortDir = 'asc' }
  }
</script>

<div class="page">
  <div class="page-header">
    <h1 class="page-title">{$t('cicdTokens.title')}</h1>
    <button class="primary" on:click={() => showCreate = true}>{$t('cicdTokens.newToken')}</button>
  </div>

  {#if newTokenValue}
    <div class="card success mb-4">
      <strong>{$t('cicdTokens.tokenCreated')}</strong>
      <div class="copy-block mt-2">
        <span class="copy-block-text">{newTokenValue}</span>
        <button class="copy-btn" on:click={copyToken}>
          {copyState === 'copied' ? $t('common.actions.copied') : copyState === 'failed' ? $t('common.actions.copyFailed') : $t('common.actions.copy')}
        </button>
      </div>
      <button class="mt-2" on:click={() => newTokenValue = null}>{$t('common.actions.dismiss')}</button>
    </div>
  {/if}

  {#if error}<div class="page-error">{error}</div>{/if}
  {#if loading}<span class="spinner"></span>
  {:else}
    <table class="cicd-table">
      <colgroup>
        <col><!-- name: flexible -->
        <col class="col-scope"><!-- scope badge -->
        <col class="col-created"><!-- created date -->
        <col class="col-expires"><!-- expires date/badge -->
        <col class="col-actions"><!-- actions -->
      </colgroup>
      <thead><tr>
        <th class="sortable" on:click={() => toggleSort('name')}>{$t('cicdTokens.columns.name')}{sortIndicator('name', sortCol, sortDir)}</th>
        <th class="sortable" on:click={() => toggleSort('scope')}>{$t('cicdTokens.columns.scope')}{sortIndicator('scope', sortCol, sortDir)}</th>
        <th class="sortable" on:click={() => toggleSort('createdAt')}>{$t('cicdTokens.columns.created')}{sortIndicator('createdAt', sortCol, sortDir)}</th>
        <th class="sortable" on:click={() => toggleSort('expiresAt')}>{$t('cicdTokens.columns.expires')}{sortIndicator('expiresAt', sortCol, sortDir)}</th>
        <th></th>
      </tr></thead>
      <tbody>
        {#each sorted as tok (tok.id)}
          {@const label = capabilitiesToLabel(tok.capabilities)}
          <tr>
            <td>{tok.name}</td>
            <td><span class="badge {label}">{label}</span></td>
            <td class="text-muted">{$formatDateShort(tok.createdAt)}</td>
            <td>
              {#if expired(tok)}<span class="badge expired">{$t('cicdTokens.expired')}</span>
              {:else if tok.expiresAt}{$formatDateShort(tok.expiresAt)}
              {:else}{$t('common.never')}{/if}
            </td>
            <td><button class="danger btn-sm" on:click={() => revoke(tok.id)}>{$t('common.actions.revoke')}</button></td>
          </tr>
        {/each}
        {#if tokens.length === 0}<tr><td colspan="5" class="text-center text-muted">{$t('cicdTokens.empty')}</td></tr>{/if}
      </tbody>
    </table>
  {/if}
</div>

<style>
  .cicd-table .col-scope   { width: 80px; }
  .cicd-table .col-created { width: 110px; }
  .cicd-table .col-expires { width: 130px; }
  .cicd-table .col-actions { width: 90px; }
</style>

{#if showCreate}
  <div class="modal-backdrop">
    <div class="modal">
      <h3>{$t('cicdTokens.modal.title')}</h3>
      {#if error}<div class="error-msg">{error}</div>{/if}
      <div class="form-row"><label>{$t('cicdTokens.modal.name')}</label><input bind:value={newName} placeholder={$t('cicdTokens.modal.namePlaceholder')} /></div>
      <div class="form-row">
        <label>{$t('cicdTokens.modal.scope')}</label>
        <select bind:value={newScope} class="w-auto"><option value="pull">pull</option><option value="push">push</option></select>
      </div>
      <div class="form-row"><label>{$t('cicdTokens.modal.expiresAt')}</label><input type="datetime-local" bind:value={newExpiry} /></div>
      <div class="modal-actions">
        <button on:click={() => showCreate = false}>{$t('common.actions.cancel')}</button>
        <button class="primary" on:click={create} disabled={creating}>{creating ? $t('common.actions.creating') : $t('common.actions.create')}</button>
      </div>
    </div>
  </div>
{/if}
