<script>
  import { t } from 'svelte-i18n'
  import { api } from '../lib/api.js'
  import { currentOrg } from '../lib/store.js'
  import { formatDateShort } from '../lib/format.js'
  import { copyToClipboard } from '../lib/clipboard.js'
  import { sortIndicator } from '../lib/sortIndicator.js'
  import { presetToCapabilities, capabilitiesToLabel } from '../lib/tokenCapabilities.js'

  let tokens = [], loading = true, error = ''
  let showCreate = false, newScope = 'pull', newExpiry = '', creating = false
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
      const data = await api.createToken(presetToCapabilities(newScope), newExpiry || null)
      newTokenValue = data.token
      tokens = [data.record, ...tokens]
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

  let sortCol = 'createdAt', sortDir = 'desc'
  // The "scope" column displays a label derived from capabilities, so sort by that
  // same label when the user clicks the header. Other columns sort by raw field.
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

  {#if error}<div class="page-error">{error}</div>{/if}
  {#if loading}<span class="spinner"></span>
  {:else}
    <table class="tokens-table">
      <colgroup>
        <col class="col-id"><!-- id truncated -->
        <col class="col-scope"><!-- scope badge -->
        <col class="col-created"><!-- created date -->
        <col class="col-expires"><!-- expires date/badge -->
        <col class="col-actions"><!-- actions -->
      </colgroup>
      <thead><tr>
        <th>{$t('tokens.columns.id')}</th>
        <th class="sortable" on:click={() => toggleSort('scope')}>{$t('tokens.columns.scope')}{sortIndicator('scope', sortCol, sortDir)}</th>
        <th class="sortable" on:click={() => toggleSort('createdAt')}>{$t('tokens.columns.created')}{sortIndicator('createdAt', sortCol, sortDir)}</th>
        <th class="sortable" on:click={() => toggleSort('expiresAt')}>{$t('tokens.columns.expires')}{sortIndicator('expiresAt', sortCol, sortDir)}</th>
        <th></th>
      </tr></thead>
      <tbody>
        {#each sorted as tok (tok.id)}
          <tr>
            <td class="t-mono t-sm">{tok.id.slice(0,8)}…</td>
            <td><span class="badge">{capabilitiesToLabel(tok.capabilities)}</span></td>
            <td class="text-muted">{$formatDateShort(tok.createdAt)}</td>
            <td>
              {#if expired(tok)}<span class="badge expired">{$t('tokens.expired')}</span>
              {:else}{tok.expiresAt ? $formatDateShort(tok.expiresAt) : '—'}{/if}
            </td>
            <td><button class="danger btn-sm" on:click={() => revoke(tok.id)}>{$t('common.actions.revoke')}</button></td>
          </tr>
        {/each}
        {#if tokens.length === 0}<tr><td colspan="5" class="text-center text-muted">{$t('tokens.empty')}</td></tr>{/if}
      </tbody>
    </table>
  {/if}
</div>

<style>
  .tokens-table .col-id      { width: 100px; }
  .tokens-table .col-scope   { width: 80px; }
  .tokens-table .col-created { width: 110px; }
  .tokens-table .col-expires { width: 130px; }
  .tokens-table .col-actions { width: 90px; }
</style>

{#if showCreate}
  <div class="modal-backdrop">
    <div class="modal">
      <h3>{$t('tokens.modal.title')}</h3>
      <div class="form-row">
        <label>{$t('tokens.modal.scope')}</label>
        <select bind:value={newScope} class="w-auto">
          <option value="pull">pull</option>
          <option value="push">push</option>
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
