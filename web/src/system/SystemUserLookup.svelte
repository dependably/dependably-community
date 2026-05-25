<script>
  import { t } from 'svelte-i18n'
  import { systemApi } from '../lib/api.js'

  let email = '', tenantSlug = ''
  let results = [], loading = false, error = ''
  let searched = false
  let resetResult = null  // { email, temporaryPassword }
  let resetTarget = null  // pending confirmation: the row whose password is about to be reset
  let resetBusy = false
  let actionBusyKey = ''

  async function search() {
    if (!email && !tenantSlug) {
      error = $t('system.userLookup.needFilter')
      return
    }
    loading = true
    error = ''
    searched = true
    resetResult = null
    try {
      const data = await systemApi.lookupUsers({
        email: email || undefined,
        tenantSlug: tenantSlug || undefined,
      })
      results = data.items
    } catch (e) {
      error = e.message
      results = []
    } finally {
      loading = false
    }
  }

  async function setStatus(row, status) {
    const key = `${row.email}|${row.tenantSlug}|status`
    actionBusyKey = key
    error = ''
    try {
      await systemApi.setAccountStatus(row.email, row.tenantSlug, status)
      await search()
    } catch (e) { error = e.message }
    finally { actionBusyKey = '' }
  }

  function openReset(row) {
    resetTarget = row
    error = ''
  }

  async function confirmReset() {
    if (!resetTarget) return
    const row = resetTarget
    resetBusy = true
    error = ''
    try {
      const result = await systemApi.issuePasswordReset(row.email, row.tenantSlug)
      resetTarget = null
      // search() resets resetResult; set the banner AFTER refresh so it survives.
      await search()
      resetResult = result
    } catch (e) { error = e.message }
    finally { resetBusy = false }
  }
</script>

<div class="page">
  <h1>{$t('system.userLookup.title')}</h1>

  <form class="search-form" on:submit|preventDefault={search}>
    <div class="form-row">
      <label>{$t('system.userLookup.email')}</label>
      <input type="email" bind:value={email} placeholder="alice@example.com" />
    </div>
    <div class="form-row">
      <label>{$t('system.userLookup.tenantSlug')}</label>
      <input bind:value={tenantSlug} placeholder="acme" />
    </div>
    <button class="primary" type="submit" disabled={loading}>
      {loading ? $t('system.userLookup.searching') : $t('system.userLookup.search')}
    </button>
  </form>

  {#if error}<div class="page-error">{error}</div>{/if}

  {#if resetResult}
    <div class="reset-banner">
      <strong>{$t('system.userLookup.resetBannerLine1', { values: { email: resetResult.email, slug: resetResult.tenantSlug } })}</strong>
      <code>{resetResult.temporaryPassword}</code>
      <p>{$t('system.userLookup.resetBannerLine2')}</p>
      <button on:click={() => resetResult = null}>{$t('system.userLookup.dismiss')}</button>
    </div>
  {/if}

  {#if searched && !loading}
    <table>
      <thead>
        <tr>
          <th>{$t('system.userLookup.columns.email')}</th>
          <th>{$t('system.userLookup.columns.tenant')}</th>
          <th>{$t('system.userLookup.columns.role')}</th>
          <th>{$t('system.userLookup.columns.status')}</th>
          <th>{$t('system.userLookup.columns.mfa')}</th>
          <th>{$t('system.userLookup.columns.lastLogin')}</th>
          <th>{$t('system.userLookup.columns.passwordReset')}</th>
          <th>{$t('system.userLookup.columns.actions')}</th>
        </tr>
      </thead>
      <tbody>
        {#each results as r (r.email + '|' + r.tenantSlug)}
          {@const statusKey = `${r.email}|${r.tenantSlug}|status`}
          <tr>
            <td>{r.email}</td>
            <td>{r.tenantSlug}</td>
            <td>{r.role}</td>
            <td>{r.accountStatus}{r.mustChangePassword ? $t('system.userLookup.mustRotateSuffix') : ''}</td>
            <td>
              {#if r.mfaEnabled}
                <svg width="14" height="14" aria-hidden="true" aria-label="MFA enabled"><use href="/icons.svg#icon-check"/></svg>
              {:else}
                —
              {/if}
            </td>
            <td>{r.lastLoginAt ? new Date(r.lastLoginAt).toLocaleString() : '—'}</td>
            <td>{r.passwordResetIssuedAt ? new Date(r.passwordResetIssuedAt).toLocaleString() : '—'}</td>
            <td class="actions">
              {#if r.accountStatus === 'active'}
                <button on:click={() => setStatus(r, 'locked')} disabled={actionBusyKey === statusKey}>{$t('system.userLookup.lock')}</button>
              {:else}
                <button on:click={() => setStatus(r, 'active')} disabled={actionBusyKey === statusKey}>{$t('system.userLookup.unlock')}</button>
              {/if}
              <button on:click={() => openReset(r)}>{$t('system.userLookup.resetPassword')}</button>
            </td>
          </tr>
        {/each}
        {#if results.length === 0}
          <tr><td colspan="8" class="text-center text-muted">{$t('system.userLookup.noMatches')}</td></tr>
        {/if}
      </tbody>
    </table>
  {/if}
</div>

{#if resetTarget}
  <div class="modal-backdrop">
    <div class="modal">
      <h3>{$t('system.userLookup.resetModalTitle')}</h3>
      <p>{$t('system.userLookup.resetConfirm', { values: { email: resetTarget.email, slug: resetTarget.tenantSlug } })}</p>
      <div class="modal-actions">
        <button on:click={() => resetTarget = null} disabled={resetBusy}>{$t('common.actions.cancel')}</button>
        <button class="primary" on:click={confirmReset} disabled={resetBusy}>
          {resetBusy ? $t('common.actions.saving') : $t('system.userLookup.resetPassword')}
        </button>
      </div>
    </div>
  </div>
{/if}

<style>
  .search-form { display: flex; gap: 12px; align-items: flex-end; margin-bottom: 16px; }
  /* Override the global .form-row margin-bottom — with align-items: flex-end,
     that margin shifts the row's bottom edge below the submit button's. */
  .search-form .form-row { margin-bottom: 0; }
  .form-row { display: flex; flex-direction: column; gap: 4px; }
  .form-row label { font-size: 12px; color: var(--text2); }
  /* Match the global button's min-height (36px) so inputs and the submit button
     share a baseline when the form row uses align-items: flex-end. */
  .form-row input {
    padding: 6px 8px;
    min-height: 36px;
    box-sizing: border-box;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    background: var(--bg);
    color: var(--text);
  }
  /* Override the global table-layout: fixed so the email column can size to its
     content instead of being clipped under an 8-way equal split. */
  table { width: 100%; border-collapse: collapse; table-layout: auto; }
  th, td { padding: 8px; text-align: left; border-bottom: 1px solid var(--border); font-size: 13px; }
  .actions { display: flex; gap: 4px; }
  .actions button { font-size: 12px; padding: 3px 8px; }
  .reset-banner {
    background: var(--bg2);
    border: 1px solid var(--accent);
    border-radius: var(--radius);
    padding: 12px;
    margin-bottom: 16px;
  }
  .reset-banner code {
    display: inline-block;
    margin: 4px 0;
    padding: 4px 8px;
    background: var(--bg);
    border-radius: 3px;
    font-size: 13px;
    user-select: all;
  }
  .reset-banner p { margin: 8px 0; font-size: 12px; color: var(--text2); }
</style>
