<script>
  import { onMount } from 'svelte'
  import { t } from 'svelte-i18n'
  import { systemApi } from '../lib/api.js'

  let tenants = [], loading = true, error = ''
  let showCreate = false
  let newSlug = '', newOwnerEmail = ''
  let createBusy = false
  let createdResult = null  // { tenant, owner: { email, ownerPassword } }

  async function load() {
    loading = true
    error = ''
    try {
      const data = await systemApi.listTenants(1, 200)
      tenants = data.items
    } catch (e) { error = e.message }
    finally { loading = false }
  }

  onMount(load)

  async function create() {
    createBusy = true
    error = ''
    try {
      createdResult = await systemApi.createTenant(newSlug, newOwnerEmail)
      newSlug = ''
      newOwnerEmail = ''
      await load()
    } catch (e) { error = e.message }
    finally { createBusy = false }
  }

  async function softDelete(slug) {
    if (!confirm($t('system.tenants.deleteConfirm', { values: { slug } }))) return
    try {
      await systemApi.softDeleteTenant(slug)
      await load()
    } catch (e) { error = e.message }
  }

  async function restore(slug) {
    try {
      await systemApi.restoreTenant(slug)
      await load()
    } catch (e) { error = e.message }
  }
</script>

<div class="page">
  <div class="page-header">
    <h1>{$t('system.tenants.title')}</h1>
    <button class="primary" on:click={() => { showCreate = true; createdResult = null }}>{$t('system.tenants.newTenant')}</button>
  </div>

  {#if error}<div class="page-error">{error}</div>{/if}

  {#if loading}
    <span class="spinner"></span>
  {:else}
    <table>
      <thead>
        <tr>
          <th>{$t('system.tenants.columns.slug')}</th>
          <th>{$t('system.tenants.columns.status')}</th>
          <th>{$t('system.tenants.columns.created')}</th>
          <th>{$t('system.tenants.columns.deleted')}</th>
          <th></th>
        </tr>
      </thead>
      <tbody>
        {#each tenants as ten (ten.id)}
          <tr class:deleted={ten.deletedAt}>
            <td><strong>{ten.slug}</strong></td>
            <td>{ten.deletedAt ? $t('system.tenants.status.softDeleted') : $t('system.tenants.status.active')}</td>
            <td>{new Date(ten.createdAt).toLocaleDateString()}</td>
            <td>{ten.deletedAt ? new Date(ten.deletedAt).toLocaleDateString() : '—'}</td>
            <td>
              {#if ten.deletedAt}
                <button on:click={() => restore(ten.slug)}>{$t('system.tenants.restore')}</button>
              {:else}
                <button class="danger" on:click={() => softDelete(ten.slug)}>{$t('system.tenants.delete')}</button>
              {/if}
            </td>
          </tr>
        {/each}
        {#if tenants.length === 0}
          <tr><td colspan="5" class="text-center text-muted">{$t('system.tenants.empty')}</td></tr>
        {/if}
      </tbody>
    </table>
  {/if}
</div>

{#if showCreate}
  <div class="modal-backdrop">
    <div class="modal">
      {#if createdResult}
        <h3>{$t('system.tenants.created.title')}</h3>
        <p><strong>{$t('system.tenants.created.warning')}</strong></p>
        <dl>
          <dt>{$t('system.tenants.created.tenantSlug')}</dt><dd>{createdResult.tenant.slug}</dd>
          <dt>{$t('system.tenants.created.ownerEmail')}</dt><dd>{createdResult.owner.email}</dd>
          <dt>{$t('system.tenants.created.ownerPassword')}</dt><dd><code>{createdResult.owner.ownerPassword}</code></dd>
        </dl>
        <div class="modal-actions">
          <button class="primary" on:click={() => { showCreate = false; createdResult = null }}>{$t('system.tenants.created.done')}</button>
        </div>
      {:else}
        <h3>{$t('system.tenants.modal.title')}</h3>
        <div class="form-row">
          <label>{$t('system.tenants.modal.slug')}</label>
          <input bind:value={newSlug} placeholder={$t('system.tenants.modal.slugPlaceholder')} />
        </div>
        <div class="form-row">
          <label>{$t('system.tenants.modal.ownerEmail')}</label>
          <input type="email" bind:value={newOwnerEmail} placeholder={$t('system.tenants.modal.ownerEmailPlaceholder')} />
        </div>
        <div class="modal-actions">
          <button on:click={() => showCreate = false}>{$t('common.actions.cancel')}</button>
          <button class="primary" on:click={create} disabled={createBusy || !newSlug || !newOwnerEmail}>
            {createBusy ? $t('system.tenants.modal.creating') : $t('system.tenants.modal.create')}
          </button>
        </div>
      {/if}
    </div>
  </div>
{/if}

<style>
  .page-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 16px; }
  table { width: 100%; border-collapse: collapse; }
  th, td { padding: 8px; text-align: left; border-bottom: 1px solid var(--border); }
  tr.deleted { color: var(--text2); }
  .modal-backdrop {
    position: fixed; inset: 0;
    background: var(--overlay-scrim);
    display: flex; align-items: center; justify-content: center;
    z-index: 100;
  }
  .modal {
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 20px;
    width: 400px;
  }
  .form-row { display: flex; flex-direction: column; gap: 4px; margin-bottom: 12px; }
  .form-row label { font-size: 13px; color: var(--text2); }
  .form-row input {
    padding: 6px 8px;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    background: var(--bg);
    color: var(--text);
  }
  .modal-actions { display: flex; gap: 8px; justify-content: flex-end; margin-top: 16px; }
  dl { display: grid; grid-template-columns: max-content 1fr; gap: 4px 12px; }
  dt { font-weight: 600; }
  code { background: var(--bg); padding: 2px 6px; border-radius: 3px; }
</style>
