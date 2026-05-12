<script>
  import { onMount } from 'svelte'
  import { t } from 'svelte-i18n'
  import { systemApi } from '../lib/api.js'

  let items = [], total = 0, loading = true, error = ''
  let page = 1
  const limit = 50

  async function load() {
    loading = true
    error = ''
    try {
      const data = await systemApi.listAudit(page, limit)
      items = data.items
      total = data.total
    } catch (e) { error = e.message }
    finally { loading = false }
  }

  onMount(load)

  function prev() { if (page > 1) { page--; load() } }
  function next() { if (page * limit < total) { page++; load() } }
</script>

<div class="page">
  <h1>{$t('system.audit.title')}</h1>
  <p class="subtitle">{$t('system.audit.subtitle')}</p>

  {#if error}<div class="page-error">{error}</div>{/if}

  {#if loading}
    <span class="spinner"></span>
  {:else}
    <table>
      <thead>
        <tr>
          <th>{$t('system.audit.columns.when')}</th>
          <th>{$t('system.audit.columns.event')}</th>
          <th>{$t('system.audit.columns.actor')}</th>
          <th>{$t('system.audit.columns.tenant')}</th>
          <th>{$t('system.audit.columns.detail')}</th>
        </tr>
      </thead>
      <tbody>
        {#each items as e (e.id)}
          <tr>
            <td>{new Date(e.createdAt).toLocaleString()}</td>
            <td><code>{e.action}</code></td>
            <td>{e.actorId ?? '—'}</td>
            <td>{e.orgId ?? '—'}</td>
            <td><pre>{e.detail ?? ''}</pre></td>
          </tr>
        {/each}
        {#if items.length === 0}
          <tr><td colspan="5" class="text-center text-muted">{$t('system.audit.empty')}</td></tr>
        {/if}
      </tbody>
    </table>

    <div class="pager">
      <button on:click={prev} disabled={page === 1}>{$t('system.audit.prev')}</button>
      <span>{$t('system.audit.pageInfo', { values: { page, total } })}</span>
      <button on:click={next} disabled={page * limit >= total}>{$t('system.audit.next')}</button>
    </div>
  {/if}
</div>

<style>
  .subtitle { color: var(--text2); font-size: 13px; margin: 0 0 16px; }
  table { width: 100%; border-collapse: collapse; }
  th, td { padding: 8px; text-align: left; border-bottom: 1px solid var(--border); font-size: 13px; vertical-align: top; }
  pre { margin: 0; font-size: 12px; white-space: pre-wrap; word-break: break-word; max-width: 500px; }
  code { background: var(--bg); padding: 2px 6px; border-radius: 3px; font-size: 12px; }
  .pager { display: flex; gap: 12px; align-items: center; margin-top: 16px; }
</style>
