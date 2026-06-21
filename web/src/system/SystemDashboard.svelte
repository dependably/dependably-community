<script>
  import { onMount } from 'svelte'
  import { t } from 'svelte-i18n'
  import { systemApi } from '../lib/api.js'
  import { navigate } from '../lib/store.js'
  import { formatBytes } from '../lib/format.js'

  let data = null
  let loading = true
  let error = ''

  async function load() {
    loading = true
    error = ''
    try {
      data = await systemApi.getDashboard()
    } catch (e) { error = e.message }
    finally { loading = false }
  }

  onMount(load)

  function fmtDuration(ms) {
    if (ms === null || ms === undefined) return '—'
    if (ms < 1000) return `${ms} ms`
    if (ms < 60_000) return `${(ms / 1000).toFixed(2)} s`
    const total = Math.round(ms / 1000)
    return `${Math.floor(total / 60)}m ${total % 60}s`
  }
</script>

<div class="page">
  <h1>{$t('system.dashboard.title')}</h1>
  <p class="subtitle">{$t('system.dashboard.subtitle')}</p>

  {#if error}<div class="page-error">{error}</div>{/if}

  {#if loading && !data}
    <span class="spinner"></span>
  {:else if data}
    <div class="cards">
      <section class="card clickable" on:click={() => navigate('system-tenants')}
               role="link" tabindex="0"
               on:keydown={(e) => { if (e.key === 'Enter' || e.key === ' ') navigate('system-tenants') }}>
        <h2>{$t('system.dashboard.tenants.title')}</h2>
        <div class="stat-grid">
          <div class="stat"><div class="stat-value">{data.tenants.active}</div><div class="stat-label">{$t('system.dashboard.tenants.active')}</div></div>
          <div class="stat"><div class="stat-value warn">{data.tenants.suspended}</div><div class="stat-label">{$t('system.dashboard.tenants.suspended')}</div></div>
          <div class="stat"><div class="stat-value muted">{data.tenants.softDeleted}</div><div class="stat-label">{$t('system.dashboard.tenants.softDeleted')}</div></div>
        </div>
        <div class="stat-foot">{$t('system.dashboard.tenants.total', { values: { count: data.tenants.total } })}</div>
      </section>

      <section class="card clickable" on:click={() => navigate('system-admins')}
               role="link" tabindex="0"
               on:keydown={(e) => { if (e.key === 'Enter' || e.key === ' ') navigate('system-admins') }}>
        <h2>{$t('system.dashboard.admins.title')}</h2>
        <div class="stat-grid">
          <div class="stat"><div class="stat-value">{data.admins.active}</div><div class="stat-label">{$t('system.dashboard.admins.active')}</div></div>
          <div class="stat"><div class="stat-value warn">{data.admins.locked}</div><div class="stat-label">{$t('system.dashboard.admins.locked')}</div></div>
          <div class="stat"><div class="stat-value muted">{data.admins.disabled}</div><div class="stat-label">{$t('system.dashboard.admins.disabled')}</div></div>
        </div>
        <div class="stat-foot">{$t('system.dashboard.admins.total', { values: { count: data.admins.total } })}</div>
      </section>

      <section class="card">
        <h2>{$t('system.dashboard.storage.title')}</h2>
        <div class="stat-grid storage-grid">
          <div class="stat"><div class="stat-value">{$formatBytes(data.storage?.byTier?.cache ?? 0)}</div><div class="stat-label">{$t('system.dashboard.storage.cache')}</div></div>
          <div class="stat"><div class="stat-value">{$formatBytes(data.storage?.byTier?.registry ?? 0)}</div><div class="stat-label">{$t('system.dashboard.storage.registry')}</div></div>
        </div>
        <div class="stat-foot">{$t('system.dashboard.storage.total', { values: { total: $formatBytes(data.storage?.totalBytes ?? 0) } })}</div>
      </section>
    </div>

    <section class="card">
      <div class="card-header">
        <h2>{$t('system.dashboard.recentJobs.title')}</h2>
        <button class="link-button" type="button" on:click={() => navigate('system-audit')}>
          {$t('system.dashboard.recentJobs.viewAll')}
        </button>
      </div>
      {#if data.recentJobs.length === 0}
        <p class="muted">{$t('system.dashboard.recentJobs.empty')}</p>
      {:else}
        <table class="table-auto jobs-mini">
          <thead>
            <tr>
              <th>{$t('system.backgroundJobs.columns.jobName')}</th>
              <th>{$t('system.backgroundJobs.columns.startedAt')}</th>
              <th>{$t('system.backgroundJobs.columns.duration')}</th>
              <th>{$t('system.backgroundJobs.columns.outcome')}</th>
            </tr>
          </thead>
          <tbody>
            {#each data.recentJobs as j (j.id)}
              <tr>
                <td><code>{j.jobName}</code></td>
                <td>{new Date(j.startedAt).toLocaleString()}</td>
                <td class="num">{fmtDuration(j.durationMs)}</td>
                <td><span class="outcome outcome-{j.outcome}">{$t(`system.backgroundJobs.outcome.${j.outcome}`, { default: j.outcome })}</span></td>
              </tr>
            {/each}
          </tbody>
        </table>
      {/if}
    </section>
  {/if}
</div>

<style>
  .subtitle { color: var(--text2); font-size: 13px; margin: 0 0 20px; }
  .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 16px; margin-bottom: 16px; }
  .card {
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 16px 20px;
  }
  .card h2 { margin: 0 0 12px; font-size: 14px; font-weight: 600; color: var(--text); text-transform: uppercase; letter-spacing: 0.04em; }
  .card.clickable { cursor: pointer; transition: border-color 0.1s ease; }
  .card.clickable:hover, .card.clickable:focus-visible { border-color: var(--accent); outline: none; }

  .stat-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; }
  .stat-grid.storage-grid { grid-template-columns: repeat(2, 1fr); }
  .stat { text-align: left; }
  .stat-value { font-size: 28px; font-weight: 600; line-height: 1.1; font-variant-numeric: tabular-nums; }
  .stat-value.warn { color: var(--warning); }
  .stat-value.muted { color: var(--text2); }
  .stat-label { font-size: 11px; color: var(--text2); text-transform: uppercase; letter-spacing: 0.04em; margin-top: 2px; }
  .stat-foot { font-size: 11px; color: var(--text2); margin-top: 10px; }

  .card-header { display: flex; align-items: center; justify-content: space-between; }
  .link-button {
    background: none; border: none; padding: 0;
    color: var(--accent); font-size: 12px; cursor: pointer;
  }
  .link-button:hover { text-decoration: underline; }

  .jobs-mini { width: 100%; border-collapse: collapse; font-size: 13px; }
  .jobs-mini th, .jobs-mini td { padding: 6px 8px; border-bottom: 1px solid var(--border); text-align: left; }
  .jobs-mini th { color: var(--text2); font-weight: 500; font-size: 12px; }
  .num { text-align: right; font-variant-numeric: tabular-nums; }
  code { background: var(--bg); padding: 2px 6px; border-radius: 3px; font-size: 12px; }

  .outcome {
    display: inline-block;
    font-size: 11px;
    padding: 2px 8px;
    border-radius: 999px;
    border: 1px solid var(--border);
    background: var(--bg);
    text-transform: capitalize;
  }
  .outcome-success { color: var(--success); }
  .outcome-server_error { color: var(--danger); }
  .outcome-cancelled { color: var(--text2); }

  .muted { color: var(--text2); font-size: 13px; }
</style>
