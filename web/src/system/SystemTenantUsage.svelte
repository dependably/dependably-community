<!--
  One tenant's usage series — daily (default) or hourly buckets per meter, its latest storage
  snapshot, and a current-UTC-month-to-date summary independent of the requested range. The
  request counts, artefact and entry counts and database rows are shown apart from the metered
  bytes, labelled as operator signals that are never billed. Drilled
  into from the fleet SystemUsage.svelte table and from each row in SystemTenants.svelte.
-->
<script>
  import { t } from 'svelte-i18n'
  import { systemApi } from '../lib/api.js'
  import { navigate } from '../lib/store.js'
  import { reportPageLoad } from '../lib/pageLoad.js'
  import { formatBytes, formatDate, formatNumber } from '../lib/format.js'
  import ErrorBanner from '../lib/ErrorBanner.svelte'
  import { readQuery, writeQuery } from '../lib/tableState.js'

  /** The route params this page was mounted for, supplied by RouteView. @type {Record<string, any>} */
  export let params = {}
  /** The route transition this page was mounted for, supplied by RouteView. @type {number | null} */
  export let pageToken = null

  const DEFAULTS = { from: '', to: '', granularity: 'day' }
  const init = readQuery(DEFAULTS)

  let from = init.from
  let to = init.to
  /** @type {'day' | 'hour'} */
  let granularity = init.granularity === 'hour' ? 'hour' : 'day'

  let data = null
  let loading = true, error = ''
  let seq = 0

  $: reportPageLoad(pageToken, loading)
  $: slug = params.slug

  function sync() {
    writeQuery({ from, to, granularity }, DEFAULTS)
  }

  async function load() {
    if (!slug) return
    const mine = ++seq
    loading = true
    error = ''
    try {
      const p = { granularity }
      if (from) p.from = from
      if (to) p.to = to
      data = await systemApi.getTenantUsage(slug, p)
    } catch (e) {
      if (mine !== seq) return
      error = e.message
    } finally {
      if (mine === seq) loading = false
    }
  }

  $: if (slug) load()

  function onFilterChange() { sync(); load() }
  function setGranularity(g) {
    if (g === granularity) return
    granularity = g
    onFilterChange()
  }
</script>

<div class="page">
  <header class="page-header">
    <button type="button" class="link-button back" on:click={() => navigate('system-usage')}>
      {$t('system.tenantUsage.back')}
    </button>
    <h1 class="page-title">{$t('system.tenantUsage.title', { values: { slug } })}</h1>
    {#if data}
      <span class="status-badge status-{data.status}">{$t(`system.tenants.status.${data.status === 'suspended' ? 'suspended' : 'active'}`, { default: data.status })}</span>
    {/if}
  </header>

  <div class="toolbar">
    <div class="range">
      <label>
        {$t('system.usage.from')}
        <input type="date" bind:value={from} on:change={onFilterChange} />
      </label>
      <label>
        {$t('system.usage.to')}
        <input type="date" bind:value={to} on:change={onFilterChange} />
      </label>
      <div class="granularity" role="group" aria-label={$t('system.tenantUsage.granularity')}>
        <button type="button" class:active={granularity === 'day'} on:click={() => setGranularity('day')}>
          {$t('system.tenantUsage.day')}
        </button>
        <button type="button" class:active={granularity === 'hour'} on:click={() => setGranularity('hour')}>
          {$t('system.tenantUsage.hour')}
        </button>
      </div>
    </div>
  </div>

  <ErrorBanner message={error} />

  {#if loading && !data}
    <span class="spinner"></span>
  {:else if data}
    <div class="cards">
      <section class="card">
        <h2>{$t('system.tenantUsage.monthToDate.title')}</h2>
        <div class="stat-grid">
          <div class="stat"><div class="stat-value">{$formatBytes(data.monthToDate.egressBytes)}</div><div class="stat-label">{$t('system.usage.totals.egress')}</div></div>
          <div class="stat"><div class="stat-value">{$formatBytes(data.monthToDate.egressMetadataBytes)}</div><div class="stat-label">{$t('system.usage.totals.metadata')}</div></div>
          <div class="stat"><div class="stat-value">{$formatBytes(data.monthToDate.billableStorageBytes)}</div><div class="stat-label">{$t('system.usage.totals.storage')}</div></div>
          <div class="stat"><div class="stat-value">{$formatBytes(data.monthToDate.cacheStorageBytes)}</div><div class="stat-label">{$t('system.usage.totals.cacheStorage')}</div></div>
        </div>
        <div class="stat-foot">{data.monthToDate.from} – {data.monthToDate.to}</div>
      </section>

      <section class="card">
        <h2>{$t('system.tenantUsage.snapshot.title')}</h2>
        {#if data.latestSnapshot}
          <div class="stat-grid">
            <div class="stat"><div class="stat-value">{$formatBytes(data.latestSnapshot.billableBytes)}</div><div class="stat-label">{$t('system.tenantUsage.snapshot.billable')}</div></div>
            <div class="stat"><div class="stat-value">{$formatBytes(data.latestSnapshot.hostedBytes)}</div><div class="stat-label">{$t('system.tenantUsage.snapshot.hosted')}</div></div>
            <div class="stat"><div class="stat-value">{$formatBytes(data.latestSnapshot.ociUploadedBytes)}</div><div class="stat-label">{$t('system.tenantUsage.snapshot.oci')}</div></div>
            <div class="stat"><div class="stat-value">{$formatBytes(data.latestSnapshot.cacheAttributedBytes)}</div><div class="stat-label">{$t('system.tenantUsage.snapshot.cache')}</div></div>
          </div>
          <div class="stat-foot">{$t('system.tenantUsage.snapshot.capturedAt', { values: { date: $formatDate(data.latestSnapshot.capturedAt) } })}</div>
        {:else}
          <p class="muted">{$t('system.tenantUsage.snapshot.none')}</p>
        {/if}
      </section>

      <section class="card signals-card" aria-labelledby="tenant-signals-title">
        <h2 id="tenant-signals-title">{$t('system.tenantUsage.signals.title')}</h2>
        <p class="signals-note">{$t('system.tenantUsage.signals.note')}</p>
        <div class="stat-grid">
          <div class="stat"><div class="stat-value">{$formatNumber(data.monthToDate.requestCount)}</div><div class="stat-label">{$t('system.tenantUsage.signals.requests')}</div></div>
          <div class="stat"><div class="stat-value">{$formatNumber(data.monthToDate.metadataRequestCount)}</div><div class="stat-label">{$t('system.tenantUsage.signals.metadataRequests')}</div></div>
          {#if data.latestSnapshot}
            <div class="stat"><div class="stat-value">{$formatNumber(data.latestSnapshot.artifactCount)}</div><div class="stat-label">{$t('system.tenantUsage.signals.artifacts')}</div></div>
            <div class="stat"><div class="stat-value">{$formatNumber(data.latestSnapshot.hostedVersionCount)}</div><div class="stat-label">{$t('system.tenantUsage.signals.hostedVersions')}</div></div>
            <div class="stat"><div class="stat-value">{$formatNumber(data.latestSnapshot.ociManifestCount)}</div><div class="stat-label">{$t('system.tenantUsage.signals.ociManifests')}</div></div>
            <div class="stat"><div class="stat-value">{$formatNumber(data.latestSnapshot.ociBlobCount)}</div><div class="stat-label">{$t('system.tenantUsage.signals.ociBlobs')}</div></div>
            <div class="stat"><div class="stat-value">{$formatNumber(data.latestSnapshot.cacheEntryCount)}</div><div class="stat-label">{$t('system.tenantUsage.signals.cacheEntries')}</div></div>
            <div class="stat"><div class="stat-value">{$formatNumber(data.latestSnapshot.dbRowCount)}</div><div class="stat-label">{$t('system.tenantUsage.signals.dbRows')}</div></div>
          {/if}
        </div>
        {#if !data.latestSnapshot}
          <p class="muted">{$t('system.tenantUsage.signals.noSnapshot')}</p>
        {/if}
      </section>
    </div>

    <section class="card">
      <h2>{$t('system.tenantUsage.series.title')}</h2>
      {#if data.series.length === 0}
        <p class="muted">{$t('system.tenantUsage.series.empty')}</p>
      {:else}
        <table class="table-auto">
          <thead>
            <tr>
              <th>{$t('system.tenantUsage.series.bucket')}</th>
              <th class="num">{$t('system.usage.columns.egress')}</th>
              <th class="num">{$t('system.tenantUsage.series.redirect')}</th>
              <th class="num">{$t('system.usage.columns.metadata')}</th>
              {#if granularity === 'day'}
                <th class="num">{$t('system.usage.columns.storage')}</th>
                <th class="num">{$t('system.usage.columns.cacheStorage')}</th>
              {/if}
              <th class="num signal">{$t('system.tenantUsage.series.requests')}</th>
              <th class="num signal">{$t('system.tenantUsage.series.metadataRequests')}</th>
            </tr>
          </thead>
          <tbody>
            {#each data.series as b (b.bucket)}
              <tr>
                <td class="mono">{b.bucket}</td>
                <td class="num">{$formatBytes(b.egressBytes)}</td>
                <td class="num">{$formatBytes(b.egressRedirectBytes)}</td>
                <td class="num">{$formatBytes(b.egressMetadataBytes)}</td>
                {#if granularity === 'day'}
                  <td class="num">{b.storageBytes !== null && b.storageBytes !== undefined ? $formatBytes(b.storageBytes) : '—'}</td>
                  <td class="num">{b.cacheStorageBytes !== null && b.cacheStorageBytes !== undefined ? $formatBytes(b.cacheStorageBytes) : '—'}</td>
                {/if}
                <td class="num signal">{$formatNumber(b.requestCount)}</td>
                <td class="num signal">{$formatNumber(b.metadataRequestCount)}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      {/if}
    </section>
  {/if}
</div>

<style>
  .page-header { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
  .back { font-size: 13px; }
  .status-badge {
    font-size: 11px;
    padding: 2px 8px;
    border-radius: 10px;
    background: var(--bg3);
    color: var(--text2);
    text-transform: uppercase;
    letter-spacing: 0.4px;
  }
  .status-badge.status-suspended { color: var(--warning-text); }

  .toolbar { margin-bottom: 16px; }
  .range { display: flex; align-items: flex-end; gap: 16px; flex-wrap: wrap; }
  .range label {
    display: flex;
    flex-direction: column;
    gap: 4px;
    font-size: 12px;
    color: var(--text2);
  }
  .range input[type="date"] { font: inherit; padding: 4px 6px; }
  .granularity { display: flex; gap: 2px; }
  .granularity button {
    font-size: 12px;
    padding: 4px 10px;
    border: 1px solid var(--border);
    background: var(--bg2);
    cursor: pointer;
  }
  .granularity button.active { background: var(--accent); color: white; border-color: var(--accent); }
  .granularity button:first-child { border-radius: var(--radius) 0 0 var(--radius); }
  .granularity button:last-child { border-radius: 0 var(--radius) var(--radius) 0; }

  .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 16px; margin-bottom: 16px; }
  .muted { color: var(--text2); }
  .num { text-align: right; }
  .signal { color: var(--text2); }
  .signals-card { border-style: dashed; }
  .signals-note { margin: 0 0 10px; font-size: 12px; color: var(--text2); }
</style>
