<!--
  Fleet usage report: one row per tenant over a date range (defaults to the current UTC month to
  date), fleet totals, and a per-ecosystem breakdown. Raw byte counts and raw counts only — the
  server never converts units, rates, or plans; this page is where they become human-readable.
  Metered requests, artefact counts and database rows are operator signals, never billed meters,
  and are labelled as such.
-->
<script>
  import { onMount } from 'svelte'
  import { t } from 'svelte-i18n'
  import { systemApi } from '../lib/api.js'
  import { navigate } from '../lib/store.js'
  import { reportPageLoad } from '../lib/pageLoad.js'
  import { formatBytes, formatNumber } from '../lib/format.js'
  import DataTable from '../lib/DataTable.svelte'
  import Pagination from '../lib/Pagination.svelte'
  import ErrorBanner from '../lib/ErrorBanner.svelte'
  import { readQuery, writeQuery } from '../lib/tableState.js'

  const DEFAULTS = { from: '', to: '', sort: 'egressBytes', dir: 'desc', page: 1, pageSize: 50 }
  const init = readQuery(DEFAULTS)

  /** The route transition this page was mounted for, supplied by RouteView. @type {number | null} */
  export let pageToken = null

  let from = init.from
  let to = init.to
  let sortCol = init.sort
  let sortDir = init.dir
  let page = init.page
  let pageSize = init.pageSize

  let items = [], total = 0, totals = null, ecosystems = []
  let rangeFrom = '', rangeTo = ''
  let loading = true, error = ''
  let exporting = false, exportError = ''

  $: reportPageLoad(pageToken, loading)

  // Request sequence — a range/sort/page change can fire overlapping loads; a response whose
  // token no longer matches the latest issued request is stale and must not overwrite newer state.
  let seq = 0

  function sync() {
    writeQuery({ from, to, sort: sortCol, dir: sortDir, page, pageSize }, DEFAULTS)
  }

  async function load() {
    const mine = ++seq
    loading = true
    error = ''
    try {
      const params = { sort: sortCol, dir: sortDir, page, pageSize }
      if (from) params.from = from
      if (to) params.to = to
      const data = await systemApi.getFleetUsage(params)
      if (mine !== seq) return
      items = data.items
      total = data.total
      totals = data.totals
      ecosystems = data.ecosystems
      rangeFrom = data.from
      rangeTo = data.to
    } catch (e) {
      if (mine !== seq) return
      error = e.message
    } finally {
      if (mine === seq) loading = false
    }
  }

  onMount(load)

  function onRangeChange() { page = 1; sync(); load() }
  function onPageChange(e) { page = e.detail.page; sync(); load() }
  function onLimitChange(e) { pageSize = e.detail.limit; page = 1; sync(); load() }
  function onSortChange(e) { sortCol = e.detail.col; sortDir = e.detail.dir; page = 1; sync(); load() }

  async function exportCsv() {
    exporting = true
    exportError = ''
    try {
      const params = { sort: sortCol, dir: sortDir }
      if (from) params.from = from
      if (to) params.to = to
      await systemApi.exportFleetUsage(params)
    } catch (e) { exportError = e.message }
    finally { exporting = false }
  }

  function openTenant(row) {
    if (!row.slug) return
    navigate('system-tenant-usage', { slug: row.slug })
  }

  // Paged + server-sorted, so every comparator is a no-op — DataTable's stable sort preserves
  // the order the server already returned the page in.
  const NOOP_CMP = () => 0
  $: columns = [
    { key: 'slug',                label: $t('system.usage.columns.tenant'),         sortable: true },
    { key: 'egressBytes',         label: $t('system.usage.columns.egress'),         sortable: true, align: 'right', defaultDir: 'desc' },
    { key: 'egressMetadataBytes', label: $t('system.usage.columns.metadata'),       sortable: true, align: 'right', defaultDir: 'desc' },
    { key: 'billableStorageBytes', label: $t('system.usage.columns.storage'),       sortable: true, align: 'right', defaultDir: 'desc' },
    { key: 'cacheStorageBytes',   label: $t('system.usage.columns.cacheStorage'),   sortable: true, align: 'right', defaultDir: 'desc' },
    { key: 'snapshot',            label: $t('system.usage.columns.snapshot'),       sortable: false, align: 'right' },
    { key: 'requestCount',        label: $t('system.usage.columns.requests'),       sortable: true, align: 'right', defaultDir: 'desc' },
    { key: 'metadataRequestCount', label: $t('system.usage.columns.metadataRequests'), sortable: true, align: 'right', defaultDir: 'desc' },
    { key: 'artifactCount',       label: $t('system.usage.columns.artifacts'),      sortable: true, align: 'right', defaultDir: 'desc' },
    { key: 'dbRowCount',          label: $t('system.usage.columns.dbRows'),         sortable: true, align: 'right', defaultDir: 'desc' },
  ]
  $: comparators = Object.fromEntries(columns.map(c => [c.key, NOOP_CMP]))
</script>

<div class="page">
  <header class="page-header">
    <h1 class="page-title">{$t('system.usage.title')}</h1>
  </header>
  <p class="subtitle">{$t('system.usage.subtitle')}</p>

  <div class="toolbar">
    <div class="range">
      <label>
        {$t('system.usage.from')}
        <input type="date" bind:value={from} on:change={onRangeChange} />
      </label>
      <label>
        {$t('system.usage.to')}
        <input type="date" bind:value={to} on:change={onRangeChange} />
      </label>
      {#if rangeFrom && rangeTo}
        <span class="range-effective muted">{$t('system.usage.effectiveRange', { values: { from: rangeFrom, to: rangeTo } })}</span>
      {/if}
    </div>
    <button type="button" on:click={exportCsv} disabled={exporting}>
      <svg width="13" height="13" aria-hidden="true"><use href="/icons.svg#icon-download"/></svg>
      {exporting ? $t('system.usage.exporting') : $t('system.usage.downloadCsv')}
    </button>
  </div>

  <ErrorBanner message={exportError} />
  <ErrorBanner message={error} />

  {#if totals}
    <div class="totals-strip">
      <div class="totals-item">
        <span class="totals-label">{$t('system.usage.totals.egress')}</span>
        <span class="totals-value">{$formatBytes(totals.egressBytes)}</span>
      </div>
      <div class="totals-item">
        <span class="totals-label">{$t('system.usage.totals.redirect')}</span>
        <span class="totals-value">{$formatBytes(totals.egressRedirectBytes)}</span>
      </div>
      <div class="totals-item">
        <span class="totals-label">{$t('system.usage.totals.metadata')}</span>
        <span class="totals-value">{$formatBytes(totals.egressMetadataBytes)}</span>
      </div>
      <div class="totals-item">
        <span class="totals-label">{$t('system.usage.totals.storage')}</span>
        <span class="totals-value">{$formatBytes(totals.billableStorageBytes)}</span>
      </div>
      <div class="totals-item">
        <span class="totals-label">{$t('system.usage.totals.cacheStorage')}</span>
        <span class="totals-value">{$formatBytes(totals.cacheStorageBytes)}</span>
      </div>
    </div>
    <section class="signals-strip" aria-labelledby="usage-signals-title">
      <h2 id="usage-signals-title" class="signals-title">{$t('system.usage.signalsTitle')}</h2>
      <p class="signals-note">{$t('system.usage.signalsNote')}</p>
      <div class="signals-items">
        <div class="totals-item">
          <span class="totals-label">{$t('system.usage.totals.requests')}</span>
          <span class="totals-value">{$formatNumber(totals.requestCount)}</span>
        </div>
        <div class="totals-item">
          <span class="totals-label">{$t('system.usage.totals.metadataRequests')}</span>
          <span class="totals-value">{$formatNumber(totals.metadataRequestCount)}</span>
        </div>
      </div>
    </section>
  {/if}

  {#if ecosystems.length > 0}
    <section class="card ecosystems-card">
      <h2>{$t('system.usage.ecosystems.title')}</h2>
      <table class="table-auto">
        <thead>
          <tr>
            <th>{$t('system.usage.ecosystems.ecosystem')}</th>
            <th>{$t('system.usage.ecosystems.meter')}</th>
            <th class="num">{$t('system.usage.ecosystems.bytes')}</th>
            <th class="num">{$t('system.usage.ecosystems.redirectBytes')}</th>
          </tr>
        </thead>
        <tbody>
          {#each ecosystems as e (e.ecosystem + e.meter)}
            <tr>
              <td><span class="badge {e.ecosystem}">{e.ecosystem}</span></td>
              <td>{$t(`system.usage.meter.${e.meter}`, { default: e.meter })}</td>
              <td class="num">{$formatBytes(e.bytes)}</td>
              <td class="num">{$formatBytes(e.redirectBytes)}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </section>
  {/if}

  <DataTable
    {columns}
    rows={items}
    {comparators}
    {loading}
    loadingRows={pageSize}
    memoryKey="system-usage"
    emptyText={$t('system.usage.empty')}
    initialSort={{ key: sortCol, dir: sortDir }}
    on:sortchange={onSortChange}
    let:row={r}
  >
    <tr class="cursor-pointer" class:disabled={!r.slug} on:click={() => openTenant(r)}>
      <td>
        {#if r.slug}
          <span class="mono">{r.slug}</span>
        {:else}
          <span class="muted" title={$t('system.usage.orphanedOrgTitle', { values: { orgId: r.orgId } })}>
            {$t('system.usage.orphanedOrg')}
          </span>
        {/if}
      </td>
      <td class="num">{$formatBytes(r.egressBytes)}</td>
      <td class="num">{$formatBytes(r.egressMetadataBytes)}</td>
      <td class="num">{$formatBytes(r.billableStorageBytes)}</td>
      <td class="num">{$formatBytes(r.cacheStorageBytes)}</td>
      <td class="num">
        {#if r.snapshot}
          {$formatBytes(r.snapshot.billableBytes)}
        {:else}
          <span class="muted">—</span>
        {/if}
      </td>
      <td class="num signal">{$formatNumber(r.requestCount)}</td>
      <td class="num signal">{$formatNumber(r.metadataRequestCount)}</td>
      <td class="num signal">
        {#if r.snapshot}{$formatNumber(r.snapshot.artifactCount)}{:else}<span class="muted">—</span>{/if}
      </td>
      <td class="num signal">
        {#if r.snapshot}{$formatNumber(r.snapshot.dbRowCount)}{:else}<span class="muted">—</span>{/if}
      </td>
    </tr>
  </DataTable>

  <Pagination total={total} page={page} limit={pageSize}
    on:pagechange={onPageChange}
    on:limitchange={onLimitChange} />
</div>

<style>
  .subtitle { color: var(--text2); font-size: 13px; margin: 0 0 16px; }
  .toolbar {
    display: flex;
    align-items: flex-end;
    justify-content: space-between;
    gap: 12px;
    margin-bottom: 16px;
    flex-wrap: wrap;
  }
  .range { display: flex; align-items: flex-end; gap: 16px; flex-wrap: wrap; }
  .range label {
    display: flex;
    flex-direction: column;
    gap: 4px;
    font-size: 12px;
    color: var(--text2);
  }
  .range input[type="date"] {
    font: inherit;
    padding: 4px 6px;
  }
  .range-effective { font-size: 12px; padding-bottom: 4px; }
  .muted { color: var(--text2); }

  .totals-strip {
    display: flex;
    gap: 24px;
    flex-wrap: wrap;
    padding: 12px 16px;
    margin-bottom: 16px;
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: var(--radius);
  }
  .totals-item { display: flex; flex-direction: column; gap: 2px; }
  .totals-label { font-size: 11px; color: var(--text2); text-transform: uppercase; letter-spacing: 0.4px; }
  .totals-value { font-size: 16px; font-weight: 600; }

  .signals-strip {
    padding: 12px 16px;
    margin-bottom: 16px;
    border: 1px dashed var(--border);
    border-radius: var(--radius);
  }
  .signals-title { margin: 0 0 4px; font-size: 13px; }
  .signals-note { margin: 0 0 10px; font-size: 12px; color: var(--text2); }
  .signals-items { display: flex; gap: 24px; flex-wrap: wrap; }
  .signal { color: var(--text2); }

  .ecosystems-card { margin-bottom: 16px; }
  .ecosystems-card h2 { margin: 0 0 10px; font-size: 14px; }

  .cursor-pointer { cursor: pointer; }
  .cursor-pointer.disabled { cursor: default; }
  .num { text-align: right; }
</style>
