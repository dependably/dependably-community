<script>
  import { t } from 'svelte-i18n'
  import { api } from '../lib/api.js'
  import { currentOrg } from '../lib/store.js'
  import { formatDate } from '../lib/format.js'
  import Pagination from '../lib/Pagination.svelte'
  import ErrorBanner from '../lib/ErrorBanner.svelte'
  import DataTable from '../lib/DataTable.svelte'
  import { ECOSYSTEMS, ECO_LABEL } from '../lib/ecosystems.js'

  let items = [], loading = true, error = ''
  let ecosystem = ''
  let search = ''
  let page = 1, limit = 50, total = 0
  let sortCol = 'severity', sortDir = 'desc'

  $: org = $currentOrg

  async function load() {
    if (!org) { loading = false; return }
    loading = true; error = ''
    try {
      const params = { page, limit, sort: sortCol, dir: sortDir }
      if (ecosystem) params.ecosystem = ecosystem
      const data = await api.getVulnReport( params)
      items = data.items || []
      total = data.total
    } catch (e) { error = e.message; console.error(e) }
    finally { loading = false }
  }

  $: if (org !== undefined) load()

  function onPageChange(e) { page = e.detail.page; load() }
  function onLimitChange(e) { limit = e.detail.limit; page = 1; load() }
  function handleEcoChange() { page = 1; load() }
  function onSortChange(e) { sortCol = e.detail.col; sortDir = e.detail.dir; page = 1; load() }

  const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1 }

  $: filtered = items.filter(r => {
    if (!search) return true
    const q = search.toLowerCase()
    return r.packageName?.toLowerCase().includes(q)
      || r.osvId?.toLowerCase().includes(q)
      || r.summary?.toLowerCase().includes(q)
      || r.version?.toLowerCase().includes(q)
  })

  $: columns = [
    { key: 'package',   label: $t('vulnerabilities.columns.package'),   sortable: true,  width: '200px' },
    { key: 'version',   label: $t('vulnerabilities.columns.version'),   sortable: true,  width: '110px' },
    { key: 'severity',  label: $t('vulnerabilities.columns.severity'),  sortable: true,  width: '90px',  defaultDir: 'desc' },
    { key: 'score',     label: $t('vulnerabilities.columns.score'),     sortable: true,  width: '70px',  defaultDir: 'desc' },
    { key: 'osvId',     label: $t('vulnerabilities.columns.osvId'),     sortable: true,  width: '170px' },
    { key: 'summary',   label: $t('vulnerabilities.columns.summary'),   sortable: true },
    { key: 'checkedAt', label: $t('vulnerabilities.columns.checkedAt'), sortable: true,  width: '135px' },
  ]

  const comparators = {
    package:   (a, b) => (a.packageName ?? '').localeCompare(b.packageName ?? ''),
    version:   (a, b) => (a.version ?? '').localeCompare(b.version ?? ''),
    severity:  (a, b) => (SEVERITY_RANK[a.severity?.toLowerCase()] ?? 0) - (SEVERITY_RANK[b.severity?.toLowerCase()] ?? 0),
    score:     (a, b) => (a.cvssScore ?? -1) - (b.cvssScore ?? -1),
    osvId:     (a, b) => (a.osvId ?? '').localeCompare(b.osvId ?? ''),
    summary:   (a, b) => (a.summary ?? '').localeCompare(b.summary ?? ''),
    checkedAt: (a, b) => (a.vulnCheckedAt ?? '').localeCompare(b.vulnCheckedAt ?? ''),
  }
</script>

<div class="page page-wide">
  <div class="page-header">
    <h1 class="page-title">{$t('vulnerabilities.title')}</h1>
    <input placeholder="Search package, OSV ID, summary…" bind:value={search} class="header-search" />
  </div>

  <div class="search-bar">
    <select bind:value={ecosystem} on:change={handleEcoChange} class="eco-select">
      <option value="">{$t('common.allEcosystems')}</option>
      {#each ECOSYSTEMS as eco (eco)}
        <option value={eco}>{ECO_LABEL[eco]}</option>
      {/each}
    </select>
  </div>

  <ErrorBanner message={error} />

  <DataTable
    {columns}
    rows={filtered}
    {comparators}
    {loading}
    initialSort={{ key: sortCol, dir: sortDir }}
    on:sortchange={onSortChange}
    emptyText={$t('vulnerabilities.empty')}
    tableClass="table-auto vulns-table"
    let:row={r}
  >
    <tr>
      <td>
        <div class="pkg-cell">
          <span class="badge {r.ecosystem}">{r.ecosystem}</span>
          <span class="mono pkg-name" title={r.packageName}>{r.packageName}</span>
        </div>
      </td>
      <td class="mono nowrap" title={r.purl}>{r.version}</td>
      <td class="nowrap">
        {#if r.severity}
          <span class="sev sev-{r.severity.toLowerCase()}">{r.severity}</span>
        {:else}
          <span class="text-muted">—</span>
        {/if}
      </td>
      <td class="mono nowrap text-muted">
        {r.cvssScore !== null && r.cvssScore !== undefined ? r.cvssScore.toFixed(1) : '—'}
      </td>
      <td class="mono nowrap">
        <a href="https://osv.dev/vulnerability/{r.osvId}" target="_blank" rel="noreferrer">{r.osvId}</a>
      </td>
      <td class="summary-cell text-muted">
        <div class="summary-clamp" title={r.summary ?? ''}>{r.summary ?? '—'}</div>
      </td>
      <td class="nowrap text-muted t-sm">
        {r.vulnCheckedAt ? $formatDate(r.vulnCheckedAt) : '—'}
      </td>
    </tr>
  </DataTable>

  {#if !loading}
    <Pagination {total} {page} {limit}
      on:pagechange={onPageChange}
      on:limitchange={onLimitChange} />
  {/if}
</div>

<style>
  td { vertical-align: middle; }
  .nowrap { white-space: nowrap; }
  .pkg-cell { display: flex; flex-direction: column; gap: 3px; min-width: 0; }
  .pkg-name { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .summary-clamp {
    display: -webkit-box;
    -webkit-line-clamp: 2;
    line-clamp: 2;
    -webkit-box-orient: vertical;
    overflow: hidden;
    overflow-wrap: anywhere;
  }
  .page-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
  }
  .header-search { width: 260px; }
  .eco-select { width: auto; }
  .summary-cell { font-size: 13px; }
</style>
