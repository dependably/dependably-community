<script>
  import { t } from 'svelte-i18n'
  import { api } from '../lib/api.js'
  import { currentOrg } from '../lib/store.js'
  import { formatDate } from '../lib/format.js'
  import { sortIndicator } from '../lib/sortIndicator.js'
  import Pagination from '../lib/Pagination.svelte'

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
      const params = { page, limit }
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

  const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1 }

  $: filtered = items.filter(r => {
    if (!search) return true
    const q = search.toLowerCase()
    return r.packageName?.toLowerCase().includes(q)
      || r.osvId?.toLowerCase().includes(q)
      || r.summary?.toLowerCase().includes(q)
      || r.version?.toLowerCase().includes(q)
  })

  $: sorted = [...filtered].sort((a, b) => {
    let av, bv
    if (sortCol === 'package')   { av = a.packageName?.toLowerCase() ?? ''; bv = b.packageName?.toLowerCase() ?? '' }
    if (sortCol === 'version')   { av = a.version ?? '';                     bv = b.version ?? '' }
    if (sortCol === 'severity')  { av = SEVERITY_RANK[a.severity?.toLowerCase()] ?? 0; bv = SEVERITY_RANK[b.severity?.toLowerCase()] ?? 0 }
    if (sortCol === 'score')     { av = a.cvssScore ?? -1;                   bv = b.cvssScore ?? -1 }
    if (sortCol === 'osvId')     { av = a.osvId ?? '';                       bv = b.osvId ?? '' }
    if (sortCol === 'checkedAt') { av = a.vulnCheckedAt ?? '';               bv = b.vulnCheckedAt ?? '' }
    if (sortCol === 'summary')   { av = a.summary?.toLowerCase() ?? '';     bv = b.summary?.toLowerCase() ?? '' }
    if (av < bv) return sortDir === 'asc' ? -1 : 1
    if (av > bv) return sortDir === 'asc' ?  1 : -1
    return 0
  })

  function toggleSort(col) {
    if (sortCol === col) sortDir = sortDir === 'asc' ? 'desc' : 'asc'
    else { sortCol = col; sortDir = (col === 'severity' || col === 'score') ? 'desc' : 'asc' }
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
      <option value="pypi">PyPI</option>
      <option value="npm">npm</option>
      <option value="nuget">NuGet</option>
    </select>
  </div>

  {#if error}<div class="page-error">{error}</div>{/if}

    <table class="table-auto vulns-table">
      <colgroup>
        <col class="col-pkg"><!-- package badge + name -->
        <col class="col-version"><!-- version -->
        <col class="col-sev"><!-- severity chip -->
        <col class="col-score"><!-- CVSS score -->
        <col class="col-osv"><!-- OSV ID -->
        <col><!-- summary: takes leftover -->
        <col class="col-checked"><!-- checked date -->
      </colgroup>
      <thead>
        <tr>
          <th class="sortable" on:click={() => toggleSort('package')}>{$t('vulnerabilities.columns.package')}{sortIndicator('package', sortCol, sortDir)}</th>
          <th class="sortable" on:click={() => toggleSort('version')}>{$t('vulnerabilities.columns.version')}{sortIndicator('version', sortCol, sortDir)}</th>
          <th class="sortable" on:click={() => toggleSort('severity')}>{$t('vulnerabilities.columns.severity')}{sortIndicator('severity', sortCol, sortDir)}</th>
          <th class="sortable" on:click={() => toggleSort('score')}>{$t('vulnerabilities.columns.score')}{sortIndicator('score', sortCol, sortDir)}</th>
          <th class="sortable" on:click={() => toggleSort('osvId')}>{$t('vulnerabilities.columns.osvId')}{sortIndicator('osvId', sortCol, sortDir)}</th>
          <th class="sortable" on:click={() => toggleSort('summary')}>{$t('vulnerabilities.columns.summary')}{sortIndicator('summary', sortCol, sortDir)}</th>
          <th class="sortable" on:click={() => toggleSort('checkedAt')}>{$t('vulnerabilities.columns.checkedAt')}{sortIndicator('checkedAt', sortCol, sortDir)}</th>
        </tr>
      </thead>
      {#if loading}
        <tbody>
          {#each [0,1,2,3,4] as i (i)}
            <tr><td colspan="7"><span class="skeleton"></span></td></tr>
          {/each}
        </tbody>
      {:else}
      <tbody>
        {#each sorted as r, i (i)}
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
        {/each}
        {#if sorted.length === 0}
          <tr><td colspan="7" class="text-center text-muted">{$t('vulnerabilities.empty')}</td></tr>
        {/if}
      </tbody>
      {/if}
    </table>

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
  .vulns-table .col-pkg     { width: 200px; }
  .vulns-table .col-version { width: 110px; }
  .vulns-table .col-sev     { width: 90px; }
  .vulns-table .col-score   { width: 70px; }
  .vulns-table .col-osv     { width: 170px; }
  .vulns-table .col-checked { width: 135px; }
  .summary-cell { font-size: 13px; }
</style>
