<script>
  import { t } from 'svelte-i18n'
  import { api } from '../lib/api.js'
  import { currentOrg, navigate } from '../lib/store.js'
  import { formatDateShort } from '../lib/format.js'
  import { sortIndicator } from '../lib/sortIndicator.js'
  import Pagination from '../lib/Pagination.svelte'

  let items = [], loading = true, error = ''
  let search = '', filterEco = ''
  let page = 1, limit = 50, total = 0
  let sortCol = 'name', sortDir = 'asc'

  $: org = $currentOrg

  async function load() {
    loading = true
    error = ''
    try {
      const params = { page, limit, sortBy: sortCol, sortDir }
      if (filterEco) params.ecosystem = filterEco
      if (search) params.search = search
      const data = await api.listPackages( params)
      items = data.items
      total = data.total
    } catch (e) { error = e.message }
    finally { loading = false }
  }

  $: if (org) load()

  function onPageChange(e) { page = e.detail.page; load() }
  function onLimitChange(e) { limit = e.detail.limit; page = 1; load() }

  function toggleSort(col) {
    if (sortCol === col) sortDir = sortDir === 'asc' ? 'desc' : 'asc'
    else { sortCol = col; sortDir = col === 'vulns' ? 'desc' : 'asc' }
    page = 1
    load()
  }

  let searchTimeout
  function handleSearch() {
    clearTimeout(searchTimeout)
    searchTimeout = setTimeout(() => { page = 1; load() }, 300)
  }

  function handleEcoChange() {
    page = 1
    load()
  }

  function fullPurl(pkg) {
    return `pkg:${pkg.ecosystem}/${pkg.purlName}`
  }

  function openPackage(pkg) {
    navigate('version-detail', { ecosystem: pkg.ecosystem, name: pkg.purlName })
  }
</script>

<div class="page page-wide">
  <div class="page-header">
    <h1 class="page-title">{$t('packages.title')}</h1>
    <input placeholder={$t('packages.searchPlaceholder')} bind:value={search} on:input={handleSearch} class="header-search" />
  </div>

  <div class="search-bar">
    <select bind:value={filterEco} on:change={handleEcoChange} class="eco-select">
      <option value="">{$t('common.allEcosystems')}</option>
      <option value="pypi">PyPI</option>
      <option value="npm">npm</option>
      <option value="nuget">NuGet</option>
    </select>
  </div>

  {#if error}<div class="page-error">{error}</div>{/if}
    <table class="table-auto">
      <colgroup>
        <col class="col-name"><!-- name: prefers 200, grows for long names -->
        <col class="col-eco"><!-- ecosystem badge -->
        <col><!-- purl: takes leftover -->
        <col class="col-versions"><!-- versions count -->
        <col class="col-vulns"><!-- vuln chips -->
        <col class="col-created"><!-- created date -->
      </colgroup>
      <thead>
        <tr>
          <th class="sortable" on:click={() => toggleSort('name')}>{$t('packages.columns.name')}{sortIndicator('name', sortCol, sortDir)}</th>
          <th class="sortable" on:click={() => toggleSort('ecosystem')}>{$t('packages.columns.ecosystem')}{sortIndicator('ecosystem', sortCol, sortDir)}</th>
          <th class="sortable" on:click={() => toggleSort('purl')}>{$t('packages.columns.purl')}{sortIndicator('purl', sortCol, sortDir)}</th>
          <th class="sortable text-right" on:click={() => toggleSort('versions')}>{$t('packages.columns.versions')}{sortIndicator('versions', sortCol, sortDir)}</th>
          <th class="sortable" on:click={() => toggleSort('vulns')}>{$t('packages.columns.vulns')}{sortIndicator('vulns', sortCol, sortDir)}</th>
          <th class="sortable" on:click={() => toggleSort('created')}>{$t('packages.columns.created')}{sortIndicator('created', sortCol, sortDir)}</th>
        </tr>
      </thead>
      {#if loading}
        <tbody>
          {#each [0,1,2,3,4] as i (i)}
            <tr><td colspan="6"><span class="skeleton"></span></td></tr>
          {/each}
        </tbody>
      {:else}
      <tbody>
        {#each items as pkg (pkg.id)}
          <tr class="cursor-pointer" on:click={() => openPackage(pkg)}>
            <td class="name-cell" title={pkg.name}><strong>{pkg.name}</strong></td>
            <td class="nowrap"><span class="badge {pkg.ecosystem}">{pkg.ecosystem}</span></td>
            <td class="mono purl-cell" title={fullPurl(pkg)}>{fullPurl(pkg)}</td>
            <td class="nowrap text-right text-muted">{pkg.versionCount ?? 0}</td>
            <td class="vuln-cell">
              {#if (pkg.criticalCount ?? 0) > 0}<span class="sev sev-critical" aria-label="{pkg.criticalCount} critical">{pkg.criticalCount}</span>{/if}
              {#if (pkg.highCount ?? 0) > 0}<span class="sev sev-high" aria-label="{pkg.highCount} high">{pkg.highCount}</span>{/if}
              {#if (pkg.mediumCount ?? 0) > 0}<span class="sev sev-medium" aria-label="{pkg.mediumCount} medium">{pkg.mediumCount}</span>{/if}
              {#if (pkg.lowCount ?? 0) > 0}<span class="sev sev-low" aria-label="{pkg.lowCount} low">{pkg.lowCount}</span>{/if}
            </td>
            <td class="nowrap text-muted">{$formatDateShort(pkg.createdAt)}</td>
          </tr>
        {/each}
        {#if items.length === 0}
          <tr><td colspan="6" class="text-center text-muted">{$t('packages.empty')}</td></tr>
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
  .page-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
  }
  .header-search {
    width: 220px;
  }
  .nowrap { white-space: nowrap; }
  .vuln-cell { white-space: nowrap; }
  .name-cell { overflow-wrap: anywhere; }
  .purl-cell { font-size: 12px; color: var(--text2); overflow-wrap: anywhere; }
  .eco-select { width: auto; }
  .col-name     { width: 200px; }
  .col-eco      { width: 90px; }
  .col-versions { width: 80px; }
  .col-vulns    { width: 130px; }
  .col-created  { width: 120px; }
</style>
