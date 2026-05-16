<script>
  import { t } from 'svelte-i18n'
  import { api } from '../lib/api.js'
  import ErrorBanner from '../lib/ErrorBanner.svelte'
  import { currentOrg, navigate } from '../lib/store.js'
  import { formatDateShort } from '../lib/format.js'
  import DataTable from '../lib/DataTable.svelte'
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

  function onSortChange(e) {
    sortCol = e.detail.col
    sortDir = e.detail.dir
    page = 1
    load()
  }

  // Server already sorts and returns the page in order. DataTable's local sort
  // is bypassed here by returning 0 for every comparator — the stable sort
  // preserves the server order regardless of which column is "active".
  const NOOP_CMP = () => 0
  $: columns = [
    { key: 'name',      label: $t('packages.columns.name'),      sortable: true,  width: '200px' },
    { key: 'ecosystem', label: $t('packages.columns.ecosystem'), sortable: true,  width: '90px' },
    { key: 'purl',      label: $t('packages.columns.purl'),      sortable: true },
    { key: 'versions',  label: $t('packages.columns.versions'),  sortable: true,  width: '80px' },
    { key: 'vulns',     label: $t('packages.columns.vulns'),     sortable: true,  width: '130px', defaultDir: 'desc' },
    { key: 'created',   label: $t('packages.columns.created'),   sortable: true,  width: '120px' },
  ]
  const comparators = {
    name: NOOP_CMP, ecosystem: NOOP_CMP, purl: NOOP_CMP,
    versions: NOOP_CMP, vulns: NOOP_CMP, created: NOOP_CMP,
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

  <ErrorBanner message={error} />
  <DataTable
    {columns}
    rows={items}
    {comparators}
    {loading}
    initialSort={{ key: sortCol, dir: sortDir }}
    emptyText={$t('packages.empty')}
    on:sortchange={onSortChange}
    let:row={pkg}
  >
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
  </DataTable>

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
</style>
