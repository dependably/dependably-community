<script>
  import { t } from 'svelte-i18n'
  import { api } from '../lib/api.js'
  import ErrorBanner from '../lib/ErrorBanner.svelte'
  import { currentOrg, navigate } from '../lib/store.js'
  import { formatDateShort } from '../lib/format.js'
  import DataTable from '../lib/DataTable.svelte'
  import Pagination from '../lib/Pagination.svelte'
  import SearchInput from '../lib/SearchInput.svelte'
  import RowActionsMenu from '../lib/RowActionsMenu.svelte'
  import { ECOSYSTEMS, ECO_LABEL } from '../lib/ecosystems.js'
  import { readQuery, writeQuery } from '../lib/tableState.js'

  // Table state lives in the URL query string so it survives navigating into a
  // package's detail page and back (this component is recreated on every route
  // change) as well as reloads and copied links.
  const DEFAULTS = { q: '', eco: '', page: 1, limit: 50, sort: 'name', dir: 'asc' }
  const init = readQuery(DEFAULTS)

  let items = [], loading = true, error = ''
  let search = init.q, filterEco = init.eco
  let page = init.page, limit = init.limit, total = 0
  let sortCol = init.sort, sortDir = init.dir
  let versionOverwritePolicy = 'block'
  let openActionsId = null

  function sync() {
    writeQuery({ q: search, eco: filterEco, page, limit, sort: sortCol, dir: sortDir }, DEFAULTS)
  }

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
      versionOverwritePolicy = data.versionOverwritePolicy ?? 'block'
    } catch (e) { error = e.message }
    finally { loading = false }
  }

  $: if (org) load()

  function onPageChange(e) { page = e.detail.page; sync(); load() }
  function onLimitChange(e) { limit = e.detail.limit; page = 1; sync(); load() }

  function onSortChange(e) {
    sortCol = e.detail.col
    sortDir = e.detail.dir
    page = 1
    sync()
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
    { key: 'downloads', label: $t('packages.columns.downloads'), sortable: true,  width: '100px', defaultDir: 'desc' },
    { key: 'latest',    label: $t('packages.columns.latest'),    sortable: false, width: '70px' },
    { key: 'vulns',     label: $t('packages.columns.vulns'),     sortable: true,  width: '130px', defaultDir: 'desc' },
    { key: 'created',   label: $t('packages.columns.created'),   sortable: true,  width: '120px' },
    ...(versionOverwritePolicy !== 'block'
      ? [{ key: 'actions', label: '', sortable: false, width: '48px' }]
      : []),
  ]
  const comparators = {
    name: NOOP_CMP, ecosystem: NOOP_CMP, purl: NOOP_CMP,
    versions: NOOP_CMP, downloads: NOOP_CMP, latest: NOOP_CMP, vulns: NOOP_CMP, created: NOOP_CMP,
    actions: NOOP_CMP,
  }

  function handleSearch() {
    page = 1
    sync()
    load()
  }

  function handleEcoChange() {
    page = 1
    sync()
    load()
  }

  function fullPurl(pkg) {
    return `pkg:${pkg.ecosystem}/${pkg.purlName}`
  }

  function openPackage(pkg) {
    navigate('version-detail', { ecosystem: pkg.ecosystem, name: pkg.purlName })
  }

  async function setOverwrite(pkg, override) {
    openActionsId = null
    try {
      await api.setPackageVersionOverwrite(pkg.ecosystem, pkg.name, override)
      await load()
    } catch (e) {
      error = e.message
    }
  }
</script>

<div class="page page-wide">
  <div class="page-header">
    <h1 class="page-title">{$t('packages.title')}</h1>
    <SearchInput placeholder={$t('packages.searchPlaceholder')} bind:value={search} on:search={handleSearch} class="header-search" />
  </div>

  <div class="search-bar">
    <select bind:value={filterEco} on:change={handleEcoChange} class="eco-select">
      <option value="">{$t('common.allEcosystems')}</option>
      {#each ECOSYSTEMS as eco (eco)}
        <option value={eco}>{ECO_LABEL[eco]}</option>
      {/each}
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
      <td class="name-cell" title={pkg.name}>
        <strong>{pkg.name}</strong>
        {#if pkg.hasMaliciousVersion}
          <span class="badge malicious ml-1" title={$t('packages.malicious.help')}>
            <svg width="11" height="11" aria-hidden="true"><use href="/icons.svg#icon-alert"/></svg>
            {$t('packages.malicious.label')}
          </span>
        {/if}
      </td>
      <td class="nowrap"><span class="badge {pkg.ecosystem}">{ECO_LABEL[pkg.ecosystem] ?? pkg.ecosystem}</span></td>
      <td class="mono purl-cell" title={fullPurl(pkg)}>{fullPurl(pkg)}</td>
      <td class="nowrap text-right text-muted">{pkg.versionCount ?? 0}</td>
      <td class="nowrap text-right text-muted">{(pkg.totalDownloads ?? 0).toLocaleString()}</td>
      <td class="nowrap text-center latest-cell">
        <!-- Instant hover bubble (no native `title` delay) reveals the upstream latest
             version number; mirrors InfoTip.svelte's bubble. -->
        <span class="latest-tip-wrap">
          {#if pkg.latestState === 'current'}
            <svg class="latest-yes" width="14" height="14" role="img" aria-label={$t('packages.latest.current')}><use href="/icons.svg#icon-check"/></svg>
          {:else if pkg.latestState === 'stale'}
            <svg class="latest-no" width="14" height="14" role="img" aria-label={$t('packages.latest.stale')}><use href="/icons.svg#icon-x"/></svg>
          {:else}
            <span class="text-muted" aria-label={$t('packages.latest.unknown')}>—</span>
          {/if}
          {#if pkg.upstreamLatestVersion}
            <span class="latest-tip-bubble" role="tooltip">{$t('packages.latest.versionLabel', { values: { version: pkg.upstreamLatestVersion } })}</span>
          {/if}
        </span>
      </td>
      <td class="vuln-cell">
        {#if (pkg.criticalCount ?? 0) > 0}<span class="sev sev-critical" aria-label="{pkg.criticalCount} critical">{pkg.criticalCount}</span>{/if}
        {#if (pkg.highCount ?? 0) > 0}<span class="sev sev-high" aria-label="{pkg.highCount} high">{pkg.highCount}</span>{/if}
        {#if (pkg.mediumCount ?? 0) > 0}<span class="sev sev-medium" aria-label="{pkg.mediumCount} medium">{pkg.mediumCount}</span>{/if}
        {#if (pkg.lowCount ?? 0) > 0}<span class="sev sev-low" aria-label="{pkg.lowCount} low">{pkg.lowCount}</span>{/if}
      </td>
      <td class="nowrap text-muted">{$formatDateShort(pkg.createdAt)}</td>
      {#if versionOverwritePolicy !== 'block'}
        <td class="actions-cell" on:click|stopPropagation>
          <div class="row-actions">
            <RowActionsMenu id={pkg.name + '/' + pkg.ecosystem} bind:openId={openActionsId} ariaLabel={$t('packages.actionsMenu.open')}>
              {#if versionOverwritePolicy === 'exception'}
                <button
                  class="popover-item"
                  disabled={pkg.sameVersionPushOverride === 'allow'}
                  on:click|stopPropagation={() => setOverwrite(pkg, 'allow')}
                >
                  {#if pkg.sameVersionPushOverride === 'allow'}
                    <svg width="12" height="12" aria-hidden="true" class="menu-check"><use href="/icons.svg#icon-check"/></svg>
                  {/if}
                  {$t('packages.actionsMenu.allowSameVersionPush')}
                </button>
                <button
                  class="popover-item"
                  disabled={!pkg.sameVersionPushOverride}
                  on:click|stopPropagation={() => setOverwrite(pkg, null)}
                >
                  {$t('packages.actionsMenu.inheritOrgDefault')}
                </button>
              {:else if versionOverwritePolicy === 'allow'}
                <button
                  class="popover-item"
                  disabled={pkg.sameVersionPushOverride === 'block'}
                  on:click|stopPropagation={() => setOverwrite(pkg, 'block')}
                >
                  {#if pkg.sameVersionPushOverride === 'block'}
                    <svg width="12" height="12" aria-hidden="true" class="menu-check"><use href="/icons.svg#icon-check"/></svg>
                  {/if}
                  {$t('packages.actionsMenu.blockSameVersionPush')}
                </button>
                <button
                  class="popover-item"
                  disabled={!pkg.sameVersionPushOverride}
                  on:click|stopPropagation={() => setOverwrite(pkg, null)}
                >
                  {$t('packages.actionsMenu.inheritOrgDefault')}
                </button>
              {/if}
            </RowActionsMenu>
          </div>
        </td>
      {/if}
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
  .page-header :global(.header-search) {
    width: 220px;
  }
  .nowrap { white-space: nowrap; }
  .vuln-cell { white-space: nowrap; }
  /* The global `td { overflow: hidden }` (cell ellipsis) would clip the absolutely
     positioned hover bubble, which pops up out of the cell, down to a thin sliver.
     This cell holds only a small icon, so it never needs ellipsis clipping. */
  .latest-cell { font-weight: 600; overflow: visible; }
  .latest-yes { color: var(--success); }
  .latest-no { color: var(--danger); }

  /* Instant hover tooltip for the upstream latest version — mirrors InfoTip.svelte's
     bubble so there's no native `title` reveal delay. */
  .latest-tip-wrap {
    position: relative;
    display: inline-flex;
    vertical-align: middle;
  }
  .latest-tip-bubble {
    position: absolute;
    bottom: calc(100% + 6px);
    left: 50%;
    transform: translateX(-50%);
    z-index: 10;
    width: max-content;
    max-width: 240px;
    padding: 6px 9px;
    border-radius: var(--radius);
    background: var(--bg2);
    color: var(--text);
    border: 1px solid var(--border);
    font-size: 12px;
    font-weight: 400;
    line-height: 1.4;
    white-space: nowrap;
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.25);
    opacity: 0;
    visibility: hidden;
    pointer-events: none;
  }
  .latest-tip-wrap:hover .latest-tip-bubble,
  .latest-tip-wrap:focus-within .latest-tip-bubble {
    opacity: 1;
    visibility: visible;
  }
  .name-cell { overflow-wrap: anywhere; }
  .purl-cell { font-size: 12px; color: var(--text2); overflow-wrap: anywhere; }
  .eco-select { width: auto; }
  .actions-cell { overflow: visible; width: 48px; }
  .row-actions { display: flex; justify-content: center; }
  .menu-check { color: var(--success); margin-right: 4px; vertical-align: middle; }
</style>
