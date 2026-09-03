<!--
  The rows behind the Overview dashboard's risk tiles. Operational risk lists the versions that
  have fallen behind upstream; License risk lists the versions carrying a blocklisted SPDX
  identifier, no license at all, or a licence the org marked conditional. Both surfaces are
  read-only — a row clicks through to the package's version-detail page, which is where a
  version is actually blocked or unblocked.

  The conditional rows are the odd ones out: they are not at risk in the sense the other two
  reasons are — they serve normally — but they are the review surface the conditional
  disposition exists to feed, so they share this drill-down. They are deliberately excluded
  from the dashboard tile's count, which has always meant "these are problems".

  Not an admin-only page: the endpoints gate on read:packages, the same capability that serves
  the dashboard tiles, so every role that can see a number can open the rows behind it.
-->
<script>
  import { t } from 'svelte-i18n'
  import { api } from '../lib/api.js'
  import { currentOrg, navigate } from '../lib/store.js'
  import { reportPageLoad } from '../lib/pageLoad.js'
  import { formatDateShort } from '../lib/format.js'
  import { extractErrorMessage } from '../lib/form.js'
  import DataTable from '../lib/DataTable.svelte'
  import Pagination from '../lib/Pagination.svelte'
  import ErrorBanner from '../lib/ErrorBanner.svelte'
  import Skeleton from '../lib/Skeleton.svelte'
  import { ECOSYSTEMS, ECO_LABEL } from '../lib/ecosystems.js'
  import { readQuery, writeQuery } from '../lib/tableState.js'

  // Tab + filter state lives in the URL query string so the dashboard tiles can deep-link
  // straight into a tab (navigate('risk', { tab: 'license' })), and so the state survives a
  // click into version-detail and back. `sort`/`dir` are left blank in DEFAULTS rather than
  // pinned to one table's default: the two tabs' natural orderings disagree (worst-versions-
  // behind-first for operational, most-severe-reason-first for license), so an omitted sort
  // resolves through tabDefaultSort() below instead of a single shared literal.
  const DEFAULTS = { tab: 'operational', eco: '', reason: '', page: 1, limit: 50, sort: '', dir: '' }
  const init = readQuery(DEFAULTS)

  // The sort applied when the caller (URL, or a tab switch) names none — kept in step with the
  // server's own DefaultOperationalRiskSort / DefaultLicenseRiskSort so an omitted sort renders
  // identically to an explicit one naming the default.
  function tabDefaultSort(tab) {
    return tab === 'license' ? { sort: 'reason', dir: 'asc' } : { sort: 'behind', dir: 'desc' }
  }

  /** The route transition this page was mounted for, supplied by RouteView. @type {number | null} */
  export let pageToken = null

  let activeTab = init.tab === 'license' ? 'license' : 'operational'
  let filterEco = init.eco
  let reason = init.reason
  let page = init.page, limit = init.limit
  let sortCol = init.sort || tabDefaultSort(activeTab).sort
  let sortDir = init.dir || tabDefaultSort(activeTab).dir

  let items = [], total = 0, loading = true, error = ''
  // Operational only: the tile's own number (distinct packages, not versions).
  let packageCount = 0
  let threshold = 0

  // Vulnerability-tracker enrichment coverage — an org-wide figure, not per-tab, so it is loaded
  // once independently of the operational/license list rather than threaded through load()'s
  // per-tab branches. Same OrgStats payload the Dashboard tile reads (api.getStats), so the two
  // surfaces can never disagree about the same count.
  let enrichmentLoaded = false
  let trackerConfigured = false
  let enrichedAdvisoryCount = 0
  let totalAdvisoryCount = 0
  // Own sequence counter, mirroring load()'s `seq` above for the same reason: an org switch
  // fires this reactive block again before the previous fetch resolves, and a stale response
  // landing after a newer one would show the wrong org's coverage figures.
  let enrichmentSeq = 0

  async function loadEnrichmentCoverage() {
    const mine = ++enrichmentSeq
    try {
      const stats = await api.getStats()
      if (mine !== enrichmentSeq) return
      trackerConfigured = stats.trackerConfigured ?? false
      enrichedAdvisoryCount = stats.enrichedAdvisoryCount ?? 0
      totalAdvisoryCount = stats.totalAdvisoryCount ?? 0
    } catch {
      // A failed fetch here must not block the risk list this page exists to show — the strip
      // simply stays unrendered, matching the "nothing to report yet" empty state rather than
      // surfacing a second error banner for a secondary figure.
      if (mine !== enrichmentSeq) return
    } finally {
      if (mine === enrichmentSeq) enrichmentLoaded = true
    }
  }

  $: if (org) loadEnrichmentCoverage()
  $: enrichmentPercent = totalAdvisoryCount > 0
    ? Math.round((enrichedAdvisoryCount / totalAdvisoryCount) * 100)
    : null
  // Request sequence — page/filter/tab changes can fire overlapping loads; a response whose
  // token no longer matches the latest issued request is stale and must not overwrite newer state.
  let seq = 0

  function sync() {
    writeQuery({ tab: activeTab, eco: filterEco, reason, page, limit, sort: sortCol, dir: sortDir }, DEFAULTS)
  }

  $: org = $currentOrg
  // Holds the deferred navigation that mounted this page until the data is here, so the swap
  // shows the loaded page rather than a shimmer that lives for a hundred milliseconds.
  $: reportPageLoad(pageToken, loading)

  async function load() {
    const mine = ++seq
    loading = true
    error = ''
    try {
      const params = { page, limit, sort: sortCol, dir: sortDir }
      if (filterEco) params.ecosystem = filterEco
      if (activeTab === 'operational') {
        const data = await api.getOperationalRisk(params)
        if (mine !== seq) return
        items = data.items
        total = data.total
        packageCount = data.packageCount
        threshold = data.threshold
      } else {
        if (reason) params.reason = reason
        const data = await api.getLicenseRisk(params)
        if (mine !== seq) return
        items = data.items
        total = data.total
      }
    } catch (e) {
      if (mine !== seq) return
      error = extractErrorMessage(e)
    } finally {
      if (mine === seq) loading = false
    }
  }

  // Reload whenever the org resolves or the active tab changes; the filter and paging
  // handlers call load() directly.
  $: if (org && activeTab) load()

  function selectTab(tab) {
    if (tab === activeTab) return
    activeTab = tab
    page = 1
    // `reason` only applies to the license tab — drop it so the operational URL stays clean.
    if (tab === 'operational') reason = ''
    // The two tabs' sortable columns are disjoint sets, so a sort chosen on one tab is never a
    // valid header to highlight on the other — reset to the incoming tab's own default.
    const def = tabDefaultSort(tab)
    sortCol = def.sort
    sortDir = def.dir
    items = []
    sync()
  }

  function onFilterChange() { page = 1; sync(); load() }
  function onPageChange(e) { page = e.detail.page; sync(); load() }
  function onLimitChange(e) { limit = e.detail.limit; page = 1; sync(); load() }
  // Sorting resets to page 1: page 4 of the old order is rarely a page of the new one.
  function onSortChange(e) { sortCol = e.detail.col; sortDir = e.detail.dir; page = 1; sync(); load() }

  function openVersion(r) {
    navigate('version-detail', { ecosystem: r.ecosystem, name: r.name })
  }

  // The list is paged, so its sort is server-side — a client-side sort would order the current
  // page against itself while the pager counts the whole set. Every comparator is therefore a
  // no-op: the server returns the page in the order it wants rendered, and DataTable's stable
  // sort preserves it.
  const NOOP_CMP = () => 0

  // Every column maps to a `sort=` key RiskController.Operational accepts (parity pinned by
  // RiskSortKeyParityTests), matching PackageAnalyticsRepository.OperationalRiskSortColumns'
  // own per-column default direction.
  $: operationalColumns = [
    { key: 'package',   label: $t('risk.columns.package'),        sortable: true },
    { key: 'version',   label: $t('risk.columns.version'),        sortable: true, width: '120px' },
    { key: 'behind',    label: $t('risk.columns.versionsBehind'), sortable: true, width: '110px', align: 'right', defaultDir: 'desc' },
    { key: 'latest',    label: $t('risk.columns.latest'),         sortable: true, width: '120px' },
    { key: 'origin',    label: $t('risk.columns.origin'),         sortable: true, width: '90px' },
    { key: 'published', label: $t('risk.columns.published'),      sortable: true, width: '110px', defaultDir: 'desc' },
  ]
  // `licenses` is deliberately not sortable: the SPDX identifiers are stitched onto the page's
  // rows by RiskController.License AFTER paging (one lookup per owner id), so — like
  // ProjectRepository's per-page-computed components/severity/policy columns — sorting on it
  // would order one page against itself and disagree with the pager's own total.
  $: licenseColumns = [
    { key: 'package',   label: $t('risk.columns.package'),   sortable: true },
    { key: 'version',   label: $t('risk.columns.version'),   sortable: true, width: '120px' },
    { key: 'licenses',  label: $t('risk.columns.licenses'),  sortable: false, width: '180px' },
    { key: 'reason',    label: $t('risk.columns.reason'),    sortable: true, width: '110px' },
    { key: 'origin',    label: $t('risk.columns.origin'),    sortable: true, width: '90px' },
    { key: 'published', label: $t('risk.columns.published'), sortable: true, width: '110px', defaultDir: 'desc' },
  ]
  $: comparators = Object.fromEntries(
    (activeTab === 'operational' ? operationalColumns : licenseColumns).map(c => [c.key, NOOP_CMP]))
</script>

<div class="page">
  <header class="page-header">
    <h1>{$t('risk.title')}</h1>
  </header>

  <div class="tabs" role="tablist">
    <button class="tab" class:active={activeTab === 'operational'} role="tab"
            aria-selected={activeTab === 'operational'}
            on:click={() => selectTab('operational')}>{$t('risk.tabs.operational')}</button>
    <button class="tab" class:active={activeTab === 'license'} role="tab"
            aria-selected={activeTab === 'license'}
            on:click={() => selectTab('license')}>{$t('risk.tabs.license')}</button>
  </div>

  <p class="intro">{$t(`risk.intro.${activeTab}`)}</p>

  <!-- Enrichment coverage strip: not configured / no advisories / a measured percent, the same
       three-state discipline as the Dashboard tile this mirrors — never a fabricated 0% for an
       absent connection, never a permanent 0% for an org with nothing to enrich. -->
  {#if enrichmentLoaded}
    <div class="enrichment-strip">
      {#if !trackerConfigured}
        <span class="enrichment-empty">{$t('risk.enrichment.notConfigured')}</span>
      {:else if totalAdvisoryCount === 0}
        <span class="enrichment-empty">{$t('risk.enrichment.none')}</span>
      {:else}
        <span class="enrichment-percent">
          {$t('risk.enrichment.percent', { values: { percent: enrichmentPercent } })}
        </span>
        <span class="enrichment-detail">
          {$t('risk.enrichment.detail', { values: {
            enriched: enrichedAdvisoryCount,
            total: totalAdvisoryCount,
          } })}
        </span>
      {/if}
    </div>
  {/if}

  <div class="toolbar">
    <!-- The toolbar stacks vertically, so hiding this line while loading dropped the filter row
         below it the moment the counts arrived. Render it always and reserve its height. -->
    <span class="summary">
      {#if loading}
        <Skeleton width="280px" height="12px" />
      {:else if activeTab === 'operational'}
        {$t('risk.summary.operational', { values: { packages: packageCount, versions: total, threshold } })}
      {:else}
        {$t('risk.summary.license', { values: { count: total } })}
      {/if}
    </span>

    <div class="filters">
      <select bind:value={filterEco} on:change={onFilterChange} aria-label={$t('risk.filters.ecosystem')}>
        <option value="">{$t('risk.filters.allEcosystems')}</option>
        {#each ECOSYSTEMS as e (e)}
          <option value={e}>{ECO_LABEL[e] ?? e}</option>
        {/each}
      </select>

      {#if activeTab === 'license'}
        <select bind:value={reason} on:change={onFilterChange} aria-label={$t('risk.columns.reason')}>
          <option value="">{$t('risk.reasonFilter.all')}</option>
          <option value="blocklisted">{$t('risk.reason.blocklisted')}</option>
          <option value="unknown">{$t('risk.reason.unknown')}</option>
          <option value="conditional">{$t('risk.reason.conditional')}</option>
        </select>
      {/if}
    </div>
  </div>

  <ErrorBanner message={error} />

  {#if activeTab === 'operational'}
    <DataTable
      columns={operationalColumns}
      rows={items}
      {comparators}
      {loading}
      loadingRows={limit}
      memoryKey="risk:operational"
      emptyText={$t('risk.empty.operational')}
      initialSort={{ key: sortCol, dir: sortDir }}
      on:sortchange={onSortChange}
      let:row={r}
    >
      <tr class="cursor-pointer" on:click={() => openVersion(r)}>
        <td>
          <div class="pkg-cell">
            <span class="badge {r.ecosystem}">{r.ecosystem}</span>
            <span class="mono pkg-name" title={r.purl ?? r.displayName}>{r.displayName}</span>
          </div>
        </td>
        <td class="mono nowrap">{r.version}</td>
        <td class="right"><span class="behind">{r.versionsBehind}</span></td>
        <td class="mono nowrap">{r.upstreamLatestVersion ?? '—'}</td>
        <td><span class="badge origin-{r.origin}">{$t(`risk.origin.${r.origin}`)}</span></td>
        <td class="nowrap">{r.publishedAt ? $formatDateShort(r.publishedAt) : '—'}</td>
      </tr>
    </DataTable>
  {:else}
    <DataTable
      columns={licenseColumns}
      rows={items}
      {comparators}
      {loading}
      loadingRows={limit}
      memoryKey="risk:license"
      emptyText={$t('risk.empty.license')}
      initialSort={{ key: sortCol, dir: sortDir }}
      on:sortchange={onSortChange}
      let:row={r}
    >
      <tr class="cursor-pointer" on:click={() => openVersion(r)}>
        <td>
          <div class="pkg-cell">
            <span class="badge {r.ecosystem}">{r.ecosystem}</span>
            <span class="mono pkg-name" title={r.purl ?? r.displayName}>{r.displayName}</span>
            {#if r.filename}<span class="filename" title={r.filename}>{r.filename}</span>{/if}
          </div>
        </td>
        <td class="mono nowrap">{r.version}</td>
        <td>
          {#if r.licenses?.length}
            <div class="licenses">
              {#each r.licenses as spdx (spdx)}<span class="badge spdx mono">{spdx}</span>{/each}
            </div>
          {:else}
            <span class="text-muted">—</span>
          {/if}
        </td>
        <td><span class="reason reason-{r.reason}">{$t(`risk.reason.${r.reason}`)}</span></td>
        <td><span class="badge origin-{r.origin}">{$t(`risk.origin.${r.origin}`)}</span></td>
        <td class="nowrap">{r.publishedAt ? $formatDateShort(r.publishedAt) : '—'}</td>
      </tr>
    </DataTable>
  {/if}

  <Pagination {total} {page} {limit}
    on:pagechange={onPageChange}
    on:limitchange={onLimitChange} />
</div>

<style>
  .page { padding: 20px 24px; }
  .page-header { margin-bottom: 12px; }
  h1 { margin: 0; font-size: 20px; font-weight: 600; }
  .intro { color: var(--text2); font-size: 13px; margin: 12px 0 16px; max-width: 780px; }

  .tabs { display: flex; gap: 4px; border-bottom: 1px solid var(--border); }
  .tab {
    background: none;
    border: none;
    border-bottom: 2px solid transparent;
    border-radius: 0;
    min-height: 0;
    padding: 8px 14px;
    font-size: 13px;
    color: var(--text2);
    cursor: pointer;
  }
  .tab:hover { color: var(--text); background: none; }
  .tab.active { color: var(--accent); border-bottom-color: var(--accent); }

  .enrichment-strip {
    display: flex;
    align-items: baseline;
    gap: 8px;
    font-size: 12px;
    color: var(--text2);
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 6px 12px;
    margin: 0 0 12px;
    width: fit-content;
  }
  .enrichment-percent { font-weight: 600; color: var(--text); }
  .enrichment-empty { font-style: italic; }

  .toolbar { display: flex; flex-direction: column; align-items: flex-start; gap: 8px; margin-bottom: 12px; }
  .filters { display: flex; align-items: center; gap: 8px; }
  .summary { font-size: 12px; color: var(--text2); min-height: 1.25em; }

  td { vertical-align: middle; }
  .right { text-align: right; }
  .pkg-cell { display: flex; align-items: center; gap: 8px; min-width: 0; }
  .pkg-name { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .filename { font-size: 11px; color: var(--text2); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .licenses { display: flex; flex-wrap: wrap; gap: 4px; }

  /* The count itself is the signal on this page — every listed row is already at or over the
     threshold, so it is emphasized rather than colour-coded by severity. */
  .behind { font-weight: 600; }

  .reason { font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.04em; }
  .reason-blocklisted { color: var(--danger); }
  .reason-unknown { color: var(--text2); }
  /* Conditional artifacts serve — this is a review cue, not a failure, so it does not borrow
     the danger colour the blocklisted rows use. */
  .reason-conditional { color: var(--badge-sky-text); }
</style>
