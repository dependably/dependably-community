<script>
  import { t } from 'svelte-i18n'
  import { api } from '../lib/api.js'
  import ErrorBanner from '../lib/ErrorBanner.svelte'
  import { bootstrapInfo, currentOrg, navigate } from '../lib/store.js'
  import { reportPageLoad } from '../lib/pageLoad.js'
  import { formatDateShort, formatNumber } from '../lib/format.js'
  import DataTable from '../lib/DataTable.svelte'
  import Pagination from '../lib/Pagination.svelte'
  import SearchInput from '../lib/SearchInput.svelte'
  import RowActionsMenu from '../lib/RowActionsMenu.svelte'
  import { ECOSYSTEMS, ECO_LABEL } from '../lib/ecosystems.js'
  import { readQuery, writeQuery } from '../lib/tableState.js'
  import { copyToClipboard } from '../lib/clipboard.js'
  import { packageInstallCommand, registryOrigin } from '../lib/installCommand.js'

  // Table state lives in the URL query string so it survives navigating into a
  // package's detail page and back (this component is recreated on every route
  // change) as well as reloads and copied links.
  const DEFAULTS = { q: '', eco: '', page: 1, limit: 50, sort: 'name', dir: 'asc' }
  const init = readQuery(DEFAULTS)

  /** The route transition this page was mounted for, supplied by RouteView. @type {number | null} */
  export let pageToken = null

  let items = [], loading = true, error = ''
  let search = init.q, filterEco = init.eco
  let page = init.page, limit = init.limit, total = 0
  let sortCol = init.sort, sortDir = init.dir
  let versionOverwritePolicy = 'block'
  let openActionsId = null
  // Request sequence — page/filter/search changes can fire overlapping loads; a response whose
  // token no longer matches the latest issued request is stale and must not overwrite newer state.
  let seq = 0

  function sync() {
    writeQuery({ q: search, eco: filterEco, page, limit, sort: sortCol, dir: sortDir }, DEFAULTS)
  }

  $: org = $currentOrg

  async function load() {
    const mine = ++seq
    loading = true
    error = ''
    try {
      const params = { page, limit, sortBy: sortCol, sortDir }
      if (filterEco) params.ecosystem = filterEco
      if (search) params.search = search
      const data = await api.listPackages( params)
      if (mine !== seq) return
      items = data.items
      total = data.total
      versionOverwritePolicy = data.versionOverwritePolicy ?? 'block'
    } catch (e) {
      if (mine !== seq) return
      error = e.message
    } finally {
      if (mine === seq) loading = false
    }
  }

  $: if (org) load()
  // Holds the deferred navigation that mounted this page until the data is here, so the swap
  // shows the loaded page rather than a shimmer that lives for a hundred milliseconds.
  $: reportPageLoad(pageToken, loading)

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
  // The fixed columns sum to 722px so the purl — the one flexible column — keeps a usable share
  // of a laptop content column; `created` leaves under 1100px, where it would otherwise starve
  // the purl into wrapping. Latest holds two 14px icons, their 8px gap and the cell padding.
  $: columns = [
    { key: 'name',      label: $t('packages.columns.name'),      sortable: true,  width: '180px' },
    { key: 'ecosystem', label: $t('packages.columns.ecosystem'), sortable: true,  width: '80px' },
    { key: 'purl',      label: $t('packages.columns.purl'),      sortable: true },
    { key: 'versions',  label: $t('packages.columns.versions'),  sortable: true,  width: '64px',  align: 'right' },
    { key: 'downloads', label: $t('packages.columns.downloads'), sortable: true,  width: '88px',  defaultDir: 'desc', align: 'right' },
    { key: 'latest',    label: $t('packages.columns.latest'),    sortable: false, width: '64px',  align: 'center' },
    { key: 'vulns',     label: $t('packages.columns.vulns'),     sortable: true,  width: '110px', defaultDir: 'desc' },
    { key: 'created',   label: $t('packages.columns.created'),   sortable: true,  width: '96px',  hideBelow: 1100 },
    // Always present: the row menu now also carries the install command, which every viewer
    // can use — not just the admins the same-version-push items are gated to.
    { key: 'actions', label: '', sortable: false, width: '40px' },
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

  // Registry URL to embed in a copied command. Follows bootstrap, which is what tells us the
  // operator declared an HTTPS deployment even when this browser reached the SPA over HTTP.
  $: origin = registryOrigin($bootstrapInfo, window.location)

  // Same identity RowActionsMenu keys on, so the acknowledgement lands on the row clicked.
  const rowKey = (pkg) => `${pkg.name}/${pkg.ecosystem}`

  let copiedId = null
  async function copyInstall(pkg, command) {
    const ok = await copyToClipboard(command)
    if (!ok) { openActionsId = null; return }
    // Hold the menu open briefly so the acknowledgement is actually readable.
    copiedId = rowKey(pkg)
    setTimeout(() => {
      if (copiedId === rowKey(pkg)) { copiedId = null; openActionsId = null }
    }, 1200)
  }

  // The latest-version bubble is position:fixed so the table's horizontal scroller cannot clip
  // it and it floats above the sticky topbar. A fixed element has no relation to its trigger, so
  // the trigger's viewport rectangle is read as the pointer arrives and the bubble is placed
  // under it; any scroll dismisses it rather than leaving it detached from its row.
  let tip = null
  function showTip(e, text) {
    const r = e.currentTarget.getBoundingClientRect()
    tip = { top: r.bottom + 6, left: r.left + r.width / 2, text }
  }
  function hideTip() { tip = null }
  // No bubble for a package whose upstream latest is unknown: the icon alone already says so.
  function showLatestTip(e, pkg) {
    if (!pkg.upstreamLatestVersion) return
    showTip(e, $t('packages.latest.versionLabel', { values: { version: pkg.upstreamLatestVersion } }))
  }

  async function setOverwrite(pkg, override) {
    openActionsId = null
    try {
      await api.setPackageVersionOverwrite(pkg.ecosystem, pkg.purlName, override)
      await load()
    } catch (e) {
      error = e.message
    }
  }
</script>

<svelte:window on:scroll|capture={hideTip} />

{#if tip}
  <span class="latest-tip-bubble" role="tooltip" style:top="{tip.top}px" style:left="{tip.left}px">{tip.text}</span>
{/if}

<div class="page">
  <div class="page-header">
    <h1 class="page-title">{$t('packages.title')}</h1>
  </div>

  <div class="page-toolbar">
    <SearchInput placeholder={$t('packages.searchPlaceholder')} bind:value={search} on:search={handleSearch} class="toolbar-search" />
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
    loadingRows={limit}
    memoryKey="packages"
    initialSort={{ key: sortCol, dir: sortDir }}
    emptyText={$t('packages.empty')}
    on:sortchange={onSortChange}
    let:row={pkg}
    let:hidden
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
        {#if pkg.hasKevVersion}
          <span class="badge kev ml-1" title={$t('packages.kev.help')}>{$t('packages.kev.label')}</span>
        {/if}
      </td>
      <td class="nowrap"><span class="badge {pkg.ecosystem}">{ECO_LABEL[pkg.ecosystem] ?? pkg.ecosystem}</span></td>
      <td class="mono purl-cell" title={fullPurl(pkg)}>{fullPurl(pkg)}</td>
      <td class="nowrap text-right text-muted">{pkg.versionCount ?? 0}</td>
      <td class="nowrap text-right text-muted">{$formatNumber(pkg.totalDownloads)}</td>
      <td class="nowrap text-center latest-cell">
        <!-- Instant hover bubble (no native `title` delay) reveals the upstream latest
             version number. -->
        <!-- The wrappers are layout only (the icons carry their own labels), hence presentation. -->
        <span
          class="latest-tip-wrap"
          role="presentation"
          on:mouseenter={(e) => showLatestTip(e, pkg)}
          on:mouseleave={hideTip}
        >
          {#if pkg.latestState === 'current'}
            <svg class="latest-yes" width="14" height="14" role="img" aria-label={$t('packages.latest.current')}><use href="/icons.svg#icon-check"/></svg>
          {:else if pkg.latestState === 'stale'}
            <svg class="latest-no" width="14" height="14" role="img" aria-label={$t('packages.latest.stale')}><use href="/icons.svg#icon-x"/></svg>
          {:else}
            <span class="text-muted" aria-label={$t('packages.latest.unknown')}>—</span>
          {/if}
        </span>
        {#if pkg.abandonedState === 'abandoned'}
          <!-- Never rendered for 'unknown' — an unknown publish timestamp is not evidence
               of abandonment. -->
          <span
            class="latest-tip-wrap"
            role="presentation"
            on:mouseenter={(e) => showTip(e, $t('packages.abandoned.help'))}
            on:mouseleave={hideTip}
          >
            <svg class="abandoned-icon" width="14" height="14" role="img" aria-label={$t('packages.abandoned.label')}><use href="/icons.svg#icon-alert"/></svg>
          </span>
        {/if}
      </td>
      <td class="vuln-cell">
        {#if (pkg.criticalCount ?? 0) > 0}<span class="sev sev-critical" aria-label="{pkg.criticalCount} critical">{pkg.criticalCount}</span>{/if}
        {#if (pkg.highCount ?? 0) > 0}<span class="sev sev-high" aria-label="{pkg.highCount} high">{pkg.highCount}</span>{/if}
        {#if (pkg.mediumCount ?? 0) > 0}<span class="sev sev-medium" aria-label="{pkg.mediumCount} medium">{pkg.mediumCount}</span>{/if}
        {#if (pkg.lowCount ?? 0) > 0}<span class="sev sev-low" aria-label="{pkg.lowCount} low">{pkg.lowCount}</span>{/if}
        {#if ((pkg.criticalCount ?? 0) + (pkg.highCount ?? 0) + (pkg.mediumCount ?? 0) + (pkg.lowCount ?? 0)) === 0}<span class="text-muted" aria-label={$t('packages.vulns.none')}>—</span>{/if}
      </td>
      {#if !hidden.has('created')}
        <td class="nowrap text-muted">{$formatDateShort(pkg.createdAt)}</td>
      {/if}
      <td class="actions-cell" on:click|stopPropagation>
        <div class="row-actions">
          <RowActionsMenu id={pkg.name + '/' + pkg.ecosystem} bind:openId={openActionsId} ariaLabel={$t('packages.actionsMenu.open')}>
            <!-- Unpinned form. Omitted for the ecosystems that cannot express "latest"
                 without a version (Maven, Terraform) or a tag (OCI) — the list carries
                 neither, and a command that would 404 is worse than no command. -->
            {@const installCmd = packageInstallCommand({
              ecosystem: pkg.ecosystem, name: pkg.purlName ?? pkg.name, origin,
            })}
            {#if installCmd}
              <button
                class="popover-item"
                on:click|stopPropagation={() => copyInstall(pkg, installCmd.command)}
              >
                {copiedId === rowKey(pkg)
                  ? $t('common.actions.copied')
                  : $t('packages.actionsMenu.copyInstall')}
              </button>
            {/if}
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
    </tr>
  </DataTable>

  <Pagination {total} {page} {limit}
    on:pagechange={onPageChange}
    on:limitchange={onLimitChange} />
</div>

<style>
  .nowrap { white-space: nowrap; }
  .vuln-cell { white-space: nowrap; }
  .latest-cell { font-weight: 600; }
  .latest-yes { color: var(--success); }
  .latest-no { color: var(--danger); }
  .abandoned-icon { color: var(--warning); }

  .latest-tip-wrap {
    display: inline-flex;
    vertical-align: middle;
  }
  /* The latest-state icon and the abandoned icon sit side by side in a centred cell; without a
     gap the two glyphs read as one. */
  .latest-tip-wrap + .latest-tip-wrap { margin-left: 8px; }
  /* Instant hover tooltip, fixed to the viewport (positioned from the script) so it opens below
     its icon, clear of the table's scroll clipping and above the sticky topbar. */
  .latest-tip-bubble {
    position: fixed;
    transform: translateX(-50%);
    z-index: 45;
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
    pointer-events: none;
  }
  .name-cell { overflow-wrap: anywhere; }
  /* The floor is what stops the flexible column collapsing: with `overflow-wrap: anywhere` its
     minimum width is one character, so without it the fixed columns take the whole row at 1024
     and the purl wraps one glyph per line rather than the table scrolling. */
  .purl-cell { font-size: 12px; color: var(--text2); overflow-wrap: anywhere; min-width: 160px; }
  .actions-cell { overflow: visible; width: 40px; }
  .row-actions { display: flex; justify-content: center; }
  .menu-check { color: var(--success); margin-right: 4px; vertical-align: middle; }
</style>
