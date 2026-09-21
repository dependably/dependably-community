<script>
  import { t } from 'svelte-i18n'
  import { api } from '../lib/api.js'
  import { currentOrg, user } from '../lib/store.js'
  import { reportPageLoad } from '../lib/pageLoad.js'
  import { formatBytes, formatDate } from '../lib/format.js'
  import { copyToClipboard } from '../lib/clipboard.js'
  import { readQuery, writeQuery } from '../lib/tableState.js'
  import { ECO_LABEL } from '../lib/ecosystems.js'
  import Breadcrumbs from '../lib/Breadcrumbs.svelte'
  import DataTable from '../lib/DataTable.svelte'
  import ErrorBanner from '../lib/ErrorBanner.svelte'
  import Pagination from '../lib/Pagination.svelte'
  import RiskPillars from '../lib/RiskPillars.svelte'
  import SbomExportDialog from '../lib/SbomExportDialog.svelte'
  import SearchInput from '../lib/SearchInput.svelte'
  import Toggle from '../lib/Toggle.svelte'
  import SbomUploadModal from '../lib/sbom/SbomUploadModal.svelte'
  import ComponentAdvisoryPanel from '../lib/sbom/ComponentAdvisoryPanel.svelte'
  import SbomConformancePanel from '../lib/sbom/SbomConformancePanel.svelte'
  import VexAnalysisEditor from '../lib/sbom/VexAnalysisEditor.svelte'
  import {
    DEFAULT_TABLE_STATE,
    REACHABILITIES,
    SCOPE_CHIPS,
    SEVERITIES,
    analysisQuery,
    blindSpotNote,
    dependencyScopeBadge,
    excludedByScopeNote,
    exportFilename,
    isBlocklisted,
    licenseBreakdown,
    licenseList,
    licenseRollupSignal,
    mergeAnalysisRow,
    policySignal,
    priorityBreakdown,
    reachBadge,
    registryChips,
    rowPriority,
    rowReach,
    sbomScopeBadge,
    severityChips,
    shortSha,
    suppressedCount,
    uncoordinatedNote,
    unscannableNote,
    worstSeverity,
  } from '../lib/sbom/analysis.js'

  /**
   * Route params supplied by RouteView: `id` is the project GUID and `versionId` the project
   * version GUID, or the literal `latest`, which the server resolves against `is_latest`.
   * Read as a prop rather than from the route store because a deferred navigation mounts this
   * page while the store still names the page being left.
   * @type {Record<string, any>}
   */
  export let params = {}

  /** The route transition this page was mounted for, supplied by RouteView. @type {number | null} */
  export let pageToken = null

  /**
   * The shared SBOM upload modal, passed in as a component constructor so this page can offer
   * an upload entry point without owning the modal. Left null, the page renders no upload
   * button — the API token path is the CI mainline and stands on its own.
   * @type {any}
   */

  // Table state lives in the URL query string so filters, sort and page survive expanding a
  // row, navigating into a package and back, a reload, and a copied link.
  const DEFAULTS = DEFAULT_TABLE_STATE
  const init = readQuery(DEFAULTS)

  let search = init.q
  let scope = init.scope
  let severity = init.sev
  let reach = init.reach
  let registryFilter = init.registry
  let violationsOnly = init.violations === 'true'
  let showSuppressed = init.suppressed === 'true'
  let page = init.page, limit = init.limit
  let sortCol = init.sort, sortDir = init.dir

  let project = null
  let versionLabel = ''
  let items = [], rollup = null, orphans = [], total = 0
  let loading = true, error = ''
  let documents = [], documentsError = ''
  let licenseBlocklist = new Set()
  let expandedId = null
  let exportOpen = false
  let exportBusy = false
  let exportError = ''
  let copiedKey = ''
  // `savingKey` is the advisory whose PUT is in flight; `saveErrorKey` is the advisory a
  // failed save belongs to. They are separate because the in-flight key clears in `finally`,
  // and an error tied to it would clear with it before the operator could read it.
  let savingKey = '', saveErrorKey = '', saveError = '', saveToken = 0
  let uploadOpen = false
  let rescanning = false, rescanError = '', rescanRetryAfterMs = 0
  let expandedOrphanKey = null

  // Request sequence — a filter change can fire a second load while the first is in flight; a
  // response whose token is stale must not overwrite newer state.
  let seq = 0

  $: org = $currentOrg
  $: projectId = params.id ?? params.projectId ?? ''
  $: versionId = params.versionId ?? 'latest'
  $: isAdmin = $user?.role === 'admin' || $user?.role === 'owner'
  $: reportPageLoad(pageToken, loading)

  function sync() {
    writeQuery({
      q: search,
      scope,
      sev: severity,
      reach,
      registry: registryFilter,
      violations: violationsOnly ? 'true' : '',
      suppressed: showSuppressed ? 'true' : '',
      page,
      limit,
      sort: sortCol,
      dir: sortDir,
    }, DEFAULTS)
  }

  function tableState() {
    return {
      q: search,
      scope,
      sev: severity,
      reach,
      registry: registryFilter,
      violations: violationsOnly ? 'true' : '',
      suppressed: showSuppressed ? 'true' : '',
      page,
      limit,
      sort: sortCol,
      dir: sortDir,
    }
  }

  /**
   * Fetch the analysis page. `quiet` refreshes in place after a triage save: the rows already on
   * screen stay rendered while the request is out, so the table neither collapses to a shimmer
   * nor loses the expanded row.
   */
  async function load(quiet = false) {
    if (!org || !projectId) return
    const mine = ++seq
    if (!quiet) loading = true
    error = ''
    try {
      const data = await api.getProjectVersionAnalysis(projectId, versionId, analysisQuery(tableState()))
      if (mine !== seq) return
      items = data.items ?? []
      rollup = data.rollup ?? null
      orphans = data.orphanAnalysis ?? []
      total = data.total ?? items.length
    } catch (e) {
      if (mine !== seq) return
      error = e.message
    } finally {
      if (mine === seq && !quiet) loading = false
    }
  }

  // The analysis payload describes the components, not the project — the header, the export
  // filenames and the "latest" alias all need the project's own record.
  async function loadProject() {
    if (!org || !projectId) return
    try {
      project = await api.getProject(projectId)
      const versions = project?.versions ?? []
      const match = versionId === 'latest'
        ? versions.find(v => v.isLatest)
        : versions.find(v => v.id === versionId)
      versionLabel = match?.version ?? ''
    } catch (e) {
      error = e.message
    }
  }

  // Supplemental: the documents card is a receipts list, and a failure to read it must not take
  // the analysis down with it.
  async function loadDocuments() {
    if (!org || !projectId) return
    documentsError = ''
    try {
      const data = await api.listProjectVersionDocuments(projectId, versionId)
      documents = data.items ?? []
    } catch (e) {
      documents = []
      documentsError = e.message
    }
  }

  // The org's own licence blocklist, for the licence column and the License pillar. The
  // analysis payload carries the policy verdict per advisory, not per licence string.
  async function loadLicensePolicy() {
    try {
      const policy = await api.getLicensePolicy()
      licenseBlocklist = new Set((policy.blocklist || []).map(e => (e.licenseSpdx ?? '').toUpperCase()))
    } catch { licenseBlocklist = new Set() }
  }

  // `versionId` is named in both statements on purpose: it is what changes when a reader moves
  // between two versions of the same project, and a statement that does not reference it would
  // keep showing the version it first mounted with.
  $: if (org && projectId && versionId) {
    loadProject()
    loadDocuments()
    loadLicensePolicy()
  }
  $: if (org && projectId && versionId) load()

  // Projects / <containing folders> / <project> / <version>. The project crumb is this page's way
  // back to the versions table — landing here from a deep link means there is no history entry to
  // go back to, so an up-trail is the only affordance that always works.
  $: crumbs = [
    { label: $t('projects.title'), page: 'projects' },
    ...(project?.ancestors ?? []).map((a) => ({
      label: a.name, page: 'project-detail', params: { id: a.id },
    })),
    { label: project?.name ?? '', page: 'project-detail', params: { id: projectId } },
    { label: versionLabel || $t('projects.detail.isLatest') },
  ]

  function reload() { page = 1; sync(); load() }
  function onPageChange(e) { page = e.detail.page; sync(); load() }
  function onLimitChange(e) { limit = e.detail.limit; page = 1; sync(); load() }
  function onSortChange(e) { sortCol = e.detail.col; sortDir = e.detail.dir; page = 1; sync(); load() }
  function setScope(value) { scope = value; reload() }
  function setSeverity(value) { severity = value; reload() }

  function toggleRow(item) {
    expandedId = expandedId === item.componentId ? null : item.componentId
  }

  function toggleOrphan(key) {
    expandedOrphanKey = expandedOrphanKey === key ? null : key
  }

  // On-demand component rescan, mirroring VersionTable's package-plane pattern: a 1-hour
  // server-enforced cooldown reported back as 429 + Retry-After, read off ApiError.retryAfter
  // rather than guessed at client side.
  async function rescan() {
    rescanning = true
    rescanError = ''
    try {
      await api.rescanProjectVersion(projectId, versionId)
      await load(true)
    } catch (e) {
      rescanError = e.message
      rescanRetryAfterMs = e.retryAfter ? Number(e.retryAfter) * 1000 : 0
    } finally {
      rescanning = false
    }
  }

  async function copy(key, text) {
    const ok = await copyToClipboard(text)
    copiedKey = ok ? key : ''
    setTimeout(() => { if (copiedKey === key) copiedKey = '' }, 2000)
  }

  function showViolationsOnly() {
    violationsOnly = true
    reload()
  }

  // The blind-spot count is a control, not a readout: the number is only useful if the operator
  // can immediately see which components it names. Clicking it a second time clears the filter.
  function toggleBlindSpotFilter() {
    registryFilter = registryFilter === 'absent' ? '' : 'absent'
    reload()
  }

  function toggleUncoordinatedFilter() {
    registryFilter = registryFilter === 'unknown' ? '' : 'unknown'
    reload()
  }

  // ── Export dialog (normalized re-renders) ────────────────────────────────────
  // Distinct from the documents card below, which serves the verbatim uploads back. The dialog
  // renders the version's current state into a fresh CycloneDX document under the chosen options;
  // the card hands back the exact bytes someone uploaded, digest and all.
  async function runExport(e) {
    const { variant, format, specVersion, scope } = e.detail
    exportBusy = true
    exportError = ''
    try {
      const name = exportFilename(
        project?.name ?? 'project', versionLabel || versionId, variant, { specVersion, scope })
      if (variant === 'vex') await api.exportProjectVersionVex(projectId, versionId, specVersion, name)
      else await api.exportProjectVersionSbom(projectId, versionId, { variant, format, specVersion, scope }, name)
      exportOpen = false
    } catch (err) {
      exportError = err.message
    } finally {
      exportBusy = false
    }
  }

  async function downloadOriginal(doc) {
    exportError = ''
    try {
      await api.downloadProjectDocument(doc.id, doc.fileName ?? `${doc.docType}-${shortSha(doc.sha256)}.json`)
    } catch (e) {
      exportError = e.message
    }
  }

  function closeExport() {
    if (exportBusy) return
    exportOpen = false
  }

  // ── Triage ──────────────────────────────────────────────────────────────────
  // The PUT answers with the refreshed analysis row, which is overlaid on the advisory already
  // rendered so the priority badge and the state flip immediately. The rollup counts are the
  // server's to compute, so a quiet refetch follows and swaps them in without a page reload.
  async function saveTriage(e) {
    const { purlKey, vulnKey, body } = e.detail
    savingKey = vulnKey
    saveErrorKey = ''
    saveError = ''
    try {
      const refreshed = await api.putProjectVersionAnalysis(projectId, versionId, body)
      items = items.map(item => {
        if ((item.purlKey ?? item.purl) !== purlKey) return item
        return {
          ...item,
          advisories: (item.advisories ?? []).map(a =>
            a.vulnKey === vulnKey ? mergeAnalysisRow(a, refreshed) : a),
        }
      })
      saveToken += 1
      await load(true)
    } catch (err) {
      saveErrorKey = vulnKey
      saveError = err.message
    } finally {
      savingKey = ''
    }
  }

  // ── Header signals ──────────────────────────────────────────────────────────
  $: policy = policySignal(rollup)
  $: worst = worstSeverity(rollup)
  // Null at zero: nothing unscannable renders nothing, never a reassuring zero-count badge.
  $: unscannable = unscannableNote(rollup)
  // Components this registry has never served, and — reported separately, never folded in —
  // components carrying no coordinate the registry could be asked about. Both null at zero.
  $: blindSpot = blindSpotNote(rollup)
  $: uncoordinated = uncoordinatedNote(rollup)
  // Components the SBOM's own producer marked excluded from the build. Null at zero.
  $: excludedByScope = excludedByScopeNote(rollup)
  // The version-wide priority tally for the ribbon — always four entries, server-computed.
  $: priorities = priorityBreakdown(rollup)
  // Licences flagged: undeclared, or on the org blocklist — read off the rollup, which counts
  // the whole version rather than the page currently on screen.
  $: licenseSignal = licenseRollupSignal(rollup, licenseBlocklist)
  $: licenseTop = licenseBreakdown(rollup, 5)
  $: pillars = [
    {
      key: 'security',
      label: $t('sbomAnalysis.pillars.security'),
      // 'unscored' is its own bucket, rendered through the unknown-severity chip rather than
      // as a severity nobody assigned.
      sev: worst === 'unscored' ? 'unknown' : worst,
      text: worst ? (worst === 'unscored' ? $t('sbomAnalysis.panel.unscored') : worst) : $t('sbomAnalysis.pillars.noAdvisories'),
      tone: worst ? '' : 'clean',
    },
    {
      key: 'license',
      label: $t('sbomAnalysis.pillars.license'),
      text: licenseSignal.flagged > 0
        ? $t('sbomAnalysis.pillars.licenseFlagged', { values: { count: licenseSignal.flagged } })
        : $t('sbomAnalysis.pillars.licenseClean'),
      // A free breakdown off the rollup's already-sorted per-identifier tally — data, not a
      // translated sentence, so only the label prefix goes through the catalogue.
      title: licenseTop.length
        ? `${$t('sbomAnalysis.pillars.licenseBreakdown')}: ${licenseTop.map(l => `${l.identifier} (${l.count})`).join(', ')}`
        : undefined,
      tone: licenseSignal.flagged > 0 ? 'warn' : 'clean',
    },
    {
      key: 'policy',
      label: $t('sbomAnalysis.pillars.policy'),
      text: policy.status === 'violation'
        ? $t('sbomAnalysis.policy.violations', { values: { count: policy.count } })
        : $t(`sbomAnalysis.policy.${policy.status}`),
      tone: policy.tone,
    },
  ]

  // Server sorts and pages; DataTable's local sort is neutralized so its header UI keeps
  // working without reordering the page the server already ordered.
  // Column keys double as the API's `sort` values — the server rejects anything outside its
  // own set, so a header key that drifts from it 422s the whole table rather than sorting it.
  const NOOP_CMP = () => 0
  const comparators = {
    name: NOOP_CMP, version: NOOP_CMP, scope: NOOP_CMP, sbomScope: NOOP_CMP, dep: NOOP_CMP,
    licenses: NOOP_CMP, severity: NOOP_CMP, priority: NOOP_CMP, reach: NOOP_CMP,
  }
  // Dependency scope and document-declared scope stay two columns with two sort keys: folding
  // them would make a component the SBOM excluded indistinguishable from a dev dependency. The
  // component type is a classification, not a verdict, so it rides under the component name as
  // a chip rather than taking a column. Priority is the row's verdict and always shows; reach
  // leaves the table below 1440px (the width at which every fixed column fits beside an expanded
  // sidebar) because the expanded advisory panel repeats it, so nothing is lost on a laptop.
  $: columns = [
    { key: 'name',      label: $t('sbomAnalysis.columns.component'),   sortable: true,  width: '180px' },
    { key: 'version',   label: $t('sbomAnalysis.columns.version'),     sortable: true,  width: '140px' },
    { key: 'scope',     label: $t('sbomAnalysis.columns.dependency'),  sortable: true,  width: '110px' },
    { key: 'sbomScope', label: $t('sbomAnalysis.columns.scope'),       sortable: true,  width: '110px' },
    { key: 'dep',       label: $t('sbomAnalysis.columns.dep'),         sortable: true,  width: '90px' },
    { key: 'licenses',  label: $t('sbomAnalysis.columns.licenses'),    sortable: true,  width: '140px' },
    { key: 'severity',  label: $t('sbomAnalysis.columns.vulns'),       sortable: true,  width: '130px', defaultDir: 'desc' },
    { key: 'priority',  label: $t('sbomAnalysis.columns.priority'),    sortable: true,  width: '100px', defaultDir: 'desc' },
    { key: 'reach',     label: $t('sbomAnalysis.columns.reach'),       sortable: true,  width: '120px', hideBelow: 1440 },
  ]
</script>

<div class="page">
  <div class="page-header">
    <div class="header-id-block">
      <Breadcrumbs {crumbs} ariaLabel={$t('projects.breadcrumb')} />
      <div class="header-id">
        <h1 class="page-title">{project?.name ?? $t('sbomAnalysis.title')}</h1>
        {#if versionLabel}<span class="badge version-badge mono">{versionLabel}</span>{/if}
      </div>
    </div>
    <div class="header-actions">
      <button type="button" data-testid="export" on:click={() => { exportError = ''; exportOpen = true }}>
        <svg width="13" height="13" aria-hidden="true"><use href="/icons.svg#icon-download"/></svg>
        {$t('sbomAnalysis.export.button')}
      </button>
      {#if isAdmin}
        <button type="button" class="primary" data-testid="upload" on:click={() => uploadOpen = true}>
          <svg width="13" height="13" aria-hidden="true"><use href="/icons.svg#icon-upload"/></svg>
          {$t('sbomUpload.button')}
        </button>
      {/if}
    </div>
  </div>

  <SbomExportDialog
    open={exportOpen}
    surface="version"
    busy={exportBusy}
    on:export={runExport}
    on:close={closeExport}
  />

  <div class="title-row">
    <!-- The ribbon is a control only when it has somewhere to take you: with violations it
         applies the violations-only filter, and without them it is a status readout, not a
         dead button the browser greys out. -->
    {#if policy.status === 'violation'}
      <button type="button" class="ribbon hot" on:click={showViolationsOnly}>
        <span class="dot" aria-hidden="true"></span>
        <span class="label">{$t('sbomAnalysis.policy.violations', { values: { count: policy.count } })}</span>
        {#if rollup}
          <span class="splits">
            <span class="split"><b>{rollup.componentTotal ?? 0}</b> {$t('sbomAnalysis.rollup.components')}</span>
            <span class="split"><b>{rollup.prodCount ?? 0}</b> {$t('sbomAnalysis.rollup.prod')}</span>
            <span class="split"><b>{rollup.devCount ?? 0}</b> {$t('sbomAnalysis.rollup.dev')}</span>
            <span class="split"><b>{rollup.unknownScopeCount ?? 0}</b> {$t('sbomAnalysis.rollup.unknownScope')}</span>
            {#each priorities as p (p.key)}
              <span class="split prio-split"><b class="prio-{p.key}">{p.count}</b> {$t(p.labelKey)}</span>
            {/each}
            {#if unscannable}
              <span class="split" title={$t(unscannable.titleKey)}><b>{unscannable.count}</b> {$t(unscannable.labelKey)}</span>
            {/if}
            {#if excludedByScope}
              <span class="split excluded-by-scope-split" title={$t(excludedByScope.titleKey)}><b>{excludedByScope.count}</b> {$t(excludedByScope.labelKey)}</span>
            {/if}
          </span>
        {/if}
      </button>
    {:else}
      <span class="ribbon ribbon-static">
        <span class="dot" aria-hidden="true"></span>
        <span class="label">{$t(`sbomAnalysis.policy.ribbon.${policy.status}`)}</span>
        {#if rollup}
          <span class="splits">
            <span class="split"><b>{rollup.componentTotal ?? 0}</b> {$t('sbomAnalysis.rollup.components')}</span>
            <span class="split"><b>{rollup.prodCount ?? 0}</b> {$t('sbomAnalysis.rollup.prod')}</span>
            <span class="split"><b>{rollup.devCount ?? 0}</b> {$t('sbomAnalysis.rollup.dev')}</span>
            <span class="split"><b>{rollup.unknownScopeCount ?? 0}</b> {$t('sbomAnalysis.rollup.unknownScope')}</span>
            {#each priorities as p (p.key)}
              <span class="split prio-split"><b class="prio-{p.key}">{p.count}</b> {$t(p.labelKey)}</span>
            {/each}
            {#if unscannable}
              <span class="split" title={$t(unscannable.titleKey)}><b>{unscannable.count}</b> {$t(unscannable.labelKey)}</span>
            {/if}
            {#if excludedByScope}
              <span class="split excluded-by-scope-split" title={$t(excludedByScope.titleKey)}><b>{excludedByScope.count}</b> {$t(excludedByScope.labelKey)}</span>
            {/if}
          </span>
        {/if}
      </span>
    {/if}
    {#if rollup?.lastScanAt}
      <span class="text-muted t-sm">{$t('sbomAnalysis.rollup.lastScan', { values: { at: $formatDate(rollup.lastScanAt) } })}</span>
    {:else}
      <span class="text-muted t-sm">{$t('sbomAnalysis.rollup.neverScanned')}</span>
    {/if}
    {#if isAdmin}
      <button
        type="button"
        class="rescan-btn"
        disabled={rescanning}
        title={$t('sbomAnalysis.rescan.title')}
        on:click={rescan}
      >{rescanning ? $t('sbomAnalysis.rescan.scanning') : $t('sbomAnalysis.rescan.button')}</button>
    {/if}
  </div>
  {#if rescanError}
    <ErrorBanner message={rescanRetryAfterMs > 0
      ? $t('sbomAnalysis.rescan.cooldown', { values: { minutes: Math.ceil(rescanRetryAfterMs / 60000) } })
      : rescanError} />
  {/if}

  <!-- Registry coverage. Rendered only when there is something to report: nothing unvetted
       renders no affordance at all, never a reassuring zero. Each count is a filter, because a
       number an operator cannot open is a number they cannot act on. -->
  {#if blindSpot || uncoordinated}
    <div class="coverage-row">
      {#if blindSpot}
        <button
          type="button"
          class="coverage-chip warn"
          class:active={registryFilter === 'absent'}
          title={$t(blindSpot.titleKey)}
          aria-pressed={registryFilter === 'absent'}
          on:click={toggleBlindSpotFilter}
        >
          <svg width="12" height="12" aria-hidden="true"><use href="/icons.svg#icon-alert"/></svg>
          <b>{blindSpot.count}</b> {$t(blindSpot.labelKey)}
        </button>
      {/if}
      {#if uncoordinated}
        <button
          type="button"
          class="coverage-chip"
          class:active={registryFilter === 'unknown'}
          title={$t(uncoordinated.titleKey)}
          aria-pressed={registryFilter === 'unknown'}
          on:click={toggleUncoordinatedFilter}
        >
          <b>{uncoordinated.count}</b> {$t(uncoordinated.labelKey)}
        </button>
      {/if}
    </div>
  {/if}

  <RiskPillars {loading} {pillars} />

  <div class="page-toolbar">
    <SearchInput
      placeholder={$t('sbomAnalysis.searchPlaceholder')}
      bind:value={search}
      on:search={reload}
      class="toolbar-search"
    />

    <div class="sev-filter" role="group" aria-label={$t('sbomAnalysis.scopeFilter.label')}>
      {#each SCOPE_CHIPS as chip (chip)}
        <button
          type="button"
          class="sev-chip"
          class:active={scope === chip}
          on:click={() => setScope(chip)}
        >{$t(`sbomAnalysis.scopeFilter.${chip || 'all'}`)}</button>
      {/each}
    </div>

    <div class="sev-filter" role="group" aria-label={$t('sbomAnalysis.severityFilter.label')}>
      <button type="button" class="sev-chip" class:active={severity === ''} on:click={() => setSeverity('')}>
        {$t('sbomAnalysis.severityFilter.all')}
      </button>
      {#each SEVERITIES as s (s)}
        <button type="button" class="sev-chip" class:active={severity === s} on:click={() => setSeverity(s)}>
          <span class="sev-dot sev-{s}" aria-hidden="true"></span>{$t(`sbomAnalysis.severityFilter.${s}`)}
        </button>
      {/each}
    </div>

    <select bind:value={reach} on:change={reload} class="w-auto" aria-label={$t('sbomAnalysis.reachFilter.label')}>
      <option value="">{$t('sbomAnalysis.reachFilter.all')}</option>
      {#each REACHABILITIES as r (r)}
        <option value={r}>{$t(`sbomAnalysis.reach.${r}`)}</option>
      {/each}
    </select>

    <span class="filter-toggle">
      <Toggle bind:checked={violationsOnly} on:change={reload} ariaLabel={$t('sbomAnalysis.violationsOnly')} />
      {$t('sbomAnalysis.violationsOnly')}
    </span>

    <span class="filter-toggle">
      <Toggle bind:checked={showSuppressed} on:change={reload} ariaLabel={$t('sbomAnalysis.showSuppressed')} />
      {$t('sbomAnalysis.showSuppressed')}
    </span>
  </div>

  <ErrorBanner message={error} />
  {#if exportError}<ErrorBanner message={exportError} />{/if}

  <DataTable
    {columns}
    rows={items}
    {comparators}
    {loading}
    loadingRows={limit}
    loadingRowHeight="44px"
    memoryKey="sbom-components"
    initialSort={{ key: sortCol, dir: sortDir }}
    emptyText={$t('sbomAnalysis.empty')}
    on:sortchange={onSortChange}
    let:row={item}
    let:hidden={hiddenCols}
  >
    {@const depBadge = dependencyScopeBadge(item)}
    {@const sbomBadge = sbomScopeBadge(item)}
    {@const chips = severityChips(item, showSuppressed)}
    {@const prio = rowPriority(item, showSuppressed)}
    {@const reachValue = reachBadge(rowReach(item, showSuppressed))}
    {@const licenses = licenseList(item)}
    {@const hidden = suppressedCount(item)}
    {@const regChips = registryChips(item)}
    <tr
      class="component-row cursor-pointer"
      class:expanded-row={expandedId === item.componentId}
      on:click={() => toggleRow(item)}
    >
      <td class="name-cell">
        <div class="stacked">
          <span class="mono comp-name" title={item.name}>{item.name}</span>
          {#if item.ecosystem || item.componentType}
            <span class="name-chips">
              {#if item.ecosystem}
                <span class="badge {item.ecosystem}">{ECO_LABEL[item.ecosystem] ?? item.ecosystem}</span>
              {/if}
              {#if item.componentType}
                <span class="badge type-chip" title={$t('sbomAnalysis.columns.type')}>{item.componentType}</span>
              {/if}
            </span>
          {/if}
        </div>
      </td>
      <td class="version-cell">
        <span class="mono nowrap">{item.version ?? '—'}</span>
        <!-- What this registry already knows about the coordinate. Every verdict is the
             server's; the row picks a class and a locale key. -->
        {#if regChips.length}
          <span class="registry-chips">
            {#each regChips as c (c.key)}
              <span class="badge {c.cls}" title={$t(c.titleKey, { values: c.values ?? {} })}>
                {$t(c.labelKey, { values: c.values ?? {} })}
              </span>
            {/each}
          </span>
        {:else if item.registry?.presence === 'absent'}
          <span class="registry-chips">
            <span class="badge registry-absent" title={$t('sbomAnalysis.registry.notInRegistryHelp')}>
              {$t('sbomAnalysis.registry.notInRegistry')}
            </span>
          </span>
        {/if}
      </td>
      <td class="scope-cell">
        <span class="badge {depBadge.cls}" title={$t(depBadge.titleKey)} aria-label={$t(depBadge.labelKey)}>{$t(depBadge.labelKey)}</span>
      </td>
      <td class="scope-cell">
        {#if sbomBadge}
          <span class="badge {sbomBadge.cls}" title={$t(sbomBadge.titleKey)} aria-label={$t(sbomBadge.labelKey)}>{$t(sbomBadge.labelKey)}</span>
        {:else}
          <span class="text-muted">—</span>
        {/if}
      </td>
      <td class="text-muted t-sm nowrap">
        <!-- Only the two kinds the schema constrains are translated; any other value the
             payload grows renders verbatim rather than as a raw locale key. -->
        {#if item.dependencyKind === 'direct' || item.dependencyKind === 'transitive'}
          {$t(`sbomAnalysis.dependencyKind.${item.dependencyKind}`)}
        {:else if item.dependencyKind}
          {item.dependencyKind}
        {:else}
          &#8212;
        {/if}
      </td>
      <td class="license-cell">
        {#if licenses.length === 0}
          <span class="text-muted" title={$t('sbomAnalysis.licenseUndeclaredHelp')}>{$t('sbomAnalysis.licenseUndeclared')}</span>
        {:else}
          {#each licenses as l (l)}
            <span class="mono license" class:blocked={isBlocklisted(l, licenseBlocklist)}>{l}</span>
          {/each}
        {/if}
      </td>
      <td class="vuln-cell">
        {#if chips.critical > 0}<span class="sev sev-critical" aria-label="{chips.critical} critical">{chips.critical}</span>{/if}
        {#if chips.high > 0}<span class="sev sev-high" aria-label="{chips.high} high">{chips.high}</span>{/if}
        {#if chips.medium > 0}<span class="sev sev-medium" aria-label="{chips.medium} medium">{chips.medium}</span>{/if}
        {#if chips.low > 0}<span class="sev sev-low" aria-label="{chips.low} low">{chips.low}</span>{/if}
        {#if chips.unscored > 0}
          <span class="sev sev-unknown" title={$t('sbomAnalysis.panel.unscoredHelp')} aria-label="{chips.unscored} {$t('sbomAnalysis.panel.unscored')}">{chips.unscored}</span>
        {/if}
        {#if chips.critical + chips.high + chips.medium + chips.low + chips.unscored === 0}
          <span class="text-muted" aria-label={$t('sbomAnalysis.noAdvisories')}>—</span>
        {/if}
        {#if !showSuppressed && hidden > 0}
          <span class="hidden-count" title={$t('sbomAnalysis.suppressedHidden', { values: { count: hidden } })}>+{hidden}</span>
        {/if}
      </td>
      <td class="nowrap">
        {#if prio}
          <span class="badge prio-{prio}" title={$t('sbomAnalysis.priority.help')} aria-label={$t(`sbomAnalysis.priority.${prio}`)}>
            {$t(`sbomAnalysis.priority.${prio}`)}
          </span>
        {:else}
          <span class="text-muted" aria-label={$t('sbomAnalysis.priority.none')}>—</span>
        {/if}
      </td>
      {#if !hiddenCols.has('reach')}
        <td class="nowrap">
          {#if reachValue}
            <span class="badge {reachValue.cls}" aria-label={reachValue.labelKey ? $t(reachValue.labelKey) : reachValue.raw}>
              {reachValue.labelKey ? $t(reachValue.labelKey) : reachValue.raw}
            </span>
          {:else}
            <span class="text-muted" title={$t('sbomAnalysis.panel.noReachabilityHelp')} aria-label={$t('sbomAnalysis.panel.noReachabilityHelp')}>—</span>
          {/if}
        </td>
      {/if}
    </tr>

    {#if expandedId === item.componentId}
      <tr class="detail-row">
        <td colspan={columns.length - hiddenCols.size}>
          <div class="detail-panel">
            <ComponentAdvisoryPanel
              {item}
              {showSuppressed}
              {savingKey}
              {saveErrorKey}
              {saveError}
              {saveToken}
              canEdit={isAdmin}
              on:save={saveTriage}
            />
          </div>
        </td>
      </tr>
    {/if}
  </DataTable>

  <Pagination {total} {page} {limit} on:pagechange={onPageChange} on:limitchange={onLimitChange} />

  {#if orphans.length > 0}
    <!-- Analysis rows whose PURL matched no component in this version's SBOM: a VEX statement
         or a SARIF result about something the SBOM does not list. Surfaced rather than dropped —
         a statement nobody can see is a statement nobody can correct. -->
    <div class="card orphan-card">
      <h2 class="card-title">{$t('sbomAnalysis.orphans.title')}</h2>
      <p class="form-hint">{$t('sbomAnalysis.orphans.help')}</p>
      <table class="table-auto">
        <thead>
          <tr>
            <th>{$t('sbomAnalysis.orphans.purlKey')}</th>
            <th>{$t('sbomAnalysis.orphans.vulnKey')}</th>
            <th>{$t('sbomAnalysis.vex.title')}</th>
            <th>{$t('sbomAnalysis.columns.reach')}</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {#each orphans as o, oi (o.purlKey + '::' + o.vulnKey + '::' + oi)}
            {@const oKey = o.purlKey + '::' + o.vulnKey + '::' + oi}
            {@const oReach = reachBadge(o.reachability)}
            <tr class="cursor-pointer" on:click={() => toggleOrphan(oKey)}>
              <td class="mono">{o.purlKey ?? '—'}</td>
              <td class="mono">{o.vulnKey ?? '—'}</td>
              <td>
                {#if o.vexState}
                  <span class="badge vex-{o.vexState}">{$t(`sbomAnalysis.vex.state.${o.vexState}`)}</span>
                {:else}
                  <span class="text-muted">{$t('sbomAnalysis.vex.noState')}</span>
                {/if}
                {#if o.inherited}
                  <span class="badge prio-track" title={$t('sbomAnalysis.panel.inheritedHelp')}>
                    {$t('sbomAnalysis.panel.inherited', { values: { at: $formatDate(o.vexUpdatedAt) } })}
                  </span>
                {/if}
              </td>
              <td>
                {#if oReach}
                  <span class="badge {oReach.cls}">{oReach.labelKey ? $t(oReach.labelKey) : oReach.raw}</span>
                {:else}
                  <span class="text-muted">—</span>
                {/if}
              </td>
              <td class="actions-cell">
                <button type="button" class="icon-btn" aria-label={$t('sbomAnalysis.orphans.detailsToggle')} on:click|stopPropagation={() => toggleOrphan(oKey)}>
                  <svg class="chev" class:open={expandedOrphanKey === oKey} width="12" height="12" aria-hidden="true"><use href="/icons.svg#icon-chevron-down"/></svg>
                </button>
              </td>
            </tr>
            {#if expandedOrphanKey === oKey}
              <tr class="detail-row">
                <td colspan="5">
                  <div class="detail-panel orphan-detail">
                    <div class="detail-meta">
                      {#if o.confidence}
                        <div class="meta-item">
                          <span class="detail-label">{$t('sbomAnalysis.panel.confidence')}</span>
                          <span class="detail-value mono">{o.confidence}</span>
                        </div>
                      {/if}
                      {#if o.securitySeverity !== null && o.securitySeverity !== undefined}
                        <div class="meta-item">
                          <span class="detail-label">{$t('sbomAnalysis.panel.securitySeverity')}</span>
                          <span class="detail-value mono">{o.securitySeverity}</span>
                        </div>
                      {/if}
                      {#if o.severityOrigin}
                        <div class="meta-item">
                          <span class="detail-label">{$t('sbomAnalysis.panel.severityOrigin')}</span>
                          <span class="detail-value">{o.severityOrigin}</span>
                        </div>
                      {/if}
                      {#if o.sarifSuppressed}
                        <div class="meta-item">
                          <span class="detail-label">{$t('sbomAnalysis.panel.sarifSuppressed')}</span>
                          <span class="detail-value">{$t('sbomAnalysis.panel.sarifSuppressedHelp')}</span>
                        </div>
                      {/if}
                    </div>
                    <VexAnalysisEditor
                      advisory={o}
                      purlKey={o.purlKey}
                      canEdit={isAdmin}
                      {saveToken}
                      saving={savingKey === o.vulnKey}
                      error={saveErrorKey === o.vulnKey ? saveError : ''}
                      on:save={(e) => saveTriage({ detail: { purlKey: o.purlKey, vulnKey: o.vulnKey, body: e.detail.body } })}
                    />
                  </div>
                </td>
              </tr>
            {/if}
          {/each}
        </tbody>
      </table>
    </div>
  {/if}

  <!-- Receipts: the documents exactly as they were uploaded, digest and all. Downloading one
       here returns those bytes; the Export menu above renders fresh documents instead. -->
  <div class="card documents-card">
    <h2 class="card-title">{$t('sbomAnalysis.documents.title')}</h2>
    <p class="form-hint">{$t('sbomAnalysis.documents.help')}</p>
    <ErrorBanner message={documentsError} />
    {#if documents.length === 0}
      <p class="text-muted">{$t('sbomAnalysis.documents.empty')}</p>
    {:else}
      <table class="table-auto">
        <thead>
          <tr>
            <th>{$t('sbomAnalysis.documents.type')}</th>
            <th>{$t('sbomAnalysis.documents.format')}</th>
            <th>{$t('sbomAnalysis.documents.tool')}</th>
            <th>{$t('sbomAnalysis.documents.digest')}</th>
            <th class="text-right">{$t('sbomAnalysis.documents.size')}</th>
            <th>{$t('sbomAnalysis.documents.uploaded')}</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {#each documents as doc (doc.id)}
            <tr>
              <td><span class="badge doc-{doc.docType}">{doc.docType}</span></td>
              <td class="text-muted t-sm">
                {doc.format ?? '—'}{doc.specVersion ? ` ${doc.specVersion}` : ''}
              </td>
              <td class="text-muted t-sm">
                {doc.toolName ?? '—'}{doc.toolVersion ? ` ${doc.toolVersion}` : ''}
              </td>
              <td class="digest-cell">
                <span class="mono t-sm" title={doc.sha256}>{shortSha(doc.sha256)}</span>
                <button
                  type="button"
                  class="copy-btn"
                  aria-label={$t('sbomAnalysis.documents.copyDigest')}
                  title={copiedKey === doc.id ? $t('common.actions.copied') : $t('sbomAnalysis.documents.copyDigest')}
                  on:click={() => copy(doc.id, doc.sha256)}
                >
                  <svg width="12" height="12" aria-hidden="true"><use href="/icons.svg#icon-{copiedKey === doc.id ? 'check' : 'copy'}"/></svg>
                </button>
              </td>
              <td class="text-right text-muted t-sm">{$formatBytes(doc.sizeBytes ?? 0)}</td>
              <td class="text-muted t-sm">
                {doc.uploadedAt ? $formatDate(doc.uploadedAt) : '—'}{doc.uploadedBy ? ` · ${doc.uploadedBy}` : ''}
              </td>
              <td class="actions-cell">
                <div class="row-actions">
                  <button
                    type="button"
                    class="icon-btn"
                    aria-label={$t('sbomAnalysis.documents.download')}
                    title={$t('sbomAnalysis.documents.download')}
                    on:click={() => downloadOriginal(doc)}
                  >
                    <svg width="14" height="14" aria-hidden="true"><use href="/icons.svg#icon-download"/></svg>
                  </button>
                </div>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
    {#if documents.some((d) => d.docType === 'sbom')}
      <SbomConformancePanel {projectId} {versionId} />
    {/if}
  </div>

  <!-- Guarded on `project`, not on `uploadOpen` alone: the modal reads its parent target once, at
       mount, so opening it before the detail payload resolves would freeze the folder at null and
       file the upload into the root scope. -->
  {#if uploadOpen && project}
    <SbomUploadModal
      presetProjectId={projectId}
      presetProjectName={project.name}
      presetParentId={project.parentId ?? null}
      presetParentName={project.ancestors?.at(-1)?.name ?? null}
      presetVersionLabel={versionLabel}
      on:close={() => { uploadOpen = false; loadDocuments(); load() }}
    />
  {/if}
</div>

<style>
  /* The trail stacks above the title; the title and its version badge stay on one line. */
  .header-id-block { min-width: 0; }
  .header-id { display: flex; align-items: center; gap: 10px; }
  .version-badge { font-size: 12px; }

  .title-row { flex-wrap: wrap; }
  .ribbon-static { cursor: default; }

  /* Priority splits in the header ribbon — read-only counts, colour-matched to the same
     priority badges the table and advisory panel use. There is no server-side priority filter,
     so these are never rendered as buttons. */
  .split.prio-split b.prio-act { color: var(--badge-prio-act-text); }
  .split.prio-split b.prio-attend { color: var(--badge-prio-attend-text); }
  .split.prio-split b.prio-track { color: var(--badge-prio-track-text); }
  .split.prio-split b.prio-suppressed { color: var(--badge-prio-suppressed-text); }

  .rescan-btn { min-height: 26px; padding: 2px 10px; font-size: 12px; }

  .chev { transform: rotate(-90deg); transition: transform 120ms ease; }
  .chev.open { transform: rotate(0deg); }
  .orphan-detail { display: flex; flex-direction: column; gap: 10px; padding: 10px 12px; }

  .filter-toggle {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-size: 13px;
    color: var(--text2);
  }

  .nowrap { white-space: nowrap; }
  .stacked { display: flex; flex-direction: column; gap: 3px; min-width: 0; align-items: flex-start; }
  .comp-name { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 100%; }
  .name-cell { overflow-wrap: anywhere; }
  .version-cell { font-size: 12px; }

  /* Registry cross-link chips. The "…, other version" variants are deliberately quieter than
     their exact-match siblings but never invisible: the condition is real, only its scope is
     wider than the row. */
  .registry-chips { display: flex; flex-wrap: wrap; gap: 4px; margin-top: 4px; }
  .badge.registry-blocked {
    background: var(--danger-bg);
    border: 1px solid var(--danger-border);
    color: var(--danger-text);
  }
  .badge.registry-blocked-other {
    background: var(--bg3);
    border: 1px solid var(--danger-border);
    color: var(--danger-text);
  }
  .badge.registry-deprecated,
  .badge.registry-outdated {
    background: var(--warning-bg);
    border: 1px solid var(--warning-border);
    color: var(--warning-text);
  }
  /* No native version ordering for this ecosystem — a statement of what is known, not a verdict,
     so it carries no risk colour at all. */
  .badge.registry-unknown,
  .badge.registry-absent {
    background: var(--bg3);
    border: 1px solid var(--border);
    color: var(--text2);
  }

  /* Registry-coverage controls. Each is a filter, so each is a real button. */
  .coverage-row { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
  .coverage-chip {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 2px 10px;
    min-height: 26px;
    font-size: 12px;
    border-radius: 999px;
    border: 1px solid var(--border);
    background: var(--bg2);
    color: var(--text2);
  }
  .coverage-chip b { color: var(--text); }
  .coverage-chip.warn {
    border-color: var(--warning-border);
    background: var(--warning-soft);
    color: var(--warning-text);
  }
  .coverage-chip.warn b { color: var(--warning-text); }
  .coverage-chip.active {
    border-color: var(--accent);
    background: var(--accent-soft);
  }
  .scope-cell { white-space: normal; }
  .name-chips { display: flex; flex-wrap: wrap; gap: 4px; }
  /* The raw CycloneDX component type (library, application, …) reads as a plain chip beside
     the ecosystem badge: a classification, not a verdict. */
  .type-chip { font-weight: 500; }
  .license-cell { overflow-wrap: anywhere; }
  .license { font-size: 12px; color: var(--text2); margin-right: 4px; }
  .license.blocked { color: var(--danger); font-weight: 600; }
  .vuln-cell { white-space: nowrap; }
  .hidden-count { color: var(--text2); font-size: 11px; margin-left: 4px; }

  /* Compact in-cell buttons: the global button min-height would balloon a table row. */
  .copy-btn, .icon-btn {
    min-height: 0;
    padding: 2px 5px;
    background: transparent;
    border: 1px solid transparent;
    color: var(--text2);
    cursor: pointer;
    line-height: 1;
  }
  .copy-btn:hover, .icon-btn:hover { background: var(--bg3); color: var(--text); }

  /* Row actions live in their own wrapper — never `display: flex` on the <td>, which collapses
     table layout for the whole column. */
  .actions-cell { overflow: visible; width: 48px; }
  .row-actions { display: flex; justify-content: flex-end; }

  .component-row { cursor: pointer; }
  /* The tint is global; the panel cell itself carries no padding so the advisory panel runs
     edge to edge under the row that opened it. */
  .detail-row td { padding: 0; border-top: none; }

  .orphan-card, .documents-card { margin-top: 24px; }
  .card-title { font-size: 15px; font-weight: 700; margin: 0 0 4px; }
  .digest-cell { white-space: nowrap; }
</style>
