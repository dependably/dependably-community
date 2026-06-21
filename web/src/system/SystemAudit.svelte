<script>
  import { onMount } from 'svelte'
  import { t } from 'svelte-i18n'
  import { systemApi } from '../lib/api.js'
  import DataTable from '../lib/DataTable.svelte'
  import SearchInput from '../lib/SearchInput.svelte'
  import { readQuery, writeQuery } from '../lib/tableState.js'

  // Tab + filter state lives in the URL query string so it survives route changes,
  // reloads, and copied links. Events keys: q/action/page/limit; jobs keys: jq/job/out/jpage/jlimit.
  const DEFAULTS = { tab: 'events', q: '', action: '', page: 1, limit: 50, jq: '', job: '', out: '', jpage: 1, jlimit: 50 }
  const init = readQuery(DEFAULTS)

  function sync() {
    writeQuery({
      tab: activeTab,
      q: search, action: actionFilter, page, limit,
      jq: jobsSearch, job: jobNameFilter, out: outcomeFilter, jpage: jobsPage, jlimit: jobsLimit,
    }, DEFAULTS)
  }

  // ── Tabs ─────────────────────────────────────────────────────────────────
  let activeTab = init.tab                          // 'events' | 'jobs'
  let jobsLoaded = false                            // lazy-load on first selection

  function selectTab(tab) {
    activeTab = tab
    sync()
    if (tab === 'jobs' && !jobsLoaded) {
      jobsLoaded = true
      void loadJobs()
      void loadJobFacets()
    }
  }

  // ── Audit Events tab ─────────────────────────────────────────────────────
  let items = [], total = 0, loading = true, error = ''
  let page = init.page
  const limit = init.limit

  let search = init.q
  let actionFilter = init.action
  let sortBy = 'createdAt'
  let sortDir = 'desc'
  let actions = []                                  // distinct action values for the dropdown

  async function loadEvents() {
    loading = true
    error = ''
    try {
      const data = await systemApi.listAudit({
        page, limit,
        search: search || undefined,
        action: actionFilter || undefined,
        sortBy, sortDir,
      })
      items = data.items
      total = data.total
    } catch (e) { error = e.message }
    finally { loading = false }
  }

  async function loadActions() {
    try {
      const data = await systemApi.listSystemAuditActions()
      actions = data.actions ?? []
    } catch { /* dropdown is non-essential; leave empty on failure */ }
  }

  function onSearch() { page = 1; sync(); loadEvents() }

  function onFilterChange() { page = 1; sync(); loadEvents() }

  function onSortChangeEvents(e) {
    sortBy = e.detail.col
    sortDir = e.detail.dir
    page = 1
    sync()
    loadEvents()
  }

  function prev() { if (page > 1) { page--; sync(); loadEvents() } }
  function next() { if (page * limit < total) { page++; sync(); loadEvents() } }

  // ── Background Jobs tab ──────────────────────────────────────────────────
  let jobsItems = [], jobsTotal = 0, jobsLoading = false, jobsError = ''
  let jobsPage = init.jpage
  const jobsLimit = init.jlimit

  let jobsSearch = init.jq
  let jobNameFilter = init.job
  let outcomeFilter = init.out
  let jobsSortBy = 'startedAt'
  let jobsSortDir = 'desc'
  let jobNames = [], outcomes = []
  let expandedErrorId = null

  async function loadJobs() {
    jobsLoading = true
    jobsError = ''
    try {
      const data = await systemApi.listBackgroundJobs({
        page: jobsPage, limit: jobsLimit,
        search: jobsSearch || undefined,
        jobName: jobNameFilter || undefined,
        outcome: outcomeFilter || undefined,
        sortBy: jobsSortBy, sortDir: jobsSortDir,
      })
      jobsItems = data.items
      jobsTotal = data.total
    } catch (e) { jobsError = e.message }
    finally { jobsLoading = false }
  }

  async function loadJobFacets() {
    try {
      const data = await systemApi.getBackgroundJobFacets()
      jobNames = data.jobNames ?? []
      outcomes = data.outcomes ?? []
    } catch { /* non-essential */ }
  }

  function onJobsSearch() { jobsPage = 1; sync(); loadJobs() }

  function onJobsFilterChange() { jobsPage = 1; sync(); loadJobs() }

  function onSortChangeJobs(e) {
    jobsSortBy = e.detail.col
    jobsSortDir = e.detail.dir
    jobsPage = 1
    sync()
    loadJobs()
  }

  function jobsPrev() { if (jobsPage > 1) { jobsPage--; sync(); loadJobs() } }
  function jobsNext() { if (jobsPage * jobsLimit < jobsTotal) { jobsPage++; sync(); loadJobs() } }

  function toggleError(id) {
    expandedErrorId = expandedErrorId === id ? null : id
  }

  function fmtDuration(ms) {
    if (ms === null || ms === undefined) return '—'
    if (ms < 1000) return `${ms} ms`
    if (ms < 60_000) return `${(ms / 1000).toFixed(2)} s`
    const totalSeconds = Math.round(ms / 1000)
    const m = Math.floor(totalSeconds / 60)
    const s = totalSeconds % 60
    return `${m}m ${s}s`
  }

  // Audit detail is a JSON string in the common case; pretty-print so the column reads
  // top-to-bottom instead of wrapping a single line at every other character. Raw strings
  // (legacy rows, non-JSON payloads) fall through unchanged.
  function fmtDetail(raw) {
    if (!raw) return ''
    try {
      return JSON.stringify(JSON.parse(raw), null, 2)
    } catch {
      return raw
    }
  }

  // ── Init ─────────────────────────────────────────────────────────────────
  onMount(() => {
    loadEvents()
    loadActions()
    if (activeTab === 'jobs' && !jobsLoaded) {
      jobsLoaded = true
      void loadJobs()
      void loadJobFacets()
    }
  })

  // Server returns rows already sorted; comparators below are no-ops because the
  // DataTable's sortchange event re-queries the API and replaces the list.
  const NOOP = () => 0
  $: eventColumns = [
    { key: 'createdAt', label: $t('system.audit.columns.when'),   sortable: true, width: '180px' },
    { key: 'action',    label: $t('system.audit.columns.event'),  sortable: true, width: '200px' },
    { key: 'actorId',   label: $t('system.audit.columns.actor'),  sortable: false, width: '180px' },
    { key: 'orgId',     label: $t('system.audit.columns.tenant'), sortable: false, width: '160px' },
    { key: 'detail',    label: $t('system.audit.columns.detail'), sortable: false },
  ]
  const eventComparators = { createdAt: NOOP, action: NOOP }

  $: jobColumns = [
    { key: 'jobName',     label: $t('system.backgroundJobs.columns.jobName'),   sortable: true, width: '180px' },
    { key: 'startedAt',   label: $t('system.backgroundJobs.columns.startedAt'), sortable: true, width: '180px' },
    { key: 'durationMs',  label: $t('system.backgroundJobs.columns.duration'),  sortable: true, width: '120px' },
    { key: 'outcome',     label: $t('system.backgroundJobs.columns.outcome'),   sortable: true, width: '120px' },
    { key: 'errorMessage',label: $t('system.backgroundJobs.columns.error'),     sortable: false },
  ]
  const jobComparators = { jobName: NOOP, startedAt: NOOP, durationMs: NOOP, outcome: NOOP }
</script>

<div class="page">
  <h1>{$t('system.audit.title')}</h1>
  <p class="subtitle">{$t('system.audit.subtitle')}</p>

  <div class="tabs" role="tablist">
    <button class="tab" class:active={activeTab === 'events'}
            role="tab" aria-selected={activeTab === 'events'}
            on:click={() => selectTab('events')}>{$t('system.audit.tabs.events')}</button>
    <button class="tab" class:active={activeTab === 'jobs'}
            role="tab" aria-selected={activeTab === 'jobs'}
            on:click={() => selectTab('jobs')}>{$t('system.audit.tabs.backgroundJobs')}</button>
  </div>

  {#if activeTab === 'events'}
    {#if error}<div class="page-error">{error}</div>{/if}

    <div class="toolbar">
      <SearchInput
        class="table-search"
        placeholder={$t('system.audit.searchPlaceholder')}
        ariaLabel={$t('system.audit.searchPlaceholder')}
        bind:value={search}
        on:search={onSearch}
      />
      <select bind:value={actionFilter} on:change={onFilterChange} class="filter-select"
              aria-label={$t('system.audit.filterAction')}>
        <option value="">{$t('system.audit.filterAction')}</option>
        {#each actions as a (a)}
          <option value={a}>{a}</option>
        {/each}
      </select>
    </div>

    <DataTable
      columns={eventColumns}
      comparators={eventComparators}
      rows={items}
      {loading}
      initialSort={{ key: sortBy, dir: sortDir }}
      on:sortchange={onSortChangeEvents}
      emptyText={$t('system.audit.empty')}
      tableClass="table-auto audit-table"
      let:row={e}
    >
      <tr>
        <td>{new Date(e.createdAt).toLocaleString()}</td>
        <td><code>{e.action}</code></td>
        <td>{e.actorEmail ?? e.actorId ?? '—'}</td>
        <td>{e.orgSlug ?? (e.orgId ?? $t('system.audit.apexTenant'))}</td>
        <td><pre>{fmtDetail(e.detail)}</pre></td>
      </tr>
    </DataTable>

    <div class="pager">
      <button on:click={prev} disabled={page === 1}>{$t('system.audit.prev')}</button>
      <span>{$t('system.audit.pageInfo', { values: { page, total } })}</span>
      <button on:click={next} disabled={page * limit >= total}>{$t('system.audit.next')}</button>
    </div>
  {:else}
    {#if jobsError}<div class="page-error">{jobsError}</div>{/if}

    <div class="toolbar">
      <SearchInput
        class="table-search"
        placeholder={$t('system.backgroundJobs.searchPlaceholder')}
        ariaLabel={$t('system.backgroundJobs.searchPlaceholder')}
        bind:value={jobsSearch}
        on:search={onJobsSearch}
      />
      <select bind:value={jobNameFilter} on:change={onJobsFilterChange} class="filter-select"
              aria-label={$t('system.backgroundJobs.filterJob')}>
        <option value="">{$t('system.backgroundJobs.filterJob')}</option>
        {#each jobNames as name (name)}
          <option value={name}>{name}</option>
        {/each}
      </select>
      <select bind:value={outcomeFilter} on:change={onJobsFilterChange} class="filter-select"
              aria-label={$t('system.backgroundJobs.filterOutcome')}>
        <option value="">{$t('system.backgroundJobs.filterOutcome')}</option>
        {#each outcomes as o (o)}
          <option value={o}>{$t(`system.backgroundJobs.outcome.${o}`, { default: o })}</option>
        {/each}
      </select>
    </div>

    <DataTable
      columns={jobColumns}
      comparators={jobComparators}
      rows={jobsItems}
      loading={jobsLoading}
      initialSort={{ key: jobsSortBy, dir: jobsSortDir }}
      on:sortchange={onSortChangeJobs}
      emptyText={$t('system.backgroundJobs.empty')}
      tableClass="table-auto jobs-table"
      let:row={j}
    >
      <tr>
        <td><code>{j.jobName}</code></td>
        <td>{new Date(j.startedAt).toLocaleString()}</td>
        <td class="num">{fmtDuration(j.durationMs)}</td>
        <td><span class="outcome outcome-{j.outcome}">{$t(`system.backgroundJobs.outcome.${j.outcome}`, { default: j.outcome })}</span></td>
        <td>
          {#if j.errorMessage}
            <button type="button" class="error-toggle" on:click={() => toggleError(j.id)}>
              {expandedErrorId === j.id
                ? $t('system.backgroundJobs.viewError.hide')
                : $t('system.backgroundJobs.viewError.show')}
            </button>
            {#if expandedErrorId === j.id}
              <pre class="error-message">{j.errorMessage}</pre>
            {/if}
          {:else}
            —
          {/if}
        </td>
      </tr>
    </DataTable>

    <div class="pager">
      <button on:click={jobsPrev} disabled={jobsPage === 1}>{$t('system.audit.prev')}</button>
      <span>{$t('system.audit.pageInfo', { values: { page: jobsPage, total: jobsTotal } })}</span>
      <button on:click={jobsNext} disabled={jobsPage * jobsLimit >= jobsTotal}>{$t('system.audit.next')}</button>
    </div>
  {/if}
</div>

<style>
  /* Override the global 1100px page cap — the JSON detail column needs the breathing room. */
  .page { max-width: 1500px; }
  .subtitle { color: var(--text2); font-size: 13px; margin: 0 0 16px; }
  /* Toolbar proportions: the global `input, select, textarea { width: 100% }` rule makes flex
     children fight for the whole track. Search grows but is capped; selects size to their content. */
  .toolbar { display: flex; gap: 8px; margin-bottom: 12px; align-items: center; flex-wrap: wrap; }
  .toolbar :global(.table-search) {
    flex: 1 1 240px; min-width: 200px; max-width: 360px;
  }
  .toolbar :global(.table-search input) { font-size: 13px; }
  .filter-select {
    flex: 0 0 auto; width: auto; min-width: 200px;
    padding: 6px 10px;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    background: var(--bg);
    color: var(--text);
    font-size: 13px;
  }
  /* Pretty-printed JSON in Detail; give the column enough room before the cell starts wrapping. */
  pre { margin: 0; font-size: 12px; white-space: pre-wrap; word-break: break-word; max-width: 720px; }
  code { background: var(--bg); padding: 2px 6px; border-radius: 3px; font-size: 12px; }
  .num { text-align: right; font-variant-numeric: tabular-nums; }
  .pager { display: flex; gap: 12px; align-items: center; margin-top: 16px; }

  .outcome {
    display: inline-block;
    font-size: 11px;
    padding: 2px 8px;
    border-radius: 999px;
    border: 1px solid var(--border);
    background: var(--bg);
    text-transform: capitalize;
  }
  .outcome-success { color: var(--success); }
  .outcome-server_error { color: var(--danger); }
  .outcome-cancelled { color: var(--text2); }

  .error-toggle {
    background: transparent;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 2px 8px;
    font-size: 11px;
    color: var(--text2);
    cursor: pointer;
  }
  .error-toggle:hover { background: var(--bg3); color: var(--text); }
  .error-message {
    margin-top: 6px;
    padding: 6px 8px;
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    color: var(--danger);
    font-size: 12px;
  }
</style>
