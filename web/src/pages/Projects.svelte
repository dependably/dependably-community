<!--
  Projects list — root-level projects (parent == null) with per-row rollups from the list API.
  Search flattens: a matched child at any depth renders indented directly under its parent (a
  real row when the parent matched too, a synthesized header when it did not) — grouped rows,
  no tree widget. Grouping itself lives in lib/projectGrouping.js so it can be unit-tested apart
  from the DOM.

  Filing lives here: "New folder" creates a `kind: 'collection'` project, and each row's kebab
  offers Edit (rename/re-describe/relocate) and Delete. Version-scoped mutations (promote, delete
  a version) stay on ProjectDetail.svelte. Every mutation is admin/owner-gated in-page, same
  `isAdmin` idiom as the detail page; read visibility is every member's
  (see routes.js ADMIN_ONLY_PAGES / Sidebar.svelte).
-->
<script>
  import { t } from 'svelte-i18n'
  import { api } from '../lib/api.js'
  import ErrorBanner from '../lib/ErrorBanner.svelte'
  import DataTable from '../lib/DataTable.svelte'
  import Pagination from '../lib/Pagination.svelte'
  import SearchInput from '../lib/SearchInput.svelte'
  import { currentOrg, navigate, user } from '../lib/store.js'
  import SbomUploadModal from '../lib/sbom/SbomUploadModal.svelte'
  import ProjectEditModal from '../lib/ProjectEditModal.svelte'
  import RowActionsMenu from '../lib/RowActionsMenu.svelte'
  import Breadcrumbs from '../lib/Breadcrumbs.svelte'
  import { reportPageLoad } from '../lib/pageLoad.js'
  import { formatDateShort } from '../lib/format.js'
  import { extractErrorMessage } from '../lib/form.js'

  $: isAdmin = $user?.role === 'admin' || $user?.role === 'owner'
  let uploadOpen = false
  // null = closed. `{ project: null }` is the create-a-folder mode; `{ project: row }` edits.
  let editTarget = null
  let openActionsId = null
  let deletingId = null
  import { readQuery, writeQuery } from '../lib/tableState.js'
  import { buildProjectDisplayRows } from '../lib/projectGrouping.js'

  // Table state lives in the URL query string, same convention as Packages.svelte — it survives
  // navigating into a project's detail page and back, plus reloads and copied links. The API
  // paginates with limit/offset (not page), so `page` here is a display concept only; it is
  // converted to `offset` right before the request.
  const DEFAULTS = { q: '', page: 1, limit: 50, sort: 'name', dir: 'asc' }
  const init = readQuery(DEFAULTS)

  /** The route transition this page was mounted for, supplied by RouteView. @type {number | null} */
  export let pageToken = null

  let items = [], loading = true, error = ''
  let search = init.q
  let page = init.page, limit = init.limit, total = 0
  let sortCol = init.sort, sortDir = init.dir
  // Request sequence — page/search changes can fire overlapping loads; a response whose token
  // no longer matches the latest issued request is stale and must not overwrite newer state.
  let seq = 0

  function sync() {
    writeQuery({ q: search, page, limit, sort: sortCol, dir: sortDir }, DEFAULTS)
  }

  async function load() {
    const mine = ++seq
    loading = true
    error = ''
    try {
      const params = { limit, offset: (page - 1) * limit, sort: sortCol, dir: sortDir }
      if (search) params.q = search
      const data = await api.listProjects(params)
      if (mine !== seq) return
      items = data.items ?? []
      total = data.total ?? 0
    } catch (e) {
      if (mine !== seq) return
      error = $t('projects.loadFailed', { values: { message: e.message } })
    } finally {
      if (mine === seq) loading = false
    }
  }

  $: org = $currentOrg
  $: if (org) load()
  $: reportPageLoad(pageToken, loading)

  $: displayRows = buildProjectDisplayRows(items, !!search)

  function onPageChange(e) { page = e.detail.page; sync(); load() }
  function onLimitChange(e) { limit = e.detail.limit; page = 1; sync(); load() }
  // Sorting resets to page 1: page 4 of the old order is rarely a page of the new one.
  function onSortChange(e) { sortCol = e.detail.col; sortDir = e.detail.dir; page = 1; sync(); load() }

  function handleSearch() {
    page = 1
    sync()
    load()
  }

  // The list is paged, so its sort is server-side — a client-side sort would order the current
  // page against itself while the pager counts the whole set. Every comparator is therefore a
  // no-op: the server returns the page in the order it wants rendered (and, while searching, the
  // grouping pass above depends on that order surviving), and DataTable's stable sort preserves it.
  const NOOP_CMP = () => 0

  // Only the columns the paged query can actually order by are sortable. Components, severity and
  // a collection's rolled-up verdict are computed per page after the rows are chosen, so offering
  // them would sort one page against itself — the header would promise an ordering of the result
  // set that the pager's own total contradicts. Kept in step with ProjectRepository.ListSortKeys.
  $: columns = [
    { key: 'name',        label: $t('projects.columns.name'),       sortable: true },
    { key: 'components',  label: $t('projects.columns.components'), sortable: false, width: '110px', align: 'right' },
    { key: 'severity',    label: $t('projects.columns.severity'),   sortable: false, width: '170px' },
    { key: 'policy',      label: $t('projects.columns.policy'),     sortable: true, width: '110px' },
    { key: 'latest',      label: $t('projects.columns.latest'),     sortable: true, width: '120px' },
    { key: 'lastUpload',  label: $t('projects.columns.lastUpload'), sortable: false, width: '130px' },
    // Header-less trailing column: the kebab needs a cell, and a labelled one would read as data.
    // No width — DESIGN §5.8 gives an empty th its own.
    ...(isAdmin ? [{ key: 'actions', label: '', sortable: false }] : []),
  ]
  const comparators = {
    name: NOOP_CMP, components: NOOP_CMP, severity: NOOP_CMP,
    policy: NOOP_CMP, latest: NOOP_CMP, lastUpload: NOOP_CMP, actions: NOOP_CMP,
  }

  function openProject(row) {
    if (row.isHeader) return
    navigate('project-detail', { id: row.id })
  }

  function startEdit(row) {
    openActionsId = null
    editTarget = { project: row }
  }

  function startNewFolder() {
    editTarget = { project: null }
  }

  function onSaved() {
    editTarget = null
    load()
  }

  async function remove(row) {
    openActionsId = null
    if (!confirm($t('projects.detail.deleteProjectConfirm', { values: { name: row.name } }))) return
    deletingId = row.id
    error = ''
    try {
      await api.deleteProject(row.id)
      await load()
    } catch (e) {
      error = extractErrorMessage(e)
    } finally {
      deletingId = null
    }
  }
</script>

<div class="page">
  <div class="page-header">
    <div>
      <!-- A single, unlinked crumb: this is the root of the tree, so there is nowhere above it to
           go. It renders anyway so the header sits at the same height as every page below it —
           without it the title jumps up a line the moment you navigate back out of a folder. -->
      <Breadcrumbs crumbs={[{ label: $t('projects.title') }]} ariaLabel={$t('projects.breadcrumb')} />
      <h1 class="page-title">{$t('projects.title')}</h1>
    </div>
    {#if isAdmin}
      <div class="header-actions">
        <!-- data-testid so the e2e spec need not match the localized label: the suite shares one
             admin account whose language another spec switches, so any selector keyed on English
             chrome is a race. Same hook convention as Toggle.svelte / SettingsRetention.svelte. -->
        <button type="button" data-testid="new-folder" on:click={startNewFolder}>
          <svg width="13" height="13" aria-hidden="true"><use href="/icons.svg#icon-hierarchy"/></svg>
          {$t('projects.folders.newFolder')}
        </button>
        <button type="button" class="primary" on:click={() => (uploadOpen = true)}>
          <svg width="13" height="13" aria-hidden="true"><use href="/icons.svg#icon-upload"/></svg>
          {$t('sbomUpload.button')}
        </button>
      </div>
    {/if}
  </div>

  <div class="page-toolbar">
    <SearchInput placeholder={$t('projects.searchPlaceholder')} bind:value={search} on:search={handleSearch} class="toolbar-search" />
  </div>

  <ErrorBanner message={error} />
  <DataTable
    {columns}
    rows={displayRows}
    {comparators}
    {loading}
    loadingRows={limit}
    memoryKey="projects"
    emptyText={search ? $t('projects.emptySearch') : $t('projects.empty')}
    tableClass="table-auto"
    initialSort={{ key: sortCol, dir: sortDir }}
    on:sortchange={onSortChange}
    let:row
  >
    {#if row.isHeader}
      <!-- Synthesized grouping header: the matched child's parent did not itself match the
           search. Not clickable — there is nothing behind it to open. -->
      <tr class="group-header">
        <td colspan={columns.length}>{row.name}</td>
      </tr>
    {:else}
      <tr class="cursor-pointer" on:click={() => openProject(row)}>
        <td class="name-cell" title={row.name}>
          <span class="row-indent" class:visible={row.indent}></span>
          <strong>{row.name}</strong>
          {#if row.kind === 'collection'}
            <span class="badge has-icon ml-1">
              <svg width="11" height="11" aria-hidden="true"><use href="/icons.svg#icon-hierarchy"/></svg>
              {$t('projects.collection')}
            </span>
          {/if}
        </td>
        <td class="nowrap text-right text-muted">{row.componentCount ?? 0}</td>
        <td class="vuln-cell">
          {#if (row.severityCounts?.critical ?? 0) > 0}<span class="sev sev-critical" aria-label={$t('projects.severity.critical', { values: { count: row.severityCounts.critical } })}>{row.severityCounts.critical}</span>{/if}
          {#if (row.severityCounts?.high ?? 0) > 0}<span class="sev sev-high" aria-label={$t('projects.severity.high', { values: { count: row.severityCounts.high } })}>{row.severityCounts.high}</span>{/if}
          {#if (row.severityCounts?.medium ?? 0) > 0}<span class="sev sev-medium" aria-label={$t('projects.severity.medium', { values: { count: row.severityCounts.medium } })}>{row.severityCounts.medium}</span>{/if}
          {#if (row.severityCounts?.low ?? 0) > 0}<span class="sev sev-low" aria-label={$t('projects.severity.low', { values: { count: row.severityCounts.low } })}>{row.severityCounts.low}</span>{/if}
          {#if (row.severityCounts?.unscored ?? 0) > 0}<span class="sev sev-unknown" aria-label={$t('projects.severity.unscored', { values: { count: row.severityCounts.unscored } })}>{row.severityCounts.unscored}</span>{/if}
          {#if (row.severityCounts?.kevCount ?? 0) > 0}<span class="badge kev ml-1" title={$t('vulnerabilities.kevHelp')} aria-label={$t('projects.severity.kev', { values: { count: row.severityCounts.kevCount } })}>{$t('vulnerabilities.kev')}</span>{/if}
          {#if !row.severityCounts || Object.values(row.severityCounts).every((n) => !n)}<span class="text-muted" aria-label={$t('projects.severity.none')}>—</span>{/if}
        </td>
        <td class="nowrap">
          {#if row.policyStatus}
            <span class="badge policy-{row.policyStatus}">{$t(`projects.policy.${row.policyStatus}`)}</span>
          {:else}
            <span class="text-muted">{$t('projects.policy.unscanned')}</span>
          {/if}
          <!-- A folder's grey badge is otherwise a dead end: 49-passing-and-1-unscanned renders
               exactly like a folder nobody has touched. The count says which, and is the only
               actionable number here — a status is a state, a count is a to-do list. -->
          {#if row.subtreeUnevaluatedProjectCount > 0 && row.subtreeUnevaluatedProjectCount < row.subtreeProjectCount}
            <span class="text-muted t-sm">{$t('projects.unevaluatedOf', { values: { count: row.subtreeUnevaluatedProjectCount, total: row.subtreeProjectCount } })}</span>
          {/if}
        </td>
        <td class="mono nowrap">{row.latestVersion ?? $t('projects.noVersion')}</td>
        <td class="nowrap text-muted">{row.lastUploadAt ? $formatDateShort(row.lastUploadAt) : $t('projects.noVersion')}</td>
        {#if isAdmin}
          <td class="actions-cell" on:click|stopPropagation>
            <div class="row-actions">
              <RowActionsMenu
                id={row.id}
                bind:openId={openActionsId}
                ariaLabel={$t('projects.folders.actionsMenu', { values: { name: row.name } })}
              >
                <button class="popover-item" on:click|stopPropagation={() => startEdit(row)}>
                  {$t('projects.folders.edit')}
                </button>
                <div class="popover-divider"></div>
                <button
                  class="popover-item danger"
                  disabled={deletingId === row.id}
                  on:click|stopPropagation={() => remove(row)}
                >
                  {$t('common.actions.delete')}
                </button>
              </RowActionsMenu>
            </div>
          </td>
        {/if}
      </tr>
    {/if}
  </DataTable>

  <Pagination {total} {page} {limit}
    on:pagechange={onPageChange}
    on:limitchange={onLimitChange} />

  {#if uploadOpen}
    <SbomUploadModal on:close={() => (uploadOpen = false)} on:uploaded={() => load()} />
  {/if}

  {#if editTarget}
    <ProjectEditModal
      project={editTarget.project}
      on:saved={onSaved}
      on:close={() => (editTarget = null)}
    />
  {/if}
</div>

<style>
  .nowrap { white-space: nowrap; }
  /* Matches ProjectDetail: app.css centres .page-header, which floats the actions against a
     stacked crumb + title. */
  .page-header { align-items: flex-start; }
  .vuln-cell { white-space: nowrap; }
  .name-cell { overflow-wrap: anywhere; }
  /* .badge.has-icon is global (app.css) — reused as-is. */
  .ml-1 { margin-left: 6px; }

  /* Grouped/indented rows on search — no tree widget. row-indent is an empty inline spacer
     rather than padding on the cell, so the strong/badge that follows still starts flush after
     it instead of the whole cell's text shifting including its title tooltip anchor. */
  .row-indent { display: inline-block; width: 0; }
  .row-indent.visible { width: 20px; }
  /* The kebab popover escapes the cell, so the cell must not clip it. Row actions live in their
     own wrapper div — never display:flex directly on the td. */
  .actions-cell { overflow: visible; white-space: nowrap; text-align: right; }
  .row-actions { display: flex; gap: 6px; align-items: center; justify-content: flex-end; }

  .group-header td {
    color: var(--text2);
    font-size: 12px;
    font-weight: 600;
    background: var(--bg2);
    cursor: default;
  }
</style>
