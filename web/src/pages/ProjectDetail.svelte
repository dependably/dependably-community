<!--
  Project detail — header + stat-card row, then either a versions table (normal project) or a
  children table (collection; collections hold no versions and accept no uploads, so the upload
  affordance and the versions table are both absent here). Mutations (promote-to-latest,
  delete version, delete project) are admin/owner-gated in-page, same idiom as
  VersionDetail.svelte's `isAdmin` check — there is no frontend capability helper.

  A collection's stat cards and child rows read `rollup` and the per-child rollup the endpoint
  sends: a folder sums its whole subtree, so the numbers here match what the same row shows on the
  projects list. A plain project has no `rollup` — its cards are built from its own versions.
-->
<script>
  import { t } from 'svelte-i18n'
  import { api } from '../lib/api.js'
  import ErrorBanner from '../lib/ErrorBanner.svelte'
  import { navigate, user } from '../lib/store.js'
  import { reportPageLoad } from '../lib/pageLoad.js'
  import { formatDate } from '../lib/format.js'
  import { extractErrorMessage } from '../lib/form.js'
  import Breadcrumbs from '../lib/Breadcrumbs.svelte'
  import DataTable from '../lib/DataTable.svelte'
  import ProjectEditModal from '../lib/ProjectEditModal.svelte'
  import RowActionsMenu from '../lib/RowActionsMenu.svelte'
  import SbomUploadModal from '../lib/sbom/SbomUploadModal.svelte'
  import { exportFilename } from '../lib/sbom/analysis.js'

  /** The route params this page was mounted for, supplied by RouteView. @type {Record<string, any>} */
  export let params = {}

  /** The route transition this page was mounted for, supplied by RouteView. @type {number | null} */
  export let pageToken = null

  let project = null, loading = true, error = ''
  let promotingId = null, deletingId = null
  // Child-row actions: the kebab whose popover is open, the child being deleted, and the child
  // being edited (null = no dialog).
  let openChildActionsId = null, deletingChildId = null, editChild = null
  let uploadOpen = false
  let exportOpen = false, exportError = ''

  // One document for the whole folder: every descendant project's latest version, nested so each
  // library still says which project shipped it. Offered only on a collection — a plain project's
  // export is version-scoped and lives on the version page, where the version is chosen.
  async function runCollectionExport(variant) {
    exportOpen = false
    exportError = ''
    try {
      await api.exportCollectionSbom(
        params.id, variant, exportFilename(project?.name ?? 'collection', 'all', variant))
    } catch (e) {
      exportError = extractErrorMessage(e)
    }
  }

  function closeExport(e) {
    if (e.target?.closest && e.target.closest('.export-menu')) return
    exportOpen = false
  }

  $: isAdmin = $user?.role === 'admin' || $user?.role === 'owner'
  $: isCollection = project?.kind === 'collection'

  async function load() {
    loading = true
    error = ''
    try {
      project = await api.getProject(params.id)
    } catch (e) {
      error = $t('projects.detail.loadFailed', { values: { message: e.message } })
    } finally {
      loading = false
    }
  }

  $: if (params.id) load()
  $: reportPageLoad(pageToken, loading)

  // Projects / <containing folders, root first> / <this project>. `ancestors` comes from the
  // detail payload already resolved, so the trail costs no extra request and is correct at any
  // nesting depth. The trailing crumb is this page and carries no link.
  $: crumbs = [
    { label: $t('projects.title'), page: 'projects' },
    ...(project?.ancestors ?? []).map((a) => ({
      label: a.name, page: 'project-detail', params: { id: a.id },
    })),
    { label: project?.name ?? '' },
  ]

  // Both tables load every row in one payload and are unpaged, so sort is client-side — the
  // in-memory arm of DESIGN §5.8, not the NOOP_CMP arm, which exists for a server-ordered page.
  // Labels are resolved in a reactive block; a `const` would freeze them in whichever locale was
  // active at mount.
  $: childColumns = [
    { key: 'name',       label: $t('projects.detail.columns.name'),  sortable: true },
    { key: 'components', label: $t('projects.columns.components'),   sortable: true, width: '110px', align: 'right' },
    { key: 'severity',   label: $t('projects.columns.severity'),     sortable: true, width: '170px' },
    { key: 'latest',     label: $t('projects.detail.columns.latest'), sortable: true, width: '140px' },
    { key: 'policy',     label: $t('projects.detail.columns.policy'), sortable: true, width: '110px' },
    // Header-less: the kebab needs a cell, and a labelled one would read as data. §5.8 gives an
    // empty th its own width, so none is declared here.
    ...(isAdmin ? [{ key: 'actions', label: '', sortable: false }] : []),
  ]

  $: versionColumns = [
    { key: 'version',    label: $t('projects.detail.columns.version'),    sortable: true },
    { key: 'components', label: $t('projects.detail.columns.components'), sortable: true, width: '120px', align: 'right' },
    { key: 'policy',     label: $t('projects.detail.columns.policy'),     sortable: true, width: '120px' },
    { key: 'uploaded',   label: $t('projects.detail.columns.uploaded'),   sortable: true, width: '170px', defaultDir: 'desc' },
    ...(isAdmin ? [{ key: 'actions', label: '', sortable: false }] : []),
  ]

  // Ordered worst-first so a descending sort surfaces what needs attention; an unevaluated row
  // sorts last rather than being treated as a pass it never earned.
  const POLICY_RANK = { violation: 3, warn: 2, pass: 1 }
  const rankPolicy = (status) => POLICY_RANK[status] ?? 0

  // Severity sorts by the worst finding present, then by how many of it — a row with one critical
  // outranks a row with nine lows, which a plain total would invert.
  function severityWeight(counts) {
    const c = counts ?? {}
    if (c.critical) return 4_000_000 + c.critical
    if (c.high) return 3_000_000 + c.high
    if (c.medium) return 2_000_000 + c.medium
    if (c.low) return 1_000_000 + c.low
    return c.unscored ?? 0
  }

  const byText = (a, b) => String(a ?? '').localeCompare(String(b ?? ''))

  const childComparators = {
    name: (a, b) => byText(a.name, b.name),
    components: (a, b) => (a.componentCount ?? 0) - (b.componentCount ?? 0),
    severity: (a, b) => severityWeight(a.severityCounts) - severityWeight(b.severityCounts),
    latest: (a, b) => byText(a.latestVersion, b.latestVersion),
    policy: (a, b) => rankPolicy(a.policyStatus) - rankPolicy(b.policyStatus),
  }

  const versionComparators = {
    version: (a, b) => byText(a.version, b.version),
    components: (a, b) => (a.componentCount ?? 0) - (b.componentCount ?? 0),
    policy: (a, b) => rankPolicy(a.policyStatus) - rankPolicy(b.policyStatus),
    uploaded: (a, b) => byText(a.createdAt, b.createdAt),
  }

  // Whether the subtree rollup carries any advisory at all. Computed in a reactive statement
  // rather than called inline: a bare helper call in markup does not re-run when `project` changes.
  $: hasFindings = Object.values(project?.rollup?.severityCounts ?? {}).some((n) => n > 0)

  // Some but not all of the subtree was evaluated — the case where a bare "Not scanned" would
  // read as "nothing here has been looked at", which is the opposite of the truth.
  $: partiallyEvaluated =
    (project?.rollup?.unevaluatedProjectCount ?? 0) > 0 &&
    project.rollup.unevaluatedProjectCount < project.rollup.projectCount

  // The version the stat-card row summarizes: is_latest wins; falls back to the first row so a
  // project mid-scan (no version promoted yet) still has something to show.
  $: statVersion = (project?.versions ?? []).find((v) => v.isLatest) ?? (project?.versions ?? [])[0] ?? null

  function openChild(child) {
    navigate('project-detail', { id: child.id })
  }

  function openVersion(ver) {
    navigate('project-version', { id: params.id, versionId: ver.id })
  }

  async function promote(ver) {
    if (promotingId) return
    promotingId = ver.id
    try {
      await api.promoteLatest(params.id, ver.id)
      await load()
    } catch (e) {
      error = e.message
    } finally {
      promotingId = null
    }
  }

  async function deleteVersion(ver) {
    if (!confirm($t('projects.detail.deleteVersionConfirm', { values: { version: ver.version } }))) return
    deletingId = ver.id
    try {
      await api.deleteProjectVersion(params.id, ver.id)
      project = { ...project, versions: project.versions.filter((v) => v.id !== ver.id) }
    } catch (e) {
      error = e.message
    } finally {
      deletingId = null
    }
  }

  // Deleting a row is offered from the table that lists it, not from the page that IS it — the
  // projects list for a root-level row, this children table for a nested one. That is why the
  // page-level "Delete project" button is gone: a control that destroys the page you are standing
  // on, sitting where every other page puts a primary action, is the easiest destructive button in
  // the app to press by accident.
  async function deleteChild(child) {
    openChildActionsId = null
    // A collection cascades to everything beneath it, which is a materially bigger statement than
    // deleting one project — so it gets its own confirmation rather than the project wording.
    const key = child.kind === 'collection'
      ? 'projects.detail.deleteCollectionConfirm'
      : 'projects.detail.deleteProjectConfirm'
    if (!confirm($t(key, { values: { name: child.name } }))) return

    deletingChildId = child.id
    error = ''
    try {
      await api.deleteProject(child.id)
      // Reload rather than splice the row out: the collection's own rolled-up counts are computed
      // over the subtree that just shrank, so a local removal would leave the stat cards lying.
      await load()
    } catch (e) {
      error = extractErrorMessage(e)
    } finally {
      deletingChildId = null
    }
  }

  function startEditChild(child) {
    openChildActionsId = null
    editChild = child
  }

  async function onChildSaved() {
    editChild = null
    // A rename or a relocation both change this table — a relocated child leaves it entirely.
    await load()
  }
</script>

<svelte:window on:click={closeExport} />

<div class="page">
  <div class="page-header">
    <div>
      <Breadcrumbs {crumbs} ariaLabel={$t('projects.breadcrumb')} />
      <h1 class="page-title">
        {project?.name ?? ''}
        {#if project?.classifier}
          <span class="badge">{project.classifier}</span>
        {/if}
        {#if isCollection}
          <span class="badge has-icon">
            <svg width="12" height="12" aria-hidden="true"><use href="/icons.svg#icon-hierarchy"/></svg>
            {$t('projects.detail.collectionBadge')}
          </span>
        {/if}
      </h1>
      {#if project?.description}
        <p class="project-description text-muted">{project.description}</p>
      {/if}
    </div>
    {#if isAdmin && project}
      <div class="header-actions">
        {#if isCollection}
          <span class="export-menu">
            <button type="button" on:click|stopPropagation={() => (exportOpen = !exportOpen)} aria-haspopup="true" aria-expanded={exportOpen}>
              <svg width="13" height="13" aria-hidden="true"><use href="/icons.svg#icon-download"/></svg>
              {$t('sbomAnalysis.export.button')}
            </button>
            {#if exportOpen}
              <div class="export-popover" role="menu">
                <p class="export-hint">{$t('projects.detail.exportHint')}</p>
                <button class="popover-item" on:click|stopPropagation={() => runCollectionExport('inventory')}>{$t('sbomAnalysis.export.inventory')}</button>
                <button class="popover-item" on:click|stopPropagation={() => runCollectionExport('vdr')}>{$t('sbomAnalysis.export.vdr')}</button>
              </div>
            {/if}
          </span>
        {/if}
        <!-- data-testid for the same reason as new-folder: the label is localized, and this
             header now holds more than one button, so "the header button" no longer identifies
             one element. -->
        <button type="button" class="primary" data-testid="upload" on:click={() => (uploadOpen = true)}>
          <svg width="13" height="13" aria-hidden="true"><use href="/icons.svg#icon-upload"/></svg>
          {$t('sbomUpload.button')}
        </button>
      </div>
    {/if}
  </div>

  <ErrorBanner message={error} />
  <ErrorBanner message={exportError} />

  {#if !loading && project}
    <div class="stat-grid mb-3">
      {#if isCollection}
        <div class="stat-card">
          <span class="eyebrow">{$t('projects.detail.stat.children')}</span>
          <span class="stat-value">{(project.children ?? []).length}</span>
        </div>
        <div class="stat-card">
          <span class="eyebrow">{$t('projects.detail.stat.subtreeProjects')}</span>
          <span class="stat-value">{project.rollup?.projectCount ?? 0}</span>
        </div>
        <div class="stat-card">
          <span class="eyebrow">{$t('projects.detail.stat.subtreeComponents')}</span>
          <span class="stat-value">{project.rollup?.componentCount ?? 0}</span>
        </div>
        <div class="stat-card">
          <span class="eyebrow">{$t('projects.detail.stat.subtreeSeverity')}</span>
          <span class="vuln-cell">
            {#if (project.rollup?.severityCounts?.critical ?? 0) > 0}<span class="sev sev-critical" aria-label={$t('projects.severity.critical', { values: { count: project.rollup.severityCounts.critical } })}>{project.rollup.severityCounts.critical}</span>{/if}
            {#if (project.rollup?.severityCounts?.high ?? 0) > 0}<span class="sev sev-high" aria-label={$t('projects.severity.high', { values: { count: project.rollup.severityCounts.high } })}>{project.rollup.severityCounts.high}</span>{/if}
            {#if (project.rollup?.severityCounts?.medium ?? 0) > 0}<span class="sev sev-medium" aria-label={$t('projects.severity.medium', { values: { count: project.rollup.severityCounts.medium } })}>{project.rollup.severityCounts.medium}</span>{/if}
            {#if (project.rollup?.severityCounts?.low ?? 0) > 0}<span class="sev sev-low" aria-label={$t('projects.severity.low', { values: { count: project.rollup.severityCounts.low } })}>{project.rollup.severityCounts.low}</span>{/if}
            {#if (project.rollup?.severityCounts?.unscored ?? 0) > 0}<span class="sev sev-unknown" aria-label={$t('projects.severity.unscored', { values: { count: project.rollup.severityCounts.unscored } })}>{project.rollup.severityCounts.unscored}</span>{/if}
            {#if !hasFindings}<span class="text-muted" aria-label={$t('projects.severity.none')}>—</span>{/if}
          </span>
        </div>
        <div class="stat-card">
          <span class="eyebrow">{$t('projects.detail.stat.subtreePolicy')}</span>
          {#if project.rollup?.policyStatus}
            <span class="badge policy-{project.rollup.policyStatus}">{$t(`projects.policy.${project.rollup.policyStatus}`)}</span>
          {:else}
            <span class="text-muted">{$t('projects.policy.unscanned')}</span>
          {/if}
          {#if partiallyEvaluated}
            <span class="text-muted t-sm">{$t('projects.unevaluatedOf', { values: { count: project.rollup.unevaluatedProjectCount, total: project.rollup.projectCount } })}</span>
          {/if}
        </div>
      {:else}
        <div class="stat-card">
          <span class="eyebrow">{$t('projects.detail.stat.versions')}</span>
          <span class="stat-value">{(project.versions ?? []).length}</span>
        </div>
        <div class="stat-card">
          <span class="eyebrow">{$t('projects.detail.stat.components')}</span>
          <span class="stat-value">{statVersion?.componentCount ?? 0}</span>
        </div>
        <div class="stat-card">
          <span class="eyebrow">{$t('projects.detail.stat.policy')}</span>
          {#if statVersion?.policyStatus}
            <span class="badge policy-{statVersion.policyStatus}">{$t(`projects.policy.${statVersion.policyStatus}`)}</span>
          {:else}
            <span class="text-muted">{$t('projects.policy.unscanned')}</span>
          {/if}
        </div>
      {/if}
    </div>
  {/if}

  {#if !loading && project && isCollection}
    <h2 class="section-h">{$t('projects.detail.childrenTitle')}</h2>
    <DataTable
      columns={childColumns}
      rows={project.children ?? []}
      comparators={childComparators}
      memoryKey="project-children"
      emptyText={$t('projects.detail.childrenEmpty')}
      tableClass="table-auto"
      let:row={child}
    >
          <tr class="cursor-pointer" on:click={() => openChild(child)}>
            <td>
              <strong>{child.name}</strong>
              {#if child.kind === 'collection'}
                <span class="badge has-icon ml-1">
                  <svg width="11" height="11" aria-hidden="true"><use href="/icons.svg#icon-hierarchy"/></svg>
                  {$t('projects.collection')}
                </span>
              {/if}
            </td>
            <td class="text-right text-muted">{child.componentCount ?? 0}</td>
            <td class="vuln-cell">
              {#if (child.severityCounts?.critical ?? 0) > 0}<span class="sev sev-critical" aria-label={$t('projects.severity.critical', { values: { count: child.severityCounts.critical } })}>{child.severityCounts.critical}</span>{/if}
              {#if (child.severityCounts?.high ?? 0) > 0}<span class="sev sev-high" aria-label={$t('projects.severity.high', { values: { count: child.severityCounts.high } })}>{child.severityCounts.high}</span>{/if}
              {#if (child.severityCounts?.medium ?? 0) > 0}<span class="sev sev-medium" aria-label={$t('projects.severity.medium', { values: { count: child.severityCounts.medium } })}>{child.severityCounts.medium}</span>{/if}
              {#if (child.severityCounts?.low ?? 0) > 0}<span class="sev sev-low" aria-label={$t('projects.severity.low', { values: { count: child.severityCounts.low } })}>{child.severityCounts.low}</span>{/if}
              {#if (child.severityCounts?.unscored ?? 0) > 0}<span class="sev sev-unknown" aria-label={$t('projects.severity.unscored', { values: { count: child.severityCounts.unscored } })}>{child.severityCounts.unscored}</span>{/if}
              {#if !child.severityCounts || Object.values(child.severityCounts).every((n) => !n)}<span class="text-muted" aria-label={$t('projects.severity.none')}>—</span>{/if}
            </td>
            <td class="mono">{child.latestVersion ?? $t('projects.noVersion')}</td>
            <td>
              {#if child.policyStatus}
                <span class="badge policy-{child.policyStatus}">{$t(`projects.policy.${child.policyStatus}`)}</span>
              {:else}
                <span class="text-muted">{$t('projects.policy.unscanned')}</span>
              {/if}
            </td>
            {#if isAdmin}
              <td class="actions-cell" on:click|stopPropagation>
                <div class="row-actions">
                  <RowActionsMenu
                    id={child.id}
                    bind:openId={openChildActionsId}
                    ariaLabel={$t('projects.folders.actionsMenu', { values: { name: child.name } })}
                  >
                    <button
                      class="popover-item danger"
                      disabled={deletingChildId === child.id}
                      on:click|stopPropagation={() => deleteChild(child)}
                    >
                      {$t('common.actions.delete')}
                    </button>
                    <div class="popover-divider"></div>
                    <button class="popover-item" on:click|stopPropagation={() => startEditChild(child)}>
                      {$t('projects.folders.edit')}
                    </button>
                  </RowActionsMenu>
                </div>
              </td>
            {/if}
          </tr>
    </DataTable>
  {/if}

  {#if !loading && project && !isCollection}
    <h2 class="section-h">{$t('projects.detail.versionsTitle')}</h2>
    <DataTable
      columns={versionColumns}
      rows={project.versions ?? []}
      comparators={versionComparators}
      initialSort={{ key: 'uploaded', dir: 'desc' }}
      memoryKey="project-versions"
      emptyText={$t('projects.detail.versionsEmpty')}
      tableClass="table-auto"
      let:row={ver}
    >
          <tr class="cursor-pointer" on:click={() => openVersion(ver)}>
            <td class="mono">
              {ver.version}
              {#if ver.isLatest}<span class="badge success ml-1">{$t('projects.detail.isLatest')}</span>{/if}
            </td>
            <td class="text-right text-muted">{ver.componentCount ?? 0}</td>
            <td>
              {#if ver.policyStatus}
                <span class="badge policy-{ver.policyStatus}">{$t(`projects.policy.${ver.policyStatus}`)}</span>
              {:else}
                <span class="text-muted">{$t('projects.policy.unscanned')}</span>
              {/if}
            </td>
            <td class="text-muted">{$formatDate(ver.createdAt)}</td>
            {#if isAdmin}
              <td class="actions-cell" on:click|stopPropagation>
                <div class="row-actions">
                  <button
                    class="btn-sm"
                    disabled={ver.isLatest || promotingId === ver.id}
                    on:click={() => promote(ver)}
                  >
                    {promotingId === ver.id ? $t('projects.detail.promoting') : $t('projects.detail.promote')}
                  </button>
                  <button
                    class="danger btn-sm"
                    disabled={deletingId === ver.id}
                    on:click={() => deleteVersion(ver)}
                  >
                    {$t('projects.detail.deleteVersion')}
                  </button>
                </div>
              </td>
            {/if}
          </tr>
    </DataTable>
  {/if}

  <!-- What the upload targets is decided by the page it was opened from, not by the form: on a
       collection it files into THIS folder (a new project, or an existing one picked from the
       folder's own children); on a project it adds a version to THAT project. Neither needs the
       operator to re-state where they already are.

       A nested project passes its OWN containing folder as the parent, because that is the scope
       its name resolves in: sent without one, the upload addresses the root scope, where this
       project does not exist, and lands a second top-level project of the same name. -->
  {#if uploadOpen && project}
    <SbomUploadModal
      presetProjectId={isCollection ? null : project.id}
      presetProjectName={isCollection ? null : project.name}
      presetParentId={isCollection ? project.id : (project.parentId ?? null)}
      presetParentName={isCollection ? project.name : (project.ancestors?.at(-1)?.name ?? null)}
      on:close={() => (uploadOpen = false)}
      on:uploaded={() => load()}
    />
  {/if}

  {#if editChild}
    <ProjectEditModal
      project={editChild}
      on:saved={onChildSaved}
      on:close={() => (editChild = null)}
    />
  {/if}
</div>

<style>
  /* .badge.has-icon is global (app.css); this page's usages also want a left margin off the
     preceding badge/title text, which the shared rule intentionally leaves to callers. */
  .badge.has-icon { margin-left: 6px; }
  .ml-1 { margin-left: 6px; }
  /* .mb-3 is global (app.css) — reused as-is. */
  .project-description { margin: 6px 0 0; max-width: 70ch; }
  /* app.css centres .page-header, which reads fine against a lone h1 but floats the action
     halfway down a stacked breadcrumb + title + description. Pin it to the title's line. */
  .page-header { align-items: flex-start; }
  .header-actions { display: flex; align-items: center; gap: 8px; flex-shrink: 0; }
  /* Same popover contract the version page's export menu uses: anchored to its own button rather
     than positioned against the viewport, so it needs no measurement pass. */
  .export-menu { position: relative; display: inline-flex; }
  .export-popover {
    position: absolute;
    top: calc(100% + 4px);
    right: 0;
    z-index: 1000;
    min-width: 260px;
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    box-shadow: var(--shadow);
    padding: 4px 0;
    text-align: left;
  }
  .export-hint { margin: 4px 12px 6px; font-size: 11px; color: var(--text2); }
  .header-actions button { display: inline-flex; align-items: center; gap: 6px; }
  /* .sev-* chips are global (app.css); the cell just must not wrap between them. */
  .vuln-cell { white-space: nowrap; }
  /* .stat-card is a flex column, so a badge child stretches to the card's full width and reads
     as a progress bar rather than a status chip. Shrink it back to its content. */
  .stat-card .badge { align-self: flex-start; }
  .actions-cell { overflow: visible; white-space: nowrap; text-align: right; }
  .actions-col { width: 48px; }
  /* Row actions live in their own wrapper div, never display:flex directly on the td. */
  .row-actions { display: flex; gap: 6px; align-items: center; justify-content: flex-end; }
  /* .btn-sm (padding/font-size) is global (app.css); min-height brings it to the 28px hit
     target the row-actions convention elsewhere in the app uses (e.g. Packages.svelte). */
  .btn-sm { min-height: 28px; }
</style>
