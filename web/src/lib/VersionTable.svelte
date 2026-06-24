<!--
  Version table extracted from VersionDetail.svelte. Owns the table's local UI
  state — sort col/dir, which row is expanded, which row's actions popover is open,
  popover position — and renders the row + the expanded detail panel + the actions
  popover itself. Parent passes the data and the action handlers and supplies the
  copy helper.

  Rows are grouped by version. Most ecosystems map a version to a single artifact, so
  a group holds one file and renders as a flat row. Maven (jar + pom + sidecars) and
  PyPI (wheel + sdist) map one version to several files; their group collapses into a
  single version row whose expanded panel lists each file with a per-file download.
  Release-level actions (block / unblock / rescan / delete) act on the whole version;
  download is per-file because each file has its own bytes.

  Severity badges in the expanded detail panel come from VulnerabilityRow.svelte;
  UNSCORED / NO CVSS labelling is preserved there intentionally (security-UI
  uncertainty surface).
-->
<script>
  import { createEventDispatcher } from 'svelte'
  import { SvelteMap } from 'svelte/reactivity'
  import { t } from 'svelte-i18n'
  import VulnerabilityRow from './VulnerabilityRow.svelte'
  import { formatDate, formatBytes, formatNumber } from './format.js'
  import { sortIndicator } from './sortIndicator.js'

  /** @type {{ ecosystem: string, isProxy: boolean, name: string, upstreamLatestVersion?: string | null, latestState?: string } | null} */
  export let pkg = null
  export let versions = []
  /** @type {Map<string, Array<{osvId: string, severity?: string, summary?: string, cvssScore?: number}>>} */
  export let vulnsByPurl
  export let isAdmin = false
  export let scanningId = null
  export let loading = false
  /**
   * Returns ms remaining in the post-scan cooldown (0 if cooldown expired).
   * @type {(ver: { vulnCheckedAt?: string | null }) => number}
   */
  export let scanCooldownRemaining = () => 0
  /**
   * Caller's copy-to-clipboard helper (kept in the parent so tests can swap it).
   * @type {(text: string) => void}
   */
  export let copy = () => {}

  const dispatch = createEventDispatcher()

  let sortCol = 'pushed', sortDir = 'desc'
  let expandedKey = null
  let openActionsId = null
  let popoverPos = { top: 0, left: 0 }

  // Worst-first rank for collapsing several files' statuses into the version's overall status.
  const STATUS_RANK = { blocked: 0, vulnerable: 1, deprecated: 2, unscanned: 3, allowed: 4, clean: 5 }

  // Collapse the flat per-file list into one display group per version. A single-file group
  // renders exactly like the old flat row; a multi-file group aggregates the file-level columns
  // and exposes the per-file breakdown only in the expanded panel.
  function buildGroups(list) {
    const byKey = new SvelteMap()
    for (const v of list) {
      let g = byKey.get(v.version)
      if (!g) { g = { key: v.version, version: v.version, purl: v.purl, files: [] }; byKey.set(v.version, g) }
      g.files.push(v)
    }
    return [...byKey.values()].map(summarize)
  }

  function summarize(g) {
    const files = g.files
    const single = files.length === 1
    const rep = files[0]
    const worstStatus = files
      .map(f => f.status)
      .filter(Boolean)
      .sort((a, b) => (STATUS_RANK[a] ?? 9) - (STATUS_RANK[b] ?? 9))[0] ?? null
    // Most-recent cache time represents the version's recency for the default "pushed" sort.
    const createdAt = files.reduce((m, f) => (m && new Date(m) >= new Date(f.createdAt) ? m : f.createdAt), null)
    // Surface the strongest provenance signal across the version's files (failed dominates).
    const provenanceStatus =
        files.some(f => f.provenanceStatus === 'failed') ? 'failed'
      : files.some(f => f.provenanceStatus === 'unsigned') ? 'unsigned'
      : files.some(f => f.provenanceStatus === 'verified') ? 'verified'
      : null
    return {
      key: g.key,
      version: g.version,
      purl: g.purl,
      // Release-level actions key by version string, so the representative id only needs to be
      // stable for the scanning/cooldown highlight and the open-popover lookup.
      id: rep.id,
      files,
      fileCount: files.length,
      single,
      firstFetch: files.some(f => f.firstFetch),
      yanked: files.some(f => f.yanked),
      deprecated: files.find(f => f.deprecated)?.deprecated ?? null,
      hasInstallScript: files.some(f => f.hasInstallScript),
      installScriptKind: files.find(f => f.hasInstallScript)?.installScriptKind ?? null,
      provenanceStatus,
      provenanceSigner: files.find(f => f.provenanceStatus === 'verified')?.provenanceSigner ?? null,
      isMalicious: files.some(f => f.isMalicious),
      status: worstStatus,
      // Single-checksum / integrity belong to one file; null them out for multi-file groups
      // (the per-file checksums live in the expanded panel).
      checksumSha256: single ? rep.checksumSha256 : null,
      checksumSha1: single ? rep.checksumSha1 : null,
      upstreamIntegrityValue: single ? rep.upstreamIntegrityValue : null,
      upstreamIntegrityAlgorithm: single ? rep.upstreamIntegrityAlgorithm : null,
      origin: rep.origin,
      licenses: [...new Set(files.flatMap(f => f.licenses ?? []))],
      sizeBytes: files.reduce((s, f) => s + (f.sizeBytes ?? 0), 0),
      downloadCount: files.reduce((s, f) => s + (f.downloadCount ?? 0), 0),
      createdAt,
      publishedAt: rep.publishedAt,
      vulnCheckedAt: rep.vulnCheckedAt,
      tags: rep.tags,
    }
  }

  $: groups = buildGroups(versions)

  $: sortedGroups = [...groups].sort((a, b) => {
    let cmp = 0
    if (sortCol === 'version')  cmp = a.version.localeCompare(b.version, undefined, { numeric: true, sensitivity: 'base' })
    else if (sortCol === 'size')      cmp = a.sizeBytes - b.sizeBytes
    else if (sortCol === 'pushed')    cmp = new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime()
    else if (sortCol === 'checksum')  cmp = (a.checksumSha256 ?? '').localeCompare(b.checksumSha256 ?? '')
    else if (sortCol === 'license')   cmp = (a.licenses?.join(', ') ?? '').localeCompare(b.licenses?.join(', ') ?? '')
    else if (sortCol === 'downloads') cmp = (a.downloadCount ?? 0) - (b.downloadCount ?? 0)
    else if (sortCol === 'status')    cmp = (a.status ?? '').localeCompare(b.status ?? '')
    return sortDir === 'asc' ? cmp : -cmp
  })

  function toggleSort(col) {
    if (sortCol === col) sortDir = sortDir === 'asc' ? 'desc' : 'asc'
    else { sortCol = col; sortDir = 'desc' }
  }

  // OCI hosted images are keyed by their manifest digest; the full `sha256:…` string
  // is 71 unbreakable characters that blow out the version column and squish the tag
  // column beside it. Show a short digest in the cell (full value on hover); the tag
  // column, the checksum column, and the expanded row's PURL/SHA-256 carry the rest.
  function shortVersion(version) {
    if (pkg?.ecosystem === 'oci' && /^sha256:[0-9a-f]{64}$/i.test(version)) {
      return version.slice(0, 19) + '…'
    }
    return version
  }

  // Short, technical label for a constituent file so the per-file rows read as
  // "jar / pom / wheel / sdist" rather than opaque hashes. Falls back to the extension.
  function fileType(filename) {
    const f = (filename ?? '').toLowerCase()
    if (pkg?.ecosystem === 'pypi') {
      if (f.endsWith('.whl')) return 'wheel'
      if (f.endsWith('.tar.gz') || f.endsWith('.zip') || f.endsWith('.tar.bz2') || f.endsWith('.egg')) return 'sdist'
    }
    if (pkg?.ecosystem === 'maven') {
      if (f.endsWith('-sources.jar')) return 'sources'
      if (f.endsWith('-javadoc.jar')) return 'javadoc'
      if (f.endsWith('.jar')) return 'jar'
      if (f.endsWith('.pom')) return 'pom'
      if (f.endsWith('.module')) return 'module'
    }
    const dot = f.lastIndexOf('.')
    return dot >= 0 ? f.slice(dot + 1) : 'file'
  }

  function toggleExpand(key) {
    expandedKey = expandedKey === key ? null : key
  }

  /** Reset state when the package or selected version churns (parent reloads after action). */
  export function reset() {
    expandedKey = null
    openActionsId = null
  }

  function severityOrder(s) {
    return { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 }[s] ?? 4
  }

  function toggleActions(id, e) {
    e.stopPropagation()
    if (openActionsId === id) { openActionsId = null; return }
    const rect = e.currentTarget.getBoundingClientRect()
    const POPOVER_WIDTH = 160
    popoverPos = {
      top: rect.bottom + 4,
      left: Math.max(8, rect.right - POPOVER_WIDTH),
    }
    openActionsId = id
  }

  function handleWindowClick(e) {
    if (openActionsId === null) return
    if (e.target?.closest && (e.target.closest('.actions-popover') || e.target.closest('.kebab-btn'))) return
    openActionsId = null
  }

  function fire(name, payload) {
    openActionsId = null
    dispatch(name, payload)
  }
</script>

<svelte:window on:click={handleWindowClick} />

<!-- Package-level upstream-currency banner. The per-row "Latest" column can only mark which
     cached version IS the upstream latest; when the package is stale that version isn't cached
     at all, so every row falls to "—" and the staleness signal (the red x in the packages list)
     would otherwise vanish here. This banner restores it so the two views agree. -->
{#if pkg?.latestState === 'stale'}
  <div class="latest-banner latest-banner-stale" role="status">
    <svg class="latest-no" width="14" height="14" aria-hidden="true"><use href="/icons.svg#icon-x"/></svg>
    <span>{$t('versionDetail.latestBanner.stale', { values: { version: pkg.upstreamLatestVersion } })}</span>
  </div>
{:else if pkg?.latestState === 'current'}
  <div class="latest-banner latest-banner-current" role="status">
    <svg class="latest-yes" width="14" height="14" aria-hidden="true"><use href="/icons.svg#icon-check"/></svg>
    <span>{$t('versionDetail.latestBanner.current', { values: { version: pkg.upstreamLatestVersion } })}</span>
  </div>
{/if}

<table class="table-auto versions-table">
  <colgroup>
    <col class="col-version">
    {#if pkg?.ecosystem === 'oci'}<col class="col-tag">{/if}
    <col class="col-latest">
    <col class="col-origin">
    <col class="col-checksum">
    <col class="col-size">
    <col class="col-pushed">
    <col class="col-license">
    <col class="col-downloads">
    <col class="col-status">
    <col class="col-actions">
  </colgroup>
  <thead>
    <tr>
      <th class="sortable" on:click={() => toggleSort('version')}>{$t('versionDetail.columns.version')}{sortIndicator('version', sortCol, sortDir)}</th>
      {#if pkg?.ecosystem === 'oci'}<th>{$t('versionDetail.columns.tag')}</th>{/if}
      <th class="text-center">{$t('versionDetail.columns.latest')}</th>
      <th>{$t('versionDetail.columns.origin')}</th>
      <th class="sortable" on:click={() => toggleSort('checksum')}>{$t('versionDetail.columns.checksum')}{sortIndicator('checksum', sortCol, sortDir)}</th>
      <th class="sortable" on:click={() => toggleSort('size')}>{$t('versionDetail.columns.size')}{sortIndicator('size', sortCol, sortDir)}</th>
      <th class="sortable" on:click={() => toggleSort('pushed')}>{$t('versionDetail.columns.pushed')}{sortIndicator('pushed', sortCol, sortDir)}</th>
      <th class="sortable" on:click={() => toggleSort('license')}>{$t('versionDetail.columns.license')}{sortIndicator('license', sortCol, sortDir)}</th>
      <th class="sortable num-col" on:click={() => toggleSort('downloads')}>{$t('versionDetail.columns.downloads')}{sortIndicator('downloads', sortCol, sortDir)}</th>
      <th class="sortable status-th" on:click={() => toggleSort('status')}>{$t('versionDetail.columns.status')}{sortIndicator('status', sortCol, sortDir)}</th>
      <th>{$t('versionDetail.columns.actions')}</th>
    </tr>
  </thead>
  {#if loading}
    <tbody>
      {#each [0,1,2,3,4] as i (i)}
        <tr><td colspan={pkg?.ecosystem === 'oci' ? 11 : 10}><span class="skeleton"></span></td></tr>
      {/each}
    </tbody>
  {:else}
  <tbody>
    {#each sortedGroups as g (g.key)}
      {@const vulns = (vulnsByPurl.get(g.purl) ?? []).slice().sort((a, b) => severityOrder(a.severity) - severityOrder(b.severity))}
      {@const isExpanded = expandedKey === g.key}
      {@const verShort = shortVersion(g.version)}
      <tr
        class:first-fetch-row={g.firstFetch}
        class:expanded-row={isExpanded}
        class="cursor-pointer"
        on:click={() => toggleExpand(g.key)}
      >
        <td class="version-cell">
          <strong class:mono={verShort !== g.version} title={verShort === g.version ? null : g.version}>{verShort}</strong>
          {#if !g.single}<span class="badge files-badge ml-1">{$t('versionDetail.fileCount', { values: { count: g.fileCount } })}</span>{/if}
          {#if g.yanked}<span class="badge yanked ml-1">{$t('versionDetail.badges.yanked')}</span>{/if}
          {#if g.deprecated}<span class="badge deprecated ml-1" title={g.deprecated}>{$t('versionDetail.badges.deprecated')}</span>{/if}
          {#if g.hasInstallScript}<span class="badge install-script ml-1" title={$t('versionDetail.badges.installScriptHelp', { values: { kind: g.installScriptKind || '' } })}>{$t('versionDetail.badges.installScript')}</span>{/if}
          {#if g.provenanceStatus === 'verified'}<span class="badge prov-verified ml-1" title={$t('versionDetail.badges.provenanceVerifiedHelp', { values: { signer: g.provenanceSigner || '' } })}>{$t('versionDetail.badges.provenanceVerified')}</span>{/if}
          {#if g.provenanceStatus === 'failed'}<span class="badge prov-failed ml-1" title={$t('versionDetail.badges.provenanceFailedHelp')}>{$t('versionDetail.badges.provenanceFailed')}</span>{/if}
          {#if g.provenanceStatus === 'unsigned'}<span class="badge prov-unsigned ml-1" title={$t('versionDetail.badges.provenanceUnsignedHelp')}>{$t('versionDetail.badges.provenanceUnsigned')}</span>{/if}
          {#if vulns.length > 0}
            {@const critical = vulns.filter(v => v.severity === 'CRITICAL').length}
            {@const high     = vulns.filter(v => v.severity === 'HIGH').length}
            {@const medium   = vulns.filter(v => v.severity === 'MEDIUM').length}
            {@const low      = vulns.filter(v => v.severity === 'LOW').length}
            <span class="inline-vulns">
              {#if critical > 0}<span class="sev sev-critical" aria-label="{critical} critical">{critical}</span>{/if}
              {#if high > 0}<span class="sev sev-high" aria-label="{high} high">{high}</span>{/if}
              {#if medium > 0}<span class="sev sev-medium" aria-label="{medium} medium">{medium}</span>{/if}
              {#if low > 0}<span class="sev sev-low" aria-label="{low} low">{low}</span>{/if}
            </span>
          {/if}
        </td>
        {#if pkg?.ecosystem === 'oci'}
          <td class="tag-cell">
            {#if g.tags?.length > 0}
              {#each g.tags as tag (tag)}
                <span class="badge tag-badge">{tag}</span>
              {/each}
            {:else}
              <span class="text-muted">—</span>
            {/if}
          </td>
        {/if}
        <td class="text-center latest-cell">
          <!-- When the upstream latest is known, every row resolves to current (check) or behind (x);
               the dash is reserved for packages with no upstream baseline to compare against. -->
          {#if pkg?.upstreamLatestVersion && g.version === pkg.upstreamLatestVersion}
            <svg class="latest-yes" width="14" height="14" role="img" aria-label={$t('versionDetail.latestCell.isLatest')}><use href="/icons.svg#icon-check"/></svg>
          {:else if pkg?.upstreamLatestVersion}
            <svg class="latest-no" width="14" height="14" role="img" aria-label={$t('versionDetail.latestCell.behind')}><use href="/icons.svg#icon-x"/></svg>
          {:else}
            <span class="text-muted" aria-label={$t('versionDetail.latestCell.unknown')}>—</span>
          {/if}
        </td>
        <td class="nowrap">
          {#if pkg}
            <span class="badge {pkg.isProxy ? 'proxy' : 'hosted'}">
              {pkg.isProxy ? $t('packages.proxy') : $t('packages.hosted')}
            </span>
          {/if}
        </td>
        {#if g.single}
          <td class="mono checksum-cell nowrap" title={g.checksumSha256 ?? ''}>{g.checksumSha256?.slice(0,8) ?? '—'}…</td>
        {:else}
          <td class="checksum-cell nowrap text-muted" title={$t('versionDetail.multiFileHint')}>—</td>
        {/if}
        <td class="nowrap">{$formatBytes(g.sizeBytes)}</td>
        <td class="nowrap text-muted">{$formatDate(g.createdAt)}</td>
        <td class="license-cell">
          {#if g.licenses?.length > 0}
            {g.licenses.join(', ')}
          {:else}
            <span class="text-muted">—</span>
          {/if}
        </td>
        <td class="nowrap num-col">{$formatNumber(g.downloadCount)}</td>
        <td>
          {#if g.isMalicious}
            <span class="status-badge status-malicious" title={$t('versionDetail.status.maliciousHelp')}>
              <svg width="11" height="11" aria-hidden="true"><use href="/icons.svg#icon-alert"/></svg>
              {$t('versionDetail.status.malicious')}
            </span>
          {/if}
          {#if g.status}
            <span class="status-badge status-{g.status}">{$t(`versionDetail.status.${g.status}`)}</span>
          {/if}
        </td>
        <td>
          {#if isAdmin || g.single}
            <button
              class="kebab-btn"
              on:click={(e) => toggleActions(g.id, e)}
              aria-label={$t('versionDetail.actionsMenu.open')}
              aria-haspopup="true"
              aria-expanded={openActionsId === g.id}
            >⋯</button>
          {/if}
        </td>
      </tr>

      {#if isExpanded}
        <tr class="detail-row">
          <td colspan={pkg?.ecosystem === 'oci' ? 11 : 10}>
            <div class="detail-panel">
              {#if !g.single}
                <div class="files-section">
                  <span class="detail-label">{$t('versionDetail.detail.files')}</span>
                  <table class="files-table">
                    <thead>
                      <tr>
                        <th>{$t('versionDetail.files.name')}</th>
                        <th>{$t('versionDetail.files.type')}</th>
                        <th>{$t('versionDetail.columns.checksum')}</th>
                        <th>{$t('versionDetail.columns.size')}</th>
                        <th class="num-col">{$t('versionDetail.columns.downloads')}</th>
                        <th></th>
                      </tr>
                    </thead>
                    <tbody>
                      {#each g.files as f (f.id)}
                        <tr>
                          <td class="mono filename-cell">{f.filename ?? '—'}</td>
                          <td><span class="badge file-type">{fileType(f.filename)}</span></td>
                          <td class="checksum-cell">
                            {#if f.checksumSha256}
                              <span class="checksum-inline">
                                <code class="mono checksum-full">{f.checksumSha256}</code>
                                <button class="copy-btn" on:click|stopPropagation={() => copy(f.checksumSha256)}>{$t('versionDetail.detail.copy')}</button>
                              </span>
                            {:else}
                              <span class="text-muted">—</span>
                            {/if}
                          </td>
                          <td class="nowrap">{$formatBytes(f.sizeBytes)}</td>
                          <td class="nowrap num-col">{$formatNumber(f.downloadCount)}</td>
                          <td class="text-right">
                            <button class="file-dl-btn" on:click|stopPropagation={() => fire('download', { version: g.version, file: f.filename })}>{$t('versionDetail.actionsMenu.download')}</button>
                          </td>
                        </tr>
                      {/each}
                    </tbody>
                  </table>
                </div>
              {/if}

              <div class="detail-section">
                <span class="detail-label">{$t('versionDetail.detail.purl')}</span>
                <code class="detail-value mono">{g.purl}</code>
                <button class="copy-btn" on:click={() => copy(g.purl)}>{$t('versionDetail.detail.copy')}</button>
              </div>

              {#if g.single && g.checksumSha256}
                <div class="detail-section">
                  <span class="detail-label">{$t('versionDetail.detail.checksum')}</span>
                  <code class="detail-value mono">{g.checksumSha256}</code>
                  <button class="copy-btn" on:click={() => copy(g.checksumSha256)}>{$t('versionDetail.detail.copy')}</button>
                </div>
              {/if}

              {#if g.single && (g.upstreamIntegrityValue || (pkg?.ecosystem === 'npm' && g.origin === 'proxy' && g.checksumSha1))}
                {@const showNpmShasum = pkg?.ecosystem === 'npm' && g.origin === 'proxy' && g.checksumSha1}
                {#if g.upstreamIntegrityValue}
                  <div class="detail-section">
                    <span class="detail-label">{$t(`versionDetail.detail.upstreamIntegrity.${g.upstreamIntegrityAlgorithm}`)}</span>
                    <code class="detail-value mono">{g.upstreamIntegrityValue}</code>
                    <button class="copy-btn" on:click={() => copy(g.upstreamIntegrityValue)}>{$t('versionDetail.detail.copy')}</button>
                  </div>
                {/if}
                {#if showNpmShasum}
                  <div class="detail-section">
                    <span class="detail-label">{$t('versionDetail.detail.upstreamIntegrity.shasum')}</span>
                    <code class="detail-value mono">{g.checksumSha1}</code>
                    <button class="copy-btn" on:click={() => copy(g.checksumSha1)}>{$t('versionDetail.detail.copy')}</button>
                  </div>
                {/if}
              {/if}

              <div class="detail-section">
                <span class="detail-label">{$t('versionDetail.detail.published')}</span>
                <span class="detail-value text-muted">
                  {g.publishedAt ? $formatDate(g.publishedAt) : '—'}
                </span>
              </div>

              <div class="detail-section">
                <span class="detail-label">{$t('versionDetail.detail.vulnScan')}</span>
                <span class="detail-value text-muted">
                  {g.vulnCheckedAt ? $formatDate(g.vulnCheckedAt) : $t('versionDetail.vulnNever')}
                </span>
              </div>

              <div class="detail-section">
                <span class="detail-label">{$t('versionDetail.detail.vulns')}</span>
                {#if vulns.length === 0}
                  <span class="detail-empty">{$t('versionDetail.detail.noVulns')}</span>
                {:else}
                  <div class="vuln-list">
                    {#each vulns as v (v.osvId)}
                      <VulnerabilityRow vuln={v} />
                    {/each}
                  </div>
                {/if}
              </div>
            </div>
          </td>
        </tr>
      {/if}
    {/each}
  </tbody>
  {/if}
</table>

{#if openActionsId !== null}
  {@const g = groups.find(v => v.id === openActionsId)}
  {#if g}
    <div class="actions-popover" style:top="{popoverPos.top}px" style:left="{popoverPos.left}px">
      <!-- Download is available to every viewer. For a multi-file version each file downloads
           from its own row in the expanded panel, so the version-level menu only offers
           download when the version maps to a single file. -->
      {#if g.single}
        <button class="popover-item" on:click|stopPropagation={() => fire('download', { version: g.version })}>{$t('versionDetail.actionsMenu.download')}</button>
      {/if}
      {#if isAdmin}
        {#if g.single}<div class="popover-divider"></div>{/if}
        <button
          class="popover-item"
          on:click|stopPropagation={() => fire('rescan', g)}
          disabled={scanningId === g.id || scanCooldownRemaining(g) > 0}
          title={scanCooldownRemaining(g) > 0 ? $t('versionDetail.rescanCooldown', { values: { minutes: Math.ceil(scanCooldownRemaining(g)/60000) } }) : $t('versionDetail.rescanTitle')}
        >{scanningId === g.id ? $t('versionDetail.rescanning') : $t('versionDetail.actionsMenu.rescan')}</button>
        <button
          class="popover-item"
          on:click|stopPropagation={() => fire('block', g)}
          disabled={g.status === 'blocked'}
          title={g.status === 'blocked' ? $t('versionDetail.blockDisabledTitle') : ''}
        >{$t('versionDetail.actionsMenu.block')}</button>
        <button
          class="popover-item"
          on:click|stopPropagation={() => fire('unblock', g)}
          disabled={g.status !== 'blocked'}
          title={g.status !== 'blocked' ? $t('versionDetail.unblockDisabledTitle') : ''}
        >{$t('versionDetail.actionsMenu.unblock')}</button>
        <div class="popover-divider"></div>
        <button class="popover-item danger" on:click|stopPropagation={() => fire('delete', g)}>{$t('versionDetail.actionsMenu.delete')}</button>
      {/if}
    </div>
  {/if}
{/if}

<style>
  .first-fetch-row td { background: var(--badge-warning-bg) !important; color: var(--badge-warning-text); }
  .expanded-row td { background: var(--surface2); }

  .inline-vulns {
    display: inline-flex;
    gap: 3px;
    margin-left: 6px;
    vertical-align: middle;
    white-space: nowrap;
  }

  .nowrap { white-space: nowrap; }
  .version-cell { overflow-wrap: anywhere; }
  .version-cell .mono { font-size: 12px; }
  .checksum-cell { font-size: 11px; color: var(--text2); }
  .license-cell { font-size: 12px; overflow-wrap: anywhere; }
  .versions-table .col-version   { width: 180px; }
  .versions-table .col-tag       { width: 140px; }
  .versions-table .col-latest    { width: 70px; }
  .versions-table .col-origin    { width: 90px; }
  .versions-table .col-checksum  { width: 100px; }
  .versions-table .col-size      { width: 80px; }
  .versions-table .col-pushed    { width: 150px; }
  .versions-table .col-license   { width: 120px; }
  .versions-table .col-downloads { width: 100px; }
  .versions-table .col-status    { width: 100px; }
  .versions-table .col-actions   { width: 60px; }
  .num-col { text-align: right; font-variant-numeric: tabular-nums; }
  .text-right { text-align: right; }
  .tag-cell { font-size: 12px; overflow-wrap: anywhere; }
  .tag-badge { margin-right: 3px; margin-bottom: 2px; font-family: var(--font-mono, monospace); font-size: 11px; }
  .files-badge { background: var(--badge-sky-bg); color: var(--badge-sky-text); font-size: 11px; }
  .latest-cell { font-weight: 600; }
  .latest-yes { color: var(--success); }
  .latest-no { color: var(--danger); }

  .latest-banner {
    display: flex;
    align-items: center;
    gap: 6px;
    margin-bottom: 10px;
    padding: 7px 11px;
    border-radius: var(--radius);
    border: 1px solid var(--border);
    font-size: 13px;
  }
  .latest-banner svg { flex-shrink: 0; }
  .latest-banner-stale   { background: var(--badge-warning-bg); color: var(--badge-warning-text); }
  .latest-banner-current { background: var(--badge-hosted-bg);  color: var(--badge-hosted-text); }

  .detail-row td { padding: 0; border-top: none; }
  .copy-btn { padding: 1px 6px; font-size: 11px; flex-shrink: 0; }
  .vuln-list { display: flex; flex-direction: column; gap: 4px; flex: 1; }

  /* Per-file breakdown for multi-file versions (Maven jar/pom/sidecars, PyPI wheel/sdist). */
  .files-section { margin-bottom: 12px; }
  .files-table { width: 100%; border-collapse: collapse; margin-top: 4px; font-size: 12px; }
  .files-table th {
    text-align: left;
    font-weight: 600;
    font-size: 11px;
    color: var(--text2);
    text-transform: uppercase;
    letter-spacing: 0.02em;
    padding: 2px 8px;
    border-bottom: 1px solid var(--border);
  }
  .files-table td { padding: 4px 8px; border-bottom: 1px solid var(--border); }
  .files-table tr:last-child td { border-bottom: none; }
  .filename-cell { overflow-wrap: anywhere; }
  /* Full per-file checksum with an inline copy button; the hash wraps rather than truncating. */
  .checksum-inline { display: inline-flex; align-items: center; gap: 6px; }
  .checksum-full { font-size: 11px; color: var(--text2); overflow-wrap: anywhere; }
  .file-type {
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 0.03em;
    background: var(--bg3);
    color: var(--text2);
  }
  .file-dl-btn { padding: 2px 10px; font-size: 11px; white-space: nowrap; }

  .status-badge {
    display: inline-flex;
    align-items: center;
    gap: 3px;
    padding: 2px 8px;
    border-radius: 999px;
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.02em;
  }
  .status-blocked    { background: var(--badge-red-bg);    color: var(--badge-red-text); }
  .status-allowed    { background: var(--badge-sky-bg);    color: var(--badge-sky-text); }
  .status-vulnerable { background: var(--badge-warning-bg); color: var(--badge-warning-text); }
  .status-deprecated { background: var(--badge-warning-bg); color: var(--badge-warning-text); }
  .status-clean      { background: var(--badge-hosted-bg); color: var(--badge-hosted-text); }
  .status-unscanned  { background: var(--badge-warning-bg);  color: var(--badge-warning-text); }
  /* Known-malicious: the strongest danger signal in the table. A filled red pill (not the
     muted --badge-red-bg tint) so it dominates whatever gate status sits beside it. */
  .status-malicious {
    background: var(--danger);
    color: var(--on-accent);
    margin-right: 4px;
  }
  .status-th { white-space: nowrap; }

  .kebab-btn {
    background: transparent;
    border: 1px solid transparent;
    border-radius: 4px;
    padding: 2px 8px;
    font-size: 16px;
    line-height: 1;
    cursor: pointer;
    color: var(--text2);
  }
  .kebab-btn:hover { background: var(--bg3); color: var(--text); }

  .actions-popover {
    position: fixed;
    z-index: 1000;
    min-width: 160px;
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    box-shadow: var(--shadow);
    padding: 4px 0;
  }
  .popover-item {
    display: block;
    width: 100%;
    text-align: left;
    background: transparent;
    border: none;
    padding: 6px 12px;
    font-size: 13px;
    color: var(--text);
    cursor: pointer;
  }
  .popover-item:hover:not(:disabled) { background: var(--bg3); }
  .popover-item:disabled { color: var(--text2); cursor: not-allowed; }
  .popover-item.danger { color: var(--badge-red-text); }
  .popover-divider {
    height: 1px;
    margin: 4px 0;
    background: var(--border);
  }
</style>
