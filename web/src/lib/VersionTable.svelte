<!--
  Version table extracted from VersionDetail.svelte. Owns the table's local UI
  state — sort col/dir, which row is expanded, which row's actions popover is open,
  popover position — and renders the row + the expanded detail panel + the actions
  popover itself. Parent passes the data and the action handlers and supplies the
  copy helper.

  Severity badges in the expanded detail panel come from VulnerabilityRow.svelte
  (extracted in 7660c04); UNSCORED / NO CVSS labelling is preserved there
  intentionally (security-UI uncertainty surface).
-->
<script>
  import { createEventDispatcher } from 'svelte'
  import { t } from 'svelte-i18n'
  import VulnerabilityRow from './VulnerabilityRow.svelte'
  import { formatDate, formatBytes } from './format.js'
  import { sortIndicator } from './sortIndicator.js'

  /** @type {{ ecosystem: string, isProxy: boolean, name: string } | null} */
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
  let expandedPurl = null
  let openActionsId = null
  let popoverPos = { top: 0, left: 0 }

  $: sortedVersions = [...versions].sort((a, b) => {
    let cmp = 0
    if (sortCol === 'version')  cmp = a.version.localeCompare(b.version, undefined, { numeric: true, sensitivity: 'base' })
    else if (sortCol === 'size')      cmp = a.sizeBytes - b.sizeBytes
    else if (sortCol === 'pushed')    cmp = new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime()
    else if (sortCol === 'checksum')  cmp = (a.checksumSha256 ?? '').localeCompare(b.checksumSha256 ?? '')
    else if (sortCol === 'license')   cmp = (a.licenses?.join(', ') ?? '').localeCompare(b.licenses?.join(', ') ?? '')
    else if (sortCol === 'published') cmp = (a.publishedAt ?? '').localeCompare(b.publishedAt ?? '')
    else if (sortCol === 'status')    cmp = (a.status ?? '').localeCompare(b.status ?? '')
    return sortDir === 'asc' ? cmp : -cmp
  })

  function toggleSort(col) {
    if (sortCol === col) sortDir = sortDir === 'asc' ? 'desc' : 'asc'
    else { sortCol = col; sortDir = 'desc' }
  }

  function toggleExpand(purl) {
    expandedPurl = expandedPurl === purl ? null : purl
  }

  /** Reset state when the package or selected version churns (parent reloads after action). */
  export function reset() {
    expandedPurl = null
    openActionsId = null
  }

  function severityOrder(s) {
    return { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 }[s] ?? 4
  }

  function toggleActions(verId, e) {
    e.stopPropagation()
    if (openActionsId === verId) { openActionsId = null; return }
    const rect = e.currentTarget.getBoundingClientRect()
    const POPOVER_WIDTH = 160
    popoverPos = {
      top: rect.bottom + 4,
      left: Math.max(8, rect.right - POPOVER_WIDTH),
    }
    openActionsId = verId
  }

  function handleWindowClick(e) {
    if (openActionsId === null) return
    if (e.target?.closest && (e.target.closest('.actions-popover') || e.target.closest('.kebab-btn'))) return
    openActionsId = null
  }

  function fire(name, ver) {
    openActionsId = null
    dispatch(name, ver)
  }
</script>

<svelte:window on:click={handleWindowClick} />

<table class="table-auto versions-table">
  <colgroup>
    <col class="col-version">
    <col class="col-origin">
    <col class="col-checksum">
    <col class="col-size">
    <col class="col-pushed">
    <col class="col-license">
    <col class="col-published">
    <col class="col-status">
    <col class="col-actions">
  </colgroup>
  <thead>
    <tr>
      <th class="sortable" on:click={() => toggleSort('version')}>{$t('versionDetail.columns.version')}{sortIndicator('version', sortCol, sortDir)}</th>
      <th>{$t('versionDetail.columns.origin')}</th>
      <th class="sortable" on:click={() => toggleSort('checksum')}>{$t('versionDetail.columns.checksum')}{sortIndicator('checksum', sortCol, sortDir)}</th>
      <th class="sortable" on:click={() => toggleSort('size')}>{$t('versionDetail.columns.size')}{sortIndicator('size', sortCol, sortDir)}</th>
      <th class="sortable" on:click={() => toggleSort('pushed')}>{$t('versionDetail.columns.pushed')}{sortIndicator('pushed', sortCol, sortDir)}</th>
      <th class="sortable" on:click={() => toggleSort('license')}>{$t('versionDetail.columns.license')}{sortIndicator('license', sortCol, sortDir)}</th>
      <th class="sortable" on:click={() => toggleSort('published')}>{$t('versionDetail.columns.published')}{sortIndicator('published', sortCol, sortDir)}</th>
      <th class="sortable" on:click={() => toggleSort('status')}>{$t('versionDetail.columns.status')}{sortIndicator('status', sortCol, sortDir)}</th>
      <th>{$t('versionDetail.columns.actions')}</th>
    </tr>
  </thead>
  {#if loading}
    <tbody>
      {#each [0,1,2,3,4] as i (i)}
        <tr><td colspan="9"><span class="skeleton"></span></td></tr>
      {/each}
    </tbody>
  {:else}
  <tbody>
    {#each sortedVersions as ver (ver.id)}
      {@const vulns = (vulnsByPurl.get(ver.purl) ?? []).slice().sort((a, b) => severityOrder(a.severity) - severityOrder(b.severity))}
      {@const isExpanded = expandedPurl === ver.purl}
      <tr
        class:first-fetch-row={ver.firstFetch}
        class:expanded-row={isExpanded}
        class="cursor-pointer"
        on:click={() => toggleExpand(ver.purl)}
      >
        <td>
          <strong>{ver.version}</strong>
          {#if ver.yanked}<span class="badge yanked ml-1">{$t('versionDetail.badges.yanked')}</span>{/if}
          {#if ver.deprecated}<span class="badge deprecated ml-1" title={ver.deprecated}>{$t('versionDetail.badges.deprecated')}</span>{/if}
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
        <td class="nowrap">
          {#if pkg}
            <span class="badge {pkg.isProxy ? 'proxy' : 'hosted'}">
              {pkg.isProxy ? $t('packages.proxy') : $t('packages.hosted')}
            </span>
          {/if}
        </td>
        <td class="mono checksum-cell nowrap" title={ver.checksumSha256 ?? ''}>{ver.checksumSha256?.slice(0,8) ?? '—'}…</td>
        <td class="nowrap">{$formatBytes(ver.sizeBytes)}</td>
        <td class="nowrap text-muted">{$formatDate(ver.createdAt)}</td>
        <td class="license-cell">
          {#if ver.licenses?.length > 0}
            {ver.licenses.join(', ')}
          {:else}
            <span class="text-muted">—</span>
          {/if}
        </td>
        <td class="nowrap">
          {#if ver.publishedAt}
            <span class="text-muted t-xs">{$formatDate(ver.publishedAt)}</span>
          {:else}
            <span class="text-muted">—</span>
          {/if}
        </td>
        <td>
          {#if ver.status}
            <span class="status-badge status-{ver.status}">{$t(`versionDetail.status.${ver.status}`)}</span>
          {/if}
        </td>
        <td>
          <button
            class="kebab-btn"
            on:click={(e) => toggleActions(ver.id, e)}
            aria-label={$t('versionDetail.actionsMenu.open')}
            aria-haspopup="true"
            aria-expanded={openActionsId === ver.id}
          >⋯</button>
        </td>
      </tr>

      {#if isExpanded}
        <tr class="detail-row">
          <td colspan="9">
            <div class="detail-panel">
              <div class="detail-section">
                <span class="detail-label">{$t('versionDetail.detail.purl')}</span>
                <code class="detail-value mono">{ver.purl}</code>
                <button class="copy-btn" on:click={() => copy(ver.purl)}>{$t('versionDetail.detail.copy')}</button>
              </div>

              {#if ver.checksumSha256}
                <div class="detail-section">
                  <span class="detail-label">{$t('versionDetail.detail.checksum')}</span>
                  <code class="detail-value mono">{ver.checksumSha256}</code>
                  <button class="copy-btn" on:click={() => copy(ver.checksumSha256)}>{$t('versionDetail.detail.copy')}</button>
                </div>
              {/if}

              {#if ver.upstreamIntegrityValue || (pkg?.ecosystem === 'npm' && ver.origin === 'proxy' && ver.checksumSha1)}
                {@const showNpmShasum = pkg?.ecosystem === 'npm' && ver.origin === 'proxy' && ver.checksumSha1}
                {#if ver.upstreamIntegrityValue}
                  <div class="detail-section">
                    <span class="detail-label">{$t(`versionDetail.detail.upstreamIntegrity.${ver.upstreamIntegrityAlgorithm}`)}</span>
                    <code class="detail-value mono">{ver.upstreamIntegrityValue}</code>
                    <button class="copy-btn" on:click={() => copy(ver.upstreamIntegrityValue)}>{$t('versionDetail.detail.copy')}</button>
                  </div>
                {/if}
                {#if showNpmShasum}
                  <div class="detail-section">
                    <span class="detail-label">{$t('versionDetail.detail.upstreamIntegrity.shasum')}</span>
                    <code class="detail-value mono">{ver.checksumSha1}</code>
                    <button class="copy-btn" on:click={() => copy(ver.checksumSha1)}>{$t('versionDetail.detail.copy')}</button>
                  </div>
                {/if}
              {/if}

              <div class="detail-section">
                <span class="detail-label">{$t('versionDetail.detail.vulnScan')}</span>
                <span class="detail-value text-muted">
                  {ver.vulnCheckedAt ? $formatDate(ver.vulnCheckedAt) : $t('versionDetail.vulnNever')}
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
  {@const ver = versions.find(v => v.id === openActionsId)}
  {#if ver}
    <div class="actions-popover" style:top="{popoverPos.top}px" style:left="{popoverPos.left}px">
      <!-- Download is available to every viewer; the admin-only actions below are gated. -->
      <button class="popover-item" on:click|stopPropagation={() => fire('download', ver)}>{$t('versionDetail.actionsMenu.download')}</button>
      {#if isAdmin}
        <div class="popover-divider"></div>
        <button
          class="popover-item"
          on:click|stopPropagation={() => fire('rescan', ver)}
          disabled={scanningId === ver.id || scanCooldownRemaining(ver) > 0}
          title={scanCooldownRemaining(ver) > 0 ? $t('versionDetail.rescanCooldown', { values: { minutes: Math.ceil(scanCooldownRemaining(ver)/60000) } }) : $t('versionDetail.rescanTitle')}
        >{scanningId === ver.id ? $t('versionDetail.rescanning') : $t('versionDetail.actionsMenu.rescan')}</button>
        <button
          class="popover-item"
          on:click|stopPropagation={() => fire('block', ver)}
          disabled={ver.status === 'blocked'}
          title={ver.status === 'blocked' ? $t('versionDetail.blockDisabledTitle') : ''}
        >{$t('versionDetail.actionsMenu.block')}</button>
        <button
          class="popover-item"
          on:click|stopPropagation={() => fire('unblock', ver)}
          disabled={ver.status !== 'blocked'}
          title={ver.status !== 'blocked' ? $t('versionDetail.unblockDisabledTitle') : ''}
        >{$t('versionDetail.actionsMenu.unblock')}</button>
        <div class="popover-divider"></div>
        <button class="popover-item danger" on:click|stopPropagation={() => fire('delete', ver)}>{$t('versionDetail.actionsMenu.delete')}</button>
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
  .checksum-cell { font-size: 11px; color: var(--text2); }
  .license-cell { font-size: 12px; overflow-wrap: anywhere; }
  .versions-table .col-version   { width: 180px; }
  .versions-table .col-origin    { width: 90px; }
  .versions-table .col-checksum  { width: 100px; }
  .versions-table .col-size      { width: 80px; }
  .versions-table .col-pushed    { width: 150px; }
  .versions-table .col-license   { width: 120px; }
  .versions-table .col-published { width: 150px; }
  .versions-table .col-status    { width: 100px; }
  .versions-table .col-actions   { width: 60px; }

  .detail-row td { padding: 0; border-top: none; }
  .copy-btn { padding: 1px 6px; font-size: 11px; flex-shrink: 0; }
  .vuln-list { display: flex; flex-direction: column; gap: 4px; flex: 1; }

  .status-badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 999px;
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.02em;
  }
  .status-blocked   { background: var(--badge-red-bg);    color: var(--badge-red-text); }
  .status-allowed   { background: var(--badge-sky-bg);    color: var(--badge-sky-text); }
  .status-clean     { background: var(--badge-hosted-bg); color: var(--badge-hosted-text); }
  .status-unscanned { background: var(--badge-warning-bg);  color: var(--badge-warning-text); }

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
