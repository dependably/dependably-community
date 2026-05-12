<script>
  import { SvelteMap } from 'svelte/reactivity'
  import { t } from 'svelte-i18n'
  import { api } from '../lib/api.js'
  import { route, navigate, user } from '../lib/store.js'
  import { formatDate, formatBytes } from '../lib/format.js'
  import { copyToClipboard } from '../lib/clipboard.js'
  import { sortIndicator } from '../lib/sortIndicator.js'

  $: params = $route.params
  let pkg = null, versions = [], loading = true, error = ''
  // #47 claim badge: surface the resolved claim state on the package header. null = no
  // claim row (implicit unclaimed in connected mode, implicit local_only in air-gap).
  let claim = null
  let scanningId = null, scanError = ''
  let vulnsByPurl = new SvelteMap()
  let expandedPurl = null
  let sortCol = 'pushed', sortDir = 'desc'
  let openActionsId = null
  let popoverPos = { top: 0, left: 0 }

  $: sortedVersions = [...versions].sort((a, b) => {
    let cmp = 0
    if (sortCol === 'version')  cmp = a.version.localeCompare(b.version, undefined, { numeric: true, sensitivity: 'base' })
    else if (sortCol === 'size')     cmp = a.sizeBytes - b.sizeBytes
    else if (sortCol === 'pushed')   cmp = new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime()
    else if (sortCol === 'checksum') cmp = (a.checksumSha256 ?? '').localeCompare(b.checksumSha256 ?? '')
    else if (sortCol === 'license')  cmp = (a.licenses?.join(', ') ?? '').localeCompare(b.licenses?.join(', ') ?? '')
    else if (sortCol === 'purl')     cmp = (a.purl ?? '').localeCompare(b.purl ?? '')
    else if (sortCol === 'vulnScan') cmp = (a.vulnCheckedAt ?? '').localeCompare(b.vulnCheckedAt ?? '')
    else if (sortCol === 'status')   cmp = (a.status ?? '').localeCompare(b.status ?? '')
    return sortDir === 'asc' ? cmp : -cmp
  })

  function toggleSort(col) {
    if (sortCol === col) sortDir = sortDir === 'asc' ? 'desc' : 'asc'
    else { sortCol = col; sortDir = 'desc' }
  }


  $: if (params.ecosystem && params.name) load()

  async function load() {
    loading = true
    expandedPurl = null
    try {
      const data = await api.getPackage(params.ecosystem, params.name)
      pkg = data.package
      versions = data.versions
      // Resolve claim state (admin-only API; ignore on permission failures).
      try {
        claim = await api.getClaim(params.ecosystem, params.name)
      } catch { claim = null }
      // Fetch vulns for this package (supplemental — ignore errors)
      try {
        const vulnData = await api.getVulnReport({
          ecosystem: params.ecosystem,
          name: params.name,
          limit: 200
        })
        vulnsByPurl = buildVulnMap(vulnData.items || [])
      } catch { /* supplemental, ignore */ }
    } catch (e) {
      error = e.message
    } finally {
      loading = false
    }
  }

  function buildVulnMap(items) {
    const map = new SvelteMap()
    for (const r of items) {
      if (!map.has(r.purl)) map.set(r.purl, [])
      if (r.osvId) map.get(r.purl).push({ osvId: r.osvId, severity: r.severity, summary: r.summary, cvssScore: r.cvssScore })
    }
    return map
  }

  function severityOrder(s) {
    return { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 }[s] ?? 4
  }

  function toggleExpand(purl) {
    expandedPurl = expandedPurl === purl ? null : purl
  }

  async function deleteVersion(ver) {
    if (!confirm($t('versionDetail.deleteTitle', { values: { version: ver.version } }))) return
    await api.deleteVersion(params.ecosystem, params.name, ver.version)
    versions = versions.filter(v => v.id !== ver.id)
    if (expandedPurl === ver.purl) expandedPurl = null
  }

  async function rescan(ver) {
    scanningId = ver.id; scanError = ''
    openActionsId = null
    try {
      const res = await api.rescanVersion(params.ecosystem, params.name, ver.version)
      versions = versions.map(v => v.id === ver.id ? { ...v, vulnCheckedAt: res.vuln_checked_at } : v)
      // Refresh vuln data after rescan
      try {
        const vulnData = await api.getVulnReport({
          ecosystem: params.ecosystem,
          name: params.name,
          limit: 200
        })
        vulnsByPurl = buildVulnMap(vulnData.items || [])
      } catch { /* supplemental, ignore */ }
      await load()
    } catch (e) {
      scanError = e.message
    } finally {
      scanningId = null
    }
  }

  async function blockVersion(ver) {
    openActionsId = null
    try {
      await api.blockVersion(params.ecosystem, params.name, ver.version)
      await load()
    } catch (e) { error = e.message }
  }

  async function unblockVersion(ver) {
    openActionsId = null
    try {
      await api.unblockVersion(params.ecosystem, params.name, ver.version)
      await load()
    } catch (e) { error = e.message }
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

  function scanCooldownRemaining(ver) {
    if (!ver.vulnCheckedAt) return 0
    const elapsed = Date.now() - new Date(ver.vulnCheckedAt).getTime()
    return Math.max(0, 3600000 - elapsed)
  }

  function copy(text) {
    copyToClipboard(text)
  }

  $: isAdmin = $user?.role === 'admin' || $user?.role === 'owner'
</script>

<svelte:window on:click={handleWindowClick} />

<div class="page">
  <div class="page-header">
    <div>
      <button on:click={() => {
        // history.state.idx === 0 means we're at the seated initial entry; history.back()
        // would leave the SPA. Anything > 0 means we pushed our way here, so back is safe.
        if ((window.history.state?.idx ?? 0) > 0) window.history.back()
        else navigate('packages', {}, { replace: true })
      }} class="mb-2">{$t('common.actions.back')}</button>
      {#if pkg}
        <h1 class="page-title">
          <span class="badge {pkg.ecosystem}">{pkg.ecosystem}</span>
          {pkg.name}
          {#if claim && (claim.state === 'local_only' || claim.state === 'mixed')}
            <span
              class="claim-badge claim-{claim.state}"
              title={$t(`claims.states.${claim.state}`) + (claim.isImplicit ? ' (implicit)' : '')}
              aria-label={claim.state}>
              {#if claim.state === 'local_only'}
                <svg width="12" height="12" aria-hidden="true"><use href="/icons.svg#icon-lock"/></svg>
              {:else}
                <svg width="12" height="12" aria-hidden="true"><use href="/icons.svg#icon-exchange"/></svg>
              {/if}
              {$t(`claims.states.${claim.state}`)}
            </span>
          {/if}
        </h1>
      {/if}
    </div>
  </div>

  {#if error}<div class="page-error">{error}</div>{/if}
  {#if scanError}<div class="error-msg">{scanError}</div>{/if}
  {#if !loading && versions.length === 0}
    <p class="text-muted">{$t('versionDetail.empty')}</p>
  {:else}
    <table class="table-auto versions-table">
      <colgroup>
        <col class="col-version"><!-- version + badges + inline vulns -->
        <col class="col-origin"><!-- origin badge -->
        <col class="col-checksum"><!-- checksum -->
        <col class="col-size"><!-- size -->
        <col class="col-pushed"><!-- pushed -->
        <col class="col-license"><!-- license -->
        <col><!-- purl: takes leftover -->
        <col class="col-vulnscan"><!-- vulnScan: date only -->
        <col class="col-status"><!-- status badge -->
        <col class="col-actions"><!-- actions kebab -->
      </colgroup>
      <thead>
        <tr>
          <th class="sortable" on:click={() => toggleSort('version')}>{$t('versionDetail.columns.version')}{sortIndicator('version', sortCol, sortDir)}</th>
          <th>{$t('versionDetail.columns.origin')}</th>
          <th class="sortable" on:click={() => toggleSort('checksum')}>{$t('versionDetail.columns.checksum')}{sortIndicator('checksum', sortCol, sortDir)}</th>
          <th class="sortable" on:click={() => toggleSort('size')}>{$t('versionDetail.columns.size')}{sortIndicator('size', sortCol, sortDir)}</th>
          <th class="sortable" on:click={() => toggleSort('pushed')}>{$t('versionDetail.columns.pushed')}{sortIndicator('pushed', sortCol, sortDir)}</th>
          <th class="sortable" on:click={() => toggleSort('license')}>{$t('versionDetail.columns.license')}{sortIndicator('license', sortCol, sortDir)}</th>
          <th class="sortable" on:click={() => toggleSort('purl')}>{$t('versionDetail.columns.purl')}{sortIndicator('purl', sortCol, sortDir)}</th>
          <th class="sortable" on:click={() => toggleSort('vulnScan')}>{$t('versionDetail.columns.vulnScan')}{sortIndicator('vulnScan', sortCol, sortDir)}</th>
          <th class="sortable" on:click={() => toggleSort('status')}>{$t('versionDetail.columns.status')}{sortIndicator('status', sortCol, sortDir)}</th>
          <th>{$t('versionDetail.columns.actions')}</th>
        </tr>
      </thead>
      {#if loading}
        <tbody>
          {#each [0,1,2,3,4] as i (i)}
            <tr><td colspan="10"><span class="skeleton"></span></td></tr>
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
            <td class="mono purl-cell" title={ver.purl}>{ver.purl}</td>
            <td class="nowrap">
              {#if ver.vulnCheckedAt}
                <span class="text-muted t-xs">{$formatDate(ver.vulnCheckedAt)}</span>
              {:else}
                <span class="text-muted t-xs">{$t('versionDetail.vulnNever')}</span>
              {/if}
            </td>
            <td>
              {#if ver.status}
                <span class="status-badge status-{ver.status}">{$t(`versionDetail.status.${ver.status}`)}</span>
              {/if}
            </td>
            <td>
              {#if isAdmin}
                <button
                  class="kebab-btn"
                  on:click={(e) => toggleActions(ver.id, e)}
                  aria-label={$t('versionDetail.actionsMenu.open')}
                  aria-haspopup="true"
                  aria-expanded={openActionsId === ver.id}
                >⋯</button>
              {/if}
            </td>
          </tr>

          {#if isExpanded}
            <tr class="detail-row">
              <td colspan="10">
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

                  <div class="detail-section">
                    <span class="detail-label">{$t('versionDetail.detail.vulns')}</span>
                    {#if vulns.length === 0}
                      <span class="detail-empty">{$t('versionDetail.detail.noVulns')}</span>
                    {:else}
                      <div class="vuln-list">
                        {#each vulns as v (v.osvId)}
                          <div class="vuln-entry">
                            {#if v.severity}<span class="sev sev-{v.severity.toLowerCase()}">{v.severity}</span>{/if}
                            {#if v.cvssScore !== null && v.cvssScore !== undefined}<span class="vuln-score">{v.cvssScore.toFixed(1)}</span>{/if}
                            <a href="https://osv.dev/vulnerability/{v.osvId}" target="_blank" rel="noreferrer" on:click|stopPropagation>{v.osvId}</a>
                            {#if v.summary}<span class="vuln-summary">{v.summary}</span>{/if}
                          </div>
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
  {/if}

  {#if openActionsId !== null}
    {@const ver = versions.find(v => v.id === openActionsId)}
    {#if ver}
      <div class="actions-popover" style:top="{popoverPos.top}px" style:left="{popoverPos.left}px">
        <button
          class="popover-item"
          on:click|stopPropagation={() => rescan(ver)}
          disabled={scanningId === ver.id || scanCooldownRemaining(ver) > 0}
          title={scanCooldownRemaining(ver) > 0 ? $t('versionDetail.rescanCooldown', { values: { minutes: Math.ceil(scanCooldownRemaining(ver)/60000) } }) : $t('versionDetail.rescanTitle')}
        >{scanningId === ver.id ? $t('versionDetail.rescanning') : $t('versionDetail.actionsMenu.rescan')}</button>
        {#if ver.manualBlockState !== 'blocked'}
          <button class="popover-item" on:click|stopPropagation={() => blockVersion(ver)}>{$t('versionDetail.actionsMenu.block')}</button>
        {/if}
        {#if ver.manualBlockState !== 'allowed'}
          <button class="popover-item" on:click|stopPropagation={() => unblockVersion(ver)}>{$t('versionDetail.actionsMenu.unblock')}</button>
        {/if}
        <div class="popover-divider"></div>
        <button class="popover-item danger" on:click|stopPropagation={() => deleteVersion(ver)}>{$t('versionDetail.actionsMenu.delete')}</button>
      </div>
    {/if}
  {/if}
</div>

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
  .purl-cell { font-size: 11px; color: var(--text2); overflow-wrap: anywhere; }
  .license-cell { font-size: 12px; overflow-wrap: anywhere; }
  .versions-table .col-version  { width: 180px; }
  .versions-table .col-origin   { width: 90px; }
  .versions-table .col-checksum { width: 100px; }

  /* Origin badge — provenance at a glance per #45.
     Proxy: neutral (cached upstream); Imported: blue (operator-imported, #46); Private: green
     (privately published). High-contrast text on muted backgrounds; accessible labels via
     aria-label on the span. */
  .origin-badge {
    display: inline-block;
    padding: 1px 8px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.02em;
    text-transform: uppercase;
    line-height: 1.6;
  }
  .origin-proxy    { background: var(--bg2);          color: var(--text2); border: 1px solid var(--border); }
  .origin-imported { background: var(--info-bg); color: var(--info-text); border: 1px solid var(--info-border); }
  .origin-private  { background: var(--success-bg);  color: var(--success); border: 1px solid var(--success-border); }

  /* #47 claim badge: surfaces the resolved claim state on the package header. Visual
     hierarchy matches Claims.svelte's state-badge so the two views feel consistent. */
  .claim-badge {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 2px 10px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    margin-left: 8px;
    vertical-align: middle;
  }
  .claim-local_only { background: var(--success-bg);  color: var(--success); border: 1px solid var(--success-border); }
  .claim-mixed      { background: var(--warning-bg); color: var(--warning-text); border: 1px solid var(--warning-border); }
  .versions-table .col-size     { width: 80px; }
  .versions-table .col-pushed   { width: 150px; }
  .versions-table .col-license  { width: 120px; }
  .versions-table .col-vulnscan { width: 140px; }
  .versions-table .col-status   { width: 100px; }
  .versions-table .col-actions  { width: 60px; }
  .rescan-btn { padding: 2px 6px; font-size: 11px; margin-left: 4px; min-height: 28px; }
  .action-btn { padding: 3px 6px; font-size: 12px; min-height: 28px; }

  .detail-row td {
    padding: 0;
    border-top: none;
  }

  .copy-btn {
    padding: 1px 6px;
    font-size: 11px;
    flex-shrink: 0;
  }

  .vuln-list {
    display: flex;
    flex-direction: column;
    gap: 4px;
    flex: 1;
  }

  .vuln-entry {
    display: flex;
    align-items: baseline;
    gap: 6px;
    flex-wrap: wrap;
    font-size: 12px;
  }

  .vuln-summary {
    color: var(--text2);
  }

  .vuln-score {
    font-family: var(--mono);
    font-size: 11px;
    color: var(--text2);
  }

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
