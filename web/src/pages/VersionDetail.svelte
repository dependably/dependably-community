<script>
  import { SvelteMap } from 'svelte/reactivity'
  import { t } from 'svelte-i18n'
  import { api } from '../lib/api.js'
  import ErrorBanner from '../lib/ErrorBanner.svelte'
  import Skeleton from '../lib/Skeleton.svelte'
  import VersionTable from '../lib/VersionTable.svelte'
  import { navigate, user } from '../lib/store.js'
  import { reportPageLoad } from '../lib/pageLoad.js'
  import { copyToClipboard } from '../lib/clipboard.js'

  /**
   * The route params this page was mounted for, supplied by RouteView. Read as a prop rather than
   * from the `route` store because a deferred navigation mounts this page while the store still
   * names the page being left — asking the store would fetch the outgoing package.
   * @type {Record<string, any>}
   */
  export let params = {}

  /** The route transition this page was mounted for, supplied by RouteView. @type {number | null} */
  export let pageToken = null

  let pkg = null, versions = [], loading = true, error = ''
  // Claim badge: surface the resolved claim state on the package header. null = no
  // claim row (implicit unclaimed in connected mode, implicit local_only in air-gap).
  let claim = null
  let scanningId = null, scanError = ''
  let vulnsByPurl = new SvelteMap()
  let versionTable
  // Blocklisted SPDX identifiers (uppercased) for the license risk-pillar summary below.
  // Fetched once per page load from the existing license-policy endpoint — no new API surface.
  let licenseBlocklist = new Set()

  $: if (params.ecosystem && params.name) load()
  $: reportPageLoad(pageToken, loading)

  async function load() {
    loading = true
    versionTable?.reset()
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
      // License blocklist for the license risk-pillar summary (supplemental — ignore errors).
      try {
        const policy = await api.getLicensePolicy()
        licenseBlocklist = new Set((policy.blocklist || []).map(e => (e.licenseSpdx ?? '').toUpperCase()))
      } catch { licenseBlocklist = new Set() }
    } catch (e) {
      error = e.message
    } finally {
      loading = false
    }
  }

  // ── Three-pillar risk summary (Security / License / Operational) ─────────────

  const SEVERITY_RANK = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, UNKNOWN: 4 }

  // Worst (lowest-rank) severity across every advisory linked to any version in this package.
  // Null when no version carries an advisory.
  $: worstSeverity = [...vulnsByPurl.values()].flat().reduce((worst, v) => {
    const sev = v.severity || 'UNKNOWN'
    return worst === null || (SEVERITY_RANK[sev] ?? 5) < (SEVERITY_RANK[worst] ?? 5) ? sev : worst
  }, null)

  // Versions carrying either a blocklisted SPDX license or no extracted license at all —
  // mirrors the dashboard license-risk tile's definition (see PackageAnalyticsRepository).
  $: licenseRiskCount = versions.filter(v => {
    const licenses = v.licenses ?? []
    return licenses.length === 0 || licenses.some(l => licenseBlocklist.has((l ?? '').toUpperCase()))
  }).length

  // Worst (highest) known versions-behind count across every version. Null when every version's
  // count is unknown — never coerced to 0.
  $: operationalWorst = versions.reduce(
    (max, v) => v.versionsBehind !== null && v.versionsBehind !== undefined && (max === null || v.versionsBehind > max) ? v.versionsBehind : max,
    null)

  function buildVulnMap(items) {
    const map = new SvelteMap()
    for (const r of items) {
      if (!r.osvId) continue
      if (!map.has(r.purl)) map.set(r.purl, [])
      const list = map.get(r.purl)
      // Multi-file versions (Maven jar/pom, PyPI wheel/sdist) map several files to one purl, so the
      // vuln report returns the same advisory once per affected file. Collapse to one entry per
      // osvId so the per-version advisory list neither double-counts nor trips Svelte's keyed each.
      if (list.some(x => x.osvId === r.osvId)) continue
      list.push({ osvId: r.osvId, severity: r.severity, summary: r.summary, cvssScore: r.cvssScore })
    }
    return map
  }

  async function deleteVersion(ver) {
    if (!confirm($t('versionDetail.deleteTitle', { values: { version: ver.version } }))) return
    await api.deleteVersion(params.ecosystem, params.name, ver.version)
    // Delete acts on the whole release, so drop every file row sharing the version — a multi-file
    // version (Maven jar/pom, PyPI wheel/sdist) otherwise leaves its siblings stranded in the list.
    versions = versions.filter(v => v.version !== ver.version)
  }

  // `ver.file` is set when the event comes from a per-file row in a multi-file version's expanded
  // panel; absent for single-file versions, where the server serves the version's only artifact.
  async function downloadVersion(ver) {
    try {
      await api.downloadVersion(params.ecosystem, params.name, ver.version, ver.file)
    } catch (e) { error = e.message }
  }

  async function rescan(ver) {
    scanningId = ver.id; scanError = ''
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
    try {
      await api.blockVersion(params.ecosystem, params.name, ver.version)
      await load()
    } catch (e) { error = e.message }
  }

  async function unblockVersion(ver) {
    try {
      await api.unblockVersion(params.ecosystem, params.name, ver.version)
      await load()
    } catch (e) { error = e.message }
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

<div class="page page-fluid">
  <div class="page-header">
    <div>
      <button on:click={() => {
        // history.state.idx === 0 means we're at the seated initial entry; history.back()
        // would leave the SPA. Anything > 0 means we pushed our way here, so back is safe.
        if ((window.history.state?.idx ?? 0) > 0) window.history.back()
        else navigate('packages', {}, { replace: true })
      }} class="mb-2">{$t('common.actions.back')}</button>
      <!-- Ecosystem and name come from the route, so the title stands before the package
           fetch resolves and the table below it does not shift down when it lands. The
           fetched display name replaces the purl name in place. -->
      <h1 class="page-title">
        <span class="badge {pkg?.ecosystem ?? params.ecosystem}">{pkg?.ecosystem ?? params.ecosystem}</span>
        {pkg?.name ?? params.name}
        {#if claim && (claim.state === 'local_only' || claim.state === 'mixed')}
          <span
            class="badge has-icon state-{claim.state}"
            title={$t(`claims.states.${claim.state}`) + (claim.isImplicit ? ' (implicit)' : '')}
            aria-label={$t(`claims.states.${claim.state}`) + (claim.isImplicit ? ' (implicit)' : '')}>
            {#if claim.state === 'local_only'}
              <svg width="12" height="12" aria-hidden="true"><use href="/icons.svg#icon-lock"/></svg>
            {:else}
              <svg width="12" height="12" aria-hidden="true"><use href="/icons.svg#icon-exchange"/></svg>
            {/if}
            {$t(`claims.states.${claim.state}`)}
          </span>
        {/if}
      </h1>
      <!-- Rendered in both states and floored at two clamped description lines plus the link
           row, so the risk pillars and table below sit at the same offset before and after
           the fetch resolves. -->
      <div class="pkg-meta">
        {#if pkg?.description}
          <p class="pkg-description">{pkg.description}</p>
        {/if}
        {#if pkg?.homepage || pkg?.repositoryUrl}
          <div class="pkg-links">
            {#if pkg.homepage}
              <a class="pkg-link" href={pkg.homepage} target="_blank" rel="noopener noreferrer">
                <svg width="12" height="12" aria-hidden="true"><use href="/icons.svg#icon-external"/></svg>
                {$t('versionDetail.meta.homepage')}
              </a>
            {/if}
            {#if pkg.repositoryUrl}
              <a class="pkg-link" href={pkg.repositoryUrl} target="_blank" rel="noopener noreferrer">
                <svg width="12" height="12" aria-hidden="true"><use href="/icons.svg#icon-external"/></svg>
                {$t('versionDetail.meta.repository')}
              </a>
            {/if}
          </div>
        {/if}
      </div>
    </div>
  </div>

  <ErrorBanner message={error} />
  {#if scanError}<div class="error-msg">{scanError}</div>{/if}

  <!-- Three-pillar risk summary: Security / License / Operational, side by side. Signal-display
       only — no composite/weighted score across the pillars. -->
  {#if loading || (pkg && versions.length > 0)}
    <div class="risk-pillars">
      <div class="pillar">
        <span class="pillar-label">{$t('versionDetail.pillars.security')}</span>
        {#if loading}
          <span class="pillar-value"><Skeleton width="80px" height="16px" /></span>
        {:else if worstSeverity}
          <span class="pillar-value sev {worstSeverity === 'UNKNOWN' ? 'sev-unknown' : 'sev-' + worstSeverity.toLowerCase()}">
            {worstSeverity === 'UNKNOWN' ? $t('dashboard.unscored') : worstSeverity}
          </span>
        {:else}
          <span class="pillar-value pillar-clean">{$t('versionDetail.pillars.noAdvisories')}</span>
        {/if}
      </div>
      <div class="pillar">
        <span class="pillar-label">{$t('versionDetail.pillars.license')}</span>
        {#if loading}
          <span class="pillar-value"><Skeleton width="80px" height="16px" /></span>
        {:else}
          <span class="pillar-value" class:pillar-warn={licenseRiskCount > 0}>
            {$t('versionDetail.pillars.licenseCount', { values: { count: licenseRiskCount } })}
          </span>
        {/if}
      </div>
      <div class="pillar">
        <span class="pillar-label">{$t('versionDetail.pillars.operational')}</span>
        {#if loading}
          <span class="pillar-value"><Skeleton width="80px" height="16px" /></span>
        {:else if operationalWorst !== null}
          <span class="pillar-value" class:pillar-warn={operationalWorst > 0}>
            {$t('versionDetail.behindCell.count', { values: { count: operationalWorst } })}
          </span>
        {:else}
          <span class="pillar-value text-muted">{$t('versionDetail.behindCell.unscored')}</span>
        {/if}
      </div>
    </div>
  {/if}

  {#if !loading && versions.length === 0}
    <p class="text-muted">{$t('versionDetail.empty')}</p>
  {:else}
    <VersionTable
      bind:this={versionTable}
      {pkg}
      {versions}
      {licenseBlocklist}
      {vulnsByPurl}
      {isAdmin}
      {scanningId}
      {loading}
      {scanCooldownRemaining}
      {copy}
      on:download={(e) => downloadVersion(e.detail)}
      on:rescan={(e) => rescan(e.detail)}
      on:block={(e) => blockVersion(e.detail)}
      on:unblock={(e) => unblockVersion(e.detail)}
      on:delete={(e) => deleteVersion(e.detail)}
    />
  {/if}
</div>

<style>
  /* Claim state badge needs a left margin to separate it from the package name in the H1. */
  .badge.has-icon { margin-left: 8px; }

  /* Three-pillar risk summary: compact, side-by-side, signal-display only. */
  .risk-pillars {
    display: flex;
    gap: 20px;
    margin-bottom: 14px;
    padding: 10px 14px;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    background: var(--bg2);
  }
  .pillar { display: flex; flex-direction: column; gap: 2px; }
  .pillar-label {
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.02em;
    color: var(--text2);
  }
  .pillar-value { font-size: 13px; font-weight: 600; }
  .pillar-clean { color: var(--success); }
  .pillar-warn { color: var(--badge-warning-text); }

  /* Package-level metadata (homepage / repository / description) under the title. Floored at
     two clamped description lines plus the link row, and rendered whether or not the fetch has
     landed, so the risk pillars and version table sit at the same offset either way. */
  .pkg-meta { min-height: 62px; }
  .pkg-description {
    margin: 6px 0 8px;
    color: var(--text2);
    max-width: 70ch;
    display: -webkit-box;
    -webkit-line-clamp: 2;
    line-clamp: 2;
    -webkit-box-orient: vertical;
    overflow: hidden;
  }
  .pkg-links { display: flex; flex-wrap: wrap; gap: 16px; margin-bottom: 10px; }
  .pkg-link { display: inline-flex; align-items: center; gap: 4px; color: var(--accent); text-decoration: none; font-size: 13px; }
  .pkg-link:hover { text-decoration: underline; }
  .pkg-link svg { flex-shrink: 0; }
</style>
