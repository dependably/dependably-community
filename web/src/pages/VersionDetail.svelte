<script>
  import { SvelteMap } from 'svelte/reactivity'
  import { t } from 'svelte-i18n'
  import { api } from '../lib/api.js'
  import ErrorBanner from '../lib/ErrorBanner.svelte'
  import RiskPillars from '../lib/RiskPillars.svelte'
  import VersionTable from '../lib/VersionTable.svelte'
  import { bootstrapInfo, navigate, user } from '../lib/store.js'
  import { overflowCount } from '../lib/blastRadius.js'
  import { reportPageLoad } from '../lib/pageLoad.js'
  import { copyToClipboard } from '../lib/clipboard.js'
  import { registryOrigin } from '../lib/installCommand.js'
  import { ECO_LABEL } from '../lib/ecosystems.js'
  import {
    licenseStateFor,
    resolveStateVersion,
    rowsForVersion,
    versionsBehindFor,
    worstSeverityFor
  } from '../lib/packageRisk.js'

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
  // Licences the org marked conditional. Separate from the blocklist because they serve — the
  // pillar reports them as "review", not as blocked.
  let licenseConditional = new Set()
  // "Which of my applications ship this?" — the reverse of the SBOM component cross-link, and the
  // question a quarantine decision on this page immediately raises. Latest project versions only.
  // Supplemental: a failure leaves the affordance unrendered rather than asserting zero.
  let blastRadius = null
  let blastRadiusOpen = false

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
        licenseConditional = new Set((policy.allowlist || [])
          .filter(e => e.disposition === 'conditional')
          .map(e => (e.licenseSpdx ?? '').toUpperCase()))
      } catch { licenseBlocklist = new Set(); licenseConditional = new Set() }
      // Blast radius over the projects plane (supplemental — ignore errors). `pkg.purlName` is
      // the canonical name the SBOM components are keyed by; the route's `name` may be spelled
      // any way a client wrote it.
      try {
        blastRadius = await api.getBlastRadiusByPackage(
          pkg.ecosystem, pkg.purlName ?? params.name, { limit: 25 })
      } catch { blastRadius = null }
    } catch (e) {
      error = e.message
    } finally {
      loading = false
    }
  }

  // ── Three-pillar risk summary (Security / License / Operational) ─────────────
  // All three describe ONE version — the one the package's state is read off,
  // resolved in packageRisk.js — not the worst value anywhere in the release
  // history. Per-version detail stays in the table below, a row at a time.

  $: stateVersion = resolveStateVersion(pkg, versions)
  $: stateRows = rowsForVersion(versions, stateVersion)
  $: worstSeverity = worstSeverityFor(stateRows, vulnsByPurl)
  $: licenseState = licenseStateFor(stateRows, licenseBlocklist, licenseConditional)
  $: versionsBehind = versionsBehindFor(stateRows)

  // Descriptors for the shared strip. Reactive rather than const so the labels follow a locale
  // change, and so every pillar re-reads its source the moment that source resolves.
  $: riskPillars = [
    {
      key: 'security',
      label: $t('versionDetail.pillars.security'),
      // UNKNOWN is the packageRisk vocabulary for "advisories exist but none carries a score";
      // it renders as the unscored chip rather than as a severity nobody assigned.
      sev: worstSeverity ? (worstSeverity === 'UNKNOWN' ? 'unknown' : worstSeverity.toLowerCase()) : null,
      text: worstSeverity
        ? (worstSeverity === 'UNKNOWN' ? $t('dashboard.unscored') : worstSeverity)
        : $t('versionDetail.pillars.noAdvisories'),
      tone: worstSeverity ? '' : 'clean',
    },
    {
      key: 'license',
      label: $t('versionDetail.pillars.license'),
      text: licenseState === 'blocked' ? $t('versionDetail.pillars.licenseBlocked')
        // No extracted SPDX entry is an unknown licence, not a clean one — the block gate
        // treats the two differently, so the pillar does too.
        : licenseState === 'undeclared' ? $t('versionDetail.pillars.licenseUndeclared')
        // Serves, but the org recorded a condition on the licence. Showing this as clean would
        // hide the org's own note from the person about to depend on it.
        : licenseState === 'review' ? $t('versionDetail.pillars.licenseReview')
        : $t('versionDetail.pillars.licenseClean'),
      tone: licenseState === 'blocked' ? 'warn'
        : licenseState === 'undeclared' ? 'muted'
        : licenseState === 'review' ? 'review'
        : 'clean',
    },
    {
      key: 'operational',
      label: $t('versionDetail.pillars.operational'),
      text: versionsBehind !== null
        ? $t('versionDetail.behindCell.count', { values: { count: versionsBehind } })
        : $t('versionDetail.behindCell.unscored'),
      tone: versionsBehind === null ? 'muted' : versionsBehind > 0 ? 'warn' : 'clean',
    },
  ]

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
      list.push({
        osvId: r.osvId,
        severity: r.severity,
        summary: r.summary,
        cvssScore: r.cvssScore,
        isKev: r.isKev,
        epssScore: r.epssScore
      })
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

  // Keyed so each copy button can acknowledge its own click; `copiedKey` is threaded into
  // VersionTable so the buttons inside an expanded row behave the same as the one above it.
  let copiedKey = null
  async function copy(key, text) {
    const ok = await copyToClipboard(text)
    copiedKey = ok ? key : null
    setTimeout(() => { if (copiedKey === key) copiedKey = null }, 2000)
  }

  // The registry URL to embed in a copied command. Not reactive on window.location — it
  // cannot change during the page's lifetime — but it does follow bootstrap, which resolves
  // after mount and is what tells us the operator declared an HTTPS deployment.
  $: origin = registryOrigin($bootstrapInfo, window.location)

  $: isAdmin = $user?.role === 'admin' || $user?.role === 'owner'

  // The title's ecosystem badge follows the route until the package lands, then the package.
  $: ecosystem = pkg?.ecosystem ?? params.ecosystem
</script>

<div class="page">
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
           fetched display name replaces the purl name in place. Origin (hosted or proxy) is
           a package-level fact, so it is shown once here rather than on every version row. -->
      <h1 class="page-title">
        <span class="badge {ecosystem}">{ECO_LABEL[ecosystem] ?? ecosystem}</span>
        {pkg?.name ?? params.name}
        {#if pkg}
          <span class="badge {pkg.isProxy ? 'proxy' : 'hosted'}">
            {pkg.isProxy ? $t('packages.proxy') : $t('packages.hosted')}
          </span>
        {/if}
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
      <!-- Rendered in both states, and floored at two clamped description lines plus the link
           row only while loading, so the risk pillars and table below do not jump when the
           fetch lands metadata — and a package with none does not carry blank space. -->
      <div class="pkg-meta" class:loading>
        {#if pkg?.description}
          <p class="pkg-description">{pkg.description}</p>
        {/if}
        {#if pkg?.author}
          <p class="pkg-author">
            <span class="pkg-author-label">{$t('versionDetail.meta.author')}</span>
            {pkg.author}
          </p>
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

  <!-- Rendered only when something ships this package: nothing shipping it is a non-event, and a
       "0 applications" line would be noise on every package in a registry with no SBOMs. -->
  {#if blastRadius && blastRadius.total > 0}
    <div class="blast-radius" class:open={blastRadiusOpen}>
      <button
        type="button"
        class="blast-toggle"
        aria-expanded={blastRadiusOpen}
        on:click={() => blastRadiusOpen = !blastRadiusOpen}
      >
        <svg class="chev" class:open={blastRadiusOpen} width="12" height="12" aria-hidden="true"><use href="/icons.svg#icon-chevron-down"/></svg>
        <svg width="12" height="12" aria-hidden="true"><use href="/icons.svg#icon-layers"/></svg>
        {$t('versionDetail.blastRadius.summary', { values: { count: blastRadius.projectCount } })}
      </button>
      {#if blastRadiusOpen}
        {@const hiddenApps = overflowCount(blastRadius.total, blastRadius.items.length)}
        <ul class="blast-list">
          {#each blastRadius.items as app, ai (ai)}
            <li>
              <span class="app-name">{app.projectName}</span>
              <span class="mono text-muted">{app.projectVersion}</span>
              <span class="text-muted">{$t('versionDetail.blastRadius.ships', { values: { version: app.componentVersion ?? '—' } })}</span>
            </li>
          {/each}
        </ul>
        {#if hiddenApps > 0}
          <p class="form-hint">{$t('versionDetail.blastRadius.more', { values: { count: hiddenApps } })}</p>
        {/if}
      {/if}
    </div>
  {/if}

  <!-- Three-pillar risk summary: Security / License / Operational, side by side. Signal-display
       only — no composite/weighted score across the pillars. Every pillar reports the state of
       the version named in the caption, so the strip answers "what is this package like today"
       rather than "what is the worst thing in its history" — which described a version nobody
       installs and contradicted the currency banner below it. -->
  {#if loading || (pkg && versions.length > 0)}
    <RiskPillars
      {loading}
      pillars={riskPillars}
      subject={!loading && stateVersion
        ? { label: $t('versionDetail.pillars.subject'), value: stateVersion }
        : null}
    />
  {/if}

  {#if !loading && versions.length === 0}
    <p class="text-muted">{$t('versionDetail.empty')}</p>
  {:else}
    <VersionTable
      bind:this={versionTable}
      {pkg}
      {versions}
      {licenseBlocklist}
      {licenseConditional}
      {vulnsByPurl}
      {isAdmin}
      {scanningId}
      {loading}
      {scanCooldownRemaining}
      {copy}
      {copiedKey}
      registryOrigin={origin}
      on:download={(e) => downloadVersion(e.detail)}
      on:rescan={(e) => rescan(e.detail)}
      on:block={(e) => blockVersion(e.detail)}
      on:unblock={(e) => unblockVersion(e.detail)}
      on:delete={(e) => deleteVersion(e.detail)}
    />
  {/if}
</div>

<style>
  /* The title is a flex row so the 11px badges centre on the 20px name instead of hanging
     off its baseline; the gap spaces the ecosystem, origin and claim badges. */
  .page-title { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }

  /* Package-level metadata (homepage / repository / description) under the title. Floored at
     two clamped description lines plus the link row while the fetch is in flight, so the risk
     pillars and version table do not shift when metadata lands; once loaded it takes the
     height of whatever the package has, which is often nothing. */
  .pkg-meta.loading { min-height: 62px; }
  /* Sits between the description and the link row; the block above it is already floored at a
     fixed height, so this is allowed to be absent without shifting anything below. */
  .pkg-author {
    margin: 0 0 6px;
    color: var(--text2);
    font-size: 13px;
  }

  .pkg-author-label { color: var(--text2); margin-right: 4px; opacity: 0.8; }

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

  /* Blast radius — which applications ship this package. A disclosure, not a card: the count is
     the answer most readers want and the list is what they open when it is not zero. */
  .blast-radius { display: flex; flex-direction: column; gap: 6px; margin-bottom: 12px; }
  .blast-radius.open { margin-bottom: 22px; }
  .blast-toggle {
    align-self: flex-start;
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 2px 10px;
    min-height: 28px;
    font-size: 13px;
    border: 1px solid var(--info-border);
    border-radius: var(--radius);
    background: var(--info-bg);
    color: var(--info-text);
  }
  .blast-toggle .chev { transform: rotate(-90deg); transition: transform 120ms ease; }
  .blast-toggle .chev.open { transform: rotate(0deg); }
  .blast-list { margin: 0; padding-left: 20px; font-size: 13px; list-style: disc; }
  .blast-list li { display: list-item; margin-bottom: 2px; }
  .blast-list li > span + span { margin-left: 8px; }
  .app-name { font-weight: 600; }
</style>
