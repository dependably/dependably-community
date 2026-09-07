<script>
  import { t } from 'svelte-i18n'
  import { api } from '../lib/api.js'
  import ErrorBanner from '../lib/ErrorBanner.svelte'
  import Skeleton from '../lib/Skeleton.svelte'
  import { currentOrg, navigate, user } from '../lib/store.js'
  import { canAccessPage } from '../lib/routes.js'
  import { reportPageLoad } from '../lib/pageLoad.js'
  import { formatBytes, formatHour24, formatNumber } from '../lib/format.js'
  import { ECOSYSTEMS, ECO_LABEL } from '../lib/ecosystems.js'
  import { buildTrendMetrics } from '../lib/statsTrend.js'
  import { buildPreventionCells } from '../lib/gates.js'

  /** The route transition this page was mounted for, supplied by RouteView. @type {number | null} */
  export let pageToken = null

  let stats = null
  let loading = true
  let error = ''

  $: org = $currentOrg
  // Holds the deferred navigation that mounted this page until the data is here, so the swap
  // shows the loaded page rather than a shimmer that lives for a hundred milliseconds.
  $: reportPageLoad(pageToken, loading)

  async function load() {
    loading = true
    error = ''
    try {
      stats = await api.getStats()
    } catch (e) {
      error = e.message
    } finally {
      loading = false
    }
  }

  $: if (org) load()

  // ── Constants ────────────────────────────────────────────────────────────────

  // ECOSYSTEMS lives in lib/ecosystems.js so every page renders the same set.
  // 'UNKNOWN' is the bucket the backend emits when an advisory has no CVSS/severity
  // (e.g. some GHSA records on first publish). Render it explicitly — silently
  // dropping it would hide real vulnerabilities from the operator.
  const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']
  const sevLabel = (sev) => sev === 'UNKNOWN' ? $t('dashboard.unscored') : sev


  // ── Derived helpers ──────────────────────────────────────────────────────────

  function ecoCount(eco) {
    if (!stats) return 0
    return stats.packagesByEcosystem.find(e => e.ecosystem === eco)?.count ?? 0
  }

  function totalPackages() {
    if (!stats) return 0
    return stats.packagesByEcosystem.reduce((s, e) => s + e.count, 0)
  }

  // Reactive mirror of totalPackages() for the markup. A bare `totalPackages()` in a template
  // names no reactive variable, so the compiler has no dependency to invalidate on and the call
  // keeps its mount-time value of 0 after `stats` lands. Everything below reads this.
  $: totalPackageCount = stats ? stats.packagesByEcosystem.reduce((s, e) => s + e.count, 0) : 0

  function diskFor(eco) {
    if (!stats) return 0
    return stats.diskByEcosystem.find(e => e.ecosystem === eco)?.totalBytes ?? 0
  }

  function vulnCount(eco, severity) {
    if (!stats) return 0
    return stats.vulnsByEcosystemAndSeverity.find(
      v => v.ecosystem === eco && v.severity === severity
    )?.count ?? 0
  }

  function totalVulns(eco) {
    if (!stats) return 0
    return SEVERITIES.reduce((s, sev) => s + vulnCount(eco, sev), 0)
  }

  // Ecosystems worth a table row: any with packages, or with vulns even at 0 packages (never
  // hide a vulnerability). Keeps the table compact as the ecosystem vocabulary grows.
  $: visibleEcos = stats ? ECOSYSTEMS.filter(e => ecoCount(e) > 0 || totalVulns(e) > 0) : []

  // ── Supply-chain metric cards ────────────────────────────────────────────────

  $: blockedByGate = stats?.blockedByGate30d ?? []
  $: maliciousBlocked = blockedByGate.find(g => g.gate === 'malicious')?.count ?? 0
  // Both the plain and ransomware-specific KEV gates roll into one tile — see BlockGateService's
  // dedicated ransomware arm, distinct from the plain KEV arm it sits alongside.
  $: kevBlocked = blockedByGate
    .filter(g => g.gate === 'kev' || g.gate === 'kev_ransomware')
    .reduce((s, g) => s + g.count, 0)
  // Every gate gets a pill, fired or not — a quiet window reads as a row of zeros rather than
  // as an absent section. See buildPreventionCells for the ordering and the unknown-gate rule.
  $: preventionCells = buildPreventionCells(blockedByGate)

  // Per-gate tooltip for the Blocked-pulls card, e.g. "malicious: 2 · KEV: 1".
  $: blockedBreakdown = blockedByGate
    .map(g => `${$t('dashboard.gates.' + g.gate)}: ${g.count}`)
    .join(' · ')
  $: quarantinePending = stats?.quarantinePending ?? 0
  // Quarantine and Audit are role-restricted surfaces (see Sidebar, RESTRICTED_PAGES in routes.js).
  // A role that may not open the page behind a card sees its count as a read-only stat — the card
  // is not a link, because the page would bounce them straight back here. Quarantine is admin/
  // owner-only; Audit also admits the auditor role. The two risk tiles have no such gate: their
  // drill-down needs only read:packages, so they link for every role.
  $: isAdmin = $user?.role === 'admin' || $user?.role === 'owner'
  $: canOpenAudit = canAccessPage('audit', $user?.role)
  $: hostedPackages = stats?.hostedPackages ?? 0
  $: proxiedPackages = stats?.proxiedPackages ?? 0
  $: storageQuotaBytes = stats?.storageQuotaBytes ?? null

  // ── Risk-pillar tiles (operational + license, alongside the vuln cards above) ──
  $: operationalRiskPackageCount = stats?.operationalRiskPackageCount ?? 0
  $: versionsBehindThreshold = stats?.versionsBehindThreshold ?? 0
  $: licenseRiskVersionCount = stats?.licenseRiskVersionCount ?? 0

  // ── Scan coverage tile ───────────────────────────────────────────────────────
  // Both storage planes the org can see (uploaded + proxy), matching VulnerabilityScanService's
  // structural scan domain (org-status and air-gap predicates deliberately not mirrored — see
  // QueryCoverageStatsAsync), bucketed by whether vuln_checked_at is stamped. An org with nothing
  // scannable reads "no coverage yet" — never a fabricated 100% (nothing scanned, but also
  // nothing to scan) or 0% (which would read as "everything failed" rather than "nothing exists
  // yet"). The percent/headline is over the scannable population (scanned + unscanned) only —
  // noFeedVersionCount is a third, separate figure (an ecosystem OSV publishes no advisory feed
  // for at all, e.g. OCI/Terraform) surfaced as its own line so an org that only ever pushes
  // no-feed artefacts reads "no coverage yet · N not scannable" instead of a permanent, dead 0%
  // with nothing an operator can do about it.
  $: scannedVersionCount = stats?.scannedVersionCount ?? 0
  $: unscannedVersionCount = stats?.unscannedVersionCount ?? 0
  $: noFeedVersionCount = stats?.noFeedVersionCount ?? 0
  $: totalCoverageVersions = scannedVersionCount + unscannedVersionCount
  $: coveragePercent = totalCoverageVersions > 0
    ? Math.round((scannedVersionCount / totalCoverageVersions) * 100)
    : null

  // ── Active-overrides tile ────────────────────────────────────────────────────
  // Approved quarantine rows — a human decision that outranks every policy gate. Links to the
  // Quarantine page filtered to state=approved, the same posture as the pending-count tile linking
  // to state=pending above.
  $: activeOverrideCount = stats?.activeOverrideCount ?? 0
  $: oldestActiveOverrideDays = stats?.oldestActiveOverrideDays ?? null

  // ── Projects tile ────────────────────────────────────────────────────────────
  // One COUNT-GROUP-BY over each project's is_latest policy_status, the same materialized
  // column the projects list and detail pages already read. `totalProjects` is scoped to
  // kind='project' server-side — a collection (folder) holds no versions and so never appears
  // in the four buckets below — so the sub-line's four numbers sum exactly to the headline;
  // the unevaluated bucket is rendered rather than dropped so a reader can actually check that.
  $: totalProjects = stats?.totalProjects ?? 0
  $: projectPolicyStatus = stats?.projectVersionPolicyStatus ?? []
  $: projectViolationCount = projectPolicyStatus.find(s => s.status === 'violation')?.count ?? 0
  $: projectWarnCount = projectPolicyStatus.find(s => s.status === 'warn')?.count ?? 0
  $: projectPassCount = projectPolicyStatus.find(s => s.status === 'pass')?.count ?? 0
  $: projectUnevaluatedCount = projectPolicyStatus.find(s => s.status === 'unevaluated')?.count ?? 0

  // ── Donut chart ──────────────────────────────────────────────────────────────

  const CX = 50, CY = 50, R_OUTER = 40, R_INNER = 22

  function buildSlices() {
    if (!stats) return []
    const total = totalPackages()
    if (total === 0) return []
    const nonZero = ECOSYSTEMS.filter(e => ecoCount(e) > 0)
    if (nonZero.length === 1) {
      const eco = nonZero[0]
      const d = [
        `M ${CX} ${CY - R_OUTER}`,
        `A ${R_OUTER} ${R_OUTER} 0 1 1 ${CX} ${CY + R_OUTER}`,
        `A ${R_OUTER} ${R_OUTER} 0 1 1 ${CX} ${CY - R_OUTER}`,
        `M ${CX} ${CY - R_INNER}`,
        `A ${R_INNER} ${R_INNER} 0 1 0 ${CX} ${CY + R_INNER}`,
        `A ${R_INNER} ${R_INNER} 0 1 0 ${CX} ${CY - R_INNER}`,
        'Z'
      ].join(' ')
      return [{ eco, count: ecoCount(eco), d }]
    }
    let angle = -Math.PI / 2
    return ECOSYSTEMS.map(eco => {
      const count = ecoCount(eco)
      if (count === 0) return null
      const sweep = (count / total) * 2 * Math.PI
      const x1o = CX + R_OUTER * Math.cos(angle)
      const y1o = CY + R_OUTER * Math.sin(angle)
      const x1i = CX + R_INNER * Math.cos(angle)
      const y1i = CY + R_INNER * Math.sin(angle)
      angle += sweep
      const x2o = CX + R_OUTER * Math.cos(angle)
      const y2o = CY + R_OUTER * Math.sin(angle)
      const x2i = CX + R_INNER * Math.cos(angle)
      const y2i = CY + R_INNER * Math.sin(angle)
      const large = sweep > Math.PI ? 1 : 0
      const d = [
        `M ${x1o} ${y1o}`,
        `A ${R_OUTER} ${R_OUTER} 0 ${large} 1 ${x2o} ${y2o}`,
        `L ${x2i} ${y2i}`,
        `A ${R_INNER} ${R_INNER} 0 ${large} 0 ${x1i} ${y1i}`,
        'Z'
      ].join(' ')
      return { eco, count, d }
    }).filter((s) => s !== null)
  }

  $: slices = stats ? buildSlices() : []
  $: newVulns1d = stats?.newVulns?.day ?? 0
  $: newVulns7d = stats?.newVulns?.week ?? 0
  $: newVulns30d = stats?.newVulns?.month ?? 0
  $: vulnsHot = newVulns1d > 0 || newVulns7d > 0 || newVulns30d > 0
  $: samlCertExpiry = stats?.samlCertExpiry ?? null
  $: samlCertHot = samlCertExpiry && samlCertExpiry.status !== 'ok'

  // ── Trend sparklines (up to 30 daily points from org_stats_history) ─────────────
  //
  // Fewer than two points renders "no trend yet" rather than a fabricated flat line or a delta
  // against nothing — a single point has no direction to show. The sparkline/delta arithmetic
  // itself lives in lib/statsTrend.js so it is unit-testable (see statsTrend.test.js).
  $: trend = stats?.trend ?? []
  $: hasTrend = trend.length >= 2
  $: trendMetrics = buildTrendMetrics(trend)

  // ── Download chart ───────────────────────────────────────────────────────────

  const CHART_PX = 90

  function buildHourBars() {
    if (!stats) return []
    const currentHourMs = Math.floor(Date.now() / 3_600_000) * 3_600_000
    const slots = []
    for (let i = 23; i >= 0; i--) {
      const d = new Date(currentHourMs - i * 3_600_000)
      const key = d.toISOString().slice(0, 14) + '00:00Z'
      const entry = stats.downloadsByHour.find(h => h.hour === key)
      slots.push({ hour: d, count: entry?.count ?? 0 })
    }
    return slots
  }

  $: hourBars = stats ? buildHourBars() : []
  $: maxCount = Math.max(...hourBars.map(b => b.count), 1)
  $: barHeights = hourBars.map(b => Math.round((b.count / maxCount) * CHART_PX))

</script>

<div class="page">
  <div class="page-header title-row">
    <h1 class="page-title">{$t('dashboard.title')}</h1>

    {#if stats}
      <button
        type="button"
        class="ribbon"
        class:hot={vulnsHot}
        title={$t('dashboard.newVulnsViewAll')}
        on:click={() => navigate('vulnerabilities', { sort: 'published', dir: 'desc' })}
      >
        <span class="dot" aria-hidden="true"></span>
        <span class="label">
          {vulnsHot ? $t('dashboard.newVulnsTitle') : $t('dashboard.noNewVulns')}
        </span>
        <span class="splits">
          <span class="split"><b>{newVulns1d}</b>{$t('dashboard.window24h')}</span>
          <span class="split"><b>{newVulns7d}</b>{$t('dashboard.window7d')}</span>
          <span class="split"><b>{newVulns30d}</b>{$t('dashboard.window30d')}</span>
        </span>
      </button>
    {:else}
      <!-- Same box as the loaded ribbon; the ribbon's height floor is what keeps the page header
           at one height whether it holds the placeholder or the loaded line. -->
      <span class="ribbon" aria-hidden="true"><Skeleton width="240px" height="14px" /></span>
    {/if}
  </div>

  <ErrorBanner message={error} />

  <!-- Rendered whether or not `stats` has arrived: every helper above is null-safe and returns
       0 or an empty list, so the grid, donut, table, and chart all stand at their loaded size
       from the first paint and only the values swap in. Collapsing the body to a spinner
       instead would retract the document scrollbar and shift the whole layout. -->

    <!-- ── SAML cert-expiry alert card (admins/owners only; hot when ≤7d or expired) ── -->
    {#if samlCertHot}
      <div class="alert-card mb-4" class:hot={samlCertExpiry.status === 'expired'} class:warn={samlCertExpiry.status !== 'expired'} role="alert">
        <strong>
          {samlCertExpiry.status === 'expired'
            ? $t('dashboard.samlCertExpiredCard')
            : $t('dashboard.samlCertExpiryCard')}
        </strong>
        <span class="saml-cert-detail">
          {samlCertExpiry.status === 'expired'
            ? $t('dashboard.samlCertNotAfter', { values: { notAfter: samlCertExpiry.notAfter } })
            : $t('dashboard.samlCertDays', { values: { days: samlCertExpiry.daysRemaining } })}
        </span>
      </div>
    {/if}

    <!-- ── Summary stats ─────────────────────────────────────────────────────── -->
    <div class="stat-grid">
      <div class="stat-card">
        <div class="eyebrow">{$t('dashboard.totalPackages')}</div>
        <div class="stat-value">{#if stats}{$formatNumber(totalPackageCount)}{:else}<Skeleton width="72px" height="28px" />{/if}</div>
        <div class="stat-sub">{#if hostedPackages > 0 || proxiedPackages > 0}{$t('dashboard.hostedProxied', { values: { hosted: $formatNumber(hostedPackages), proxied: $formatNumber(proxiedPackages) } })}{/if}</div>
      </div>
      <div class="stat-card">
        <div class="eyebrow">{$t('dashboard.totalDisk')}</div>
        <div class="stat-value">{#if stats}{$formatBytes(stats.totalDiskBytes)}{:else}<Skeleton width="72px" height="28px" />{/if}</div>
        <div class="stat-sub">{#if storageQuotaBytes}{$t('dashboard.quotaUsage', { values: { total: $formatBytes(storageQuotaBytes) } })}{/if}</div>
      </div>
      <div class="stat-card">
        <div class="eyebrow">{$t('dashboard.activeUsers')}</div>
        <div class="stat-value">{#if stats}{stats.activeUsers7d ?? 0}{:else}<Skeleton width="72px" height="28px" />{/if}</div>
      </div>
      <div class="stat-card">
        <div class="eyebrow">{$t('dashboard.totalDownloads')}</div>
        <div class="stat-value">{#if stats}{$formatNumber(stats.totalDownloads30d)}{:else}<Skeleton width="72px" height="28px" />{/if}</div>
      </div>
      <!-- Not admin-gated: read:packages serves both the tile and the projects list it links to. -->
      <button
        class="stat-card stat-link"
        on:click={() => navigate('projects')}
        aria-label={$t('dashboard.totalProjects')}
      >
        <div class="eyebrow">{$t('dashboard.totalProjects')}</div>
        <div class="stat-value" class:warn={projectViolationCount > 0}>{#if stats}{$formatNumber(totalProjects)}{:else}<Skeleton width="72px" height="28px" />{/if}</div>
        <div class="stat-sub">
          {#if stats && totalProjects > 0}
            {$t('dashboard.projectsSub', { values: {
              pass: $formatNumber(projectPassCount),
              warn: $formatNumber(projectWarnCount),
              violation: $formatNumber(projectViolationCount),
              unevaluated: $formatNumber(projectUnevaluatedCount),
            } })}
          {/if}
        </div>
      </button>
      <!-- The blocked tiles drill into the Audit page's lifecycle feed, scoped to the same
           30-day window they count. That page is role-restricted (RESTRICTED_PAGES), so only a
           role that may open it gets the link — everyone else keeps the count as a read-only stat. -->
      {#if canOpenAudit}
        <button
          class="stat-card stat-link"
          title={blockedBreakdown}
          on:click={() => navigate('audit', { tab: 'lifecycle', type: 'blocked', since: '30d' })}
          aria-label={$t('dashboard.blockedPulls')}
        >
          <div class="eyebrow">{$t('dashboard.blockedPulls')}</div>
          <div class="stat-value" class:warn={stats?.blockedPulls30d > 0}>{#if stats}{$formatNumber(stats.blockedPulls30d)}{:else}<Skeleton width="72px" height="28px" />{/if}</div>
        </button>
      {:else}
        <div class="stat-card" title={blockedBreakdown}>
          <div class="eyebrow">{$t('dashboard.blockedPulls')}</div>
          <div class="stat-value" class:warn={stats?.blockedPulls30d > 0}>{#if stats}{$formatNumber(stats.blockedPulls30d)}{:else}<Skeleton width="72px" height="28px" />{/if}</div>
        </div>
      {/if}
      {#if canOpenAudit}
        <button
          class="stat-card stat-link"
          on:click={() => navigate('audit', { tab: 'lifecycle', type: 'blocked_malicious', since: '30d' })}
          aria-label={$t('dashboard.blockedMalicious')}
        >
          <div class="eyebrow">{$t('dashboard.blockedMalicious')}</div>
          <div class="stat-value" class:danger={maliciousBlocked > 0}>{#if stats}{$formatNumber(maliciousBlocked)}{:else}<Skeleton width="72px" height="28px" />{/if}</div>
        </button>
      {:else}
        <div class="stat-card">
          <div class="eyebrow">{$t('dashboard.blockedMalicious')}</div>
          <div class="stat-value" class:danger={maliciousBlocked > 0}>{#if stats}{$formatNumber(maliciousBlocked)}{:else}<Skeleton width="72px" height="28px" />{/if}</div>
        </div>
      {/if}
      <!-- This tile counts both the plain and ransomware-specific KEV gates, but the audit
           feed's type filter only exact-matches one event type at a time (the 'blocked' value
           is the sole prefix-matching special case). The search param does a substring match
           across event_type instead, so 'blocked_kev' as a search term catches both
           'blocked_kev' and 'blocked_kev_ransomware' without under-linking the drill-down. -->
      {#if canOpenAudit}
        <button
          class="stat-card stat-link"
          on:click={() => navigate('audit', { tab: 'lifecycle', q: 'blocked_kev', since: '30d' })}
          aria-label={$t('dashboard.blockedKev')}
        >
          <div class="eyebrow">{$t('dashboard.blockedKev')}</div>
          <div class="stat-value" class:danger={kevBlocked > 0}>{#if stats}{$formatNumber(kevBlocked)}{:else}<Skeleton width="72px" height="28px" />{/if}</div>
        </button>
      {:else}
        <div class="stat-card">
          <div class="eyebrow">{$t('dashboard.blockedKev')}</div>
          <div class="stat-value" class:danger={kevBlocked > 0}>{#if stats}{$formatNumber(kevBlocked)}{:else}<Skeleton width="72px" height="28px" />{/if}</div>
        </div>
      {/if}
      <!-- Risk is not admin-gated: read:packages serves both the tile and the drill-down. -->
      <button
        class="stat-card stat-link"
        on:click={() => navigate('risk', { tab: 'operational' })}
        aria-label={$t('dashboard.operationalRisk')}
      >
        <div class="eyebrow">{$t('dashboard.operationalRisk')}</div>
        <div class="stat-value" class:warn={operationalRiskPackageCount > 0}>{#if stats}{$formatNumber(operationalRiskPackageCount)}{:else}<Skeleton width="72px" height="28px" />{/if}</div>
        <div class="stat-sub">{#if versionsBehindThreshold > 0}{$t('dashboard.operationalRiskSub', { values: { threshold: versionsBehindThreshold } })}{/if}</div>
      </button>
      <button
        class="stat-card stat-link"
        on:click={() => navigate('risk', { tab: 'license' })}
        aria-label={$t('dashboard.licenseRisk')}
      >
        <div class="eyebrow">{$t('dashboard.licenseRisk')}</div>
        <div class="stat-value" class:warn={licenseRiskVersionCount > 0}>{#if stats}{$formatNumber(licenseRiskVersionCount)}{:else}<Skeleton width="72px" height="28px" />{/if}</div>
      </button>
      <!-- The queue's own default is `pending`, but the tile names it anyway: the count is
           pending-only, so the link that carries it should say so rather than inherit it. -->
      {#if isAdmin}
        <button
          class="stat-card stat-link"
          class:hot={quarantinePending > 0}
          on:click={() => navigate('quarantine', { state: 'pending' })}
          aria-label={$t('dashboard.quarantinePending')}
        >
          <div class="eyebrow">{$t('dashboard.quarantinePending')}</div>
          <div class="stat-value" class:warn={quarantinePending > 0}>{#if stats}{$formatNumber(quarantinePending)}{:else}<Skeleton width="72px" height="28px" />{/if}</div>
        </button>
      {:else}
        <div class="stat-card">
          <div class="eyebrow">{$t('dashboard.quarantinePending')}</div>
          <div class="stat-value" class:warn={quarantinePending > 0}>{#if stats}{$formatNumber(quarantinePending)}{:else}<Skeleton width="72px" height="28px" />{/if}</div>
        </div>
      {/if}
      <!-- Active overrides: approved quarantine rows. Same admin-gated link posture as the
           pending-count tile above — Quarantine is an admin/owner-only surface (RESTRICTED_PAGES). -->
      {#if isAdmin}
        <button
          class="stat-card stat-link"
          on:click={() => navigate('quarantine', { state: 'approved' })}
          aria-label={$t('dashboard.activeOverrides')}
        >
          <div class="eyebrow">{$t('dashboard.activeOverrides')}</div>
          <div class="stat-value">{#if stats}{$formatNumber(activeOverrideCount)}{:else}<Skeleton width="72px" height="28px" />{/if}</div>
          <div class="stat-sub">
            {#if stats && activeOverrideCount > 0 && oldestActiveOverrideDays !== null}
              {$t('dashboard.activeOverridesSub', { values: { days: oldestActiveOverrideDays } })}
            {/if}
          </div>
        </button>
      {:else}
        <div class="stat-card">
          <div class="eyebrow">{$t('dashboard.activeOverrides')}</div>
          <div class="stat-value">{#if stats}{$formatNumber(activeOverrideCount)}{:else}<Skeleton width="72px" height="28px" />{/if}</div>
          <div class="stat-sub">
            {#if stats && activeOverrideCount > 0 && oldestActiveOverrideDays !== null}
              {$t('dashboard.activeOverridesSub', { values: { days: oldestActiveOverrideDays } })}
            {/if}
          </div>
        </div>
      {/if}
      <!-- Scan coverage: not a link — there is no single drill-down page for "everything scanned
           this build knows about"; the operational/license risk tiles beside it are the drill-down
           surfaces for what a scan finds. -->
      <div class="stat-card">
        <div class="eyebrow">{$t('dashboard.coverage.title')}</div>
        <div class="stat-value">
          {#if stats}
            {#if totalCoverageVersions === 0}
              <span class="coverage-empty">{$t('dashboard.coverage.none')}</span>
            {:else}
              {$t('dashboard.coverage.percent', { values: { percent: coveragePercent } })}
            {/if}
          {:else}
            <Skeleton width="72px" height="28px" />
          {/if}
        </div>
        <div class="stat-sub">
          {#if stats && totalCoverageVersions > 0}
            {$t('dashboard.coverage.sub', { values: {
              scanned: $formatNumber(scannedVersionCount),
              unscanned: $formatNumber(unscannedVersionCount),
            } })}
          {/if}
        </div>
        <!-- The no-feed bucket (an ecosystem OSV publishes no advisory feed for at all, e.g.
             OCI/Terraform) is a distinct population from "unscanned" — it can never move via any
             operator action, so it gets its own line rather than inflating the scannable count
             above or hiding inside a permanent 0%/no-coverage-yet headline. -->
        {#if stats && noFeedVersionCount > 0}
          <div class="stat-sub coverage-nofeed">
            {$t('dashboard.coverage.noFeed', { values: { count: $formatNumber(noFeedVersionCount) } })}
          </div>
        {/if}
      </div>
    </div>

    <!-- ── Package breakdown: pie + table ────────────────────────────────────── -->
    <section class="section">
      <h2 class="eyebrow">{$t('dashboard.packageBreakdown')}</h2>
      <div class="breakdown-row">

        <!-- Donut chart -->
        <div class="donut-wrap">
          {#if totalPackageCount === 0}
            <div class="donut-empty">{$t('dashboard.donutEmpty')}</div>
          {:else}
            <svg viewBox="0 0 100 100" class="donut-svg">
              {#each slices as s (s.eco)}
                <path d={s.d} fill-rule="evenodd" class="slice slice-{s.eco}" />
              {/each}
              <text x="50" y="54" text-anchor="middle" class="donut-center-num">{$formatNumber(totalPackageCount)}</text>
            </svg>
          {/if}
        </div>

        <!-- Ecosystem table -->
        <div class="eco-table-wrap">
          <table class="eco-table">
            <colgroup>
              <col><!-- ecosystem name: flexible -->
              <col class="col-pkgs"><!-- packages count -->
              <col class="col-disk"><!-- disk used -->
              <col class="col-sev-w"><!-- critical -->
              <col class="col-sev-n"><!-- high -->
              <col class="col-sev-w"><!-- medium -->
              <col class="col-sev-n"><!-- low -->
              <col class="col-sev-w"><!-- unscored -->
              <col class="col-sev-n"><!-- total vulns -->
            </colgroup>
            <thead>
              <tr>
                <th>{$t('dashboard.ecosystem')}</th>
                <th class="text-right">{$t('dashboard.packages')}</th>
                <th class="text-right">{$t('dashboard.diskUsed')}</th>
                {#each SEVERITIES as sev (sev)}
                  <th class="text-right">
                    <span class="sev sev-{sev.toLowerCase()}" aria-label="{sevLabel(sev).toLowerCase()} severity">{sevLabel(sev)}</span>
                  </th>
                {/each}
                <th class="text-right">{$t('dashboard.vulns')}</th>
              </tr>
            </thead>
            {#if loading}
              <!-- Four rows plus the header stand at roughly the 160px donut beside them, which
                   is what pins this section's height once loaded. -->
              <tbody aria-hidden="true">
                {#each [0, 1, 2, 3] as i (i)}
                  <tr><td colspan="9"><span class="skeleton"></span></td></tr>
                {/each}
              </tbody>
            {:else}
            <tbody>
              {#each visibleEcos as eco (eco)}
                {@const total = totalVulns(eco)}
                <tr>
                  <td>
                    <div class="eco-name-cell">
                      <span class="eco-bar {eco}" aria-hidden="true"></span>
                      <span class="badge {eco}">{ECO_LABEL[eco]}</span>
                    </div>
                  </td>
                  <td class="text-right">{$formatNumber(ecoCount(eco))}</td>
                  <td class="text-right">{$formatBytes(diskFor(eco))}</td>
                  {#each SEVERITIES as sev (sev)}
                    {@const n = vulnCount(eco, sev)}
                    <td class="text-right">
                      {#if n > 0}
                        <span class="sev sev-{sev.toLowerCase()}" aria-label="{n} {sevLabel(sev).toLowerCase()}">{n}</span>
                      {:else}
                        <span class="zero">—</span>
                      {/if}
                    </td>
                  {/each}
                  <td class="text-right total-cell">{total > 0 ? total : '—'}</td>
                </tr>
              {:else}
                <tr>
                  <td colspan="9" class="eco-empty">{$t('dashboard.donutEmpty')}</td>
                </tr>
              {/each}
            </tbody>
            {/if}
          </table>
        </div>
      </div>
    </section>

    <!-- ── Download activity (last 24 h) ─────────────────────────────────────── -->
    <section class="section">
      <h2 class="eyebrow">{$t('dashboard.fetchesTitle')}</h2>
      <div class="chart-wrap">
        {#each hourBars as bar, i (bar.hour)}
          <div class="bar-col" title="{$formatHour24(bar.hour)}: {bar.count}">
            <div class="bar-fill" style:height="{barHeights[i]}px"></div>
          </div>
        {/each}
      </div>
      <div class="chart-labels">
        {#each hourBars as bar, i (bar.hour)}
          <div class="bar-label-cell">
            {#if i % 4 === 0}{$formatHour24(bar.hour)}{/if}
          </div>
        {/each}
      </div>
      <div class="chart-legend">
        {$t('dashboard.fetchesTotal', { values: { n: $formatNumber(hourBars.reduce((s, b) => s + b.count, 0)) } })}
      </div>
    </section>

    <!-- ── Trends: sparkline + delta-since-7d for the dashboard's own headline figures ── -->
    {#if stats}
      <section class="section">
        <h2 class="eyebrow">{$t('dashboard.trends.title')}</h2>
        {#if hasTrend}
          <div class="trend-grid">
            {#each trendMetrics as m (m.key)}
              <div class="trend-card">
                <div class="trend-head">
                  <span class="trend-label">{$t(m.labelKey)}</span>
                  <span class="trend-value">{$formatNumber(m.latest)}</span>
                </div>
                <svg viewBox="0 0 60 20" class="trend-svg" preserveAspectRatio="none" aria-hidden="true">
                  <polyline points={m.points} class="trend-line" />
                </svg>
                {#if m.delta !== null}
                  <div class="trend-delta">
                    {$t('dashboard.trends.vs7d', { values: { delta: m.delta > 0 ? `+${$formatNumber(m.delta)}` : $formatNumber(m.delta) } })}
                  </div>
                {/if}
              </div>
            {/each}
          </div>
        {:else}
          <!-- Fewer than two daily snapshots is a pending state, not a data state: the copy names
               the mechanism and the timeline, because "no trend" on its own leaves the operator
               asking when one appears. Rendered as a quiet status line rather than a bordered
               placeholder — a dashed box is this product's drop-zone chrome (see Upload). -->
          <div class="section-empty">
            <svg width="14" height="14" aria-hidden="true"><use href="/icons.svg#icon-info" /></svg>
            <div>
              <div class="section-empty-title">{$t('dashboard.trends.empty')}</div>
              <div class="section-empty-hint">{$t('dashboard.trends.emptyHint')}</div>
            </div>
          </div>
        {/if}
      </section>
    {/if}

    <!-- ── Prevention: gate-refusal counts by arm, 30d ─────────────────────────
         Renders the same per-gate breakdown the Blocked-pulls tile's tooltip already carries
         (stats.blockedByGate30d) rather than recomputing it — see PackageAnalyticsRepository's
         QueryActivityDataAsync, which matches every 'blocked%' activity event type so a newly
         added gate is covered without a dashboard change. Zero gates over the window still
         renders explicit "nothing blocked" copy, never a blank section. -->
    {#if stats}
      <section class="section">
        <h2 class="eyebrow">{$t('dashboard.prevention.title')}</h2>
        <div class="prevention-grid">
          {#each preventionCells as g (g.gate)}
            <div class="prevention-item" class:is-quiet={g.count === 0}>
              <span class="prevention-count">{$formatNumber(g.count)}</span>
              <span class="prevention-label">{$t('dashboard.gates.' + g.gate)}</span>
            </div>
          {/each}
        </div>
        {#if blockedByGate.length === 0}
          <!-- A measured zero, not a missing section: the pills above already render it as a
               figure per gate, so the note only has to separate "traffic flowed and nothing was
               refused" from "nothing was served at all", using the same 30-day download figure
               the stat tiles show. The stats payload cannot see which gates are ENABLED, so the
               copy names where enforcement modes live rather than letting a row of zeros claim
               to be protective on its own. -->
          <p class="form-hint prevention-note">
            {#if stats.totalDownloads30d > 0}
              {$t('dashboard.prevention.emptyServed', { values: { count: stats.totalDownloads30d } })}
            {:else}
              {$t('dashboard.prevention.emptyNoTraffic')}
            {/if}
          </p>
        {/if}
      </section>
    {/if}
</div>

<style>
  /* SAML cert-expiry detail line */
  .saml-cert-detail { color: var(--text2); font-size: 13px; }

  /* The loaded ribbon's 13px bold splits make a taller line than the 14px placeholder; the floor
     is the loaded height, so the header stands still while the stats arrive. */
  .ribbon { min-height: 31px; }

  /* Stat grid bottom margin */
  .stat-grid { margin-bottom: 32px; }

  /* Secondary line under a stat value (hosted/proxied split, quota, gate breakdown). Rendered
     on every tile that can carry one, empty or not, and floored at one line so the grid's row
     height is settled before the numbers arrive and the tiles below do not shift. */
  .stat-sub {
    font-size: 12px;
    color: var(--text2);
    line-height: 1.3;
    min-height: 1.3em;
  }

  /* Quarantine card doubles as a link to the review queue. Reset the button chrome so it
     reads as a card, not a control (global button{min-height:36px} would otherwise inflate it). */
  .stat-link {
    text-align: left;
    align-items: flex-start;
    font: inherit;
    min-height: 0;
    cursor: pointer;
    transition: border-color 0.12s, background 0.12s;
  }
  .stat-link:hover { border-color: var(--accent); }
  .stat-link.hot {
    border-color: var(--warning-border);
    background: var(--warning-bg);
  }

  .eco-empty {
    text-align: center;
    color: var(--text2);
    padding: 16px;
  }

  /* Sections */
  .section {
    margin-bottom: 32px;
  }

  /* Breakdown row: donut + table side by side */
  .breakdown-row {
    display: flex;
    gap: 32px;
    align-items: flex-start;
    flex-wrap: wrap;
  }

  /* Donut chart */
  .donut-wrap {
    display: flex;
    flex-direction: column;
    align-items: center;
    min-width: 160px;
  }

  .donut-svg {
    width: 160px;
    height: 160px;
  }

  .donut-center-num {
    font-size: 14px;
    font-weight: 700;
    font-variant-numeric: tabular-nums;
    fill: var(--text);
  }

  /* Holds the donut's footprint so the row does not reflow when packages appear. The ring is
     solid rather than dashed: it reads as the chart's own empty frame, where a dashed outline
     reads as a drop zone — the same chrome Upload uses for a real one. */
  .donut-empty {
    width: 160px;
    height: 160px;
    display: flex;
    align-items: center;
    justify-content: center;
    color: var(--text2);
    font-size: 13px;
    border: 1px solid var(--border);
    border-radius: 50%;
  }

  /* Ecosystem table. `min-width: 0` overrides the flex item's implicit min-content width, so
     the table stays beside the donut on a laptop column and scrolls inside its wrapper instead
     of wrapping under the chart. */
  .eco-table-wrap {
    flex: 1 1 360px;
    min-width: 0;
    overflow-x: auto;
  }

  .eco-table {
    width: auto;
    min-width: 480px;
  }
  .eco-table .col-pkgs  { width: 80px; }
  .eco-table .col-disk  { width: 90px; }
  .eco-table .col-sev-w { width: 76px; }
  .eco-table .col-sev-n { width: 68px; }
  .eco-table .total-cell { font-weight: 600; }

  /* Donut slice fills — class-based to keep CSP strict on style-src */
  .slice-pypi  { fill: var(--eco-pypi); }
  .slice-npm   { fill: var(--eco-npm); }
  .slice-nuget { fill: var(--eco-nuget); }
  .slice-maven { fill: var(--eco-maven); }
  .slice-rpm   { fill: var(--eco-rpm); }
  .slice-oci   { fill: var(--eco-oci); }
  .slice-golang { fill: var(--eco-golang); }
  .slice-cargo { fill: var(--eco-cargo); }
  .slice-apk   { fill: var(--eco-apk); }
  .slice-terraform { fill: var(--eco-terraform); }
  .slice-hex   { fill: var(--eco-hex); }

  .zero {
    color: var(--text2);
    opacity: 0.4;
  }

  /* Bar chart */
  .chart-wrap {
    display: flex;
    align-items: flex-end;
    gap: 2px;
    height: 90px;
    border-bottom: 1px solid var(--border);
  }

  .bar-col {
    flex: 1;
    display: flex;
    align-items: flex-end;
  }

  .bar-fill {
    width: 100%;
    background: var(--accent);
    border-radius: 2px 2px 0 0;
    min-height: 2px;
  }

  .chart-labels {
    display: flex;
    gap: 2px;
    margin-top: 4px;
  }

  /* Only every fourth cell carries a label, so a label wider than its cell borrows the empty
     neighbours' room rather than losing its trailing digit. */
  .bar-label-cell {
    flex: 1;
    font-size: 10px;
    color: var(--text2);
    white-space: nowrap;
    overflow: visible;
  }

  .chart-legend {
    margin-top: 8px;
    font-size: 12px;
    color: var(--text2);
  }

  /* Trend sparklines */
  .trend-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 16px;
  }

  .trend-card {
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 12px 14px;
  }

  .trend-head {
    display: flex;
    align-items: baseline;
    justify-content: space-between;
    gap: 8px;
    margin-bottom: 6px;
  }

  .trend-label {
    font-size: 12px;
    color: var(--text2);
  }

  .trend-value {
    font-size: 18px;
    font-weight: 700;
    font-variant-numeric: tabular-nums;
  }

  .trend-svg {
    width: 100%;
    height: 32px;
    display: block;
  }

  .trend-line {
    fill: none;
    stroke: var(--accent);
    stroke-width: 1.5;
    vector-effect: non-scaling-stroke;
  }

  /* Neutral colour for every metric's delta: an increase reads as worse for vulnerabilities and
     blocked pulls but better for downloads, so no single up/down colour is correct across all
     three cards — the sign in the text itself carries the direction. */
  .trend-delta {
    margin-top: 4px;
    font-size: 12px;
    color: var(--text2);
    font-variant-numeric: tabular-nums;
  }

  /* Section-level empty state: a quiet status line under the eyebrow, not a placeholder box.
     The icon is informational chrome in the secondary colour; the title carries the fact at the
     same weight the coverage tile's prose state uses. Shared by Trends and Prevention so the two
     read as one pattern while their icon and copy carry the difference. */
  .section-empty {
    display: flex;
    gap: 10px;
    align-items: flex-start;
    padding: 4px 0 8px;
    color: var(--text2);
  }
  .section-empty svg {
    flex: none;
    margin-top: 2px;
  }
  .section-empty-title {
    font-size: 13px;
    font-weight: 600;
    color: var(--text);
  }
  .section-empty-hint {
    font-size: 12px;
    line-height: 1.4;
    margin-top: 2px;
    max-width: 60ch;
  }

  /* Coverage tile's empty state reads as prose ("no coverage yet"), not a number — shrink it off
     the shared .stat-value size so it doesn't overrun the card. */
  .coverage-empty {
    font-size: 15px;
    font-weight: 600;
  }

  /* The no-feed line is a second .stat-sub, stacked below the scanned/unscanned one — not a
     failure signal (no warn/danger colour), just a distinct population. */
  .coverage-nofeed {
    margin-top: 2px;
  }

  /* Prevention panel: one pill per gate, count first. */
  .prevention-grid {
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
  }
  .prevention-item {
    display: flex;
    align-items: baseline;
    gap: 6px;
    padding: 6px 12px;
    border: 1px solid var(--border);
    border-radius: 999px;
    background: var(--bg2);
  }
  .prevention-count {
    font-weight: 700;
    font-variant-numeric: tabular-nums;
  }
  .prevention-label {
    font-size: 12px;
    color: var(--text2);
    text-transform: capitalize;
  }
  /* A gate that refused nothing still gets a pill — it is the row's whole point — but recedes,
     so the gates that did fire read first in a mixed window. */
  .prevention-item.is-quiet {
    background: none;
  }
  .prevention-item.is-quiet .prevention-count {
    font-weight: 400;
    color: var(--text2);
  }
  .prevention-note { margin: 10px 0 0; }
</style>
