<script>
  import { t } from 'svelte-i18n'
  import { api } from '../lib/api.js'
  import ErrorBanner from '../lib/ErrorBanner.svelte'
  import { currentOrg, navigate, user } from '../lib/store.js'
  import { formatBytes } from '../lib/format.js'
  import { ECOSYSTEMS, ECO_LABEL } from '../lib/ecosystems.js'

  let stats = null
  let loading = true
  let error = ''

  $: org = $currentOrg

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

  // ECOSYSTEMS lives in lib/ecosystems.js so every page renders the same six.
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
  // Per-gate tooltip for the Blocked-pulls card, e.g. "malicious: 2 · KEV: 1".
  $: blockedBreakdown = blockedByGate
    .map(g => `${$t('dashboard.gates.' + g.gate)}: ${g.count}`)
    .join(' · ')
  $: quarantinePending = stats?.quarantinePending ?? 0
  // Quarantine is an admin/owner-only surface (see Sidebar). Non-admins see the count
  // as a read-only stat, but the card is not a link into the review queue.
  $: isAdmin = $user?.role === 'admin' || $user?.role === 'owner'
  $: hostedPackages = stats?.hostedPackages ?? 0
  $: proxiedPackages = stats?.proxiedPackages ?? 0
  $: storageQuotaBytes = stats?.storageQuotaBytes ?? null

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

  function fmtHour(d) {
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', hour12: false })
  }
</script>

<div class="page page-wide">
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
    {/if}
  </div>

  <ErrorBanner message={error} />

  {#if loading}
    <span class="spinner"></span>
  {:else if stats}

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
        <div class="stat-value">{totalPackages().toLocaleString()}</div>
        {#if hostedPackages > 0 || proxiedPackages > 0}
          <div class="stat-sub">{$t('dashboard.hostedProxied', { values: { hosted: hostedPackages.toLocaleString(), proxied: proxiedPackages.toLocaleString() } })}</div>
        {/if}
      </div>
      <div class="stat-card">
        <div class="eyebrow">{$t('dashboard.totalDisk')}</div>
        <div class="stat-value">{$formatBytes(stats.totalDiskBytes)}</div>
        {#if storageQuotaBytes}
          <div class="stat-sub">{$t('dashboard.quotaUsage', { values: { total: $formatBytes(storageQuotaBytes) } })}</div>
        {/if}
      </div>
      <div class="stat-card">
        <div class="eyebrow">{$t('dashboard.activeUsers')}</div>
        <div class="stat-value">{stats.activeUsers7d ?? 0}</div>
      </div>
      <div class="stat-card">
        <div class="eyebrow">{$t('dashboard.totalDownloads')}</div>
        <div class="stat-value">{(stats.totalDownloads30d ?? 0).toLocaleString()}</div>
      </div>
      <div class="stat-card" title={blockedBreakdown}>
        <div class="eyebrow">{$t('dashboard.blockedPulls')}</div>
        <div class="stat-value" class:warn={stats.blockedPulls30d > 0}>{(stats.blockedPulls30d ?? 0).toLocaleString()}</div>
      </div>
      <div class="stat-card">
        <div class="eyebrow">{$t('dashboard.blockedMalicious')}</div>
        <div class="stat-value" class:danger={maliciousBlocked > 0}>{maliciousBlocked.toLocaleString()}</div>
      </div>
      {#if isAdmin}
        <button
          class="stat-card stat-link"
          class:hot={quarantinePending > 0}
          on:click={() => navigate('quarantine')}
          aria-label={$t('dashboard.quarantinePending')}
        >
          <div class="eyebrow">{$t('dashboard.quarantinePending')}</div>
          <div class="stat-value" class:warn={quarantinePending > 0}>{quarantinePending.toLocaleString()}</div>
        </button>
      {:else}
        <div class="stat-card">
          <div class="eyebrow">{$t('dashboard.quarantinePending')}</div>
          <div class="stat-value" class:warn={quarantinePending > 0}>{quarantinePending.toLocaleString()}</div>
        </div>
      {/if}
    </div>

    <!-- ── Package breakdown: pie + table ────────────────────────────────────── -->
    <section class="section">
      <h2 class="eyebrow">{$t('dashboard.packageBreakdown')}</h2>
      <div class="breakdown-row">

        <!-- Donut chart -->
        <div class="donut-wrap">
          {#if totalPackages() === 0}
            <div class="donut-empty">{$t('dashboard.donutEmpty')}</div>
          {:else}
            <svg viewBox="0 0 100 100" class="donut-svg">
              {#each slices as s (s.eco)}
                <path d={s.d} fill-rule="evenodd" class="slice slice-{s.eco}" />
              {/each}
              <text x="50" y="54" text-anchor="middle" class="donut-center-num">{totalPackages().toLocaleString()}</text>
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
                  <td class="text-right">{ecoCount(eco).toLocaleString()}</td>
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
          </table>
        </div>
      </div>
    </section>

    <!-- ── Download activity (last 24 h) ─────────────────────────────────────── -->
    <section class="section">
      <h2 class="eyebrow">{$t('dashboard.fetchesTitle')}</h2>
      <div class="chart-wrap">
        {#each hourBars as bar, i (bar.hour)}
          <div class="bar-col" title="{fmtHour(bar.hour)}: {bar.count}">
            <div class="bar-fill" style:height="{barHeights[i]}px"></div>
          </div>
        {/each}
      </div>
      <div class="chart-labels">
        {#each hourBars as bar, i (bar.hour)}
          <div class="bar-label-cell">
            {#if i % 4 === 0}{fmtHour(bar.hour)}{/if}
          </div>
        {/each}
      </div>
      <div class="chart-legend">
        {$t('dashboard.fetchesTotal', { values: { n: hourBars.reduce((s, b) => s + b.count, 0).toLocaleString() } })}
      </div>
    </section>

  {/if}
</div>

<style>
  /* SAML cert-expiry detail line */
  .saml-cert-detail { color: var(--text2); font-size: 13px; }

  /* Stat grid bottom margin */
  .stat-grid { margin-bottom: 32px; }

  /* Secondary line under a stat value (hosted/proxied split, quota, gate breakdown). */
  .stat-sub {
    font-size: 12px;
    color: var(--text2);
    line-height: 1.3;
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

  .donut-empty {
    width: 160px;
    height: 160px;
    display: flex;
    align-items: center;
    justify-content: center;
    color: var(--text2);
    font-size: 13px;
    border: 1px dashed var(--border);
    border-radius: 50%;
  }

  /* Ecosystem table */
  .eco-table-wrap {
    flex: 1;
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

  .bar-label-cell {
    flex: 1;
    font-size: 10px;
    color: var(--text2);
    white-space: nowrap;
    overflow: hidden;
  }

  .chart-legend {
    margin-top: 8px;
    font-size: 12px;
    color: var(--text2);
  }
</style>
