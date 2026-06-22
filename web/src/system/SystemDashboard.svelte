<script>
  import { onMount } from 'svelte'
  import { t } from 'svelte-i18n'
  import { systemApi } from '../lib/api.js'
  import { navigate } from '../lib/store.js'
  import { formatBytes } from '../lib/format.js'

  let data = null
  let loading = true
  let error = ''

  let health = null
  let healthLoading = true
  let healthError = ''

  async function load() {
    loading = true
    error = ''
    try {
      data = await systemApi.getDashboard()
    } catch (e) { error = e.message }
    finally { loading = false }
  }

  async function loadHealth() {
    healthLoading = true
    healthError = ''
    try {
      health = await systemApi.getHealth()
    } catch (e) { healthError = e.message }
    finally { healthLoading = false }
  }

  onMount(() => { load(); loadHealth() })

  function fmtDuration(ms) {
    if (ms === null || ms === undefined) return '—'
    if (ms < 1000) return `${ms} ms`
    if (ms < 60_000) return `${(ms / 1000).toFixed(2)} s`
    const total = Math.round(ms / 1000)
    return `${Math.floor(total / 60)}m ${total % 60}s`
  }

  // Relative time from an ISO timestamp or ageSeconds number.
  function relativeAge(ageSecondsOrIso) {
    let ageSeconds
    if (typeof ageSecondsOrIso === 'number') {
      ageSeconds = ageSecondsOrIso
    } else if (ageSecondsOrIso) {
      ageSeconds = Math.floor((Date.now() - new Date(ageSecondsOrIso).getTime()) / 1000)
    } else {
      return null
    }
    if (ageSeconds < 90) return $t('system.dashboard.health.ageRelative.justNow')
    if (ageSeconds < 3600) return $t('system.dashboard.health.ageRelative.minutesAgo', { values: { n: Math.floor(ageSeconds / 60) } })
    if (ageSeconds < 86400) return $t('system.dashboard.health.ageRelative.hoursAgo', { values: { n: Math.floor(ageSeconds / 3600) } })
    return $t('system.dashboard.health.ageRelative.daysAgo', { values: { n: Math.floor(ageSeconds / 86400) } })
  }

  // Build a plain-language summary of the overall health status.
  function overallSummary(h) {
    if (!h) return ''
    if (h.overall === 'healthy') return $t('system.dashboard.health.overallSummary.healthy')
    if (h.overall === 'down') return $t('system.dashboard.health.overallSummary.down')
    // Degraded: compute the cause.
    const badJobs = (h.jobs ?? []).filter(j => j.status === 'stale' || j.status === 'failing')
    if (badJobs.length > 0) {
      const detail = badJobs.length === 1
        ? `1 background job ${badJobs[0].status}`
        : `${badJobs.length} background jobs ${badJobs.some(j => j.status === 'failing') ? 'failing/stale' : 'stale'}`
      return $t('system.dashboard.health.overallSummary.degraded', { values: { detail } })
    }
    if (h.storage?.stagingBelowThreshold) {
      return $t('system.dashboard.health.overallSummary.degraded', { values: { detail: 'staging disk low' } })
    }
    return $t('system.dashboard.health.overallSummary.degraded', { values: { detail: 'stale snapshots' } })
  }

  // Non-ok jobs (stale, failing) to display in the compact list.
  $: badJobs = (health?.jobs ?? []).filter(j => j.status === 'stale' || j.status === 'failing')
  $: allJobsOk = (health?.jobs ?? []).every(j => j.status === 'ok' || j.status === 'disabled')
  $: okJobCount = (health?.jobs ?? []).filter(j => j.status === 'ok').length

  // Dependencies to display as chips (omit null/unconfigured ones).
  $: deps = (health?.dependencies ?? []).filter(d => d.name !== 'redis' || d.status !== null)
</script>

<div class="page">
  <h1>{$t('system.dashboard.title')}</h1>
  <p class="subtitle">{$t('system.dashboard.subtitle')}</p>

  {#if error}<div class="page-error">{error}</div>{/if}

  <section class="card health-card">
    <div class="card-header">
      <h2>{$t('system.dashboard.health.title')}</h2>
      <button class="link-button" type="button" on:click={loadHealth} disabled={healthLoading}>
        {$t('system.dashboard.health.refresh')}
      </button>
    </div>
    {#if healthLoading && !health}
      <p class="muted">{$t('system.dashboard.health.loading')}</p>
    {:else if healthError}
      <p class="page-error">{healthError}</p>
    {:else if health}
      <!-- Overall badge with plain-language summary -->
      <div class="health-overall">
        <span class="health-badge health-{health.overall}">
          {$t(`system.dashboard.health.overall.${health.overall}`, { default: health.overall })}
        </span>
        <span class="health-summary-text health-text-{health.overall}">{overallSummary(health)}</span>
      </div>

      <div class="health-panels">
        <!-- Dependencies as labeled chips -->
        <div class="health-section">
          <div class="health-section-label">{$t('system.dashboard.health.depsLabel')}</div>
          <div class="health-deps-chips">
            {#each deps as dep (dep.name)}
              {@const label = dep.name === 'db'
                ? $t('system.dashboard.health.depDatabase')
                : dep.name === 'blob_store'
                  ? $t('system.dashboard.health.depBlobStore')
                  : dep.name === 'redis'
                    ? $t('system.dashboard.health.depRedis')
                    : dep.name}
              <span class="dep-chip dep-chip-{dep.status}"
                    title={dep.error ?? dep.name}>
                <span class="dep-dot dep-{dep.status}"></span>
                {label}
              </span>
            {/each}
          </div>
        </div>

        <!-- Background jobs: compact list of non-ok jobs or all-ok summary -->
        <div class="health-section">
          <div class="health-section-label">{$t('system.dashboard.health.jobsLabel')}</div>
          {#if allJobsOk}
            <span class="health-all-ok">
              {$t('system.dashboard.health.jobsAllHealthy', { values: { count: okJobCount } })}
            </span>
          {:else}
            <ul class="bad-jobs-list">
              {#each badJobs as job (job.name)}
                {@const age = job.ageSeconds !== null && job.ageSeconds !== undefined ? relativeAge(job.ageSeconds) : (job.lastRunAt ? relativeAge(job.lastRunAt) : null)}
                <li>
                  <code class="job-name">{job.name}</code>
                  <span class="outcome outcome-{job.status}">{job.status}</span>
                  {#if age}
                    <span class="job-age muted">{$t('system.dashboard.health.jobLastRan', { values: { age } })}</span>
                  {/if}
                </li>
              {/each}
            </ul>
          {/if}
          <button class="link-button jobs-link" type="button" on:click={() => navigate('system-audit')}>
            {$t('system.dashboard.health.viewJobsLink')}
          </button>
        </div>

        <!-- Storage staging disk -->
        {#if health.storage}
          <div class="health-section">
            <div class="health-section-label">{$t('system.dashboard.health.stagingLabel')}</div>
            {#if health.storage.stagingBelowThreshold}
              <span class="health-warn-text">
                {$t('system.dashboard.health.stagingLowDetail', {
                  values: {
                    free: $formatBytes(health.storage.stagingAvailableBytes),
                    total: $formatBytes(health.storage.stagingAvailableBytes + health.storage.stagingUsedBytes)
                  }
                })}
              </span>
            {:else}
              <span class="muted">{$formatBytes(health.storage.stagingAvailableBytes)} free</span>
            {/if}
          </div>
        {/if}

        <!-- Tenants needing attention -->
        {#if (health.tenants?.needAttention ?? 0) > 0}
          <div class="health-section">
            <button class="link-button" type="button" on:click={() => navigate('system-tenants')}>
              {health.tenants.needAttention === 1
                ? $t('system.dashboard.health.tenants.needAttention', { values: { count: health.tenants.needAttention } })
                : $t('system.dashboard.health.tenants.needAttentionPlural', { values: { count: health.tenants.needAttention } })}
            </button>
          </div>
        {/if}
      </div>
    {/if}
  </section>

  {#if loading && !data}
    <span class="spinner"></span>
  {:else if data}
    <div class="cards">
      <section class="card clickable" on:click={() => navigate('system-tenants')}
               role="link" tabindex="0"
               on:keydown={(e) => { if (e.key === 'Enter' || e.key === ' ') navigate('system-tenants') }}>
        <h2>{$t('system.dashboard.tenants.title')}</h2>
        <div class="stat-grid">
          <div class="stat"><div class="stat-value">{data.tenants.active}</div><div class="stat-label">{$t('system.dashboard.tenants.active')}</div></div>
          <div class="stat"><div class="stat-value warn">{data.tenants.suspended}</div><div class="stat-label">{$t('system.dashboard.tenants.suspended')}</div></div>
          <div class="stat"><div class="stat-value muted">{data.tenants.softDeleted}</div><div class="stat-label">{$t('system.dashboard.tenants.softDeleted')}</div></div>
        </div>
        <div class="stat-foot">{$t('system.dashboard.tenants.total', { values: { count: data.tenants.total } })}</div>
      </section>

      <section class="card clickable" on:click={() => navigate('system-admins')}
               role="link" tabindex="0"
               on:keydown={(e) => { if (e.key === 'Enter' || e.key === ' ') navigate('system-admins') }}>
        <h2>{$t('system.dashboard.admins.title')}</h2>
        <div class="stat-grid">
          <div class="stat"><div class="stat-value">{data.admins.active}</div><div class="stat-label">{$t('system.dashboard.admins.active')}</div></div>
          <div class="stat"><div class="stat-value warn">{data.admins.locked}</div><div class="stat-label">{$t('system.dashboard.admins.locked')}</div></div>
          <div class="stat"><div class="stat-value muted">{data.admins.disabled}</div><div class="stat-label">{$t('system.dashboard.admins.disabled')}</div></div>
        </div>
        <div class="stat-foot">{$t('system.dashboard.admins.total', { values: { count: data.admins.total } })}</div>
      </section>

      <section class="card">
        <h2>{$t('system.dashboard.storage.title')}</h2>
        <div class="stat-grid storage-grid">
          <div class="stat"><div class="stat-value">{$formatBytes(data.storage?.byTier?.cache ?? 0)}</div><div class="stat-label">{$t('system.dashboard.storage.cache')}</div></div>
          <div class="stat"><div class="stat-value">{$formatBytes(data.storage?.byTier?.registry ?? 0)}</div><div class="stat-label">{$t('system.dashboard.storage.registry')}</div></div>
        </div>
        <div class="stat-foot">{$t('system.dashboard.storage.total', { values: { total: $formatBytes(data.storage?.totalBytes ?? 0) } })}</div>
      </section>
    </div>

    <section class="card">
      <div class="card-header">
        <h2>{$t('system.dashboard.recentJobs.title')}</h2>
        <button class="link-button" type="button" on:click={() => navigate('system-audit')}>
          {$t('system.dashboard.recentJobs.viewAll')}
        </button>
      </div>
      {#if data.recentJobs.length === 0}
        <p class="muted">{$t('system.dashboard.recentJobs.empty')}</p>
      {:else}
        <table class="table-auto jobs-mini">
          <thead>
            <tr>
              <th>{$t('system.backgroundJobs.columns.jobName')}</th>
              <th>{$t('system.backgroundJobs.columns.startedAt')}</th>
              <th>{$t('system.backgroundJobs.columns.duration')}</th>
              <th>{$t('system.backgroundJobs.columns.outcome')}</th>
            </tr>
          </thead>
          <tbody>
            {#each data.recentJobs as j (j.id)}
              <tr>
                <td><code>{j.jobName}</code></td>
                <td>{new Date(j.startedAt).toLocaleString()}</td>
                <td class="num">{fmtDuration(j.durationMs)}</td>
                <td><span class="outcome outcome-{j.outcome}">{$t(`system.backgroundJobs.outcome.${j.outcome}`, { default: j.outcome })}</span></td>
              </tr>
            {/each}
          </tbody>
        </table>
      {/if}
    </section>
  {/if}
</div>

<style>
  .subtitle { color: var(--text2); font-size: 13px; margin: 0 0 20px; }

  .health-card { margin-bottom: 16px; }

  .health-overall { display: flex; align-items: center; gap: 10px; margin-bottom: 14px; }
  .health-badge {
    display: inline-block;
    padding: 2px 10px;
    border-radius: 999px;
    font-size: 12px;
    font-weight: 600;
    border: 1px solid var(--border);
    flex-shrink: 0;
  }
  .health-healthy { color: var(--success); }
  .health-degraded { color: var(--warning); }
  .health-down { color: var(--danger); }
  .health-summary-text { font-size: 13px; }
  .health-text-degraded { color: var(--warning); }
  .health-text-down { color: var(--danger); }

  .health-panels { display: flex; flex-direction: column; gap: 12px; }
  .health-section { display: flex; align-items: baseline; gap: 10px; flex-wrap: wrap; }
  .health-section-label {
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    color: var(--text2);
    min-width: 110px;
    flex-shrink: 0;
  }

  /* Dependency chips */
  .health-deps-chips { display: flex; gap: 6px; flex-wrap: wrap; }
  .dep-chip {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 2px 8px;
    border-radius: 999px;
    border: 1px solid var(--border);
    background: var(--bg);
    font-size: 12px;
    cursor: default;
  }
  .dep-dot {
    display: inline-block;
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: var(--border);
  }
  .dep-dot.dep-ok { background: var(--success); }
  .dep-dot.dep-error { background: var(--danger); }
  .dep-chip-error { border-color: var(--danger); color: var(--danger); }

  /* Job list */
  .health-all-ok { font-size: 13px; color: var(--success); }
  .bad-jobs-list {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 4px;
  }
  .bad-jobs-list li { display: flex; align-items: center; gap: 6px; font-size: 13px; }
  .job-name { background: var(--bg); padding: 1px 5px; border-radius: 3px; font-size: 11px; }
  .job-age { font-size: 11px; }
  .jobs-link { font-size: 11px; }

  /* Storage */
  .health-warn-text { color: var(--warning); font-size: 13px; }

  .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 16px; margin-bottom: 16px; }
  .card {
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 16px 20px;
  }
  .card h2 { margin: 0 0 12px; font-size: 14px; font-weight: 600; color: var(--text); text-transform: uppercase; letter-spacing: 0.04em; }
  .card.clickable { cursor: pointer; transition: border-color 0.1s ease; }
  .card.clickable:hover, .card.clickable:focus-visible { border-color: var(--accent); outline: none; }

  .stat-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; }
  .stat-grid.storage-grid { grid-template-columns: repeat(2, 1fr); }
  .stat { text-align: left; }
  .stat-value { font-size: 28px; font-weight: 600; line-height: 1.1; font-variant-numeric: tabular-nums; }
  .stat-value.warn { color: var(--warning); }
  .stat-value.muted { color: var(--text2); }
  .stat-label { font-size: 11px; color: var(--text2); text-transform: uppercase; letter-spacing: 0.04em; margin-top: 2px; }
  .stat-foot { font-size: 11px; color: var(--text2); margin-top: 10px; }

  .card-header { display: flex; align-items: center; justify-content: space-between; }
  .link-button {
    background: none; border: none; padding: 0;
    color: var(--accent); font-size: 12px; cursor: pointer;
  }
  .link-button:hover { text-decoration: underline; }

  .jobs-mini { width: 100%; border-collapse: collapse; font-size: 13px; }
  .jobs-mini th, .jobs-mini td { padding: 6px 8px; border-bottom: 1px solid var(--border); text-align: left; }
  .jobs-mini th { color: var(--text2); font-weight: 500; font-size: 12px; }
  .num { text-align: right; font-variant-numeric: tabular-nums; }
  code { background: var(--bg); padding: 2px 6px; border-radius: 3px; font-size: 12px; }

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
  .outcome-server_error, .outcome-failing { color: var(--danger); }
  .outcome-cancelled, .outcome-stale { color: var(--warning); }

  .muted { color: var(--text2); font-size: 13px; }
</style>
