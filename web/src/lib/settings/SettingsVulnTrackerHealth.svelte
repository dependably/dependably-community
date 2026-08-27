<!--
  Observed health of the one instance-level vulnerability-tracker connection, shared by the
  multi-mode system SPA (SystemSettings.svelte's tracker tab, backed by systemApi.*) and the
  single-mode tenant Settings page (OrgSettings.svelte's instance tab, backed by api.*). Renders
  next to SettingsVulnTracker, the same pairing SettingsRelayHealth keeps with
  SettingsInstanceEmail: the connection an operator edits and the health it exhibits are two
  different questions about the same thing.

  Every field is a count, an instant or a status token — never a purl, an advisory id or a tenant
  identifier — so the component is safe to render unmodified in the system_admin SPA.

  Three states are kept distinct on purpose, because collapsing any pair produces a panel that
  reads plausibly and says the wrong thing:
    - not configured  → no connection exists. NOT "healthy", and not "failing".
    - never attempted → configured, but no scan pass has reached a lookup yet.
    - failing         → the scan path attempted and did not reach.
  A brand-new working connection and a deployment that never configured one produce identical
  zeroes; only `configured` tells them apart.
-->
<script>
  import { onMount } from 'svelte'
  import { t } from 'svelte-i18n'
  import { formatDate, formatNumber, utcTooltip } from '../format.js'
  import { extractErrorMessage } from '../form.js'
  import ErrorBanner from '../ErrorBanner.svelte'
  import InfoTip from '../InfoTip.svelte'

  export let getHealth  // () => Promise<health>
  export let testConnection // () => Promise<probe>

  let health = null
  let loaded = false
  let error = ''
  let refreshing = false
  let testing = false
  let probe = null
  let probeError = ''

  onMount(load)

  async function load() {
    error = ''
    try {
      health = await getHealth()
      loaded = true
    } catch (e) { error = extractErrorMessage(e) }
  }

  async function refresh() {
    refreshing = true
    try { await load() } finally { refreshing = false }
  }

  async function runTest() {
    testing = true
    probe = null
    probeError = ''
    try {
      probe = await testConnection()
      // A probe never moves the health row, but it does add a fetch-log entry — so the recent
      // list below is refreshed to show it rather than leaving the operator's own action invisible
      // until the next page load.
      await load()
    } catch (e) {
      // Only "nothing to dial" rejects. An unreached tracker resolves with reached:false.
      probeError = extractErrorMessage(e)
    } finally { testing = false }
  }

  // The scan path's state, as three named cases rather than a boolean. `health.health` is null
  // until a scan pass has actually attempted a lookup.
  $: scanState = !health?.configured
    ? 'notConfigured'
    : !health.health
      ? 'neverAttempted'
      : health.health.lastStatus === 'ok' ? 'ok' : 'failed'

  $: failing = scanState === 'failed'

  // Freshness readings pair the producer's asserted as-of with the operator's horizon, because
  // neither means much alone: "3 hours ago" is only reassuring against a horizon it is inside.
  function isStale(assertedAt) {
    if (!assertedAt || !health?.maxStalenessHours) return false
    return Date.now() - Date.parse(assertedAt) > health.maxStalenessHours * 3600_000
  }

  $: nvdStale = isStale(health?.health?.nvdAssertedAt)
  $: ssvcStale = isStale(health?.health?.ssvcAssertedAt)
</script>

<h3 class="section-h">
  {$t('settings.vulnTrackerHealth.title')}
  <InfoTip text={$t('settings.vulnTrackerHealth.hint')} />
</h3>

<ErrorBanner message={error} />

{#if !loaded}
  <span class="spinner"></span>
{:else if !health.configured}
  <!-- Deliberately not a stat grid of zeroes: an integration nobody configured is not a broken
       one, and a panel of zeroes would read as a dead connection. -->
  <p class="unconfigured">{$t('settings.vulnTrackerHealth.notConfigured')}</p>
{:else}
  <div class="tracker-health">
    <div class="status-row">
      <span class="status-badge" class:status-failed={failing} class:status-ok={scanState === 'ok'}>
        <svg width="12" height="12" aria-hidden="true">
          <use href="/icons.svg#{failing ? 'icon-alert' : scanState === 'ok' ? 'icon-check' : 'icon-info'}" />
        </svg>
        {$t(`settings.vulnTrackerHealth.state.${scanState}`)}
      </span>
      <span class="actions">
        <button class="btn-sm" on:click={runTest} disabled={testing || !health.enabled}>
          {testing ? $t('settings.vulnTrackerHealth.testing') : $t('settings.vulnTrackerHealth.test')}
        </button>
        <button class="btn-sm" on:click={refresh} disabled={refreshing}>
          {refreshing ? $t('common.loading') : $t('settings.vulnTrackerHealth.refresh')}
        </button>
      </span>
    </div>

    {#if !health.enabled}
      <p class="form-hint paused-hint">{$t('settings.vulnTrackerHealth.pausedHint')}</p>
    {/if}

    <ErrorBanner message={probeError} />

    {#if probe}
      <div class="probe-result" class:probe-failed={!probe.reached} role="status">
        {#if probe.reached}
          {$t('settings.vulnTrackerHealth.probeReached', { values: { ms: $formatNumber(probe.latencyMs) } })}
        {:else}
          {$t('settings.vulnTrackerHealth.probeFailed', {
            values: { reason: $t(`settings.vulnTrackerHealth.reason.${probe.reason}`) },
          })}
        {/if}
      </div>
    {/if}

    <div class="stat-grid">
      <div class="stat-card">
        <span class="eyebrow">{$t('settings.vulnTrackerHealth.lastSuccess')}</span>
        <span class="stat-value stat-value-time" title={utcTooltip(health.health?.lastSuccessAt)}>
          {health.health?.lastSuccessAt
            ? $formatDate(health.health.lastSuccessAt)
            : $t('settings.vulnTrackerHealth.never')}
        </span>
      </div>
      <div class="stat-card" class:danger={failing}>
        <span class="eyebrow">{$t('settings.vulnTrackerHealth.consecutiveFailures')}</span>
        <span class="stat-value" class:danger={failing}>
          {$formatNumber(health.health?.consecutiveFailures ?? 0)}
        </span>
      </div>
      <div class="stat-card" class:danger={failing}>
        <span class="eyebrow">{$t('settings.vulnTrackerHealth.failingSince')}</span>
        <span class="stat-value stat-value-time" title={utcTooltip(health.health?.failingSince)}>
          {health.health?.failingSince
            ? $formatDate(health.health.failingSince)
            : $t('settings.vulnTrackerHealth.none')}
        </span>
      </div>
      <div class="stat-card">
        <span class="eyebrow">{$t('settings.vulnTrackerHealth.enrichedAdvisories')}</span>
        <span class="stat-value">{$formatNumber(health.enrichedAdvisories)}</span>
      </div>
      <div class="stat-card" class:warn={health.staleAdvisories > 0}>
        <span class="eyebrow">{$t('settings.vulnTrackerHealth.staleAdvisories')}</span>
        <span class="stat-value" class:warn={health.staleAdvisories > 0}>
          {$formatNumber(health.staleAdvisories)}
        </span>
      </div>
      <div class="stat-card" class:warn={nvdStale}>
        <span class="eyebrow">{$t('settings.vulnTrackerHealth.nvdAsOf')}</span>
        <span class="stat-value stat-value-time" class:warn={nvdStale} title={utcTooltip(health.health?.nvdAssertedAt)}>
          {health.health?.nvdAssertedAt
            ? $formatDate(health.health.nvdAssertedAt)
            : $t('settings.vulnTrackerHealth.notAsserted')}
        </span>
      </div>
      <div class="stat-card" class:warn={ssvcStale}>
        <span class="eyebrow">{$t('settings.vulnTrackerHealth.ssvcAsOf')}</span>
        <span class="stat-value stat-value-time" class:warn={ssvcStale} title={utcTooltip(health.health?.ssvcAssertedAt)}>
          {health.health?.ssvcAssertedAt
            ? $formatDate(health.health.ssvcAssertedAt)
            : $t('settings.vulnTrackerHealth.notAsserted')}
        </span>
      </div>
    </div>

    <p class="form-hint horizon-hint">
      {$t('settings.vulnTrackerHealth.horizonHint', { values: { hours: health.maxStalenessHours } })}
    </p>

    <h4 class="subsection-h">{$t('settings.vulnTrackerHealth.recentFetches')}</h4>
    {#if health.recentFetches.length === 0}
      <p class="form-hint">{$t('settings.vulnTrackerHealth.noFetches')}</p>
    {:else}
      <div class="table-scroll">
        <table class="fetch-table">
          <thead>
            <tr>
              <th>{$t('settings.vulnTrackerHealth.col.when')}</th>
              <th>{$t('settings.vulnTrackerHealth.col.kind')}</th>
              <th>{$t('settings.vulnTrackerHealth.col.outcome')}</th>
              <th class="num">{$t('settings.vulnTrackerHealth.col.purls')}</th>
              <th class="num">{$t('settings.vulnTrackerHealth.col.advisories')}</th>
              <th class="num">{$t('settings.vulnTrackerHealth.col.duration')}</th>
            </tr>
          </thead>
          <tbody>
            {#each health.recentFetches as fetch (fetch.startedAt + fetch.kind)}
              <tr>
                <td title={utcTooltip(fetch.startedAt)}>{$formatDate(fetch.startedAt)}</td>
                <td>{$t(`settings.vulnTrackerHealth.kind.${fetch.kind}`)}</td>
                <td class:failed-cell={fetch.outcome !== 'ok'}>
                  {fetch.outcome === 'ok'
                    ? $t('settings.vulnTrackerHealth.outcomeOk')
                    : $t(`settings.vulnTrackerHealth.reason.${fetch.reason}`)}
                </td>
                <td class="num">{$formatNumber(fetch.purlCount)}</td>
                <td class="num">{$formatNumber(fetch.advisoryCount)}</td>
                <td class="num">{$formatNumber(fetch.durationMs)}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  </div>
{/if}

<style>
  .tracker-health { max-width: 720px; }
  .unconfigured { font-size: 13px; color: var(--text2); margin: 0; }
  .status-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    margin-bottom: 12px;
  }
  .actions { display: flex; gap: 8px; }
  .status-badge {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-size: 12px;
    font-weight: 600;
    padding: 4px 10px;
    border-radius: 99px;
    background: var(--bg2);
    border: 1px solid var(--border);
    color: var(--text2);
  }
  .status-ok { color: var(--success); border-color: color-mix(in srgb, var(--success) 25%, var(--border)); }
  .status-failed {
    color: var(--danger);
    background: var(--danger-soft);
    border-color: color-mix(in srgb, var(--danger) 25%, var(--border));
  }
  .probe-result {
    background: var(--bg2);
    border: 1px solid color-mix(in srgb, var(--success) 25%, var(--border));
    border-radius: var(--radius);
    padding: 8px 12px;
    margin-bottom: 12px;
    font-size: 12px;
  }
  .probe-failed {
    background: var(--danger-soft);
    border-color: color-mix(in srgb, var(--danger) 25%, var(--border));
  }
  .stat-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
    gap: 12px;
  }
  .stat-card {
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 12px 14px;
    display: flex;
    flex-direction: column;
    gap: 4px;
  }
  .stat-value { font-size: 20px; font-weight: 600; color: var(--text); }
  .stat-value-time { font-size: 13px; font-weight: 500; }
  .stat-card.warn { border-color: color-mix(in srgb, var(--warning-border) 60%, var(--border)); }
  .stat-card.danger { border-color: color-mix(in srgb, var(--danger) 25%, var(--border)); }
  .stat-value.warn { color: var(--warning-text); }
  .stat-value.danger { color: var(--danger); }
  .form-hint { font-size: 11px; color: var(--text2); }
  .horizon-hint { margin: 8px 0 0; }
  .paused-hint { margin: 0 0 12px; }
  .subsection-h { font-size: 13px; font-weight: 600; margin: 20px 0 8px; color: var(--text2); }
  /* Wide content scrolls inside its own container rather than pushing the settings pane. */
  .table-scroll { overflow-x: auto; }
  .fetch-table { width: 100%; border-collapse: collapse; font-size: 12px; }
  .fetch-table th, .fetch-table td {
    text-align: left;
    padding: 6px 10px;
    border-bottom: 1px solid var(--border);
    white-space: nowrap;
  }
  .fetch-table th { color: var(--text2); font-weight: 600; }
  .fetch-table .num { text-align: right; }
  .failed-cell { color: var(--danger); }
</style>
