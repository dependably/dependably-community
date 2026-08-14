<!--
  Operator aggregate relay-health panel — shared by the multi-mode system SPA (SystemSettings.svelte's
  email tab, backed by systemApi.getEmailHealth) and the single-mode tenant Settings page
  (OrgSettings.svelte's instance tab, backed by api.getInstanceEmailHealth). Renders next to
  SettingsInstanceEmail, the same pairing InstanceController/SystemController keep on the backend:
  the transport config and its live health are two different questions about the same relay.

  Every field here is a count or an aggregate timestamp — never a tenant identifier — so the same
  component is safe to render unmodified in the system_admin SPA, which must never show tenant
  business data.
-->
<script>
  import { onMount } from 'svelte'
  import { t } from 'svelte-i18n'
  import { formatDate, formatNumber, utcTooltip } from '../format.js'
  import { extractErrorMessage } from '../form.js'
  import ErrorBanner from '../ErrorBanner.svelte'
  import InfoTip from '../InfoTip.svelte'

  export let getHealth // () => Promise<health>

  let health = null
  let loaded = false
  let error = ''
  let refreshing = false

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
    try {
      await load()
    } finally { refreshing = false }
  }
</script>

<h3 class="section-h">
  {$t('settings.relayHealth.title')}
  <InfoTip text={$t('settings.relayHealth.hint')} />
</h3>

<ErrorBanner message={error} />

{#if !loaded}
  <span class="spinner"></span>
{:else}
  <div class="relay-health">
    <div class="status-row">
      <span class="status-badge" class:status-unhealthy={health.unhealthy} class:status-healthy={!health.unhealthy}>
        <svg width="12" height="12" aria-hidden="true">
          <use href="/icons.svg#{health.unhealthy ? 'icon-alert' : 'icon-check'}" />
        </svg>
        {health.unhealthy ? $t('settings.relayHealth.statusUnhealthy') : $t('settings.relayHealth.statusHealthy')}
      </span>
      <button class="btn-sm" on:click={refresh} disabled={refreshing}>
        {refreshing ? $t('common.loading') : $t('settings.relayHealth.refresh')}
      </button>
    </div>

    <div class="stat-grid">
      <div class="stat-card" class:danger={health.unhealthy}>
        <span class="eyebrow">{$t('settings.relayHealth.affectedTenants')}</span>
        <span class="stat-value" class:danger={health.unhealthy}>{$formatNumber(health.affectedTenants)}</span>
      </div>
      <div class="stat-card" class:danger={health.unhealthy}>
        <span class="eyebrow">{$t('settings.relayHealth.consecutiveFailures')}</span>
        <span class="stat-value" class:danger={health.unhealthy}>{$formatNumber(health.consecutiveFailures)}</span>
      </div>
      <div class="stat-card">
        <span class="eyebrow">{$t('settings.relayHealth.firstFailure')}</span>
        <span class="stat-value stat-value-time" title={utcTooltip(health.firstFailureAt)}>
          {health.firstFailureAt ? $formatDate(health.firstFailureAt) : $t('settings.relayHealth.none')}
        </span>
      </div>
      <div class="stat-card" class:warn={health.backlogDepth > 0}>
        <span class="eyebrow">{$t('settings.relayHealth.backlogDepth')}</span>
        <span class="stat-value" class:warn={health.backlogDepth > 0}>{$formatNumber(health.backlogDepth)}</span>
      </div>
      <div class="stat-card">
        <span class="eyebrow">{$t('settings.relayHealth.oldestQueued')}</span>
        <span class="stat-value stat-value-time" title={utcTooltip(health.oldestQueuedAt)}>
          {health.oldestQueuedAt ? $formatDate(health.oldestQueuedAt) : $t('settings.relayHealth.none')}
        </span>
      </div>
      <div class="stat-card" class:warn={health.deadLettered > 0}>
        <span class="eyebrow">{$t('settings.relayHealth.deadLettered')}</span>
        <span class="stat-value" class:warn={health.deadLettered > 0}>{$formatNumber(health.deadLettered)}</span>
      </div>
      <div class="stat-card" class:warn={health.expired > 0}>
        <span class="eyebrow">{$t('settings.relayHealth.expired')}</span>
        <span class="stat-value" class:warn={health.expired > 0}>{$formatNumber(health.expired)}</span>
      </div>
    </div>
  </div>
{/if}

<style>
  .relay-health { max-width: 640px; }
  .status-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 12px;
  }
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
  .status-healthy { color: var(--success); border-color: color-mix(in srgb, var(--success) 25%, var(--border)); }
  .status-unhealthy {
    color: var(--danger);
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
  .stat-card.danger { background: var(--danger-soft); border-color: color-mix(in srgb, var(--danger) 25%, var(--border)); }
  .stat-card.warn { background: var(--warning-soft); border-color: color-mix(in srgb, var(--warning) 25%, var(--border)); }
  .eyebrow { font-size: 11px; text-transform: uppercase; letter-spacing: 0.04em; color: var(--text2); }
  .stat-value { font-size: 22px; font-weight: 700; line-height: 1.1; }
  .stat-value.danger { color: var(--danger); }
  .stat-value.warn { color: var(--warning); }
  .stat-value-time { font-size: 13px; font-weight: 600; }
</style>
