<!--
  Settings → Integrations: the per-org delivery channels for admin alerts. An inner sub-tab bar
  (SystemSettings.svelte's role=tablist pattern) switches between Webhooks and Slack. Email has no
  per-org channel config — SMTP is an instance-level transport, and the tenant-facing half (gate,
  recipients, health, test send) lives on the Alerts tab. The alert-settings projection is loaded
  once here for the Slack child; Webhooks loads its own data as it always has.
-->
<script>
  import { onMount } from 'svelte'
  import { t } from 'svelte-i18n'
  import { api } from '../api.js'
  import { extractErrorMessage } from '../form.js'
  import ErrorBanner from '../ErrorBanner.svelte'
  import InfoTip from '../InfoTip.svelte'
  import SettingsWebhooks from './SettingsWebhooks.svelte'
  import SettingsIntegrationsEmail from './SettingsIntegrationsEmail.svelte'
  import SettingsIntegrationsSlack from './SettingsIntegrationsSlack.svelte'

  let subTab = 'webhooks' // 'webhooks' | 'email' | 'slack'
  let alertSettings = null
  let loaded = false
  let error = ''

  onMount(load)

  async function load() {
    try {
      alertSettings = await api.getAlertSettings()
      loaded = true
    } catch (e) { error = extractErrorMessage(e) }
  }

  function onAlertSettingsUpdated(updated) {
    alertSettings = updated
  }
</script>

<h3 class="section-h">
  {$t('settings.integrations.title')}
  <InfoTip text={$t('settings.integrations.hint')} />
</h3>

<div class="tabs" role="tablist">
  <button class="tab" class:active={subTab === 'webhooks'}
          role="tab" aria-selected={subTab === 'webhooks'}
          on:click={() => subTab = 'webhooks'}>{$t('settings.integrations.tabs.webhooks')}</button>
  <button class="tab" class:active={subTab === 'email'}
          role="tab" aria-selected={subTab === 'email'}
          on:click={() => subTab = 'email'}>{$t('settings.integrations.tabs.email')}</button>
  <button class="tab" class:active={subTab === 'slack'}
          role="tab" aria-selected={subTab === 'slack'}
          on:click={() => subTab = 'slack'}>{$t('settings.integrations.tabs.slack')}</button>
</div>

{#if subTab === 'webhooks'}
  <SettingsWebhooks />
{:else}
  <ErrorBanner message={error} />
  {#if !loaded}
    <span class="spinner"></span>
  {:else if subTab === 'email'}
    <SettingsIntegrationsEmail settings={alertSettings} onUpdated={onAlertSettingsUpdated} />
  {:else}
    <SettingsIntegrationsSlack settings={alertSettings} onUpdated={onAlertSettingsUpdated} />
  {/if}
{/if}
