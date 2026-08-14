<script>
  import { t } from 'svelte-i18n'
  import { systemApi } from '../lib/api.js'
  import SettingsInstance from '../lib/settings/SettingsInstance.svelte'
  import SettingsMetrics from '../lib/settings/SettingsMetrics.svelte'
  import SettingsInstanceEmail from '../lib/settings/SettingsInstanceEmail.svelte'
  import SettingsRelayHealth from '../lib/settings/SettingsRelayHealth.svelte'
  import SystemSlackConfig from '../lib/settings/SystemSlackConfig.svelte'

  let activeTab = 'instance'  // 'instance' | 'metrics' | 'email' | 'slack'
</script>

<div class="page">
  <h1>{$t('system.settings.title')}</h1>
  <p class="subtitle">{$t('system.settings.subtitle')}</p>

  <div class="tabs" role="tablist">
    <button class="tab" class:active={activeTab === 'instance'}
            role="tab" aria-selected={activeTab === 'instance'}
            on:click={() => activeTab = 'instance'}>{$t('system.settings.tabs.instance')}</button>
    <button class="tab" class:active={activeTab === 'metrics'}
            role="tab" aria-selected={activeTab === 'metrics'}
            on:click={() => activeTab = 'metrics'}>{$t('system.settings.tabs.metrics')}</button>
    <button class="tab" class:active={activeTab === 'email'}
            role="tab" aria-selected={activeTab === 'email'}
            on:click={() => activeTab = 'email'}>{$t('system.settings.tabs.email')}</button>
    <button class="tab" class:active={activeTab === 'slack'}
            role="tab" aria-selected={activeTab === 'slack'}
            on:click={() => activeTab = 'slack'}>{$t('system.settings.tabs.slack')}</button>
  </div>

  {#if activeTab === 'instance'}
    <SettingsInstance getSettings={systemApi.getSettings} updateSettings={systemApi.updateSettings} />
  {:else if activeTab === 'metrics'}
    <SettingsMetrics getAccess={systemApi.getMetricsAccess} updateAccess={systemApi.updateMetricsAccess} />
  {:else if activeTab === 'email'}
    <SettingsInstanceEmail
      getConfig={systemApi.getEmailConfig}
      updateConfig={systemApi.updateEmailConfig}
      testSend={systemApi.testEmailConfig}
    />
    <SettingsRelayHealth getHealth={systemApi.getEmailHealth} />
  {:else}
    <SystemSlackConfig />
  {/if}
</div>

<style>
  .subtitle { color: var(--text2); font-size: 13px; margin: 0 0 16px; }
</style>
