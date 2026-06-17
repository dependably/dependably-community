<script>
  import { t } from 'svelte-i18n'
  import { systemApi } from '../lib/api.js'
  import SettingsInstance from '../lib/settings/SettingsInstance.svelte'
  import SettingsMetrics from '../lib/settings/SettingsMetrics.svelte'

  let activeTab = 'instance'  // 'instance' | 'metrics'
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
  </div>

  {#if activeTab === 'instance'}
    <SettingsInstance getSettings={systemApi.getSettings} updateSettings={systemApi.updateSettings} />
  {:else}
    <SettingsMetrics getAccess={systemApi.getMetricsAccess} updateAccess={systemApi.updateMetricsAccess} />
  {/if}
</div>

<style>
  .subtitle { color: var(--text2); font-size: 13px; margin: 0 0 16px; }
</style>
