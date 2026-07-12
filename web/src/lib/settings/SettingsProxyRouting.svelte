<!--
  Proxy tab — transport and routing only: passthrough toggle and the upstream
  registries (self-loading) the proxy fetches from. What may be admitted once
  fetched — allowlist mode and the allowlist/blocklist — lives on the Gates tab
  alongside the other content-admission controls.

  Binds directly to the parent-owned proxySettings object; the parent retains
  sole write authority.
-->
<script>
  import { t } from 'svelte-i18n'
  import SettingsUpstreamRegistries from './SettingsUpstreamRegistries.svelte'
  import InfoTip from '../InfoTip.svelte'
  import Toggle from '../Toggle.svelte'

  export let proxySettings
  export let airGapped = false
  export let saving = false
  export let onSave = () => {}
</script>

<div class="card card-narrow">
  <div class="form-row form-row-inline">
    <label class="flex-1 label-row">{$t('settings.proxy.passthroughEnabled')} <InfoTip text={$t('settings.proxy.passthroughHint')} /></label>
    <Toggle bind:checked={proxySettings.proxy_passthrough_enabled} disabled={airGapped} ariaLabel={$t('settings.proxy.passthroughEnabled')} />
  </div>
  {#if airGapped}
    <div class="form-hint mb-3">{$t('settings.proxy.passthroughOverriddenByAirGap')}</div>
  {/if}
  <button class="primary" on:click={onSave} disabled={saving}>
    {saving ? $t('common.actions.saving') : $t('common.actions.save')}
  </button>
</div>

<SettingsUpstreamRegistries />

<style>
  .card-narrow { max-width: 480px; }
  .form-row-inline { flex-direction: row; align-items: center; gap: 12px; }
</style>
