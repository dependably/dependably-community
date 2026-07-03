<!--
  Proxy tab — transport and routing: passthrough toggle, allowlist-mode gate,
  upstream registries (self-loading), and the allowlist/blocklist that the mode
  gate governs.

  Binds directly to the parent-owned proxySettings object and allowlistMode field
  of settings; the parent retains sole write authority over both objects.
-->
<script>
  import { t } from 'svelte-i18n'
  import SettingsList from './SettingsList.svelte'
  import SettingsUpstreamRegistries from './SettingsUpstreamRegistries.svelte'
  import InfoTip from '../InfoTip.svelte'
  import Toggle from '../Toggle.svelte'

  export let proxySettings
  export let allowlistMode = false
  export let airGapped = false
  export let saving = false
  export let onSave = () => {}

  export let allowlistEntries = []
  export let allowlistLoaded = false
  export let blocklistEntries = []
  export let blocklistLoaded = false

  /** @type {() => void} */
  export let onAddAllowlist = () => {}
  /** @type {(id: string) => void} */
  export let onRemoveAllowlist = () => {}
  /** @type {() => void} */
  export let onAddBlocklist = () => {}
  /** @type {(id: string) => void} */
  export let onRemoveBlocklist = () => {}
</script>

<div class="card card-narrow">
  <div class="form-row form-row-inline">
    <label class="flex-1 label-row">{$t('settings.proxy.passthroughEnabled')} <InfoTip text={$t('settings.proxy.passthroughHint')} /></label>
    <Toggle bind:checked={proxySettings.proxy_passthrough_enabled} disabled={airGapped} ariaLabel={$t('settings.proxy.passthroughEnabled')} />
  </div>
  {#if airGapped}
    <div class="form-hint mb-3">{$t('settings.proxy.passthroughOverriddenByAirGap')}</div>
  {/if}
  <div class="form-row form-row-inline">
    <label class="flex-1">{$t('settings.proxy.allowlistMode')}</label>
    <Toggle bind:checked={allowlistMode} ariaLabel={$t('settings.proxy.allowlistMode')} />
  </div>
  <button class="primary" on:click={onSave} disabled={saving}>
    {saving ? $t('common.actions.saving') : $t('common.actions.save')}
  </button>
</div>

<SettingsUpstreamRegistries />

<div class="page-header list-header mt-4">
  <h3 class="section-h">{$t('settings.proxy.allowlistSection')}</h3>
</div>
<SettingsList
  entries={allowlistEntries}
  loading={!allowlistLoaded}
  i18nPrefix="allowlist"
  patternField="purlPattern"
  onAdd={onAddAllowlist}
  onRemove={onRemoveAllowlist} />

<div class="page-header list-header mt-4">
  <h3 class="section-h">{$t('settings.proxy.blocklistSection')}</h3>
</div>
<SettingsList
  entries={blocklistEntries}
  loading={!blocklistLoaded}
  i18nPrefix="blocklist"
  patternField="pattern"
  onAdd={onAddBlocklist}
  onRemove={onRemoveBlocklist} />

<style>
  .card-narrow { max-width: 480px; }
  .form-row-inline { flex-direction: row; align-items: center; gap: 12px; }
  .mt-4 { margin-top: 24px; }
</style>
