<!--
  Proxy tab — passthrough toggle, OSV score tolerance (0.0 – 10.0), the allowlistMode
  gate, and the Allowlist/Blocklist sections that the gate governs. Consolidating all
  proxy-related controls here makes the relationship between the mode toggle
  and the lists it gates obvious. The tolerance input stays a free-form text field
  with a decimal pattern so users can type intermediate values (`9.`) without the
  browser clamping or stripping; the blur handler normalises to one decimal place to
  match the server's stored shape.
-->
<script>
  import { t } from 'svelte-i18n'
  import SettingsList from './SettingsList.svelte'
  import SettingsNamespaces from './SettingsNamespaces.svelte'
  import SettingsUpstreamRegistries from './SettingsUpstreamRegistries.svelte'
  import InfoTip from '../InfoTip.svelte'

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

  export let reservedEntries = []
  export let reservedLoaded = false
  /** @type {() => void} */
  export let onAddReserved = () => {}
  /** @type {(id: string) => void} */
  export let onRemoveReserved = () => {}
</script>

<div class="card card-narrow">
  <div class="form-row form-row-inline">
    <label class="flex-1 label-row">{$t('settings.proxy.passthroughEnabled')} <InfoTip text={$t('settings.proxy.passthroughHint')} /></label>
    <input type="checkbox" bind:checked={proxySettings.proxy_passthrough_enabled} disabled={airGapped} class="w-auto" />
  </div>
  {#if airGapped}
    <div class="form-hint mb-3">{$t('settings.proxy.passthroughOverriddenByAirGap')}</div>
  {/if}
  <div class="form-row form-row-inline">
    <label class="flex-1">{$t('settings.proxy.allowlistMode')}</label>
    <input type="checkbox" bind:checked={allowlistMode} class="w-auto" />
  </div>
  <div class="form-row">
    <label class="label-row">{$t('settings.proxy.osvTolerance')} <InfoTip text={$t('settings.proxy.osvToleranceHint')} /></label>
    <input
      type="text"
      inputmode="decimal"
      pattern="[0-9]+(\.[0-9]+)?"
      bind:value={proxySettings.max_osv_score_tolerance}
      on:blur={(e) => proxySettings.max_osv_score_tolerance = Number(e.currentTarget.value || 0).toFixed(1)}
    />
  </div>
  <div class="form-row">
    <label class="label-row" for="min-release-age">{$t('settings.proxy.minReleaseAge')} <InfoTip text={$t('settings.proxy.minReleaseAgeHint')} /></label>
    <div class="value-unit-row">
      <input
        id="min-release-age"
        type="text"
        inputmode="numeric"
        pattern="[0-9]*"
        class="value-input"
        bind:value={proxySettings.min_release_age_value} />
      <select bind:value={proxySettings.min_release_age_unit} class="unit-select">
        <option value="hours">{$t('settings.proxy.minReleaseAgeUnitHours')}</option>
        <option value="days">{$t('settings.proxy.minReleaseAgeUnitDays')}</option>
      </select>
    </div>
  </div>
  <div class="form-row">
    <label class="label-row" for="block-deprecated">{$t('settings.proxy.blockDeprecated')} <InfoTip text={$t('settings.proxy.blockDeprecatedHint')} /></label>
    <select id="block-deprecated" bind:value={proxySettings.block_deprecated}>
      <option value="off">{$t('settings.proxy.blockDeprecatedOff')}</option>
      <option value="warn">{$t('settings.proxy.blockDeprecatedWarn')}</option>
      <option value="block_new">{$t('settings.proxy.blockDeprecatedBlockNew')}</option>
      <option value="block_all">{$t('settings.proxy.blockDeprecatedBlockAll')}</option>
    </select>
  </div>
  <div class="form-row">
    <label class="label-row" for="block-malicious">{$t('settings.proxy.blockMalicious')} <InfoTip text={$t('settings.proxy.blockMaliciousHint')} /></label>
    <select id="block-malicious" bind:value={proxySettings.block_malicious}>
      <option value="off">{$t('settings.proxy.blockMaliciousOff')}</option>
      <option value="warn">{$t('settings.proxy.blockMaliciousWarn')}</option>
      <option value="block">{$t('settings.proxy.blockMaliciousBlock')}</option>
    </select>
  </div>
  <div class="form-row">
    <label class="label-row" for="block-kev">{$t('settings.proxy.blockKev')} <InfoTip text={$t('settings.proxy.blockKevHint')} /></label>
    <select id="block-kev" bind:value={proxySettings.block_kev}>
      <option value="off">{$t('settings.proxy.blockKevOff')}</option>
      <option value="warn">{$t('settings.proxy.blockKevWarn')}</option>
      <option value="block">{$t('settings.proxy.blockKevBlock')}</option>
    </select>
  </div>
  <div class="form-row">
    <label class="label-row" for="max-epss">{$t('settings.proxy.maxEpssTolerance')} <InfoTip text={$t('settings.proxy.maxEpssToleranceHint')} /></label>
    <input
      id="max-epss"
      type="text"
      inputmode="decimal"
      pattern="[0-9]*(\.[0-9]+)?"
      placeholder={$t('settings.proxy.maxEpssTolerancePlaceholder')}
      bind:value={proxySettings.max_epss_tolerance}
    />
  </div>
  <button class="primary" on:click={onSave} disabled={saving}>
    {saving ? $t('common.actions.saving') : $t('common.actions.save')}
  </button>
</div>

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

<div class="page-header list-header mt-4">
  <h3 class="section-h">{$t('settings.proxy.reservedSection')}</h3>
</div>
<p class="form-hint">{$t('settings.proxy.reservedHint')}</p>
<SettingsNamespaces
  entries={reservedEntries}
  loading={!reservedLoaded}
  onAdd={onAddReserved}
  onRemove={onRemoveReserved} />

<SettingsUpstreamRegistries />

<style>
  .card-narrow { max-width: 480px; }
  .form-row-inline { flex-direction: row; align-items: center; gap: 12px; }
  /* Value + unit pair (e.g. "48 Hours") — number input on the left, unit picker on the right.
     Width-constrained so a 4-digit value never pushes the select off the card edge. */
  .value-unit-row { display: flex; gap: 8px; align-items: center; }
  .value-unit-row .value-input { flex: 0 0 110px; }
  .value-unit-row .unit-select { flex: 0 0 110px; }
</style>
