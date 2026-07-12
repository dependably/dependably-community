<!--
  Gates tab — content-admission gates: allowlist mode (default-deny), version-overwrite
  policy, block gates (deprecated/revoked/malicious/KEV), score and age tolerances,
  install-script policy, and the allowlist/blocklist plus install-script allowlist that
  the gates govern.

  Binds directly to the parent-owned proxySettings and settings objects so saves
  carry full whole-object payloads; the parent retains sole write authority. The
  allowlist-mode toggle rides settings.allowlistMode; the allowlist/blocklist lists
  are parent-owned state with parent-supplied add/remove handlers.

  Reactive default guard: versionOverwritePolicy defaults to 'block' on first load
  for orgs that never set the field; without it the select renders blank and saves
  undefined on the next unconditional write to the /settings endpoint.
-->
<script>
  import { t } from 'svelte-i18n'
  import SettingsInstallScriptAllowlist from './SettingsInstallScriptAllowlist.svelte'
  import SettingsList from './SettingsList.svelte'
  import InfoTip from '../InfoTip.svelte'
  import Toggle from '../Toggle.svelte'

  export let proxySettings
  export let settings
  export let saving = false
  export let onSave = () => {}

  export let allowlistMode = false
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

  export let installScriptAllowlistEntries = []
  export let installScriptAllowlistLoaded = false
  /** @type {() => void} */
  export let onAddInstallScriptAllowlist = () => {}
  /** @type {(id: string) => void} */
  export let onRemoveInstallScriptAllowlist = () => {}

  // Default to 'block' if the field is absent on first load so the select binds cleanly.
  $: if (settings && !settings.versionOverwritePolicy) {
    settings.versionOverwritePolicy = 'block'
  }
</script>

<div class="card card-narrow">
  <div class="form-row form-row-inline">
    <label class="flex-1">{$t('settings.proxy.allowlistMode')}</label>
    <Toggle bind:checked={allowlistMode} ariaLabel={$t('settings.proxy.allowlistMode')} />
  </div>
  <div class="form-row form-row-inline">
    <label class="flex-1 label-row">{$t('settings.general.versionOverwritePolicy')} <InfoTip text={$t('settings.general.versionOverwritePolicyHint')} /></label>
    <select bind:value={settings.versionOverwritePolicy} class="w-auto">
      <option value="block">{$t('settings.general.versionOverwritePolicyBlock')}</option>
      <option value="exception">{$t('settings.general.versionOverwritePolicyException')}</option>
      <option value="allow">{$t('settings.general.versionOverwritePolicyAllow')}</option>
    </select>
  </div>
  {#if settings.versionOverwritePolicy === 'allow'}
    <div class="warning-box mb-3">{$t('settings.general.versionOverwritePolicyWarning')}</div>
  {/if}

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
    <label class="label-row" for="block-revoked">{$t('settings.proxy.blockRevoked')} <InfoTip text={$t('settings.proxy.blockRevokedHint')} /></label>
    <select id="block-revoked" bind:value={proxySettings.block_revoked}>
      <option value="off">{$t('settings.proxy.blockRevokedOff')}</option>
      <option value="warn">{$t('settings.proxy.blockRevokedWarn')}</option>
      <option value="block">{$t('settings.proxy.blockRevokedBlock')}</option>
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
  <div class="form-row">
    <label class="label-row" for="block-install-scripts">{$t('settings.proxy.blockInstallScripts')} <InfoTip text={$t('settings.proxy.blockInstallScriptsHint')} /></label>
    <select id="block-install-scripts" bind:value={proxySettings.block_install_scripts}>
      <option value="off">{$t('settings.proxy.blockInstallScriptsOff')}</option>
      <option value="warn">{$t('settings.proxy.blockInstallScriptsWarn')}</option>
      <option value="block">{$t('settings.proxy.blockInstallScriptsBlock')}</option>
    </select>
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
  <h3 class="section-h">{$t('settings.proxy.installScriptAllowlistSection')}</h3>
</div>
<p class="form-hint">{$t('settings.proxy.installScriptAllowlistHint')}</p>
<SettingsInstallScriptAllowlist
  entries={installScriptAllowlistEntries}
  loading={!installScriptAllowlistLoaded}
  onAdd={onAddInstallScriptAllowlist}
  onRemove={onRemoveInstallScriptAllowlist} />

<style>
  .card-narrow { max-width: 480px; }
  .form-row-inline { flex-direction: row; align-items: center; gap: 12px; }
  .warning-box {
    background: var(--warning-bg);
    border: 1px solid var(--warning-border);
    border-radius: 4px;
    padding: 8px 12px;
    font-size: 12px;
    color: var(--text);
    max-width: 540px;
  }
  .value-unit-row { display: flex; gap: 8px; align-items: center; }
  .value-unit-row .value-input { flex: 0 0 110px; }
  .value-unit-row .unit-select { flex: 0 0 110px; }
  .mt-4 { margin-top: 24px; }
</style>
