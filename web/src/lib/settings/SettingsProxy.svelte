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
  import SettingsInstallScriptAllowlist from './SettingsInstallScriptAllowlist.svelte'
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

  export let installScriptAllowlistEntries = []
  export let installScriptAllowlistLoaded = false
  /** @type {() => void} */
  export let onAddInstallScriptAllowlist = () => {}
  /** @type {(id: string) => void} */
  export let onRemoveInstallScriptAllowlist = () => {}
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
    <label class="label-row" for="block-install-scripts">{$t('settings.proxy.blockInstallScripts')} <InfoTip text={$t('settings.proxy.blockInstallScriptsHint')} /></label>
    <select id="block-install-scripts" bind:value={proxySettings.block_install_scripts}>
      <option value="off">{$t('settings.proxy.blockInstallScriptsOff')}</option>
      <option value="warn">{$t('settings.proxy.blockInstallScriptsWarn')}</option>
      <option value="block">{$t('settings.proxy.blockInstallScriptsBlock')}</option>
    </select>
  </div>
  <div class="form-row">
    <label class="label-row" for="verify-npm-signatures">{$t('settings.proxy.verifyNpmSignatures')} <InfoTip text={$t('settings.proxy.verifyNpmSignaturesHint')} /></label>
    <select
      id="verify-npm-signatures"
      bind:value={proxySettings.verify_npm_signatures}
      disabled={!proxySettings.npm_signature_keys_configured}
    >
      <option value="off">{$t('settings.proxy.verifyNpmSignaturesOff')}</option>
      <option value="warn">{$t('settings.proxy.verifyNpmSignaturesWarn')}</option>
      <option value="block">{$t('settings.proxy.verifyNpmSignaturesBlock')}</option>
    </select>
  </div>
  {#if !proxySettings.npm_signature_keys_configured}
    <p class="form-hint">{$t('settings.proxy.verifyNpmSignaturesNoKeys')}</p>
  {/if}
  <div class="form-row">
    <label class="label-row" for="verify-nuget-signatures">{$t('settings.proxy.verifyNuGetSignatures')} <InfoTip text={$t('settings.proxy.verifyNuGetSignaturesHint')} /></label>
    <select
      id="verify-nuget-signatures"
      bind:value={proxySettings.verify_nuget_signatures}
      disabled={!proxySettings.nuget_signature_certs_configured}
    >
      <option value="off">{$t('settings.proxy.verifyNuGetSignaturesOff')}</option>
      <option value="warn">{$t('settings.proxy.verifyNuGetSignaturesWarn')}</option>
      <option value="block">{$t('settings.proxy.verifyNuGetSignaturesBlock')}</option>
    </select>
  </div>
  {#if !proxySettings.nuget_signature_certs_configured}
    <p class="form-hint">{$t('settings.proxy.verifyNuGetSignaturesNoCerts')}</p>
  {/if}
  <div class="form-row">
    <label class="label-row" for="verify-pypi-attestations">{$t('settings.proxy.verifyPyPiAttestations')} <InfoTip text={$t('settings.proxy.verifyPyPiAttestationsHint')} /></label>
    <select
      id="verify-pypi-attestations"
      bind:value={proxySettings.verify_pypi_attestations}
      disabled={!proxySettings.pypi_sigstore_roots_configured}
    >
      <option value="off">{$t('settings.proxy.verifyPyPiAttestationsOff')}</option>
      <option value="warn">{$t('settings.proxy.verifyPyPiAttestationsWarn')}</option>
      <option value="block">{$t('settings.proxy.verifyPyPiAttestationsBlock')}</option>
    </select>
  </div>
  {#if !proxySettings.pypi_sigstore_roots_configured}
    <p class="form-hint">{$t('settings.proxy.verifyPyPiAttestationsNoRoots')}</p>
  {/if}
  <div class="form-row">
    <label class="label-row" for="verify-rpm-signatures">{$t('settings.proxy.verifyRpmSignatures')} <InfoTip text={$t('settings.proxy.verifyRpmSignaturesHint')} /></label>
    <select
      id="verify-rpm-signatures"
      bind:value={proxySettings.verify_rpm_signatures}
      disabled={!proxySettings.rpm_gpg_key_configured}
    >
      <option value="off">{$t('settings.proxy.verifyRpmSignaturesOff')}</option>
      <option value="warn">{$t('settings.proxy.verifyRpmSignaturesWarn')}</option>
      <option value="block">{$t('settings.proxy.verifyRpmSignaturesBlock')}</option>
    </select>
  </div>
  {#if !proxySettings.rpm_gpg_key_configured}
    <p class="form-hint">{$t('settings.proxy.verifyRpmSignaturesNoKey')}</p>
  {/if}
  <div class="form-row">
    <label class="label-row" for="verify-maven-signatures">{$t('settings.proxy.verifyMavenSignatures')} <InfoTip text={$t('settings.proxy.verifyMavenSignaturesHint')} /></label>
    <select
      id="verify-maven-signatures"
      bind:value={proxySettings.verify_maven_signatures}
      disabled={!proxySettings.maven_signature_keys_configured}
    >
      <option value="off">{$t('settings.proxy.verifyMavenSignaturesOff')}</option>
      <option value="warn">{$t('settings.proxy.verifyMavenSignaturesWarn')}</option>
      <option value="block">{$t('settings.proxy.verifyMavenSignaturesBlock')}</option>
    </select>
  </div>
  {#if !proxySettings.maven_signature_keys_configured}
    <p class="form-hint">{$t('settings.proxy.verifyMavenSignaturesNoKeys')}</p>
  {/if}
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

<div class="page-header list-header mt-4">
  <h3 class="section-h">{$t('settings.proxy.installScriptAllowlistSection')}</h3>
</div>
<p class="form-hint">{$t('settings.proxy.installScriptAllowlistHint')}</p>
<SettingsInstallScriptAllowlist
  entries={installScriptAllowlistEntries}
  loading={!installScriptAllowlistLoaded}
  onAdd={onAddInstallScriptAllowlist}
  onRemove={onRemoveInstallScriptAllowlist} />

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
