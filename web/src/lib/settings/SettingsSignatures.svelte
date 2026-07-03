<!--
  Signatures tab — trust anchors (self-loading) placed first, followed by the
  per-ecosystem signature-verification policy toggles. Anchors precede toggles
  because they are the keys that enable the disabled={!…_configured} selects below.

  Verify-toggle bindings reach directly into the parent-owned proxySettings object
  (whole-object PUT); the parent retains sole write authority.
-->
<script>
  import { t } from 'svelte-i18n'
  import SettingsTrustAnchors from './SettingsTrustAnchors.svelte'
  import InfoTip from '../InfoTip.svelte'

  export let proxySettings
  export let saving = false
  export let onSave = () => {}
</script>

<SettingsTrustAnchors />

<div class="card card-narrow mt-4">
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

  <button class="primary" on:click={onSave} disabled={saving}>
    {saving ? $t('common.actions.saving') : $t('common.actions.save')}
  </button>
</div>

<style>
  .card-narrow { max-width: 480px; }
  .mt-4 { margin-top: 24px; }
</style>
