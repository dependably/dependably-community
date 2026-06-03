<!--
  General tab of OrgSettings — anonymous pull, allowlist mode, default language,
  allow_version_overwrite (with the supply-chain warning surface).

  Parent owns the `settings` object and the save handler so all the cross-tab
  state lives in one place; this component is a thin form binding + markup view.
-->
<script>
  import { t } from 'svelte-i18n'
  import InfoTip from '../InfoTip.svelte'

  export let settings
  export let saving = false
  export let onSave = () => {}
</script>

<div class="card card-narrow">
  <div class="form-row form-row-inline">
    <label class="flex-1">{$t('settings.general.anonymousPull')}</label>
    <input type="checkbox" bind:checked={settings.anonymousPull} class="w-auto" />
  </div>
  <div class="form-row form-row-inline">
    <label class="flex-1 label-row">{$t('settings.general.defaultLanguage')} <InfoTip text={$t('settings.general.defaultLanguageHint')} /></label>
    <select bind:value={settings.defaultLanguage} class="w-auto">
      <option value="en">English</option>
      <option value="fr">Français</option>
    </select>
  </div>

  <div class="form-row form-row-inline">
    <label class="flex-1 label-row">{$t('settings.general.allowVersionOverwrite')} <InfoTip text={$t('settings.general.allowVersionOverwriteHint')} /></label>
    <input type="checkbox" bind:checked={settings.allowVersionOverwrite} class="w-auto" />
  </div>
  {#if settings.allowVersionOverwrite}
    <div class="warning-box mb-3">{$t('settings.general.allowVersionOverwriteWarning')}</div>
  {/if}

  <div class="form-row form-row-inline">
    <label class="flex-1 label-row">{$t('settings.general.airGapped')} <InfoTip text={$t('settings.general.airGappedHint')} /></label>
    {#if settings.airGappedEnforced}
      <input type="checkbox" checked disabled class="w-auto" />
    {:else}
      <input type="checkbox" bind:checked={settings.airGapped} class="w-auto" />
    {/if}
  </div>
  {#if settings.airGappedEnforced}
    <div class="form-hint mb-3">{$t('settings.general.airGappedEnforcedNote')}</div>
  {:else if settings.airGapped}
    <div class="warning-box mb-3">{$t('settings.general.airGappedWarning')}</div>
  {/if}

  <button class="primary" on:click={onSave} disabled={saving}>
    {saving ? $t('common.actions.saving') : $t('common.actions.save')}
  </button>
</div>

<style>
  .warning-box {
    background: var(--warning-bg);
    border: 1px solid var(--warning-border);
    border-radius: 4px;
    padding: 8px 12px;
    font-size: 12px;
    color: var(--text);
    max-width: 540px;
  }
  .card-narrow { max-width: 480px; }
  .form-row-inline { flex-direction: row; align-items: center; gap: 12px; }
</style>
