<!--
  Upload-limits tab of OrgSettings. Cross-ecosystem + per-ecosystem byte caps with an
  instance-ceiling visual indicator (cap > instance limit highlights the field).
-->
<script>
  import { t } from 'svelte-i18n'

  export let settings
  export let instanceMax = null
  export let saving = false
  export let onSave = () => {}

  const uploadFields = [
    ['maxUploadBytes',     'settings.uploadLimits.allEcosystems'],
    ['maxUploadBytesPyPi', 'PyPI'],
    ['maxUploadBytesNpm',  'npm'],
    ['maxUploadBytesNuGet','NuGet'],
  ]

  function exceedsInstance(val) {
    if (!instanceMax || !val) return false
    return parseInt(val) > instanceMax
  }

  $: anyExceeds =
    exceedsInstance(settings?.maxUploadBytes) ||
    exceedsInstance(settings?.maxUploadBytesPyPi) ||
    exceedsInstance(settings?.maxUploadBytesNpm) ||
    exceedsInstance(settings?.maxUploadBytesNuGet)
</script>

<div class="card card-narrow">
  {#if instanceMax}<p class="form-hint">{$t('settings.uploadLimits.instanceCeiling', { values: { mb: (instanceMax/1024/1024).toFixed(0) } })}</p>{/if}
  {#each uploadFields as [key, labelKey] (key)}
    <div class="form-row">
      <label>{labelKey.startsWith('settings.') ? $t(labelKey) : labelKey} (bytes)</label>
      <input type="number" bind:value={settings[key]} placeholder={$t('settings.uploadLimits.inheritPlaceholder')} min="0" />
      {#if exceedsInstance(settings[key])}
        <div class="form-hint text-danger">{$t('settings.uploadLimits.exceedsCeiling', { values: { bytes: instanceMax } })}</div>
      {/if}
    </div>
  {/each}
  <button class="primary" on:click={onSave} disabled={saving || anyExceeds}>
    {saving ? $t('common.actions.saving') : $t('common.actions.save')}
  </button>
</div>

<style>
  .card-narrow { max-width: 480px; }
</style>
