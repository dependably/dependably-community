<!--
  Upload-limits tab of OrgSettings. Cross-ecosystem + per-ecosystem caps, edited and displayed
  in MB, with an instance-ceiling visual indicator (cap > instance limit highlights the field).
  Storage stays in bytes end to end (org_settings.max_upload_bytes*) — this component is the
  only place the MB<->byte conversion happens, via lib/settings/uploadLimits.js.
-->
<script>
  import { t } from 'svelte-i18n'
  import InfoTip from '../InfoTip.svelte'
  import { bytesToMb, mbToBytes, exceedsInstanceCeiling, formatMbLabel } from './uploadLimits.js'

  export let settings
  export let instanceMax = null
  export let saving = false
  export let onSave = () => {}

  const GLOBAL_KEY = 'maxUploadBytes'
  const perEcoFields = [
    ['maxUploadBytesPyPi', 'PyPI'],
    ['maxUploadBytesNpm',  'npm'],
    ['maxUploadBytesNuGet','NuGet'],
    ['maxUploadBytesMaven','Maven'],
    ['maxUploadBytesRpm',  'RPM'],
    ['maxUploadBytesOci',  'Docker'],
    ['maxUploadBytesCargo','Cargo'],
  ]
  // Iterate this array so adding an ecosystem above flows through automatically — the
  // previous hand-rolled boolean fell out of sync with the array the first time we extended it.
  const uploadFields = [[GLOBAL_KEY, 'settings.uploadLimits.allEcosystems'], ...perEcoFields]

  // Display state lives in MB; `settings` (bound from the parent) stays in bytes so saving
  // posts the same shape the API always expected. The parent only renders this tab once its
  // async load has populated `settings`, so this component-init-time conversion always sees
  // real byte values — no reactive re-derivation needed, which would otherwise clobber
  // in-progress edits every time setField below mutates `settings`.
  let mbValues = {}
  for (const [key] of uploadFields) mbValues[key] = bytesToMb(settings[key])

  function setField(key, raw) {
    mbValues = { ...mbValues, [key]: raw }
    settings[key] = mbToBytes(raw)
  }

  $: mbCeiling = formatMbLabel(instanceMax)
  $: anyExceeds = uploadFields.some(([k]) => exceedsInstanceCeiling(mbValues[k], instanceMax))
</script>

<div class="card card-narrow">
  {#if instanceMax}<p class="form-hint">{$t('settings.uploadLimits.instanceCeiling', { values: { mb: mbCeiling } })}</p>{/if}

  <div class="form-row">
    <label class="label-row" for="ul-{GLOBAL_KEY}">
      {$t('settings.uploadLimits.allEcosystems')}
      <InfoTip text={instanceMax
        ? $t('settings.uploadLimits.globalBlankHint', { values: { mb: mbCeiling } })
        : $t('settings.uploadLimits.globalBlankNoLimitHint')} />
    </label>
    <div class="input-row">
      <input id="ul-{GLOBAL_KEY}" type="number" step="any" min="0"
             value={mbValues[GLOBAL_KEY] ?? ''}
             on:input={(e) => setField(GLOBAL_KEY, e.currentTarget.value)}
             placeholder={instanceMax ? mbCeiling : ''} />
      <span class="unit">MB</span>
    </div>
    {#if exceedsInstanceCeiling(mbValues[GLOBAL_KEY], instanceMax)}
      <div class="form-hint text-danger">{$t('settings.uploadLimits.exceedsCeiling', { values: { mb: mbCeiling } })}</div>
    {/if}
  </div>

  {#each perEcoFields as [key, labelKey] (key)}
    <div class="form-row">
      <label class="label-row" for="ul-{key}">
        {labelKey}
        <InfoTip text={$t('settings.uploadLimits.perEcoHint')} />
      </label>
      <div class="input-row">
        <input id="ul-{key}" type="number" step="any" min="0"
               value={mbValues[key] ?? ''}
               on:input={(e) => setField(key, e.currentTarget.value)}
               placeholder={mbValues[GLOBAL_KEY] ? mbValues[GLOBAL_KEY] : $t('settings.uploadLimits.perEcoBlankPlaceholder')} />
        <span class="unit">MB</span>
      </div>
      {#if exceedsInstanceCeiling(mbValues[key], instanceMax)}
        <div class="form-hint text-danger">{$t('settings.uploadLimits.exceedsCeiling', { values: { mb: mbCeiling } })}</div>
      {/if}
    </div>
  {/each}

  <button class="primary" on:click={onSave} disabled={saving || anyExceeds}>
    {saving ? $t('common.actions.saving') : $t('common.actions.save')}
  </button>
</div>

<style>
  .card-narrow { max-width: 480px; }
  .input-row { display: flex; align-items: center; gap: 6px; }
  .input-row input {
    flex: 1;
    padding: 6px 8px;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    background: var(--bg);
    color: var(--text);
  }
  .unit { font-size: 12px; color: var(--text2); }
</style>
