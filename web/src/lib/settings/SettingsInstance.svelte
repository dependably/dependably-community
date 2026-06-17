<script>
  import { onMount } from 'svelte'
  import { t } from 'svelte-i18n'

  // Instance-wide settings editor, shared by the multi-mode system SPA and the single-mode
  // tenant Settings page. The caller passes the load/save fns so the same form drives both the
  // system realm (/api/v1/system/settings) and the single-mode instance realm
  // (/api/v1/instance/settings).
  export let getSettings     // () => Promise<Record<string,string>>
  export let updateSettings  // (payload) => Promise<void>

  // Schema: keys map to MB (upload limits, displayed/edited as MB while storage stays in bytes),
  // strings, or numbers. Server validates the key set.
  // labelKey resolves at render time so locale switches re-translate without a remount.
  // `default` is the display-unit default — MB for kind='mb', raw value for others — and is
  // shown in the placeholder + caption so an operator always sees what will be applied if
  // they leave the field empty. Matches InstanceSettingDefaults.cs after byte→MB conversion.
  const BYTES_PER_MB = 1024 * 1024
  const SETTING_KEYS = [
    { key: 'max_upload_bytes',       labelKey: 'system.settings.labels.maxUploadBytes',      kind: 'mb',     default: '500', defaultHumanKey: 'system.settings.defaults.maxUploadBytes' },
    { key: 'max_upload_bytes_pypi',  labelKey: 'system.settings.labels.maxUploadBytesPyPi',  kind: 'mb',     default: '100', defaultHumanKey: 'system.settings.defaults.maxUploadBytesPyPi' },
    { key: 'max_upload_bytes_npm',   labelKey: 'system.settings.labels.maxUploadBytesNpm',   kind: 'mb',     default: '50',  defaultHumanKey: 'system.settings.defaults.maxUploadBytesNpm' },
    { key: 'max_upload_bytes_nuget', labelKey: 'system.settings.labels.maxUploadBytesNuGet', kind: 'mb',     default: '250', defaultHumanKey: 'system.settings.defaults.maxUploadBytesNuGet' },
    { key: 'max_upload_bytes_maven', labelKey: 'system.settings.labels.maxUploadBytesMaven', kind: 'mb',     default: '100', defaultHumanKey: 'system.settings.defaults.maxUploadBytesMaven' },
    { key: 'max_upload_bytes_rpm',   labelKey: 'system.settings.labels.maxUploadBytesRpm',   kind: 'mb',     default: '250', defaultHumanKey: 'system.settings.defaults.maxUploadBytesRpm' },
    // OCI images routinely run multi-GB (ML/CUDA bases); 500 MB triggers opaque push failures.
    { key: 'max_upload_bytes_oci',   labelKey: 'system.settings.labels.maxUploadBytesOci',   kind: 'mb',     default: '2048', defaultHumanKey: 'system.settings.defaults.maxUploadBytesOci' },
    { key: 'max_upload_bytes_cargo', labelKey: 'system.settings.labels.maxUploadBytesCargo', kind: 'mb',     default: '100',  defaultHumanKey: 'system.settings.defaults.maxUploadBytesCargo' },
    { key: 'gc_schedule',            labelKey: 'system.settings.labels.gcSchedule',          kind: 'string', default: '0 3 * * *', defaultHumanKey: 'system.settings.defaults.gcSchedule' },
    { key: 'siem_max_lookback_days',            labelKey: 'system.settings.labels.siemMaxLookbackDays',           kind: 'number', default: '90',   defaultHumanKey: 'system.settings.defaults.siemMaxLookbackDays' },
    { key: 'default_storage_quota_bytes',       labelKey: 'system.settings.labels.defaultStorageQuotaBytes',      kind: 'mb',     default: '',     defaultHumanKey: 'system.settings.defaults.defaultStorageQuotaBytes' },
    { key: 'max_active_tokens_per_tenant',      labelKey: 'system.settings.labels.maxActiveTokensPerTenant',      kind: 'number', default: '1000', defaultHumanKey: 'system.settings.defaults.maxActiveTokensPerTenant' },
  ]

  let values = {}, loading = true, error = '', saving = false, savedAt = null

  async function load() {
    loading = true
    error = ''
    try {
      const raw = await getSettings()
      const display = {}
      for (const k of SETTING_KEYS) {
        const v = raw[k.key]
        if (v === undefined || v === '') { display[k.key] = ''; continue }
        // Storage is in bytes; surface the value in MB so operators don't read raw byte counts.
        display[k.key] = k.kind === 'mb' ? String(Number(v) / BYTES_PER_MB) : v
      }
      values = display
    } catch (e) { error = e.message }
    finally { loading = false }
  }

  onMount(load)

  async function save() {
    saving = true
    error = ''
    try {
      const payload = {}
      for (const k of SETTING_KEYS) {
        if (values[k.key] === undefined || values[k.key] === '') continue
        payload[k.key] = k.kind === 'mb'
          ? String(Math.round(Number(values[k.key]) * BYTES_PER_MB))
          : String(values[k.key])
      }
      await updateSettings(payload)
      savedAt = new Date()
    } catch (e) { error = e.message }
    finally { saving = false }
  }
</script>

{#if error}<div class="page-error">{error}</div>{/if}

{#if loading}
  <span class="spinner"></span>
{:else}
  <form on:submit|preventDefault={save}>
    {#each SETTING_KEYS as k (k.key)}
      <div class="form-row">
        <label for="set-{k.key}">{$t(k.labelKey)}</label>
        <div class="field">
          <div class="input-row">
            <input
              id="set-{k.key}"
              type={k.kind === 'string' ? 'text' : 'number'}
              bind:value={values[k.key]}
              placeholder={k.default}
            />
            {#if k.kind === 'mb'}<span class="unit">MB</span>{/if}
          </div>
          <small class="hint">{$t('system.settings.defaultHint', { values: { value: $t(k.defaultHumanKey) } })}</small>
        </div>
      </div>
    {/each}

    <button class="primary" type="submit" disabled={saving}>
      {saving ? $t('system.settings.saving') : $t('system.settings.save')}
    </button>
    {#if savedAt}<span class="saved">{$t('system.settings.savedAt', { values: { time: savedAt.toLocaleTimeString() } })}</span>{/if}
  </form>
{/if}

<style>
  form { display: flex; flex-direction: column; gap: 16px; max-width: 560px; }
  .form-row { display: grid; grid-template-columns: 1fr 240px; gap: 12px; align-items: start; }
  .form-row label { font-size: 13px; color: var(--text2); padding-top: 8px; }
  .field { display: flex; flex-direction: column; gap: 4px; }
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
  .hint { font-size: 11px; color: var(--text2); }
  .saved { color: var(--text2); font-size: 13px; margin-left: 12px; }
</style>
