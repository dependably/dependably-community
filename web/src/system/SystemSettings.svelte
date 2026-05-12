<script>
  import { onMount } from 'svelte'
  import { t } from 'svelte-i18n'
  import { systemApi } from '../lib/api.js'

  // Schema: keys map to numeric (size in bytes) or string values. Server validates the key set.
  // labelKey resolves at render time so locale switches re-translate without a remount.
  const SETTING_KEYS = [
    { key: 'max_upload_bytes',       labelKey: 'system.settings.labels.maxUploadBytes',      kind: 'bytes' },
    { key: 'max_upload_bytes_pypi',  labelKey: 'system.settings.labels.maxUploadBytesPyPi',  kind: 'bytes' },
    { key: 'max_upload_bytes_npm',   labelKey: 'system.settings.labels.maxUploadBytesNpm',   kind: 'bytes' },
    { key: 'max_upload_bytes_nuget', labelKey: 'system.settings.labels.maxUploadBytesNuGet', kind: 'bytes' },
    { key: 'gc_schedule',            labelKey: 'system.settings.labels.gcSchedule',          kind: 'string' },
    { key: 'siem_max_lookback_days', labelKey: 'system.settings.labels.siemMaxLookbackDays', kind: 'number' },
  ]

  let values = {}, loading = true, error = '', saving = false, savedAt = null

  async function load() {
    loading = true
    try {
      const data = await systemApi.getSettings()
      // Server returns array of {key, value}; flatten to a map.
      values = {}
      for (const s of data) values[s.key] = s.value
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
        if (values[k.key] !== undefined && values[k.key] !== '') {
          payload[k.key] = String(values[k.key])
        }
      }
      await systemApi.updateSettings(payload)
      savedAt = new Date()
    } catch (e) { error = e.message }
    finally { saving = false }
  }
</script>

<div class="page">
  <h1>{$t('system.settings.title')}</h1>
  <p class="subtitle">{$t('system.settings.subtitle')}</p>

  {#if error}<div class="page-error">{error}</div>{/if}

  {#if loading}
    <span class="spinner"></span>
  {:else}
    <form on:submit|preventDefault={save}>
      {#each SETTING_KEYS as k (k.key)}
        <div class="form-row">
          <label for="set-{k.key}">{$t(k.labelKey)}</label>
          <input
            id="set-{k.key}"
            type={k.kind === 'string' ? 'text' : 'number'}
            bind:value={values[k.key]}
            placeholder={k.kind === 'string' ? $t('system.settings.placeholders.string') : $t('system.settings.placeholders.number')}
          />
        </div>
      {/each}

      <button class="primary" type="submit" disabled={saving}>
        {saving ? $t('system.settings.saving') : $t('system.settings.save')}
      </button>
      {#if savedAt}<span class="saved">{$t('system.settings.savedAt', { values: { time: savedAt.toLocaleTimeString() } })}</span>{/if}
    </form>
  {/if}
</div>

<style>
  .subtitle { color: var(--text2); font-size: 13px; margin: 0 0 16px; }
  form { display: flex; flex-direction: column; gap: 12px; max-width: 520px; }
  .form-row { display: grid; grid-template-columns: 1fr 200px; gap: 12px; align-items: center; }
  .form-row label { font-size: 13px; color: var(--text2); }
  .form-row input {
    padding: 6px 8px;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    background: var(--bg);
    color: var(--text);
  }
  .saved { color: var(--text2); font-size: 13px; margin-left: 12px; }
</style>
