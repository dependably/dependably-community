<script>
  import { onMount } from 'svelte'
  import { t } from 'svelte-i18n'
  import { systemApi } from '../lib/api.js'

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
    { key: 'gc_schedule',            labelKey: 'system.settings.labels.gcSchedule',          kind: 'string', default: '0 3 * * *', defaultHumanKey: 'system.settings.defaults.gcSchedule' },
    { key: 'siem_max_lookback_days', labelKey: 'system.settings.labels.siemMaxLookbackDays', kind: 'number', default: '90', defaultHumanKey: 'system.settings.defaults.siemMaxLookbackDays' },
  ]

  let values = {}, loading = true, error = '', saving = false, savedAt = null
  let activeTab = 'instance'  // 'instance' | 'metrics'

  // /metrics access — separate endpoint, separate load/save lifecycle.
  // PUT returns 409 when env locks the knob; warnings from broad CIDRs
  // come back in the 200 response body.
  let access = null
  let accessEnabled = false
  let accessAllowedText = ''
  let accessSaving = false
  let accessError = ''
  let accessWarnings = []
  let accessSavedAt = null

  async function load() {
    loading = true
    try {
      const raw = await systemApi.getSettings()
      const display = {}
      for (const k of SETTING_KEYS) {
        const v = raw[k.key]
        if (v === undefined || v === '') { display[k.key] = ''; continue }
        // Storage is in bytes; surface the value in MB so operators don't read raw byte counts.
        display[k.key] = k.kind === 'mb' ? String(Number(v) / BYTES_PER_MB) : v
      }
      values = display

      const acc = await systemApi.getMetricsAccess()
      access = acc
      accessEnabled = acc.enabled
      accessAllowedText = (acc.allowedIps || []).join('\n')
    } catch (e) { error = e.message }
    finally { loading = false }
  }

  onMount(load)

  function broadCidrWarning(list) {
    return list.some((s) => s === '0.0.0.0/0' || s === '::/0')
  }

  async function saveAccess() {
    accessSaving = true
    accessError = ''
    accessWarnings = []
    try {
      const body = {}
      if (!access.enabledLockedByEnv) body.enabled = accessEnabled
      if (!access.allowlistLockedByEnv) {
        body.allowedIps = accessAllowedText
          .split('\n')
          .map((s) => s.trim())
          .filter((s) => s.length > 0)
      }
      const resp = await systemApi.updateMetricsAccess(body)
      if (resp && Array.isArray(resp.warnings)) accessWarnings = resp.warnings
      accessSavedAt = new Date()
      // Refresh so source badges / effective values reflect persisted state.
      const refreshed = await systemApi.getMetricsAccess()
      access = refreshed
      accessEnabled = refreshed.enabled
      accessAllowedText = (refreshed.allowedIps || []).join('\n')
    } catch (e) { accessError = e.message }
    finally { accessSaving = false }
  }

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
      await systemApi.updateSettings(payload)
      savedAt = new Date()
    } catch (e) { error = e.message }
    finally { saving = false }
  }
</script>

<div class="page">
  <h1>{$t('system.settings.title')}</h1>
  <p class="subtitle">{$t('system.settings.subtitle')}</p>

  <div class="tabs" role="tablist">
    <button class="tab" class:active={activeTab === 'instance'}
            role="tab" aria-selected={activeTab === 'instance'}
            on:click={() => activeTab = 'instance'}>{$t('system.settings.tabs.instance')}</button>
    <button class="tab" class:active={activeTab === 'metrics'}
            role="tab" aria-selected={activeTab === 'metrics'}
            on:click={() => activeTab = 'metrics'}>{$t('system.settings.tabs.metrics')}</button>
  </div>

  {#if error}<div class="page-error">{error}</div>{/if}

  {#if loading}
    <span class="spinner"></span>
  {:else if activeTab === 'instance'}
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
  {:else if access}
      <p class="subtitle">{$t('system.settings.metrics.subtitle')}</p>

      {#if access.enabledLockedByEnv || access.allowlistLockedByEnv}
        <div class="env-banner">
          {$t('system.settings.metrics.envLocked')}
        </div>
      {/if}

      {#if accessError}<div class="page-error">{accessError}</div>{/if}

      <form on:submit|preventDefault={saveAccess}>
        <div class="form-row">
          <label for="metrics-enabled">{$t('system.settings.metrics.enabled')}</label>
          <div class="field">
            <div class="input-row">
              <input
                id="metrics-enabled"
                type="checkbox"
                bind:checked={accessEnabled}
                disabled={access.enabledLockedByEnv}
              />
              <span class="source-tag source-tag-{access.enabledSource}">{access.enabledSource}</span>
            </div>
            <small class="hint">{$t('system.settings.metrics.enabledHint')}</small>
          </div>
        </div>

        <div class="form-row">
          <label for="metrics-allowed-ips">{$t('system.settings.metrics.allowedIps')}</label>
          <div class="field">
            <textarea
              id="metrics-allowed-ips"
              rows="5"
              bind:value={accessAllowedText}
              disabled={access.allowlistLockedByEnv}
              placeholder="127.0.0.1&#10;::1"
            ></textarea>
            <small class="hint">
              {$t('system.settings.metrics.allowedIpsHint')}
              <span class="source-tag source-tag-{access.allowlistSource}">{access.allowlistSource}</span>
            </small>
            {#if broadCidrWarning(accessAllowedText.split('\n').map((s) => s.trim()).filter(Boolean))}
              <small class="warn">{$t('system.settings.metrics.broadCidrWarn')}</small>
            {/if}
          </div>
        </div>

        <button
          class="primary"
          type="submit"
          disabled={accessSaving || (access.enabledLockedByEnv && access.allowlistLockedByEnv)}
        >
          {accessSaving ? $t('system.settings.saving') : $t('system.settings.metrics.save')}
        </button>
        {#if accessSavedAt}<span class="saved">{$t('system.settings.savedAt', { values: { time: accessSavedAt.toLocaleTimeString() } })}</span>{/if}

        {#each accessWarnings as warning, i (i)}
          <div class="warn-box"><svg width="12" height="12" aria-hidden="true"><use href="/icons.svg#icon-alert"/></svg> {warning}</div>
        {/each}
      </form>
  {/if}
</div>

<style>
  .subtitle { color: var(--text2); font-size: 13px; margin: 0 0 16px; }
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
  .warn { font-size: 11px; color: orange; }
  .saved { color: var(--text2); font-size: 13px; margin-left: 12px; }
  .divider { border: 0; border-top: 1px solid var(--border); margin: 32px 0 16px; max-width: 560px; }
  textarea {
    width: 100%;
    padding: 6px 8px;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    background: var(--bg);
    color: var(--text);
    font-family: var(--font-mono, monospace);
    font-size: 12px;
  }
  textarea:disabled { opacity: 0.6; cursor: not-allowed; }
  .env-banner {
    background: rgba(255, 180, 0, 0.15);
    border: 1px solid rgba(255, 180, 0, 0.4);
    padding: 8px 12px;
    border-radius: var(--radius);
    margin-bottom: 12px;
    max-width: 560px;
    font-size: 13px;
  }
  .warn-box {
    background: rgba(255, 180, 0, 0.15);
    border: 1px solid rgba(255, 180, 0, 0.4);
    padding: 6px 10px;
    border-radius: var(--radius);
    margin-top: 8px;
    font-size: 12px;
    max-width: 560px;
  }
  .source-tag {
    font-size: 10px;
    padding: 2px 6px;
    border-radius: 3px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    margin-left: 8px;
  }
  .source-tag-env { background: var(--accent); color: white; }
  .source-tag-db { background: var(--bg3); color: var(--text); border: 1px solid var(--border); }
  .source-tag-default { background: var(--bg); color: var(--text2); border: 1px solid var(--border); }
</style>
