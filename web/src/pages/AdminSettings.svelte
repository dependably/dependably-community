<script>
  import { onMount } from 'svelte'
  import { t } from 'svelte-i18n'
  import { api } from '../lib/api.js'

  let settings = {}, loading = true, saving = false, error = '', success = ''

  onMount(async () => {
    settings = await api.getInstanceSettings().catch(e => { error = e.message; return {} })
    loading = false
  })

  async function save() {
    saving = true; error = ''; success = ''
    try {
      await api.updateInstanceSettings(settings)
      success = $t('admin.settings.saved')
    } catch (e) { error = e.message }
    finally { saving = false }
  }

  const FIELD_KEYS = [
    'MAX_UPLOAD_BYTES',
    'MAX_UPLOAD_BYTES_PYPI',
    'MAX_UPLOAD_BYTES_NPM',
    'MAX_UPLOAD_BYTES_NUGET',
    'METRICS_ALLOWED_IPS',
    'GC_SCHEDULE',
    'DEFAULT_ORG_SLUG',
  ]

  const FIELD_TYPES = {
    MAX_UPLOAD_BYTES: 'number',
    MAX_UPLOAD_BYTES_PYPI: 'number',
    MAX_UPLOAD_BYTES_NPM: 'number',
    MAX_UPLOAD_BYTES_NUGET: 'number',
    METRICS_ALLOWED_IPS: 'text',
    GC_SCHEDULE: 'text',
    DEFAULT_ORG_SLUG: 'text',
  }
</script>

<div class="page page-wide">
  <div class="page-header"><h1 class="page-title">{$t('admin.settings.title')}</h1></div>

  {#if loading}<span class="spinner"></span>
  {:else}
    {#if error}<div class="page-error">{error}</div>{/if}
    {#if success}<div class="text-success mb-3">{success}</div>{/if}

    <div class="card settings-card">
      {#each FIELD_KEYS as key (key)}
        <div class="form-row">
          <label>{$t(`admin.settings.fields.${key}`)}</label>
          <input type={FIELD_TYPES[key]} bind:value={settings[key]} placeholder={$t('admin.settings.notSet')} />
        </div>
      {/each}
      <button class="primary" on:click={save} disabled={saving}>{saving ? $t('common.actions.saving') : $t('common.actions.save')}</button>
    </div>
  {/if}
</div>

<style>
  .settings-card { max-width: 540px; }
</style>
