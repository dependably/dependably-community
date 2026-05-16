<!--
  Retention tab — keep_versions, keep_days, activity_retention_days. Empty input = unlimited
  (the server stores null and the GC skips that dimension).
-->
<script>
  import { t } from 'svelte-i18n'

  export let retention
  export let saving = false
  export let onSave = () => {}
</script>

<div class="card card-narrow">
  <div class="form-row">
    <label>{$t('settings.retention.keepVersions')}</label>
    <input type="number" bind:value={retention.keep_versions} placeholder={$t('settings.retention.unlimited')} min="1" />
  </div>
  <div class="form-row">
    <label>{$t('settings.retention.keepDays')}</label>
    <input type="number" bind:value={retention.keep_days} placeholder={$t('settings.retention.unlimited')} min="1" />
  </div>
  <div class="form-row">
    <label>{$t('settings.retention.activityDays')}</label>
    <input type="number" bind:value={retention.activity_retention_days} placeholder={$t('settings.retention.unlimited')} min="1" />
  </div>
  <button class="primary" on:click={onSave} disabled={saving}>
    {saving ? $t('common.actions.saving') : $t('common.actions.save')}
  </button>
</div>

<style>
  .card-narrow { max-width: 480px; }
</style>
