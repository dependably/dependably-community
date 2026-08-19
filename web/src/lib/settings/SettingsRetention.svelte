<!--
  Retention tab — keep_versions, keep_days, activity_retention_days, purge_unlisted_after_days.

  Empty input = unlimited for THREE of the four: the server stores null and the GC skips that
  dimension entirely. activity_retention_days is the exception and must not render as unlimited —
  a null there resolves to the instance-wide ACTIVITY_RETENTION_DAYS default (90) because activity
  rows carry per-download IP/actor data and are bounded by default on purpose. The server reports
  the effective number as activity_retention_default_days so this form can say so instead of
  claiming a retention window the GC does not honour.
-->
<script>
  import { t } from 'svelte-i18n'

  export let retention
  export let saving = false
  export let onSave = () => {}

  // Bare property reads are not reactive in Svelte 4 — mirror through $: so the placeholder
  // updates when the parent hydrates `retention` after its fetch resolves.
  $: activityDefault = retention?.activity_retention_default_days
</script>

<div class="card card-narrow">
  <div class="form-row">
    <label>{$t('settings.retention.keepVersions')}</label>
    <input data-testid="retention-keep-versions" type="number" bind:value={retention.keep_versions} placeholder={$t('settings.retention.unlimited')} min="1" />
  </div>
  <div class="form-row">
    <label>{$t('settings.retention.keepDays')}</label>
    <input data-testid="retention-keep-days" type="number" bind:value={retention.keep_days} placeholder={$t('settings.retention.unlimited')} min="1" />
  </div>
  <div class="form-row">
    <label>{$t('settings.retention.activityDays')}</label>
    <input
      data-testid="retention-activity-days"
      type="number"
      bind:value={retention.activity_retention_days}
      placeholder={activityDefault ? $t('settings.retention.instanceDefault', { values: { days: activityDefault } }) : ''}
      min="1"
    />
  </div>
  <p class="hint" data-testid="retention-activity-hint">{$t('settings.retention.activityDaysHint')}</p>
  <div class="form-row">
    <label>{$t('settings.retention.purgeUnlistedDays')}</label>
    <input data-testid="retention-purge-unlisted" type="number" bind:value={retention.purge_unlisted_after_days} placeholder={$t('settings.retention.unlimited')} min="1" />
  </div>
  <button class="primary" on:click={onSave} disabled={saving}>
    {saving ? $t('common.actions.saving') : $t('common.actions.save')}
  </button>
</div>

<style>
  .card-narrow { max-width: 480px; }
  .hint { font-size: 11px; color: var(--text2); }
</style>
