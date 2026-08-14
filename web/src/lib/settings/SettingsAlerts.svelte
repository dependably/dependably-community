<!--
  Alert center settings — what fires: the per-type toggles and the vulnerability severity floor.
  Who hears about it is a delivery channel, and every channel (email, Slack, webhooks) is edited on
  the Integrations tab. This tab's PUT carries the gate columns only, so a save here can never
  clobber a channel saved there.

  Rows follow the settings-tab convention (.card.card-narrow + .form-row.form-row-inline): the
  label takes the free space and the control sits at the row's right edge, so every control on the
  tab lines up on one column with the rest of Settings.
-->
<script>
  import { onMount } from 'svelte'
  import { t } from 'svelte-i18n'
  import { api } from '../api.js'
  import { extractErrorMessage, submitForm } from '../form.js'
  import ErrorBanner from '../ErrorBanner.svelte'
  import InfoTip from '../InfoTip.svelte'
  import Toggle from '../Toggle.svelte'

  const SEVERITIES = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']

  let loaded = false
  let error = ''
  let success = ''
  let saving = false

  let quarantineAlertsEnabled = true
  let vulnAlertsEnabled = true
  let vulnMinSeverity = 'HIGH'

  onMount(load)

  async function load() {
    try {
      const s = await api.getAlertSettings()
      quarantineAlertsEnabled = s.quarantineAlertsEnabled
      vulnAlertsEnabled = s.vulnAlertsEnabled
      vulnMinSeverity = s.vulnMinSeverity
      loaded = true
    } catch (e) { error = extractErrorMessage(e) }
  }

  async function save() {
    success = ''
    await submitForm(
      () => api.updateAlertSettings({ quarantineAlertsEnabled, vulnAlertsEnabled, vulnMinSeverity }),
      {
        setSaving: v => saving = v,
        setError: v => error = v,
        onSuccess: (updated) => {
          quarantineAlertsEnabled = updated.quarantineAlertsEnabled
          vulnAlertsEnabled = updated.vulnAlertsEnabled
          vulnMinSeverity = updated.vulnMinSeverity
          success = $t('settings.saved')
        },
      })
  }
</script>

<h3 class="section-h">
  {$t('settings.alerts.section')}
  <InfoTip text={$t('settings.alerts.hint')} />
</h3>

<ErrorBanner message={error} />
{#if success}<div class="text-success mb-3">{success}</div>{/if}

{#if !loaded}
  <span class="spinner"></span>
{:else}
  <div class="card card-narrow">
    <div class="form-row form-row-inline">
      <label class="flex-1" for="alert-quarantine-enabled">{$t('settings.alerts.quarantineEnabled')}</label>
      <Toggle id="alert-quarantine-enabled" bind:checked={quarantineAlertsEnabled}
              ariaLabel={$t('settings.alerts.quarantineEnabled')} />
    </div>

    <div class="form-row form-row-inline">
      <label class="flex-1" for="alert-vuln-enabled">{$t('settings.alerts.vulnEnabled')}</label>
      <Toggle id="alert-vuln-enabled" bind:checked={vulnAlertsEnabled}
              ariaLabel={$t('settings.alerts.vulnEnabled')} />
    </div>

    <div class="form-row form-row-inline last-row">
      <label class="flex-1 label-row" for="alert-min-severity">
        {$t('settings.alerts.minSeverity')}
        <InfoTip text={$t('settings.alerts.minSeverityHint')} />
      </label>
      <select id="alert-min-severity" class="w-auto" bind:value={vulnMinSeverity}
              disabled={!vulnAlertsEnabled}>
        {#each SEVERITIES as sev (sev)}
          <option value={sev}>{sev}</option>
        {/each}
      </select>
    </div>
  </div>

  <div class="form-actions">
    <button class="primary" on:click={save} disabled={saving}>
      {saving ? $t('common.actions.saving') : $t('common.actions.save')}
    </button>
  </div>

  <p class="pointer-line">{$t('settings.alerts.pointer')}</p>
{/if}

<style>
  .card-narrow { max-width: 480px; }
  /* .form-row is a column flex box by default; the inline variant turns the row back into a
     left-aligned label + right-edge control. Without the explicit row direction the shared
     align-items lands on the cross axis and centres every control. */
  .form-row-inline { flex-direction: row; align-items: center; gap: 12px; }
  /* The card supplies the bottom padding, so the last row drops its own margin. */
  .last-row { margin-bottom: 0; }
  .pointer-line { font-size: 12px; color: var(--text2); max-width: 480px; margin: 12px 0 0; }
  .form-actions { display: flex; gap: 8px; align-items: center; margin-top: 16px; }
</style>
