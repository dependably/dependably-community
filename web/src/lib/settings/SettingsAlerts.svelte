<!--
  Alert center settings — what fires and who hears about it: per-type toggles, the vulnerability
  severity floor, and the email delivery gate (send-by-email toggle + recipient list). The
  delivery transports (Slack webhook, SMTP server) live on the Integrations tab; the base
  alert-settings PUT never touches those columns, so a save here can't clobber an
  Integrations-tab save.
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

  // Form-bound fields, seeded from the loaded settings.
  let quarantineAlertsEnabled = true
  let vulnAlertsEnabled = true
  let vulnMinSeverity = 'HIGH'
  let emailEnabled = false
  let emailRecipients = ''

  onMount(load)

  async function load() {
    try {
      const settings = await api.getAlertSettings()
      quarantineAlertsEnabled = settings.quarantineAlertsEnabled
      vulnAlertsEnabled = settings.vulnAlertsEnabled
      vulnMinSeverity = settings.vulnMinSeverity
      emailEnabled = settings.emailEnabled
      emailRecipients = settings.emailRecipients || ''
      loaded = true
    } catch (e) { error = extractErrorMessage(e) }
  }

  async function save() {
    success = ''
    await submitForm(
      () => api.updateAlertSettings({
        quarantineAlertsEnabled,
        vulnAlertsEnabled,
        vulnMinSeverity,
        emailEnabled,
        emailRecipients: emailRecipients || null,
      }),
      {
        setSaving: v => saving = v,
        setError: v => error = v,
        onSuccess: (updated) => {
          emailRecipients = updated.emailRecipients || ''
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
  <div class="alerts-settings-form">
    <div class="form-row checkbox-row">
      <span class="checkbox-label">
        <Toggle bind:checked={quarantineAlertsEnabled} ariaLabel={$t('settings.alerts.quarantineEnabled')} />
        {$t('settings.alerts.quarantineEnabled')}
      </span>
    </div>

    <div class="form-row checkbox-row">
      <span class="checkbox-label">
        <Toggle bind:checked={vulnAlertsEnabled} ariaLabel={$t('settings.alerts.vulnEnabled')} />
        {$t('settings.alerts.vulnEnabled')}
      </span>
    </div>

    <div class="form-row">
      <label for="alert-min-severity">{$t('settings.alerts.minSeverity')}</label>
      <select id="alert-min-severity" bind:value={vulnMinSeverity} disabled={!vulnAlertsEnabled}>
        {#each SEVERITIES as sev (sev)}
          <option value={sev}>{sev}</option>
        {/each}
      </select>
      <div class="form-hint">{$t('settings.alerts.minSeverityHint')}</div>
    </div>

    <div class="form-row checkbox-row">
      <span class="checkbox-label">
        <Toggle bind:checked={emailEnabled} ariaLabel={$t('settings.alerts.emailEnabled')} />
        {$t('settings.alerts.emailEnabled')}
      </span>
    </div>

    <div class="form-row">
      <label for="alert-email-recipients">{$t('settings.alerts.emailRecipients')}</label>
      <input id="alert-email-recipients" type="text" bind:value={emailRecipients}
             disabled={!emailEnabled} />
      <div class="form-hint">{$t('settings.alerts.emailRecipientsHint')}</div>
    </div>

    <p class="pointer-line">{$t('settings.alerts.pointer')}</p>

    <div class="form-actions">
      <button class="primary" on:click={save} disabled={saving}>
        {saving ? $t('common.actions.saving') : $t('common.actions.save')}
      </button>
    </div>
  </div>
{/if}

<style>
  .alerts-settings-form { max-width: 480px; }
  .checkbox-row { margin-bottom: 12px; }
  .checkbox-label {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 13px;
    font-weight: 500;
    color: var(--text2);
    cursor: pointer;
  }
  .pointer-line { font-size: 12px; color: var(--text2); margin: 12px 0; }
  .form-actions { display: flex; gap: 8px; align-items: center; margin-top: 8px; }
</style>
