<!--
  Alert center settings — per-type toggles, the vulnerability severity floor, and the optional
  Slack delivery channel. Modeled on SettingsWebhooks.svelte's write-only-secret pattern: the
  Slack webhook URL is never echoed back, only a computed hasSlackWebhook boolean.
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

  let settings = null
  let loaded = false
  let error = ''
  let success = ''
  let saving = false
  let testMsg = ''
  let testing = false

  // Form-bound fields, seeded from the loaded settings.
  let quarantineAlertsEnabled = true
  let vulnAlertsEnabled = true
  let vulnMinSeverity = 'HIGH'
  let slackEnabled = false
  let slackWebhookUrl = '' // write-only — never pre-filled from the server

  onMount(load)

  async function load() {
    try {
      settings = await api.getAlertSettings()
      quarantineAlertsEnabled = settings.quarantineAlertsEnabled
      vulnAlertsEnabled = settings.vulnAlertsEnabled
      vulnMinSeverity = settings.vulnMinSeverity
      slackEnabled = settings.slackEnabled
      loaded = true
    } catch (e) { error = extractErrorMessage(e) }
  }

  async function save() {
    success = ''
    testMsg = ''
    await submitForm(
      () => api.updateAlertSettings(
        quarantineAlertsEnabled, vulnAlertsEnabled, vulnMinSeverity, slackEnabled,
        slackWebhookUrl || null),
      {
        setSaving: v => saving = v,
        setError: v => error = v,
        onSuccess: (updated) => {
          settings = updated
          slackWebhookUrl = ''
          success = $t('settings.saved')
        },
      })
  }

  async function testSlack() {
    testMsg = ''; error = ''; testing = true
    try {
      await api.testAlertSlack()
      testMsg = $t('settings.alerts.testOk')
    } catch (e) {
      testMsg = $t('settings.alerts.testFail') + ' ' + extractErrorMessage(e)
    } finally { testing = false }
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
        <Toggle bind:checked={slackEnabled} ariaLabel={$t('settings.alerts.slackEnabled')} />
        {$t('settings.alerts.slackEnabled')}
      </span>
    </div>

    <div class="form-row">
      <label for="alert-slack-url">{$t('settings.alerts.slackUrl')}</label>
      <input id="alert-slack-url" type="password" bind:value={slackWebhookUrl} autocomplete="new-password" disabled={!slackEnabled} />
      <div class="form-hint">
        {settings.hasSlackWebhook ? $t('settings.alerts.slackUrlRotateHint') : $t('settings.alerts.slackUrlHint')}
      </div>
      {#if settings.slackLastStatus}
        <div class="slack-status" class:slack-status-failed={settings.slackLastStatus === 'failed'}>
          {$t('settings.alerts.slackLastStatus', { values: { status: settings.slackLastStatus } })}
        </div>
      {/if}
    </div>

    {#if testMsg}<p class="test-msg">{testMsg}</p>{/if}

    <div class="form-actions">
      <button class="primary" on:click={save} disabled={saving}>
        {saving ? $t('common.actions.saving') : $t('common.actions.save')}
      </button>
      {#if settings.hasSlackWebhook}
        <button class="btn-sm" on:click={testSlack} disabled={testing}>
          {$t('settings.alerts.testSend')}
        </button>
      {/if}
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
  .slack-status {
    font-size: 12px;
    color: var(--text2);
    margin-top: 4px;
  }
  .slack-status-failed { color: var(--danger); }
  .test-msg { font-size: 13px; color: var(--text2); margin: 6px 0; }
  .form-actions { display: flex; gap: 8px; align-items: center; margin-top: 8px; }
</style>
