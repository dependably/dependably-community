<!--
  Slack sub-tab of Settings → Integrations — the per-org Slack delivery channel for admin
  alerts (quarantine + vulnerability), extracted from the alert center's old combined form.
  Write-only webhook URL: never pre-filled from the server, only a computed hasSlackWebhook
  boolean. When the instance has no DEPENDABLY_MASTER_KEY configured (secretsAvailable false),
  the URL input is disabled with an explanatory hint — the PUT would fail closed anyway.
-->
<script>
  import { t } from 'svelte-i18n'
  import { api } from '../api.js'
  import { extractErrorMessage, submitForm } from '../form.js'
  import ErrorBanner from '../ErrorBanner.svelte'
  import Toggle from '../Toggle.svelte'

  /** @type {any} */
  export let settings
  /** @type {(updated: any) => void} */
  export let onUpdated = () => {}

  let error = ''
  let success = ''
  let saving = false
  let testMsg = ''
  let testing = false

  let slackEnabled = settings.slackEnabled
  let slackWebhookUrl = '' // write-only — never pre-filled from the server

  async function save() {
    success = ''
    testMsg = ''
    await submitForm(
      () => api.updateAlertSlack(slackEnabled, slackWebhookUrl || null),
      {
        setSaving: v => saving = v,
        setError: v => error = v,
        onSuccess: (updated) => {
          settings = updated
          onUpdated(updated)
          slackWebhookUrl = ''
          success = $t('settings.saved')
        },
      })
  }

  async function testSlack() {
    testMsg = ''; error = ''; testing = true
    try {
      await api.testAlertSlack()
      testMsg = $t('settings.integrations.slack.testOk')
    } catch (e) {
      testMsg = $t('settings.integrations.slack.testFail') + ' ' + extractErrorMessage(e)
    } finally { testing = false }
  }
</script>

<ErrorBanner message={error} />
{#if success}<div class="text-success mb-3">{success}</div>{/if}

<div class="slack-settings-form">
  <div class="form-row checkbox-row">
    <span class="checkbox-label">
      <Toggle bind:checked={slackEnabled} ariaLabel={$t('settings.integrations.slack.enabled')} />
      {$t('settings.integrations.slack.enabled')}
    </span>
  </div>

  <div class="form-row">
    <label for="integrations-slack-url">{$t('settings.integrations.slack.url')}</label>
    <input id="integrations-slack-url" type="password" bind:value={slackWebhookUrl}
           autocomplete="new-password" disabled={!slackEnabled || !settings.secretsAvailable} />
    {#if !settings.secretsAvailable}
      <div class="form-hint">{$t('settings.integrations.masterKeyHint')}</div>
    {:else}
      <div class="form-hint">
        {settings.hasSlackWebhook ? $t('settings.integrations.slack.urlRotateHint') : $t('settings.integrations.slack.urlHint')}
      </div>
    {/if}
    {#if settings.slackLastStatus}
      <div class="slack-status" class:slack-status-failed={settings.slackLastStatus === 'failed'}>
        {$t('settings.integrations.slack.lastStatus', { values: { status: settings.slackLastStatus } })}
        {#if settings.slackConsecutiveFailures > 0}
          {$t('settings.integrations.slack.consecutiveFailures', { values: { count: settings.slackConsecutiveFailures } })}
        {/if}
        {#if settings.slackFailingSince}
          {$t('settings.integrations.slack.failingSince', { values: { since: settings.slackFailingSince } })}
        {/if}
        {#if settings.slackLastError}
          <div class="slack-last-error">{settings.slackLastError}</div>
        {/if}
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
        {$t('settings.integrations.slack.testSend')}
      </button>
    {/if}
  </div>
</div>

<style>
  .slack-settings-form { max-width: 480px; margin-top: 12px; }
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
  .slack-last-error { font-size: 11px; color: var(--danger); margin-top: 2px; }
  .test-msg { font-size: 13px; color: var(--text2); margin: 6px 0; }
  .form-actions { display: flex; gap: 8px; align-items: center; margin-top: 8px; }
</style>
