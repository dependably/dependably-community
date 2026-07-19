<!--
  Operator Slack config (multi-tenant deployments). Control-plane events only — tenant lifecycle
  and operator-account changes — never a per-org quarantine or vulnerability alert. Modeled on
  SettingsAlerts.svelte's write-only-secret pattern: the webhook URL is never echoed back, only a
  computed hasWebhook boolean.
-->
<script>
  import { onMount } from 'svelte'
  import { t } from 'svelte-i18n'
  import { systemApi } from '../api.js'
  import { extractErrorMessage, submitForm } from '../form.js'
  import ErrorBanner from '../ErrorBanner.svelte'
  import InfoTip from '../InfoTip.svelte'
  import Toggle from '../Toggle.svelte'

  let config = null
  let loaded = false
  let error = ''
  let success = ''
  let saving = false
  let testMsg = ''
  let testing = false

  // Form-bound fields, seeded from the loaded config.
  let enabled = false
  let webhookUrl = '' // write-only — never pre-filled from the server

  onMount(load)

  async function load() {
    try {
      config = await systemApi.getSlackConfig()
      enabled = config.enabled
      loaded = true
    } catch (e) { error = extractErrorMessage(e) }
  }

  async function save() {
    success = ''
    testMsg = ''
    await submitForm(
      () => systemApi.updateSlackConfig({ enabled, webhookUrl: webhookUrl || null }),
      {
        setSaving: v => saving = v,
        setError: v => error = v,
        onSuccess: (updated) => {
          config = updated
          webhookUrl = ''
          success = $t('settings.saved')
        },
      })
  }

  async function test() {
    testMsg = ''; error = ''; testing = true
    try {
      await systemApi.testSlackConfig()
      testMsg = $t('system.settings.slack.testOk')
    } catch (e) {
      testMsg = $t('system.settings.slack.testFail') + ' ' + extractErrorMessage(e)
    } finally { testing = false }
  }
</script>

<h3 class="section-h">
  {$t('system.settings.slack.title')}
  <InfoTip text={$t('system.settings.slack.hint')} />
</h3>

<ErrorBanner message={error} />
{#if success}<div class="text-success mb-3">{success}</div>{/if}

{#if !loaded}
  <span class="spinner"></span>
{:else}
  <div class="slack-config-form">
    {#if !config.secretsAvailable}
      <div class="env-banner">{$t('system.settings.slack.masterKeyHint')}</div>
    {/if}

    <div class="form-row checkbox-row">
      <span class="checkbox-label">
        <Toggle bind:checked={enabled} disabled={!config.secretsAvailable} ariaLabel={$t('system.settings.slack.enabled')} />
        {$t('system.settings.slack.enabled')}
      </span>
    </div>

    <div class="form-row">
      <label for="system-slack-url">{$t('system.settings.slack.webhookUrl')}</label>
      <input
        id="system-slack-url"
        type="password"
        bind:value={webhookUrl}
        autocomplete="new-password"
        disabled={!enabled || !config.secretsAvailable}
      />
      <div class="form-hint">
        {config.hasWebhook ? $t('system.settings.slack.webhookUrlRotateHint') : $t('system.settings.slack.webhookUrlHint')}
      </div>
      {#if config.lastStatus}
        <div class="slack-status" class:slack-status-failed={config.lastStatus === 'failed'}>
          {$t('system.settings.slack.lastStatus', { values: { status: config.lastStatus } })}
        </div>
      {/if}
    </div>

    {#if testMsg}<p class="test-msg">{testMsg}</p>{/if}

    <div class="form-actions">
      <button class="primary" on:click={save} disabled={saving}>
        {saving ? $t('common.actions.saving') : $t('common.actions.save')}
      </button>
      {#if config.hasWebhook}
        <button class="btn-sm" on:click={test} disabled={testing}>
          {$t('system.settings.slack.testSend')}
        </button>
      {/if}
    </div>
  </div>
{/if}

<style>
  .slack-config-form { max-width: 480px; }
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
  .env-banner {
    background: rgba(255, 180, 0, 0.15);
    border: 1px solid rgba(255, 180, 0, 0.4);
    padding: 8px 12px;
    border-radius: var(--radius);
    margin-bottom: 12px;
    max-width: 480px;
    font-size: 13px;
  }
</style>
