<!--
  Email sub-tab of Settings → Integrations — the per-org email delivery channel for admin alerts
  (quarantine + vulnerability), alongside the Webhooks and Slack channels. An org owns the gate and
  the recipient list and nothing else: SMTP is an instance-level transport owned by the operator,
  so instanceEmailConfigured is the one fact this panel borrows from it, letting an admin whose
  recipients would go nowhere be told why rather than watching a silent channel.

  Writes through the channel's own PUT /alert-settings/email, mirroring Slack — the base
  alert-settings PUT never touches these columns, so an Alerts-tab save can't clobber a save here.
  The test-send button hits the server's EffectiveEmailConfigResolver, which reads the saved row,
  so it is gated on what was saved rather than on what is currently typed into the form.
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

  let emailEnabled = settings.emailEnabled
  let emailRecipients = settings.emailRecipients || ''

  function parseRecipients(value) {
    return (value || '').split(',').map((s) => s.trim()).filter(Boolean)
  }

  // Mirrors the server's resolve order (gate -> recipients -> instance transport) so the banner
  // names the first thing actually stopping delivery, in the same order the server gives up.
  $: savedRecipientCount = parseRecipients(settings.emailRecipients).length
  $: disabledReason = !settings.emailEnabled
    ? 'off'
    : savedRecipientCount === 0
      ? 'recipients'
      : !settings.instanceEmailConfigured
        ? 'instance'
        : null
  $: testEnabled = disabledReason === null

  async function save() {
    success = ''
    testMsg = ''
    await submitForm(
      () => api.updateAlertEmail(emailEnabled, emailRecipients || null),
      {
        setSaving: v => saving = v,
        setError: v => error = v,
        onSuccess: (updated) => {
          settings = updated
          onUpdated(updated)
          emailEnabled = updated.emailEnabled
          emailRecipients = updated.emailRecipients || ''
          success = $t('settings.saved')
        },
      })
  }

  async function testEmail() {
    testMsg = ''; error = ''; testing = true
    try {
      await api.testAlertEmail()
      testMsg = $t('settings.integrations.email.testOk')
    } catch (e) {
      testMsg = $t('settings.integrations.email.testFail') + ' ' + extractErrorMessage(e)
    } finally { testing = false }
  }
</script>

<ErrorBanner message={error} />
{#if success}<div class="text-success mb-3">{success}</div>{/if}

<div class="card card-narrow">
  <div class="form-row form-row-inline">
    <label class="flex-1" for="alert-email-enabled">{$t('settings.integrations.email.enabled')}</label>
    <span class="transport-tag"
          class:transport-yes={settings.instanceEmailConfigured}
          class:transport-no={!settings.instanceEmailConfigured}>
      {settings.instanceEmailConfigured
        ? $t('settings.integrations.email.mailServerConfigured')
        : $t('settings.integrations.email.mailServerNotConfigured')}
    </span>
    <Toggle id="alert-email-enabled" bind:checked={emailEnabled}
            ariaLabel={$t('settings.integrations.email.enabled')} />
  </div>

  <div class="form-row">
    <label for="alert-email-recipients">{$t('settings.integrations.email.recipients')}</label>
    <input id="alert-email-recipients" type="text" bind:value={emailRecipients}
           disabled={!emailEnabled} />
    <div class="form-hint">{$t('settings.integrations.email.recipientsHint')}</div>
  </div>

  {#if disabledReason}
    <div class="effectively-disabled-banner" role="status">
      {#if disabledReason === 'off'}
        {$t('settings.integrations.email.disabledOff')}
      {:else if disabledReason === 'recipients'}
        {$t('settings.integrations.email.disabledRecipients')}
      {:else}
        {$t('settings.integrations.email.disabledInstance')}
      {/if}
    </div>
  {/if}

  {#if settings.emailLastStatus}
    <div class="email-status" class:email-status-failed={settings.emailLastStatus === 'failed'}>
      {$t('settings.integrations.email.lastStatus', { values: { status: settings.emailLastStatus } })}
      {#if settings.emailConsecutiveFailures > 0}
        {$t('settings.integrations.slack.consecutiveFailures', { values: { count: settings.emailConsecutiveFailures } })}
      {/if}
      {#if settings.emailFailingSince}
        {$t('settings.integrations.slack.failingSince', { values: { since: settings.emailFailingSince } })}
      {/if}
      {#if settings.emailLastError}
        <div class="email-last-error">{settings.emailLastError}</div>
      {/if}
    </div>
  {/if}

  <div class="form-actions last-row">
    <button class="primary" on:click={save} disabled={saving}>
      {saving ? $t('common.actions.saving') : $t('common.actions.save')}
    </button>
    <button class="btn-sm" on:click={testEmail} disabled={testing || !testEnabled}>
      {$t('settings.integrations.email.testSend')}
    </button>
  </div>
  <div class="form-hint">{$t('settings.integrations.email.testHint')}</div>
  {#if testMsg}<p class="test-msg">{testMsg}</p>{/if}
</div>

<p class="pointer-line">{$t('settings.integrations.email.transportPointer')}</p>

<style>
  .card-narrow { max-width: 480px; margin-top: 12px; }
  /* .form-row is a column flex box by default; the inline variant turns the row back into a
     left-aligned label + right-edge control, matching the other settings tabs. */
  .form-row-inline { flex-direction: row; align-items: center; gap: 12px; }
  .last-row { margin-bottom: 0; }
  .transport-tag {
    font-size: 10px;
    padding: 2px 6px;
    border-radius: 3px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    white-space: nowrap;
  }
  .transport-yes { background: var(--accent); color: var(--on-accent); }
  .transport-no { background: var(--bg3); color: var(--text2); border: 1px solid var(--border); }
  /* Warning tint, not the neutral --bg2/--border pair: inside a card that pair renders as
     another input box, and this is a status note saying the channel sends nothing. */
  .effectively-disabled-banner {
    font-size: 12px;
    color: var(--text);
    background: var(--warning-bg);
    border: 1px solid var(--warning-border);
    border-radius: var(--radius);
    padding: 8px 10px;
    margin-bottom: 12px;
  }
  .email-status {
    font-size: 12px;
    color: var(--text2);
    margin-bottom: 12px;
  }
  .email-status-failed { color: var(--danger); }
  .email-last-error { font-size: 11px; color: var(--danger); margin-top: 2px; }
  .test-msg { font-size: 13px; color: var(--text2); margin: 6px 0 0; }
  .pointer-line { font-size: 12px; color: var(--text2); max-width: 480px; margin: 12px 0 0; }
  .form-actions { display: flex; gap: 8px; align-items: center; }
</style>
