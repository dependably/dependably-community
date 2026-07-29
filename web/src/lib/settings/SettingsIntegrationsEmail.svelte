<!--
  Email sub-tab of Settings → Integrations — the SMTP transport for admin alert emails. The
  delivery gate (send-by-email toggle) and the recipient list live on the Alerts tab; this form
  only owns how mail gets sent: inherit the instance transport, or configure the org's own. The
  SMTP password is write-only (hasEmailSmtpPassword drives the set/rotate hint, mirroring the
  Slack webhook URL convention). Inheriting the instance transport shows only a
  configured/not-configured badge — never the instance's own host/username/etc. "Resolvable"
  mirrors the server's SmtpTransportSettings truth table (host + from, plus either a
  username/password pair or security=none) so the effectively-disabled banner and the test button
  agree with what the server would actually do.
-->
<script>
  import { t } from 'svelte-i18n'
  import { api } from '../api.js'
  import { extractErrorMessage, submitForm } from '../form.js'
  import { secretPlaceholder } from '../secretField.js'
  import ErrorBanner from '../ErrorBanner.svelte'
  import Toggle from '../Toggle.svelte'

  /** @type {any} */
  export let settings
  /** @type {(updated: any) => void} */
  export let onUpdated = () => {}

  const SECURITIES = ['starttls', 'ssl', 'none']
  const DEFAULT_PORT = 587
  const DEFAULT_SECURITY = 'starttls'

  let error = ''
  let success = ''
  let saving = false
  let testMsg = ''
  let testing = false

  let emailInheritInstance = settings.emailInheritInstance
  let emailSmtpHost = settings.emailSmtpHost || ''
  let emailSmtpPort = settings.emailSmtpPort || DEFAULT_PORT
  let emailSmtpSecurity = settings.emailSmtpSecurity || DEFAULT_SECURITY
  let emailSmtpUsername = settings.emailSmtpUsername || ''
  let emailSmtpPassword = '' // write-only — never pre-filled from the server
  let emailSmtpFrom = settings.emailSmtpFrom || ''

  function parseRecipients(value) {
    return (value || '').split(',').map((s) => s.trim()).filter(Boolean)
  }

  // Mirrors SmtpTransportSettings' configured() semantics: host + from, plus either a
  // username/password pair or security=none (no credentials needed).
  function ownTransportConfigured(host, from, username, hasPassword, security) {
    return !!host && !!from && ((!!username && hasPassword) || security === 'none')
  }

  // Mirrors SmtpTransportSettings.SendsCredentialsInCleartextWhen. Computed from the live form
  // rather than the saved settings so the warning appears while the operator is choosing "none",
  // not only after they have already saved credentials into a cleartext session.
  $: cleartextCredentials = !emailInheritInstance
    && emailSmtpSecurity === 'none'
    && !!emailSmtpUsername
    && (settings.hasEmailSmtpPassword || !!emailSmtpPassword)

  $: formOwnConfigured = ownTransportConfigured(
    emailSmtpHost, emailSmtpFrom, emailSmtpUsername,
    settings.hasEmailSmtpPassword || !!emailSmtpPassword, emailSmtpSecurity)
  $: formResolved = emailInheritInstance ? settings.instanceEmailConfigured : formOwnConfigured

  // The delivery gate (enabled + recipients) is owned by the Alerts tab, so it only exists here
  // as last-saved server state. The test button hits the server's EffectiveEmailConfigResolver,
  // which reads the saved row — so it needs the saved state to fully resolve, plus the live
  // transport form (which is all this page can change) to still resolve.
  $: savedRecipients = parseRecipients(settings.emailRecipients)
  $: savedOwnConfigured = ownTransportConfigured(
    settings.emailSmtpHost, settings.emailSmtpFrom, settings.emailSmtpUsername,
    settings.hasEmailSmtpPassword, settings.emailSmtpSecurity)
  $: savedResolved = settings.emailInheritInstance ? settings.instanceEmailConfigured : savedOwnConfigured
  $: savedResolvable = settings.emailEnabled && savedRecipients.length > 0 && savedResolved

  $: testEnabled = savedResolvable && formResolved

  $: disabledReason = !settings.emailEnabled
    ? 'off'
    : savedRecipients.length === 0
      ? 'recipients'
      : !formResolved
        ? (emailInheritInstance ? 'instance' : 'ownTransport')
        : null

  async function save() {
    success = ''
    testMsg = ''
    const port = Number.isFinite(Number(emailSmtpPort)) && Number(emailSmtpPort) > 0
      ? Number(emailSmtpPort)
      : DEFAULT_PORT
    await submitForm(
      () => api.updateAlertEmail({
        emailInheritInstance,
        emailSmtpHost: emailSmtpHost || null,
        emailSmtpPort: port,
        emailSmtpSecurity,
        emailSmtpUsername: emailSmtpUsername || null,
        emailSmtpPassword: emailSmtpPassword || null,
        emailSmtpFrom: emailSmtpFrom || null,
      }),
      {
        setSaving: (v) => (saving = v),
        setError: (v) => (error = v),
        onSuccess: (updated) => {
          settings = updated
          onUpdated(updated)
          emailSmtpPassword = ''
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

<div class="email-settings-form">
  <div class="form-row checkbox-row">
    <span class="checkbox-label">
      <Toggle bind:checked={emailInheritInstance}
              ariaLabel={$t('settings.integrations.email.inheritInstance')} />
      {$t('settings.integrations.email.inheritInstance')}
    </span>
    <div class="form-hint">{$t('settings.integrations.email.inheritHint')}</div>
    {#if emailInheritInstance}
      {#if settings.instanceEmailConfigured}
        <span class="badge success" aria-label={$t('settings.integrations.email.instanceConfigured')}>
          {$t('settings.integrations.email.instanceConfigured')}
        </span>
      {:else}
        <div class="form-hint">{$t('settings.integrations.email.instanceNotConfigured')}</div>
      {/if}
    {/if}
  </div>

  <div class="own-smtp-fields">
    <div class="form-row">
      <label for="integrations-email-host">{$t('settings.integrations.email.host')}</label>
      <input id="integrations-email-host" type="text" bind:value={emailSmtpHost}
             disabled={emailInheritInstance} />
    </div>

    <div class="form-row">
      <label for="integrations-email-port">{$t('settings.integrations.email.port')}</label>
      <input id="integrations-email-port" type="number" bind:value={emailSmtpPort}
             placeholder="587" min="1" max="65535"
             disabled={emailInheritInstance} />
    </div>

    <div class="form-row">
      <label for="integrations-email-security">{$t('settings.integrations.email.security')}</label>
      <select id="integrations-email-security" bind:value={emailSmtpSecurity}
              disabled={emailInheritInstance}>
        {#each SECURITIES as sec (sec)}
          <option value={sec}>{$t(`settings.integrations.email.security${sec[0].toUpperCase()}${sec.slice(1)}`)}</option>
        {/each}
      </select>
    </div>

    <div class="form-row">
      <label for="integrations-email-username">{$t('settings.integrations.email.username')}</label>
      <input id="integrations-email-username" type="text" bind:value={emailSmtpUsername}
             disabled={emailInheritInstance} />
    </div>

    <div class="form-row">
      <label for="integrations-email-password">{$t('settings.integrations.email.password')}</label>
      <input id="integrations-email-password" type="password" bind:value={emailSmtpPassword}
             placeholder={secretPlaceholder(settings.hasEmailSmtpPassword)}
             autocomplete="new-password"
             disabled={emailInheritInstance || !settings.secretsAvailable} />
      {#if !settings.secretsAvailable}
        <div class="form-hint">{$t('settings.integrations.masterKeyHint')}</div>
      {:else}
        <div class="form-hint">
          {settings.hasEmailSmtpPassword
            ? $t('settings.integrations.email.passwordRotateHint')
            : $t('settings.integrations.email.passwordSetHint')}
        </div>
      {/if}
    </div>

    <div class="form-row">
      <label for="integrations-email-from">{$t('settings.integrations.email.from')}</label>
      <input id="integrations-email-from" type="text" bind:value={emailSmtpFrom}
             disabled={emailInheritInstance} />
    </div>
  </div>

  {#if cleartextCredentials}
    <div class="cleartext-warning" role="status">{$t('settings.integrations.email.cleartextCredentials')}</div>
  {/if}

  {#if disabledReason}
    <div class="effectively-disabled-banner" role="status">
      {#if disabledReason === 'off'}
        {$t('settings.integrations.email.disabledPointer')}
      {:else if disabledReason === 'recipients'}
        {$t('settings.integrations.email.effectivelyDisabledRecipients')}
      {:else if disabledReason === 'instance'}
        {$t('settings.integrations.email.effectivelyDisabledInstance')}
      {:else}
        {$t('settings.integrations.email.effectivelyDisabledOwnTransport')}
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

  {#if testMsg}<p class="test-msg">{testMsg}</p>{/if}

  <div class="form-actions">
    <button class="primary" on:click={save} disabled={saving}>
      {saving ? $t('common.actions.saving') : $t('common.actions.save')}
    </button>
    <button class="btn-sm" on:click={testEmail} disabled={testing || !testEnabled}>
      {$t('settings.integrations.email.testSend')}
    </button>
  </div>
  <div class="form-hint">{$t('settings.integrations.email.testHint')}</div>
</div>

<style>
  .email-settings-form { max-width: 480px; margin-top: 12px; }
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
  .own-smtp-fields { margin-top: 4px; }
  .effectively-disabled-banner {
    font-size: 12px;
    color: var(--text2);
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 8px 10px;
    margin: 12px 0;
  }
  .cleartext-warning {
    background: var(--warning-bg);
    border: 1px solid var(--warning-border);
    color: var(--warning-text);
    border-radius: var(--radius);
    padding: 8px 10px;
    margin: 12px 0;
    font-size: 12px;
  }
  .email-status {
    font-size: 12px;
    color: var(--text2);
    margin-top: 4px;
  }
  .email-status-failed { color: var(--danger); }
  .email-last-error { font-size: 11px; color: var(--danger); margin-top: 2px; }
  .test-msg { font-size: 13px; color: var(--text2); margin: 6px 0; }
  .form-actions { display: flex; gap: 8px; align-items: center; margin-top: 8px; }
</style>
