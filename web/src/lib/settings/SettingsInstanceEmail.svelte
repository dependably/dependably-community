<!--
  Instance-level SMTP transport editor, shared by the multi-mode system SPA
  (SystemSettings.svelte's email tab, backed by systemApi.*EmailConfig) and the single-mode
  tenant Settings page (OrgSettings.svelte's instance tab, backed by api.*InstanceEmailConfig).
  Modeled on SettingsMetrics/SettingsInstance: the caller passes get/update/test fns so the
  same form drives both surfaces. Write-only-secret pattern matches SettingsAlerts' Slack
  section — the password is never echoed, only a computed hasPassword boolean.
-->
<script>
  import { onMount } from 'svelte'
  import { t } from 'svelte-i18n'
  import { extractErrorMessage, submitForm } from '../form.js'
  import { secretPlaceholder } from '../secretField.js'
  import ErrorBanner from '../ErrorBanner.svelte'
  import InfoTip from '../InfoTip.svelte'
  import Toggle from '../Toggle.svelte'

  export let getConfig    // () => Promise<config>
  export let updateConfig // (payload) => Promise<config>
  export let testSend     // () => Promise<void>

  const SECURITY_MODES = ['starttls', 'ssl', 'none']

  let config = null
  let loaded = false
  let error = ''
  let success = ''
  let saving = false
  let testMsg = ''
  let testing = false

  // Form-bound fields, seeded from the loaded config.
  let enabled = false
  let host = ''
  let port = ''
  let security = 'starttls'
  let username = ''
  let password = '' // write-only — never pre-filled from the server
  let fromAddress = ''

  onMount(load)

  async function load() {
    try {
      config = await getConfig()
      enabled = config.enabled
      host = config.host || ''
      port = config.port ? String(config.port) : ''
      security = config.security || 'starttls'
      username = config.username || ''
      fromAddress = config.fromAddress || ''
      loaded = true
    } catch (e) { error = extractErrorMessage(e) }
  }

  async function save() {
    success = ''
    testMsg = ''
    await submitForm(
      () => updateConfig({
        enabled,
        host: host || null,
        port: port ? Number(port) : undefined,
        security,
        username: username || null,
        password: password || null,
        fromAddress: fromAddress || null,
      }),
      {
        setSaving: v => saving = v,
        setError: v => error = v,
        onSuccess: (updated) => {
          config = updated
          password = ''
          success = $t('settings.saved')
        },
      })
  }

  async function testEmail() {
    testMsg = ''; error = ''; testing = true
    try {
      await testSend()
      testMsg = $t('settings.instanceEmail.testOk')
    } catch (e) {
      testMsg = $t('settings.instanceEmail.testFail') + ' ' + extractErrorMessage(e)
    } finally { testing = false }
  }
</script>

<h3 class="section-h">
  {$t('settings.instanceEmail.title')}
  <InfoTip text={$t('settings.instanceEmail.hint')} />
</h3>

<ErrorBanner message={error} />
{#if success}<div class="text-success mb-3">{success}</div>{/if}

{#if !loaded}
  <span class="spinner"></span>
{:else}
  <div class="instance-email-form">
    {#if !config.secretsAvailable}
      <div class="env-banner">{$t('settings.instanceEmail.masterKeyHint')}</div>
    {/if}

    <div class="form-row checkbox-row">
      <span class="checkbox-label">
        <Toggle bind:checked={enabled} ariaLabel={$t('settings.instanceEmail.enabled')} />
        {$t('settings.instanceEmail.enabled')}
      </span>
      <span class="configured-tag" class:configured-yes={config.configured} class:configured-no={!config.configured}>
        {config.configured ? $t('settings.instanceEmail.configured') : $t('settings.instanceEmail.notConfigured')}
      </span>
    </div>

    <div class="form-row">
      <label for="instance-email-host">{$t('settings.instanceEmail.host')}</label>
      <input id="instance-email-host" type="text" bind:value={host} disabled={!enabled} />
    </div>

    <div class="form-row">
      <label for="instance-email-port">{$t('settings.instanceEmail.port')}</label>
      <input id="instance-email-port" type="number" bind:value={port} placeholder="587" disabled={!enabled} />
    </div>

    <div class="form-row">
      <label for="instance-email-security">{$t('settings.instanceEmail.security')}</label>
      <select id="instance-email-security" bind:value={security} disabled={!enabled}>
        {#each SECURITY_MODES as mode (mode)}
          <option value={mode}>{$t(`settings.instanceEmail.security${mode.charAt(0).toUpperCase()}${mode.slice(1)}`)}</option>
        {/each}
      </select>
    </div>

    <div class="form-row">
      <label for="instance-email-username">{$t('settings.instanceEmail.username')}</label>
      <input id="instance-email-username" type="text" bind:value={username} disabled={!enabled} autocomplete="off" />
    </div>

    <div class="form-row">
      <label for="instance-email-password">{$t('settings.instanceEmail.password')}</label>
      <input
        id="instance-email-password"
        type="password"
        bind:value={password}
        placeholder={secretPlaceholder(config.hasPassword)}
        autocomplete="new-password"
        disabled={!enabled || !config.secretsAvailable}
      />
      <div class="form-hint">
        {#if !config.secretsAvailable}
          {$t('settings.instanceEmail.masterKeyHint')}
        {:else if config.hasPassword}
          {$t('settings.instanceEmail.passwordRotateHint')}
        {:else}
          {$t('settings.instanceEmail.passwordSetHint')}
        {/if}
      </div>
    </div>

    <div class="form-row">
      <label for="instance-email-from">{$t('settings.instanceEmail.from')}</label>
      <input id="instance-email-from" type="text" bind:value={fromAddress} disabled={!enabled} />
    </div>

    {#if testMsg}<p class="test-msg">{testMsg}</p>{/if}

    <div class="form-actions">
      <button class="primary" on:click={save} disabled={saving}>
        {saving ? $t('common.actions.saving') : $t('common.actions.save')}
      </button>
      {#if config.configured}
        <button class="btn-sm" on:click={testEmail} disabled={testing}>
          {$t('settings.instanceEmail.testSend')}
        </button>
      {/if}
    </div>
  </div>
{/if}

<style>
  .instance-email-form { max-width: 480px; }
  .checkbox-row { margin-bottom: 12px; display: flex; align-items: center; justify-content: space-between; }
  .checkbox-label {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 13px;
    font-weight: 500;
    color: var(--text2);
    cursor: pointer;
  }
  .configured-tag {
    font-size: 10px;
    padding: 2px 6px;
    border-radius: 3px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }
  .configured-yes { background: var(--accent); color: white; }
  .configured-no { background: var(--bg3); color: var(--text2); border: 1px solid var(--border); }
  .form-hint { font-size: 11px; color: var(--text2); }
  .test-msg { font-size: 13px; color: var(--text2); margin: 6px 0; }
  .form-actions { display: flex; gap: 8px; align-items: center; margin-top: 8px; }
  .env-banner {
    background: rgba(255, 180, 0, 0.15);
    border: 1px solid rgba(255, 180, 0, 0.4);
    padding: 8px 12px;
    border-radius: var(--radius);
    margin-bottom: 12px;
    font-size: 13px;
  }
</style>
