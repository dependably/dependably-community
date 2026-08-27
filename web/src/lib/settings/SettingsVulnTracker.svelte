<!--
  Instance-level vulnerability-tracker connection editor, shared by the multi-mode system SPA
  (SystemSettings.svelte's tracker tab, backed by systemApi.*VulnTrackerConfig) and the
  single-mode tenant Settings page (OrgSettings.svelte's instance tab, backed by
  api.*InstanceVulnTrackerConfig). Same caller-passes-get/update shape as SettingsInstanceEmail,
  which the backend surface deliberately mirrors: both are operator-owned instance-level
  transports with one configuration serving every tenant and no per-org override.

  Write-only-secret pattern matches SettingsInstanceEmail's SMTP password — the token is never
  echoed, only a computed hasToken boolean, and the field is disabled with an explanatory hint
  when the deployment has no master key to encrypt it with.

  Connection health lives in the sibling SettingsVulnTrackerHealth, rendered directly below this
  by both callers: what the operator configures and what the connection actually does are two
  different questions, and a combined component would re-read health on every save.
-->
<script>
  import { onMount } from 'svelte'
  import { t } from 'svelte-i18n'
  import { extractErrorMessage, submitForm } from '../form.js'
  import { secretPlaceholder } from '../secretField.js'
  import {
    BATCH_MAX,
    BATCH_MIN,
    STALENESS_MAX,
    STALENESS_MIN,
    buildPayload,
    connectionState,
    discardsStoredToken,
    formFromConfig,
    validateForm,
  } from '../vulnTrackerForm.js'
  import ErrorBanner from '../ErrorBanner.svelte'
  import InfoTip from '../InfoTip.svelte'
  import Toggle from '../Toggle.svelte'

  export let getConfig    // () => Promise<config>
  export let updateConfig // (payload) => Promise<config>

  let config = null
  let loaded = false
  let error = ''
  let success = ''
  let saving = false

  // Form-bound fields, seeded from the loaded config.
  let enabled = false
  let baseUrl = ''
  let maxStalenessHours = ''
  let batchSize = ''
  let token = '' // write-only — never pre-filled from the server

  onMount(load)

  async function load() {
    try {
      config = await getConfig()
      const form = formFromConfig(config)
      enabled = form.enabled
      baseUrl = form.baseUrl
      maxStalenessHours = form.maxStalenessHours
      batchSize = form.batchSize
      loaded = true
    } catch (e) { error = extractErrorMessage(e) }
  }

  $: form = { enabled, baseUrl, maxStalenessHours, batchSize }
  $: state = connectionState(config)
  // Computed from the live form rather than the saved config, so the warning appears while the
  // operator is emptying the field — not after the credential is already gone.
  $: losingToken = discardsStoredToken(config, baseUrl)

  async function save() {
    success = ''
    const invalid = validateForm(form)
    if (invalid) {
      error = $t(invalid)
      return
    }

    await submitForm(
      () => updateConfig(buildPayload(form, token)),
      {
        setSaving: v => saving = v,
        setError: v => error = v,
        onSuccess: (updated) => {
          config = updated
          token = ''
          // A save that cleared the base URL also cleared the stored token server-side; reseed
          // from the response so the form reflects what was actually persisted.
          const next = formFromConfig(updated)
          enabled = next.enabled
          baseUrl = next.baseUrl
          maxStalenessHours = next.maxStalenessHours
          batchSize = next.batchSize
          success = $t('settings.saved')
        },
      })
  }
</script>

<h3 class="section-h">
  {$t('settings.vulnTracker.title')}
  <InfoTip text={$t('settings.vulnTracker.hint')} />
</h3>

<ErrorBanner message={error} />
{#if success}<div class="text-success mb-3">{success}</div>{/if}

{#if !loaded}
  <span class="spinner"></span>
{:else}
  <div class="vuln-tracker-form">
    <p class="scope-note">{$t('settings.vulnTracker.scopeNote')}</p>

    {#if !config.secretsAvailable}
      <div class="env-banner">{$t('settings.vulnTracker.masterKeyHint')}</div>
    {/if}

    <div class="form-row checkbox-row">
      <span class="checkbox-label">
        <Toggle bind:checked={enabled} ariaLabel={$t('settings.vulnTracker.enabled')} />
        {$t('settings.vulnTracker.enabled')}
      </span>
      <span class="state-tag" class:state-active={state === 'active'} class:state-paused={state === 'paused'} class:state-unset={state === 'notConfigured'}>
        {$t(`settings.vulnTracker.state.${state}`)}
      </span>
    </div>
    <p class="form-hint enabled-hint">{$t('settings.vulnTracker.enabledHint')}</p>

    <div class="form-row">
      <label for="vuln-tracker-base-url">{$t('settings.vulnTracker.baseUrl')}</label>
      <input
        id="vuln-tracker-base-url"
        type="url"
        bind:value={baseUrl}
        placeholder="https://tracker.example.com"
        autocomplete="off"
      />
      <div class="form-hint">{$t('settings.vulnTracker.baseUrlHint')}</div>
    </div>

    <div class="form-row">
      <label for="vuln-tracker-token">{$t('settings.vulnTracker.token')}</label>
      <input
        id="vuln-tracker-token"
        type="password"
        bind:value={token}
        placeholder={secretPlaceholder(config.hasToken)}
        autocomplete="new-password"
        disabled={!config.secretsAvailable}
      />
      <div class="form-hint">
        {#if !config.secretsAvailable}
          {$t('settings.vulnTracker.masterKeyHint')}
        {:else if config.hasToken}
          {$t('settings.vulnTracker.tokenRotateHint')}
        {:else}
          {$t('settings.vulnTracker.tokenSetHint')}
        {/if}
      </div>
    </div>

    <div class="form-row">
      <label for="vuln-tracker-staleness">{$t('settings.vulnTracker.maxStalenessHours')}</label>
      <input
        id="vuln-tracker-staleness"
        type="number"
        bind:value={maxStalenessHours}
        min={STALENESS_MIN}
        max={STALENESS_MAX}
      />
      <div class="form-hint">{$t('settings.vulnTracker.maxStalenessHint')}</div>
    </div>

    <div class="form-row">
      <label for="vuln-tracker-batch-size">{$t('settings.vulnTracker.batchSize')}</label>
      <input
        id="vuln-tracker-batch-size"
        type="number"
        bind:value={batchSize}
        min={BATCH_MIN}
        max={BATCH_MAX}
      />
      <div class="form-hint">{$t('settings.vulnTracker.batchSizeHint')}</div>
    </div>

    {#if losingToken}
      <div class="clear-warning" role="status">{$t('settings.vulnTracker.clearDiscardsToken')}</div>
    {/if}

    <div class="form-actions">
      <button class="primary" on:click={save} disabled={saving}>
        {saving ? $t('common.actions.saving') : $t('common.actions.save')}
      </button>
    </div>
  </div>
{/if}

<style>
  .vuln-tracker-form { max-width: 480px; }
  .scope-note { font-size: 12px; color: var(--text2); margin: 0 0 12px; }
  /* .form-row is a column flex box by default; without the explicit row direction the shared
     align-items lands on the cross axis and centres the toggle, pushing the state tag onto its
     own line. Same shape as SettingsInstanceEmail's checkbox-row. */
  .checkbox-row {
    margin-bottom: 4px;
    display: flex;
    flex-direction: row;
    align-items: center;
    justify-content: space-between;
  }
  .checkbox-label {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 13px;
    font-weight: 500;
    color: var(--text2);
    cursor: pointer;
  }
  .state-tag {
    font-size: 10px;
    padding: 2px 6px;
    border-radius: 3px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }
  .state-active { background: var(--accent); color: white; }
  .state-paused { background: var(--warning-bg); color: var(--warning-text); border: 1px solid var(--warning-border); }
  .state-unset { background: var(--bg3); color: var(--text2); border: 1px solid var(--border); }
  /* The stylesheet has no global disabled-input treatment, and the browser default is nearly
     invisible in the light theme — which would leave the master-key-unavailable token field
     looking editable while silently swallowing keystrokes. Scoped here rather than added
     globally so no other form's appearance changes. */
  .vuln-tracker-form input:disabled {
    opacity: 0.55;
    background: var(--bg3);
    cursor: not-allowed;
  }
  .form-hint { font-size: 11px; color: var(--text2); }
  .enabled-hint { margin: 0 0 12px; }
  .form-actions { display: flex; gap: 8px; align-items: center; margin-top: 8px; }
  .clear-warning {
    background: var(--warning-bg);
    border: 1px solid var(--warning-border);
    color: var(--warning-text);
    border-radius: var(--radius);
    padding: 8px 12px;
    margin: 12px 0;
    font-size: 12px;
  }
  .env-banner {
    background: rgba(255, 180, 0, 0.15);
    border: 1px solid rgba(255, 180, 0, 0.4);
    padding: 8px 12px;
    border-radius: var(--radius);
    margin-bottom: 12px;
    font-size: 13px;
  }
</style>
