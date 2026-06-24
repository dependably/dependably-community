<script>
  import { t, locale } from 'svelte-i18n'
  import { user, navigate, takePendingRoute } from '../lib/store.js'
  import ThemeToggle from '../lib/ThemeToggle.svelte'
  import { api } from '../lib/api.js'
  import { submitForm } from '../lib/form.js'
  import { locales, switchLocale } from '../lib/locale.js'
  import PasswordStrength from '../lib/PasswordStrength.svelte'
  import Licenses from './Licenses.svelte'
  import { qrSvg } from '../lib/qrcode.js'

  let currentPassword = '', newPassword = '', confirm = ''
  let modalError = '', loading = false
  let passwordSavedAt = null
  let showModal = false
  let noticesOpen = false
  let passwordValid = false

  $: passwordContext = { email: $user?.email }

  $: forced = $user?.mustChangePassword === true
  // Auto-open the password modal when the user is mid-rotation. Modal cancel is hidden in
  // that mode so they can't dismiss without changing.
  $: if (forced && !showModal) showModal = true

  $: tenantDefaultCode = $user?.tenantDefaultLanguage || 'en'
  $: tenantDefaultLabel = locales.find(l => l.code === tenantDefaultCode)?.label || tenantDefaultCode

  function openModal() {
    modalError = ''
    currentPassword = ''; newPassword = ''; confirm = ''
    showModal = true
  }

  function closeModal() {
    if (forced) return
    showModal = false
    modalError = ''
  }

  async function submitPassword() {
    modalError = ''
    if (!passwordValid) { modalError = $t('profile.errorMinLength'); return }
    if (newPassword !== confirm) { modalError = $t('profile.errorMismatch'); return }
    if (newPassword === currentPassword) { modalError = $t('profile.errorSame'); return }
    await submitForm(() => api.changePassword(currentPassword, newPassword), {
      setSaving: v => loading    = v,
      setError:  v => modalError = v,
      onSuccess: async () => {
        // Refresh user info so the must-rotate guard releases.
        try { user.set(await api.me()) } catch { /* keep stale; user can still log out */ }
        passwordSavedAt = new Date()
        currentPassword = ''; newPassword = ''; confirm = ''
        showModal = false
        // Forced flow: bounce out of /profile once rotation completes. Replace so back doesn't
        // return to the forced /profile entry. Consume any pending deep link the user was
        // originally trying to reach, falling back to the dashboard.
        if (forced) {
          const pending = takePendingRoute()
          navigate(pending?.page ?? 'dashboard', pending?.params ?? {}, { replace: true })
        }
      },
    })
  }

  // ── MFA state ────────────────────────────────────────────────────────────
  // mfaModal: null | 'setup' | 'disable' | 'regen'
  let mfaModal = null
  let mfaEnabled = $user?.mfaEnabled ?? false
  let mfaCodesRemaining = 0
  let mfaLoading = false
  let mfaError = ''

  // Setup wizard state
  let mfaOtpauthUri = ''
  let mfaManualKey = ''
  let mfaSetupCode = ''
  let mfaRecoveryCodes = []
  let mfaSetupDone = false

  // Disable / regen state
  let mfaCurrentPassword = ''
  let mfaCode = ''
  let mfaActionDone = false
  let mfaActionMessage = ''

  async function loadMfaStatus() {
    try {
      const s = await api.mfaStatus()
      mfaEnabled = s.enabled
      mfaCodesRemaining = s.recoveryCodesRemaining
    } catch {
      // Non-fatal; status shown from cached $user.mfaEnabled on first paint.
    }
  }

  // Fetch status on mount so the row reflects DB truth, not just the JWT snapshot.
  loadMfaStatus()

  function openMfaSetup() {
    mfaModal = 'setup'
    mfaError = ''
    mfaSetupCode = ''
    mfaRecoveryCodes = []
    mfaSetupDone = false
    mfaOtpauthUri = ''
    mfaManualKey = ''
    beginSetup()
  }

  async function beginSetup() {
    mfaLoading = true
    mfaError = ''
    try {
      const r = await api.mfaSetupBegin()
      mfaOtpauthUri = r.otpauthUri
      mfaManualKey = r.manualKey
    } catch {
      mfaError = $t('profile.mfa.errorFailed')
    } finally {
      mfaLoading = false
    }
  }

  async function submitSetupVerify() {
    mfaLoading = true
    mfaError = ''
    try {
      const r = await api.mfaSetupVerify(mfaSetupCode)
      mfaRecoveryCodes = r.recoveryCodes
      mfaSetupDone = true
      mfaEnabled = true
      mfaCodesRemaining = mfaRecoveryCodes.length
      user.set(await api.me())
    } catch (e) {
      mfaError = e?.status === 422 ? $t('profile.mfa.errorInvalidCode') : $t('profile.mfa.errorFailed')
    } finally {
      mfaLoading = false
    }
  }

  function closeMfaModal() {
    mfaModal = null
    mfaError = ''
    mfaSetupCode = ''
    mfaCurrentPassword = ''
    mfaCode = ''
    mfaActionDone = false
    mfaActionMessage = ''
  }

  function openMfaDisable() {
    mfaModal = 'disable'
    mfaError = ''
    mfaCurrentPassword = ''
    mfaCode = ''
    mfaActionDone = false
  }

  async function submitDisable() {
    mfaLoading = true
    mfaError = ''
    try {
      await api.mfaDisable(mfaCurrentPassword, mfaCode)
      mfaEnabled = false
      mfaCodesRemaining = 0
      mfaActionDone = true
      mfaActionMessage = $t('profile.mfa.disableSuccess')
      user.set(await api.me())
    } catch (e) {
      if (e?.status === 401) {
        mfaError = $t('profile.mfa.errorWrongPassword')
      } else if (e?.status === 400) {
        mfaError = $t('profile.mfa.errorInvalidCode')
      } else {
        mfaError = $t('profile.mfa.errorFailed')
      }
    } finally {
      mfaLoading = false
    }
  }

  function openMfaRegen() {
    mfaModal = 'regen'
    mfaError = ''
    mfaCode = ''
    mfaRecoveryCodes = []
    mfaActionDone = false
  }

  async function submitRegen() {
    mfaLoading = true
    mfaError = ''
    try {
      const r = await api.mfaRegenerateRecoveryCodes(mfaCode)
      mfaRecoveryCodes = r.recoveryCodes
      mfaCodesRemaining = mfaRecoveryCodes.length
      mfaActionDone = true
      mfaActionMessage = $t('profile.mfa.regenSuccess')
    } catch (e) {
      mfaError = e?.status === 400 ? $t('profile.mfa.errorInvalidCode') : $t('profile.mfa.errorFailed')
    } finally {
      mfaLoading = false
    }
  }

  async function copyRecoveryCodes() {
    try {
      await navigator.clipboard.writeText(mfaRecoveryCodes.join('\n'))
    } catch {
      // Silent — clipboard permission may be denied in some browsers.
    }
  }

  $: mfaQrSvg = mfaOtpauthUri ? qrSvg(mfaOtpauthUri, { size: 180 }) : ''
</script>

<div class="page profile-page">
  <div class="page-header">
    <h1 class="page-title">{$t('profile.title')}</h1>
  </div>

  {#if forced}
    <div class="warning-banner">{$t('profile.forcedReason')}</div>
  {/if}

  <div class="card settings-panel">
    <!-- Password row -->
    <div class="settings-row">
      <div class="settings-row-text">
        <div class="settings-row-title">{$t('profile.rows.passwordTitle')}</div>
        <div class="settings-row-help">{$t('profile.rows.passwordHelp')}</div>
        {#if passwordSavedAt}
          <div class="settings-row-success">{$t('profile.success')}</div>
        {/if}
      </div>
      <div class="settings-row-control">
        <button on:click={openModal}>{$t('profile.changePasswordButton')}</button>
      </div>
    </div>

    <!-- MFA row -->
    <div class="settings-row">
      <div class="settings-row-text">
        <div class="settings-row-title">{$t('profile.mfa.rowTitle')}</div>
        <div class="settings-row-help">
          {#if mfaEnabled}
            {$t('profile.mfa.rowHelpOn', { values: { count: mfaCodesRemaining } })}
          {:else}
            {$t('profile.mfa.rowHelpOff')}
          {/if}
        </div>
      </div>
      <div class="settings-row-control">
        {#if mfaEnabled}
          <button on:click={openMfaRegen}>{$t('profile.mfa.regenButton')}</button>
          <button class="danger-outline" on:click={openMfaDisable}>{$t('profile.mfa.disableButton')}</button>
        {:else}
          <button on:click={openMfaSetup}>{$t('profile.mfa.enableButton')}</button>
        {/if}
      </div>
    </div>

    <!-- Theme row -->
    <div class="settings-row">
      <div class="settings-row-text">
        <div class="settings-row-title">{$t('profile.rows.themeTitle')}</div>
        <div class="settings-row-help">{$t('profile.rows.themeHelp')}</div>
      </div>
      <div class="settings-row-control">
        <ThemeToggle />
      </div>
    </div>

    <!-- Language row -->
    <div class="settings-row">
      <div class="settings-row-text">
        <div class="settings-row-title">{$t('profile.rows.languageTitle')}</div>
        <div class="settings-row-help">{$t('profile.rows.languageHelpTenantDefault', { values: { language: tenantDefaultLabel } })}</div>
      </div>
      <div class="settings-row-control">
        <select value={$locale} on:change={e => switchLocale(e.currentTarget.value)} aria-label={$t('profile.rows.languageTitle')}>
          {#each locales as l (l.code)}
            <option value={l.code}>{l.label}</option>
          {/each}
        </select>
      </div>
    </div>

    <!-- About row -->
    <div class="settings-row">
      <div class="settings-row-text">
        <div class="settings-row-title">{$t('profile.rows.aboutTitle')}</div>
        <div class="settings-row-help">{$t('profile.rows.aboutHelp')}</div>
      </div>
      <div class="settings-row-control">
        <button on:click={() => (noticesOpen = true)}>{$t('profile.openSourceNotices')}</button>
      </div>
    </div>
  </div>
</div>

{#if noticesOpen}
  <Licenses on:close={() => (noticesOpen = false)} />
{/if}

{#if showModal}
  <div class="modal-backdrop">
    <div class="modal">
      <h3>{forced ? $t('profile.forcedTitle') : $t('profile.changePasswordModalTitle')}</h3>
      {#if modalError}<div class="error-msg">{modalError}</div>{/if}
      <form on:submit|preventDefault={submitPassword}>
        <div class="form-row">
          <label>{$t('profile.currentPassword')}</label>
          <input type="password" bind:value={currentPassword} required autocomplete="current-password" />
        </div>
        <div class="form-row">
          <label>{$t('profile.newPassword')} <span class="text-muted t-xs">{$t('profile.passwordHint')}</span></label>
          <input type="password" bind:value={newPassword} required minlength="12" autocomplete="new-password" />
          <PasswordStrength value={newPassword} context={passwordContext} bind:valid={passwordValid} />
        </div>
        <div class="form-row">
          <label>{$t('profile.confirmPassword')}</label>
          <input type="password" bind:value={confirm} required autocomplete="new-password" />
        </div>
        <div class="modal-actions">
          {#if !forced}
            <button type="button" on:click={closeModal}>{$t('common.actions.cancel')}</button>
          {/if}
          <button type="submit" class="primary" disabled={loading || !passwordValid}>
            {loading ? $t('common.actions.saving') : $t('profile.submit')}
          </button>
        </div>
      </form>
    </div>
  </div>
{/if}

<!-- MFA setup modal -->
{#if mfaModal === 'setup'}
  <div class="modal-backdrop">
    <div class="modal mfa-modal">
      <h3>{$t('profile.mfa.setupTitle')}</h3>
      {#if mfaError}<div class="error-msg">{mfaError}</div>{/if}

      {#if mfaSetupDone}
        <!-- Recovery codes display -->
        <p class="mfa-success">{$t('profile.mfa.setupSuccess')}</p>
        <div class="mfa-recovery-header">
          <span class="settings-row-title">{$t('profile.mfa.recoveryCodesTitle')}</span>
          <button type="button" class="btn-link" on:click={copyRecoveryCodes}>{$t('common.actions.copy')}</button>
        </div>
        <p class="mfa-hint">{$t('profile.mfa.recoveryCodesHelp')}</p>
        <ul class="recovery-codes">
          {#each mfaRecoveryCodes as code (code)}
            <li>{code}</li>
          {/each}
        </ul>
        <div class="modal-actions">
          <button type="button" class="primary" on:click={closeMfaModal}>{$t('common.actions.dismiss')}</button>
        </div>
      {:else}
        {#if mfaLoading && !mfaOtpauthUri}
          <p class="mfa-hint">{$t('common.loading')}</p>
        {:else}
          <p class="mfa-hint">{$t('profile.mfa.setupStep1')}</p>
          {#if mfaQrSvg}
            <div class="mfa-qr">
              <!-- eslint-disable-next-line svelte/no-at-html-tags -->
              {@html mfaQrSvg}
            </div>
          {/if}
          <div class="mfa-manual-key">
            <span class="settings-row-help">{$t('profile.mfa.manualKey')}:</span>
            <code>{mfaManualKey}</code>
          </div>
          <p class="mfa-hint">{$t('profile.mfa.setupStep2')}</p>
          <form on:submit|preventDefault={submitSetupVerify}>
            <div class="form-row">
              <label>{$t('profile.mfa.setupCode')}</label>
              <input
                type="text"
                inputmode="numeric"
                autocomplete="one-time-code"
                maxlength="6"
                bind:value={mfaSetupCode}
                required
              />
            </div>
            <div class="modal-actions">
              <button type="button" on:click={closeMfaModal}>{$t('common.actions.cancel')}</button>
              <button type="submit" class="primary" disabled={mfaLoading}>
                {mfaLoading ? $t('common.actions.saving') : $t('profile.mfa.setupSubmit')}
              </button>
            </div>
          </form>
        {/if}
      {/if}
    </div>
  </div>
{/if}

<!-- MFA disable modal -->
{#if mfaModal === 'disable'}
  <div class="modal-backdrop">
    <div class="modal">
      <h3>{$t('profile.mfa.disableTitle')}</h3>
      {#if mfaError}<div class="error-msg">{mfaError}</div>{/if}

      {#if mfaActionDone}
        <p class="mfa-success">{mfaActionMessage}</p>
        <div class="modal-actions">
          <button type="button" class="primary" on:click={closeMfaModal}>{$t('common.actions.dismiss')}</button>
        </div>
      {:else}
        <p class="mfa-hint">{$t('profile.mfa.disableHelp')}</p>
        <form on:submit|preventDefault={submitDisable}>
          <div class="form-row">
            <label>{$t('profile.mfa.currentPassword')}</label>
            <input type="password" bind:value={mfaCurrentPassword} required autocomplete="current-password" />
          </div>
          <div class="form-row">
            <label>{$t('profile.mfa.code')}</label>
            <input type="text" inputmode="numeric" autocomplete="one-time-code" bind:value={mfaCode} required />
          </div>
          <div class="modal-actions">
            <button type="button" on:click={closeMfaModal}>{$t('common.actions.cancel')}</button>
            <button type="submit" class="danger" disabled={mfaLoading}>
              {mfaLoading ? $t('common.actions.saving') : $t('profile.mfa.disableSubmit')}
            </button>
          </div>
        </form>
      {/if}
    </div>
  </div>
{/if}

<!-- MFA regenerate recovery codes modal -->
{#if mfaModal === 'regen'}
  <div class="modal-backdrop">
    <div class="modal mfa-modal">
      <h3>{$t('profile.mfa.regenTitle')}</h3>
      {#if mfaError}<div class="error-msg">{mfaError}</div>{/if}

      {#if mfaActionDone}
        <p class="mfa-success">{mfaActionMessage}</p>
        <ul class="recovery-codes">
          {#each mfaRecoveryCodes as code (code)}
            <li>{code}</li>
          {/each}
        </ul>
        <div class="modal-actions">
          <button type="button" on:click={copyRecoveryCodes}>{$t('common.actions.copy')}</button>
          <button type="button" class="primary" on:click={closeMfaModal}>{$t('common.actions.dismiss')}</button>
        </div>
      {:else}
        <p class="mfa-hint">{$t('profile.mfa.regenHelp')}</p>
        <form on:submit|preventDefault={submitRegen}>
          <div class="form-row">
            <label>{$t('profile.mfa.code')}</label>
            <input type="text" inputmode="numeric" autocomplete="one-time-code" bind:value={mfaCode} required />
          </div>
          <div class="modal-actions">
            <button type="button" on:click={closeMfaModal}>{$t('common.actions.cancel')}</button>
            <button type="submit" class="primary" disabled={mfaLoading}>
              {mfaLoading ? $t('common.actions.saving') : $t('profile.mfa.regenSubmit')}
            </button>
          </div>
        </form>
      {/if}
    </div>
  </div>
{/if}

<style>
  .profile-page { max-width: 720px; }
  .warning-banner {
    background: var(--accent-soft);
    border: 1px solid var(--accent);
    color: var(--text);
    border-radius: var(--radius);
    padding: 12px;
    margin-bottom: 16px;
    font-size: 13px;
  }

  /* Settings-row pattern: scales to N rows. Title + help on the left, control on the right. */
  .settings-panel { padding: 0; }
  .settings-row {
    display: flex;
    align-items: center;
    gap: 24px;
    padding: 16px;
    border-bottom: 1px solid var(--border);
  }
  .settings-row:last-child { border-bottom: none; }
  .settings-row-text { flex: 1; min-width: 0; }
  .settings-row-title { font-size: 14px; font-weight: 600; color: var(--text); }
  .settings-row-help { font-size: 12px; color: var(--text2); margin-top: 2px; }
  .settings-row-success { font-size: 12px; color: var(--success); margin-top: 4px; }
  .settings-row-control { flex: 0 0 auto; display: flex; align-items: center; gap: 8px; }
  .settings-row-control select { width: auto; font-size: 13px; }

  /* MFA modal extras */
  .mfa-modal { max-width: 480px; }
  .mfa-qr { display: flex; justify-content: center; margin: 12px 0; }
  .mfa-manual-key { font-size: 12px; color: var(--text2); margin-bottom: 12px; word-break: break-all; }
  .mfa-manual-key code { font-family: var(--font-mono, monospace); font-size: 13px; color: var(--text); }
  .mfa-hint { font-size: 13px; color: var(--text2); margin-bottom: 8px; }
  .mfa-success { font-size: 13px; color: var(--success); margin-bottom: 12px; }
  .mfa-recovery-header { display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 4px; }
  .recovery-codes {
    list-style: none;
    padding: 0;
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 4px;
    margin-bottom: 16px;
  }
  .recovery-codes li {
    font-family: var(--font-mono, monospace);
    font-size: 13px;
    background: var(--surface2);
    padding: 4px 8px;
    border-radius: 4px;
  }
  .btn-link {
    background: none;
    border: none;
    color: var(--accent);
    cursor: pointer;
    font-size: 12px;
    padding: 0;
    min-height: 0;
  }
  .btn-link:hover { text-decoration: underline; }
  button.danger-outline {
    background: transparent;
    border: 1px solid var(--danger);
    color: var(--danger);
  }
  button.danger-outline:hover { background: color-mix(in srgb, var(--danger) 8%, transparent); }
  button.danger {
    background: var(--danger);
    color: var(--on-accent);
    border: none;
  }
  button.danger:hover { filter: brightness(0.9); }
</style>
