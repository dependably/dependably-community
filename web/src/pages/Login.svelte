<script>
  import { onMount } from 'svelte'
  import { t } from 'svelte-i18n'
  import { api } from '../lib/api.js'
  import { user, navigate, takePendingRoute, sessionExpired } from '../lib/store.js'
  import { loadActiveBanners } from '../lib/banners.js'
  import { armSessionWatch } from '../lib/session.js'

  let email = '', password = '', error = '', loading = false
  let lockoutSeconds = 0
  let countdown

  // Two-step state: 'credentials' shows the normal login form; 'totp' shows the MFA step.
  let step = 'credentials'
  let totpCode = ''
  let rememberDevice = false
  let useRecovery = false

  // Auth methods enabled for this tenant. Defaults to forms-only so the form renders even if
  // the discovery call fails for any reason.
  let methods = { forms: true, saml: false, samlButtonLabel: null }

  onMount(async () => {
    try {
      const m = await api.getAuthMethods()
      methods = { forms: !!m.forms, saml: !!m.saml, samlButtonLabel: m.samlButtonLabel }
    } catch { /* keep defaults — login page must always render */ }
  })

  function resetLockout() {
    clearInterval(countdown)
    lockoutSeconds = 0
  }

  function startCountdown() {
    clearInterval(countdown)
    countdown = setInterval(() => {
      lockoutSeconds -= 1
      if (lockoutSeconds <= 0) {
        clearInterval(countdown)
        error = ''
      } else {
        error = $t('auth.login.tooManyAttempts', { values: { seconds: lockoutSeconds } })
      }
    }, 1000)
  }

  function handleRateLimit(e) {
    lockoutSeconds = parseInt(e.retryAfter, 10)
    startCountdown()
    error = $t('auth.login.tooManyAttempts', { values: { seconds: lockoutSeconds } })
  }

  function postLoginNavigate(me) {
    // currentOrg is derived from bootstrapInfo (host-implicit); no list call needed.
    // mustChangePassword users go to profile first (rotation required); the pending route is
    // consumed by Profile.svelte once rotation and any required MFA setup complete.
    // mfaEnrollmentRequired users also go straight to profile so the auto-open reactive fires
    // the MFA setup modal immediately, without a visible dashboard→profile bounce.
    if (me.mustChangePassword || me.mfaEnrollmentRequired) {
      navigate('profile', {}, { replace: true })
    } else {
      const pending = takePendingRoute()
      navigate(pending?.page ?? 'dashboard', pending?.params ?? {}, { replace: true })
    }
  }

  async function submit() {
    error = ''
    loading = true
    try {
      const r = await api.login(email, password)
      if (r && r.mfaRequired) {
        // MFA enrolled — swap to the TOTP step without fetching the session yet.
        resetLockout()
        step = 'totp'
        return
      }
      const me = await api.me()
      user.set(me)
      sessionExpired.set(false)
      armSessionWatch(me.sessionExpiresAt, api.me)
      loadActiveBanners()
      postLoginNavigate(me)
    } catch (e) {
      if (e.status === 429 && e.retryAfter) {
        handleRateLimit(e)
      } else {
        error = e.message || $t('auth.login.failed')
      }
    } finally {
      loading = false
    }
  }

  async function submitTotp() {
    error = ''
    loading = true
    try {
      await api.loginTotp(totpCode, rememberDevice)
      const me = await api.me()
      user.set(me)
      sessionExpired.set(false)
      armSessionWatch(me.sessionExpiresAt, api.me)
      loadActiveBanners()
      postLoginNavigate(me)
    } catch (e) {
      if (e.status === 429 && e.retryAfter) {
        handleRateLimit(e)
      } else if (e.status === 401) {
        error = $t('auth.login.totp.invalidCode')
      } else {
        error = e.message || $t('auth.login.failed')
      }
    } finally {
      loading = false
    }
  }

  function backToCredentials() {
    step = 'credentials'
    totpCode = ''
    rememberDevice = false
    useRecovery = false
    error = ''
    resetLockout()
  }
</script>

<div class="login-wrap">
  <div class="login-card card">
    <div class="brand login-brand">
      <svg viewBox="0 0 64 64" width="32" height="32" fill="none" aria-hidden="true">
        <path d="M32 32L14 14M32 32L50 14M32 32L32 54" stroke="currentColor" stroke-width="4" stroke-linecap="round"/>
        <circle cx="14" cy="14" r="5" fill="currentColor"/>
        <circle cx="50" cy="14" r="5" fill="currentColor"/>
        <circle cx="32" cy="54" r="5" fill="currentColor"/>
        <circle cx="32" cy="32" r="9" fill="var(--accent)"/>
      </svg>
    </div>

    {#if step === 'credentials'}
      <h1>{$t('auth.login.title')}</h1>
      <p class="login-subtitle">{$t('auth.login.subtitle')}</p>

      {#if $sessionExpired}
        <div class="session-expired-notice" role="alert">
          <svg width="14" height="14" aria-hidden="true"><use href="/icons.svg#icon-info"/></svg>
          {$t('auth.login.sessionExpired')}
        </div>
      {/if}

      {#if error}
        <div class="error-msg">{error}</div>
      {/if}

      {#if methods.forms}
        <form on:submit|preventDefault={submit}>
          <div class="form-row">
            <label for="email">{$t('auth.login.email')}</label>
            <input id="email" type="email" bind:value={email} autocomplete="username" required />
          </div>
          <div class="form-row">
            <label for="password">{$t('auth.login.password')}</label>
            <input id="password" type="password" bind:value={password} autocomplete="current-password" required />
          </div>
          <button type="submit" class="primary login-action" disabled={loading || lockoutSeconds > 0}>
            {loading ? $t('auth.login.submitting') : $t('auth.login.submit')}
          </button>
        </form>
      {/if}

      {#if methods.saml}
        {#if methods.forms}
          <div class="login-divider"><span>{$t('auth.login.or')}</span></div>
        {/if}
        <!-- Top-level navigation, not fetch — SAML init is an HTTP redirect to the IdP. -->
        <a class="primary login-action sso-action" href="/saml/login">
          {methods.samlButtonLabel || $t('auth.login.signInWithSso')}
        </a>
      {/if}

    {:else}
      <h1>{$t('auth.login.totp.title')}</h1>
      <p class="login-subtitle">
        {useRecovery ? $t('auth.login.totp.recoveryHelp') : $t('auth.login.totp.help')}
      </p>

      {#if error}
        <div class="error-msg">{error}</div>
      {/if}

      <form on:submit|preventDefault={submitTotp}>
        <div class="form-row">
          <label for="totp-code">
            {useRecovery ? $t('auth.login.totp.recoveryLabel') : $t('auth.login.totp.codeLabel')}
          </label>
          {#if useRecovery}
            <input
              id="totp-code"
              type="text"
              bind:value={totpCode}
              autocomplete="one-time-code"
              spellcheck="false"
              required
            />
          {:else}
            <input
              id="totp-code"
              type="text"
              inputmode="numeric"
              autocomplete="one-time-code"
              maxlength="6"
              bind:value={totpCode}
              required
            />
          {/if}
        </div>

        <div class="form-row checkbox-row">
          <label class="checkbox-label">
            <input type="checkbox" bind:checked={rememberDevice} />
            {$t('auth.login.totp.rememberDevice')}
          </label>
        </div>

        <button type="submit" class="primary login-action" disabled={loading || lockoutSeconds > 0}>
          {loading ? $t('auth.login.totp.submitting') : $t('auth.login.totp.submit')}
        </button>
      </form>

      <div class="totp-links">
        <button type="button" class="link-btn" on:click={() => { useRecovery = !useRecovery; totpCode = ''; error = '' }}>
          {useRecovery ? $t('auth.login.totp.useTotp') : $t('auth.login.totp.useRecovery')}
        </button>
        <button type="button" class="link-btn" on:click={backToCredentials}>
          <svg width="12" height="12" aria-hidden="true"><use href="/icons.svg#icon-chevron-down" class="chev-left"/></svg>
          {$t('auth.login.totp.back')}
        </button>
      </div>
    {/if}
  </div>
</div>

<style>
  .session-expired-notice {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 8px 12px;
    border-radius: var(--radius);
    background: var(--info-bg, var(--bg3));
    border: 1px solid var(--info-border, var(--border));
    color: var(--info-text, var(--text2));
    font-size: 13px;
    margin-bottom: 4px;
  }

  .login-wrap {
    display: flex;
    align-items: center;
    justify-content: center;
    min-height: 100vh;
    padding: 24px;
  }
  .login-card {
    width: 100%;
    max-width: 360px;
  }
  h1 { margin: 0 0 4px; font-size: 24px; }
  .login-brand { display: flex; justify-content: center; margin-bottom: 18px; }
  .login-subtitle { color: var(--text2); margin-bottom: 20px; }
  .login-action { width: 100%; }
  .sso-action {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    text-decoration: none;
    text-align: center;
    box-sizing: border-box;
  }
  .login-divider {
    display: flex;
    align-items: center;
    text-align: center;
    color: var(--text2);
    font-size: 12px;
    margin: 16px 0;
    gap: 8px;
  }
  .login-divider::before, .login-divider::after {
    content: '';
    flex: 1;
    border-top: 1px solid var(--border);
  }
  .checkbox-row {
    margin-bottom: 4px;
  }
  .checkbox-label {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 14px;
    cursor: pointer;
  }
  .checkbox-label input[type="checkbox"] {
    margin: 0;
    min-height: 0;
    width: auto;
    flex-shrink: 0;
  }
  .totp-links {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 8px;
    margin-top: 16px;
  }
  .link-btn {
    background: none;
    border: none;
    padding: 0;
    color: var(--accent);
    font-size: 13px;
    cursor: pointer;
    display: inline-flex;
    align-items: center;
    gap: 4px;
    min-height: 0;
  }
  .link-btn:hover {
    text-decoration: underline;
  }
  .chev-left {
    transform: rotate(90deg);
    display: inline-block;
  }
</style>
