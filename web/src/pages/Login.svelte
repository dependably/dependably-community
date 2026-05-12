<script>
  import { onMount } from 'svelte'
  import { t } from 'svelte-i18n'
  import { api } from '../lib/api.js'
  import { user, navigate, takePendingRoute } from '../lib/store.js'

  let email = '', password = '', error = '', loading = false
  let lockoutSeconds = 0
  let countdown

  // Auth methods enabled for this tenant. Defaults to forms-only so the form renders even if
  // the discovery call fails for any reason.
  let methods = { forms: true, saml: false, samlButtonLabel: null }

  onMount(async () => {
    try {
      const m = await api.getAuthMethods()
      methods = { forms: !!m.forms, saml: !!m.saml, samlButtonLabel: m.samlButtonLabel }
    } catch { /* keep defaults — login page must always render */ }
  })

  async function submit() {
    error = ''
    loading = true
    try {
      await api.login(email, password)
      const me = await api.me()
      user.set(me)
      // currentOrg is derived from bootstrapInfo (host-implicit); no list call needed.
      // mustChangePassword users go to profile; the pending route (if any) is consumed by
      // Profile.svelte once rotation completes. Other users consume it now.
      if (me.mustChangePassword) {
        navigate('profile', {}, { replace: true })
      } else {
        const pending = takePendingRoute()
        navigate(pending?.page ?? 'dashboard', pending?.params ?? {}, { replace: true })
      }
    } catch (e) {
      if (e.status === 429 && e.retryAfter) {
        lockoutSeconds = parseInt(e.retryAfter, 10)
        startCountdown()
        error = $t('auth.login.tooManyAttempts', { values: { seconds: lockoutSeconds } })
      } else {
        error = e.message || $t('auth.login.failed')
      }
    } finally {
      loading = false
    }
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
    <h1>{$t('auth.login.title')}</h1>
    <p class="login-subtitle">{$t('auth.login.subtitle')}</p>

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
  </div>
</div>

<style>
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
</style>
