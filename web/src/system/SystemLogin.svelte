<script>
  import { t } from 'svelte-i18n'
  import { api, systemApi } from '../lib/api.js'
  import { user, navigate, takePendingRoute } from '../lib/store.js'

  let email = '', password = '', error = '', loading = false

  // Two-step state: 'credentials' shows the normal login form; 'totp' shows the MFA step.
  let step = 'credentials'
  let totpCode = ''
  let rememberDevice = false
  let useRecovery = false

  function postLoginNavigate(me) {
    // mustChangePassword users go to system-profile; the pending route (if any) is consumed
    // by SystemProfile.svelte once rotation completes. Other users consume it now.
    if (me.mustChangePassword) {
      navigate('system-profile', {}, { replace: true })
    } else {
      const pending = takePendingRoute()
      navigate(pending?.page ?? 'system-dashboard', pending?.params ?? {}, { replace: true })
    }
  }

  async function submit() {
    error = ''
    loading = true
    try {
      const r = await api.login(email, password)
      if (r && r.mfaRequired) {
        // MFA enrolled — swap to the TOTP step without fetching the session yet.
        step = 'totp'
        return
      }
      const me = await systemApi.me()
      user.set(me)
      postLoginNavigate(me)
    } catch (e) {
      error = e.message || $t('system.login.failed')
    } finally {
      loading = false
    }
  }

  async function submitTotp() {
    error = ''
    loading = true
    try {
      await api.loginTotp(totpCode, rememberDevice)
      const me = await systemApi.me()
      user.set(me)
      postLoginNavigate(me)
    } catch (e) {
      if (e.status === 401) {
        error = $t('auth.login.totp.invalidCode')
      } else {
        error = e.message || $t('system.login.failed')
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
  }
</script>

<div class="login-page">
  {#if step === 'credentials'}
    <form on:submit|preventDefault={submit}>
      <h1>{$t('system.login.title')}</h1>

      <label>{$t('system.login.email')}</label>
      <input type="email" bind:value={email} required autocomplete="username" />

      <label>{$t('system.login.password')}</label>
      <input type="password" bind:value={password} required autocomplete="current-password" />

      {#if error}<div class="error-msg">{error}</div>{/if}

      <button type="submit" class="primary" disabled={loading}>
        {loading ? $t('system.login.submitting') : $t('system.login.submit')}
      </button>
    </form>
  {:else}
    <form on:submit|preventDefault={submitTotp}>
      <h1>{$t('auth.login.totp.title')}</h1>
      <p class="totp-help">
        {useRecovery ? $t('auth.login.totp.recoveryHelp') : $t('auth.login.totp.help')}
      </p>

      {#if error}<div class="error-msg">{error}</div>{/if}

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

      <label class="checkbox-label">
        <input type="checkbox" bind:checked={rememberDevice} />
        {$t('auth.login.totp.rememberDevice')}
      </label>

      <button type="submit" class="primary" disabled={loading}>
        {loading ? $t('auth.login.totp.submitting') : $t('auth.login.totp.submit')}
      </button>

      <div class="totp-links">
        <button type="button" class="link-btn" on:click={() => { useRecovery = !useRecovery; totpCode = ''; error = '' }}>
          {useRecovery ? $t('auth.login.totp.useTotp') : $t('auth.login.totp.useRecovery')}
        </button>
        <button type="button" class="link-btn" on:click={backToCredentials}>
          <svg width="12" height="12" aria-hidden="true"><use href="/icons.svg#icon-chevron-down" class="chev-left"/></svg>
          {$t('auth.login.totp.back')}
        </button>
      </div>
    </form>
  {/if}
</div>

<style>
  .login-page {
    display: flex;
    align-items: center;
    justify-content: center;
    min-height: 100vh;
    background: var(--bg);
  }
  form {
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 24px;
    width: 320px;
    display: flex;
    flex-direction: column;
    gap: 12px;
  }
  h1 { margin: 0 0 8px; font-size: 22px; }
  label { font-size: 13px; color: var(--text2); }
  input[type="email"],
  input[type="password"],
  input[type="text"] {
    padding: 6px 8px;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    background: var(--bg);
    color: var(--text);
  }
  .totp-help { font-size: 13px; color: var(--text2); margin: 0; }
  .checkbox-label {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 14px;
    cursor: pointer;
    color: var(--text);
  }
  .checkbox-label input[type="checkbox"] {
    margin: 0;
    min-height: 0;
  }
  .totp-links {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 8px;
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
