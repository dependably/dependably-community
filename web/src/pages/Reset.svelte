<script>
  import { t } from 'svelte-i18n'
  import { navigate } from '../lib/store.js'
  import { api } from '../lib/api.js'
  import PasswordStrength from '../lib/PasswordStrength.svelte'

  // Extract token from URL search params — same pattern as Join.svelte.
  const token = new URLSearchParams(window.location.search).get('token') || ''
  let password = '', confirm = '', error = '', done = false, loading = false, expired = false
  let passwordValid = false

  async function submit() {
    if (!passwordValid) { error = $t('auth.reset.errorMinLength'); return }
    if (password !== confirm) { error = $t('auth.reset.errorMismatch'); return }
    error = ''
    expired = false
    loading = true
    try {
      await api.resetPassword(token, password)
      done = true
    } catch (e) {
      // 410 Gone: the link is invalid, expired, or already used — no auto-login is possible
      // and the only recovery is requesting a fresh link.
      if (e.status === 410) {
        expired = true
      } else {
        error = e.message || $t('auth.reset.errorFailed')
      }
    } finally {
      loading = false
    }
  }
</script>

<div class="login-wrap">
  <div class="card reset-card">
    <h2>{$t('auth.reset.title')}</h2>
    {#if done}
      <p>{$t('auth.reset.success')} <button class="primary" on:click={() => navigate('login')}>{$t('auth.reset.signIn')}</button></p>
    {:else if expired}
      <div class="error-msg">{$t('auth.reset.errorExpired')}</div>
      <button class="primary submit-wide" on:click={() => navigate('login')}>{$t('auth.reset.requestNew')}</button>
    {:else}
      {#if error}<div class="error-msg">{error}</div>{/if}
      <form on:submit|preventDefault={submit}>
        <div class="form-row">
          <label>{$t('auth.reset.newPassword')} <span class="text-muted t-xs">{$t('auth.reset.passwordHint')}</span></label>
          <input type="password" bind:value={password} required minlength="12" autocomplete="new-password" />
          <PasswordStrength value={password} bind:valid={passwordValid} />
        </div>
        <div class="form-row">
          <label>{$t('auth.reset.confirmPassword')}</label>
          <input type="password" bind:value={confirm} required autocomplete="new-password" />
        </div>
        <button type="submit" class="primary submit-wide" disabled={loading || !passwordValid}>
          {loading ? $t('auth.reset.submitting') : $t('auth.reset.submit')}
        </button>
      </form>
    {/if}
  </div>
</div>

<style>
  .login-wrap { display:flex; align-items:center; justify-content:center; min-height:100vh; padding:24px; }
  .reset-card { max-width: 400px; width: 100%; }
  .submit-wide { width: 100%; }
</style>
