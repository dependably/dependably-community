<script>
  import { t } from 'svelte-i18n'
  import { navigate, user } from '../lib/store.js'
  import { api } from '../lib/api.js'
  import PasswordStrength from '../lib/PasswordStrength.svelte'

  // Extract token from URL search params
  const token = new URLSearchParams(window.location.search).get('token') || ''
  let password = '', confirm = '', error = '', done = false, loading = false
  let passwordValid = false

  async function submit() {
    if (!passwordValid) { error = $t('auth.join.errorMinLength'); return }
    if (password !== confirm) { error = $t('auth.join.errorMismatch'); return }
    error = ''
    loading = true
    try {
      const res = await fetch('/api/v1/invites/accept', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token, password }),
        credentials: 'include',
      })
      if (!res.ok) {
        const d = await res.json().catch(() => ({}))
        throw new Error(d.detail || $t('auth.join.errorFailed'))
      }
      done = true
      try {
        const me = await api.me()
        user.set(me)
        // currentOrg is derived from bootstrapInfo (host-implicit); no list call needed.
        // Replace so back doesn't return to /join?token=...
        navigate('dashboard', {}, { replace: true })
      } catch {
        // Auto-login cookie not present — fall through to manual sign-in.
      }
    } catch (e) {
      error = e.message
    } finally {
      loading = false
    }
  }
</script>

<div class="login-wrap">
  <div class="card join-card">
    <h2>{$t('auth.join.title')}</h2>
    {#if done}
      <p>{$t('auth.join.success')} <button class="primary" on:click={() => navigate('login')}>{$t('auth.join.signIn')}</button></p>
    {:else}
      {#if error}<div class="error-msg">{error}</div>{/if}
      <form on:submit|preventDefault={submit}>
        <div class="form-row">
          <label>{$t('auth.join.newPassword')} <span class="text-muted t-xs">{$t('auth.join.passwordHint')}</span></label>
          <input type="password" bind:value={password} required minlength="12" autocomplete="new-password" />
          <PasswordStrength value={password} bind:valid={passwordValid} />
        </div>
        <div class="form-row">
          <label>{$t('auth.join.confirmPassword')}</label>
          <input type="password" bind:value={confirm} required autocomplete="new-password" />
        </div>
        <button type="submit" class="primary submit-wide" disabled={loading || !passwordValid}>
          {loading ? $t('auth.join.submitting') : $t('auth.join.submit')}
        </button>
      </form>
    {/if}
  </div>
</div>

<style>
  .login-wrap { display:flex; align-items:center; justify-content:center; min-height:100vh; padding:24px; }
  .join-card { max-width: 400px; width: 100%; }
  .submit-wide { width: 100%; }
</style>
