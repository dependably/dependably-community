<script>
  import { t } from 'svelte-i18n'
  import { api, systemApi } from '../lib/api.js'
  import { user, navigate, takePendingRoute } from '../lib/store.js'

  let email = '', password = '', error = '', loading = false

  async function submit() {
    error = ''
    loading = true
    try {
      await api.login(email, password)
      const me = await systemApi.me()
      user.set(me)
      // mustChangePassword users go to system-profile; the pending route (if any) is consumed
      // by SystemProfile.svelte once rotation completes. Other users consume it now.
      if (me.mustChangePassword) {
        navigate('system-profile', {}, { replace: true })
      } else {
        const pending = takePendingRoute()
        navigate(pending?.page ?? 'system-dashboard', pending?.params ?? {}, { replace: true })
      }
    } catch (e) {
      error = e.message || $t('system.login.failed')
    } finally {
      loading = false
    }
  }
</script>

<div class="login-page">
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
  input {
    padding: 6px 8px;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    background: var(--bg);
    color: var(--text);
  }
</style>
