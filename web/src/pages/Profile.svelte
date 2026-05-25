<script>
  import { t, locale } from 'svelte-i18n'
  import { user, theme, navigate, takePendingRoute } from '../lib/store.js'
  import { api } from '../lib/api.js'
  import { submitForm } from '../lib/form.js'
  import { locales, switchLocale } from '../lib/locale.js'
  import PasswordStrength from '../lib/PasswordStrength.svelte'
  import Licenses from './Licenses.svelte'

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

    <!-- Theme row -->
    <div class="settings-row">
      <div class="settings-row-text">
        <div class="settings-row-title">{$t('profile.rows.themeTitle')}</div>
        <div class="settings-row-help">{$t('profile.rows.themeHelp')}</div>
      </div>
      <div class="settings-row-control">
        <div class="segmented" role="radiogroup" aria-label={$t('profile.rows.themeTitle')}>
          <button class:active={$theme === 'light'} role="radio" aria-checked={$theme === 'light'}
                  on:click={() => theme.set('light')}>{$t('profile.theme.light')}</button>
          <button class:active={$theme === 'dark'} role="radio" aria-checked={$theme === 'dark'}
                  on:click={() => theme.set('dark')}>{$t('profile.theme.dark')}</button>
        </div>
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

  /* Compact segmented control for the theme picker. */
  .segmented { display: inline-flex; border: 1px solid var(--border); border-radius: var(--radius); overflow: hidden; }
  .segmented button {
    background: var(--bg);
    color: var(--text2);
    border: none;
    padding: 4px 12px;
    font-size: 13px;
    border-radius: 0;
    cursor: pointer;
  }
  .segmented button + button { border-left: 1px solid var(--border); }
  .segmented button.active { background: var(--accent); color: var(--on-accent); }
</style>
