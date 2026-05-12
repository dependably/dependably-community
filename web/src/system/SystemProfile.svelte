<script>
  import { onMount } from 'svelte'
  import { t, locale } from 'svelte-i18n'
  import { systemApi } from '../lib/api.js'
  import { user, theme, navigate, takePendingRoute } from '../lib/store.js'
  import { locales, switchLocale } from '../lib/locale.js'

  let me = null, loading = true, loadError = ''
  let currentPassword = '', newPassword = '', confirm = ''
  let modalError = '', saving = false
  let passwordSavedAt = null
  let showModal = false

  $: forced = me?.mustChangePassword === true
  $: if (forced && !showModal) showModal = true

  // System area has no tenant default — fall back to 'en'.
  const systemFallbackLabel = locales.find(l => l.code === 'en')?.label || 'English'

  onMount(async () => {
    try { me = await systemApi.me() }
    catch (e) { loadError = e.message }
    finally { loading = false }
  })

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
    if (newPassword.length < 12) { modalError = $t('profile.errorMinLength'); return }
    if (newPassword !== confirm) { modalError = $t('profile.errorMismatch'); return }
    if (newPassword === currentPassword) { modalError = $t('profile.errorSame'); return }
    saving = true
    const wasForced = forced
    try {
      await systemApi.changePassword(currentPassword, newPassword)
      const refreshed = await systemApi.me()
      me = refreshed
      user.set({ ...$user, mustChangePassword: false })
      passwordSavedAt = new Date()
      currentPassword = ''; newPassword = ''; confirm = ''
      showModal = false
      if (wasForced) {
        // Forced flow: bounce out of /profile once rotation completes. Consume any pending
        // deep link, falling back to the tenants list.
        const pending = takePendingRoute()
        navigate(pending?.page ?? 'system-tenants', pending?.params ?? {}, { replace: true })
      }
    } catch (e) {
      modalError = e.message
    } finally {
      saving = false
    }
  }
</script>

<div class="page profile-page">
  <div class="page-header">
    <h1 class="page-title">{$t('profile.title')}</h1>
  </div>

  {#if loading}
    <span class="spinner"></span>
  {:else if loadError}
    <div class="page-error">{loadError}</div>
  {:else}
    {#if forced}
      <div class="warning-banner">{$t('profile.forcedReason')}</div>
    {/if}

    <div class="card settings-panel">
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

      <div class="settings-row">
        <div class="settings-row-text">
          <div class="settings-row-title">{$t('profile.rows.languageTitle')}</div>
          <div class="settings-row-help">{$t('profile.rows.languageHelpSystemFallback', { values: { language: systemFallbackLabel } })}</div>
        </div>
        <div class="settings-row-control">
          <select value={$locale} on:change={e => switchLocale(e.currentTarget.value)} aria-label={$t('profile.rows.languageTitle')}>
            {#each locales as l (l.code)}
              <option value={l.code}>{l.label}</option>
            {/each}
          </select>
        </div>
      </div>
    </div>
  {/if}
</div>

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
        </div>
        <div class="form-row">
          <label>{$t('profile.confirmPassword')}</label>
          <input type="password" bind:value={confirm} required autocomplete="new-password" />
        </div>
        <div class="modal-actions">
          {#if !forced}
            <button type="button" on:click={closeModal}>{$t('common.actions.cancel')}</button>
          {/if}
          <button type="submit" class="primary" disabled={saving}>
            {saving ? $t('common.actions.saving') : $t('profile.submit')}
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
