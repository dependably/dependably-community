<script>
  import { onMount } from 'svelte'
  import { t, locale } from 'svelte-i18n'
  import { get } from 'svelte/store'
  import { api, systemApi } from '../lib/api.js'
  import { user, route, navigate, pendingRoute } from '../lib/store.js'
  import { useRouter, routeFor } from '../lib/routes.js'
  import { applyLocale } from '../lib/locale.js'
  import SystemLogin from './SystemLogin.svelte'
  import SystemTenants from './SystemTenants.svelte'
  import SystemUserLookup from './SystemUserLookup.svelte'
  import SystemAudit from './SystemAudit.svelte'
  import SystemSettings from './SystemSettings.svelte'
  import SystemProfile from './SystemProfile.svelte'

  useRouter('system')

  let initialized = false

  onMount(async () => {
    if (typeof window !== 'undefined' && window.history && 'scrollRestoration' in window.history) {
      window.history.scrollRestoration = 'auto'
    }

    const intended = routeFor(window.location.pathname) || { page: 'system-tenants', params: {} }

    let me = null
    try { me = await systemApi.me() } catch { /* unauthenticated */ }
    if (me) {
      user.set(me)
      if (me.language && me.language !== get(locale)) applyLocale(me.language)
    }

    let finalPage
    if (!me) {
      // Stash the intended deep link so post-login returns the user there.
      if (intended.page !== 'system-login') pendingRoute.set(intended)
      finalPage = 'system-login'
    }
    else if (me.mustChangePassword) finalPage = 'system-profile'
    else if (intended.page === 'system-login') finalPage = 'system-tenants'
    else finalPage = intended.page

    navigate(finalPage, {}, { replace: true })

    window.addEventListener('popstate', (e) => {
      const next = (e.state && e.state.page) ? e.state : routeFor(window.location.pathname)
      if (next) route.set({ page: next.page, params: next.params ?? {} })
    })

    initialized = true
  })

  // Belt-and-suspenders: if anyone navigates away while still on the must-rotate flag,
  // bounce back to the profile page. Replace so they can't back out of it.
  $: if ($user?.mustChangePassword
        && $route.page !== 'system-profile'
        && $route.page !== 'system-login') {
    navigate('system-profile', {}, { replace: true })
  }

  async function logout() {
    await api.logout().catch(() => {})
    user.set(null)
    pendingRoute.set(null)
    navigate('system-login', {}, { replace: true })
  }
</script>

{#if !initialized}
  <div class="loading"><span class="spinner"></span></div>
{:else if $route.page === 'system-login'}
  <SystemLogin />
{:else}
  <div class="layout">
    <nav class="navbar">
      <div class="nav-brand">
        <span class="brand-text">{$t('nav.brand')}</span>
        <span class="apex-badge">{$t('system.badge')}</span>
      </div>
      <div class="nav-links">
        <button class="nav-link" class:active={$route.page === 'system-tenants'} on:click={() => navigate('system-tenants')}>{$t('system.nav.tenants')}</button>
        <button class="nav-link" class:active={$route.page === 'system-users'} on:click={() => navigate('system-users')}>{$t('system.nav.users')}</button>
        <button class="nav-link" class:active={$route.page === 'system-audit'} on:click={() => navigate('system-audit')}>{$t('system.nav.audit')}</button>
        <button class="nav-link" class:active={$route.page === 'system-settings'} on:click={() => navigate('system-settings')}>{$t('system.nav.settings')}</button>
      </div>
      <div class="nav-actions">
        <button class="nav-link" class:active={$route.page === 'system-profile'} on:click={() => navigate('system-profile')}>{$t('system.nav.profile')}</button>
        <button on:click={logout}>{$t('system.nav.signOut')}</button>
      </div>
    </nav>

    <main class="main-content">
      {#if $route.page === 'system-tenants'}
        <SystemTenants />
      {:else if $route.page === 'system-users'}
        <SystemUserLookup />
      {:else if $route.page === 'system-audit'}
        <SystemAudit />
      {:else if $route.page === 'system-settings'}
        <SystemSettings />
      {:else if $route.page === 'system-profile'}
        <SystemProfile />
      {/if}
    </main>
  </div>
{/if}

<style>
  .loading { display: flex; align-items: center; justify-content: center; height: 100vh; }
  .layout { display: flex; flex-direction: column; min-height: 100vh; }
  .navbar {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 0 16px;
    height: 48px;
    background: var(--bg2);
    border-bottom: 1px solid var(--border);
    position: sticky; top: 0; z-index: 50;
  }
  .nav-brand { display: flex; align-items: center; gap: 8px; }
  .brand-text { font-weight: 600; }
  .apex-badge {
    font-size: 11px;
    padding: 2px 6px;
    border-radius: 3px;
    background: var(--accent);
    color: white;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }
  .nav-links { display: flex; gap: 2px; flex: 1; margin-left: 16px; }
  .nav-link {
    border: none;
    background: none;
    color: var(--text2);
    padding: 4px 10px;
    font-size: 13px;
    border-radius: var(--radius);
    cursor: pointer;
  }
  .nav-link:hover { background: var(--bg3); color: var(--text); }
  .nav-link.active { color: var(--accent); background: var(--bg); }
  .nav-actions { display: flex; gap: 6px; align-items: center; }
  .main-content { flex: 1; padding: 16px; }
</style>
