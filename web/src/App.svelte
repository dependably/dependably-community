<script>
  import { onMount } from 'svelte'
  import { t, isLoading, locale } from 'svelte-i18n'
  import { route, user, navigate, currentOrg, bootstrapInfo, pendingRoute } from './lib/store.js'
  import { useRouter, routeFor } from './lib/routes.js'
  import { api } from './lib/api.js'
  import { setupI18n } from './i18n/index.js'
  import { applyLocale } from './lib/locale.js'
  import { get } from 'svelte/store'

  import Login from './pages/Login.svelte'
  import Join from './pages/Join.svelte'
  import Packages from './pages/Packages.svelte'
  import VersionDetail from './pages/VersionDetail.svelte'
  import Audit from './pages/Audit.svelte'
  import Tokens from './pages/Tokens.svelte'
  import CicdTokens from './pages/CicdTokens.svelte'
  import OrgSettings from './pages/OrgSettings.svelte'
  import Users from './pages/Users.svelte'
  import Setup from './pages/Setup.svelte'
  import AdminSettings from './pages/AdminSettings.svelte'
  import Upload from './pages/Upload.svelte'
  import Vulnerabilities from './pages/Vulnerabilities.svelte'
  import LicensePolicy from './pages/LicensePolicy.svelte'
  import Dashboard from './pages/Dashboard.svelte'
  import Profile from './pages/Profile.svelte'
  import SamlTestResult from './pages/SamlTestResult.svelte'
  import SystemApp from './system/SystemApp.svelte'

  setupI18n()
  useRouter('tenant')

  let initialized = false

  // Guard: if a forced-rotation user navigates anywhere else, bounce back to profile.
  // Replace, not push — they shouldn't be able to back out of the rotation requirement.
  // Skip in apex mode: SystemApp owns the rotation guard there with its own page names.
  $: if ($user?.mustChangePassword
        && !($bootstrapInfo?.mode === 'multi' && $bootstrapInfo?.isApex)
        && $route.page !== 'profile' && $route.page !== 'login') {
    navigate('profile', {}, { replace: true })
  }

  onMount(async () => {
    if (typeof window !== 'undefined' && window.history && 'scrollRestoration' in window.history) {
      window.history.scrollRestoration = 'auto'
    }

    // Phase 1: fetch deployment-mode info before anything else.
    try {
      const info = await api.getBootstrap()
      bootstrapInfo.set(info)
    } catch { /* if bootstrap fails the app falls back to legacy single-mode behavior */ }

    // Multi-mode apex: SystemApp takes over rendering and runs its own init.
    const info = get(bootstrapInfo)
    if (info?.mode === 'multi' && info?.isApex) {
      initialized = true
      return
    }

    // Resolve intended page from the URL the user actually requested.
    const intended = routeFor(window.location.pathname) || { page: 'dashboard', params: {} }
    const search = new URLSearchParams(window.location.search)
    const hasJoinToken = intended.page === 'join' && !!search.get('token')

    // Resolve auth — silent failure means unauthenticated.
    let me = null
    try { me = await api.me() } catch { /* unauthenticated */ }
    if (me) {
      user.set(me)
      // Server resolves the effective locale (user override → tenant default → 'en'). If the
      // browser is currently rendering in a different locale, realign locally — no API echo.
      if (me.language && me.language !== get(locale)) applyLocale(me.language)
    }

    // Decide final page based on intended × auth × mustChangePassword.
    let finalPage, finalParams = {}
    if (!me) {
      // /join?token=... is honored even without a session — invitees won't have one yet.
      // /saml-test-result requires an authenticated admin; bounce unauth to login.
      if (hasJoinToken) finalPage = 'join'
      else {
        // Stash the intended deep link so post-login returns the user there.
        if (intended.page !== 'login' && intended.page !== 'join') {
          pendingRoute.set(intended)
        }
        finalPage = 'login'
      }
    } else if (me.mustChangePassword) {
      finalPage = 'profile'
    } else if (intended.page === 'login') {
      finalPage = 'dashboard'
    } else {
      finalPage = intended.page
      finalParams = intended.params
    }

    // Single replacing navigate seats URL + state + store with no flicker, no extra entry.
    // saml-test-result: preserve the backend's query params (?email, ?nameid, ?error, ?detail)
    // because SamlTestResult.svelte reads them from window.location.search on mount.
    navigate(finalPage, finalParams, { replace: true, preserveSearch: finalPage === 'saml-test-result' })

    // popstate: read state if present (set by our own pushState/replaceState calls); fall back
    // to URL-derived route when state is null (hard reloads, manual URL entry, some cross-origin
    // returns can drop state). Don't push — popstate already moved history.
    window.addEventListener('popstate', (e) => {
      const next = (e.state && e.state.page) ? e.state : routeFor(window.location.pathname)
      if (next) route.set({ page: next.page, params: next.params ?? {} })
    })

    initialized = true
  })

  async function logout() {
    await api.logout().catch(() => {})
    user.set(null)
    pendingRoute.set(null)
    navigate('login', {}, { replace: true })
  }

  let httpBannerDismissed = typeof localStorage !== 'undefined' && !!localStorage.getItem('httpBannerDismissed')
</script>

{#if $isLoading || !initialized}
  <div class="app-loading">
    <span class="spinner"></span>
  </div>
{:else if $bootstrapInfo?.mode === 'multi' && $bootstrapInfo?.isApex}
  <SystemApp />
{:else if $route.page === 'login'}
  <Login />
{:else if $route.page === 'join'}
  <Join />
{:else}
  <div class="layout">
    <nav class="navbar">
      <button class="nav-brand brand brand-btn" on:click={() => navigate('dashboard')}>
        <svg viewBox="0 0 64 64" width="18" height="18" fill="none" aria-hidden="true">
          <path d="M32 32L14 14M32 32L50 14M32 32L32 54" stroke="currentColor" stroke-width="4" stroke-linecap="round"/>
          <circle cx="14" cy="14" r="5" fill="currentColor"/>
          <circle cx="50" cy="14" r="5" fill="currentColor"/>
          <circle cx="32" cy="54" r="5" fill="currentColor"/>
          <circle cx="32" cy="32" r="9" fill="var(--accent)"/>
        </svg>
        <span class="brand-text">{$t('nav.brand')}</span>
      </button>

      {#if $user && $currentOrg && $bootstrapInfo?.mode === 'multi'}
        <div class="nav-org">
          <span class="nav-org-label">{$currentOrg.slug}</span>
        </div>
      {/if}

      {#if $bootstrapInfo?.airGapped}
        <div class="air-gap-badge" title={$t('nav.airGappedHint')} aria-label="air-gapped">
          <svg width="12" height="12" aria-hidden="true"><use href="/icons.svg#icon-plane"/></svg>
          {$t('nav.airGapped')}
        </div>
      {/if}

      {#if $currentOrg && !$user?.mustChangePassword}
        <div class="nav-links">
          <button class="nav-link" class:active={$route.page === 'packages'} on:click={() => navigate('packages')}>{$t('nav.packages')}</button>
          <button class="nav-link" class:active={$route.page === 'vulnerabilities'} on:click={() => navigate('vulnerabilities')}>{$t('nav.vulnerabilities')}</button>
          <button class="nav-link" class:active={$route.page === 'license-policy'} on:click={() => navigate('license-policy')}>{$t('nav.licensePolicy')}</button>
          <button class="nav-link" class:active={$route.page === 'tokens'} on:click={() => navigate('tokens')}>{$t('nav.tokens')}</button>
          {#if $user?.role === 'admin' || $user?.role === 'owner'}
            <button class="nav-link" class:active={$route.page === 'users'} on:click={() => navigate('users')}>{$t('nav.users')}</button>
            <button class="nav-link" class:active={$route.page === 'audit'} on:click={() => navigate('audit')}>{$t('nav.audit')}</button>
            <button class="nav-link" class:active={$route.page === 'upload'} on:click={() => navigate('upload')}>{$t('nav.upload')}</button>
            <button class="nav-link" class:active={$route.page === 'settings'} on:click={() => navigate('settings')}>{$t('nav.settings')}</button>
          {/if}
          <button class="nav-link" class:active={$route.page === 'setup'} on:click={() => navigate('setup')}>{$t('nav.setup')}</button>
        </div>
      {/if}

      <div class="nav-actions">
        <!-- Locale + theme moved to the Profile page; system_admin lives at the apex SPA. -->
        {#if $user}
          <button class="nav-link" class:active={$route.page === 'profile'} on:click={() => navigate('profile')} title={$t('nav.profile')}>{$t('nav.profile')}</button>
        {/if}
        <button on:click={logout}>{$t('nav.signOut')}</button>
      </div>
    </nav>

    {#if $bootstrapInfo?.insecureHttp && !httpBannerDismissed}
      <div class="http-banner" role="alert">
        <span class="http-banner-text">
          <svg width="12" height="12" aria-hidden="true"><use href="/icons.svg#icon-alert"/></svg>
          {$t('nav.insecureHttpHint')}
        </span>
        <button class="http-banner-close" on:click={() => { httpBannerDismissed = true; localStorage.setItem('httpBannerDismissed', '1') }} aria-label="Dismiss">×</button>
      </div>
    {/if}

    <main class="main-content">
      {#if $route.page === 'dashboard'}
        <Dashboard />
      {:else if $route.page === 'packages'}
        <Packages />
      {:else if $route.page === 'version-detail'}
        <VersionDetail />
      {:else if $route.page === 'audit'}
        <Audit />
      {:else if $route.page === 'tokens'}
        <Tokens />
      {:else if $route.page === 'cicd-tokens'}
        <CicdTokens />
      {:else if $route.page === 'settings'}
        <OrgSettings />
      {:else if $route.page === 'users'}
        <Users />
      {:else if $route.page === 'setup'}
        <Setup />
      {:else if $route.page === 'admin-settings'}
        <AdminSettings />
      {:else if $route.page === 'upload'}
        <Upload />
      {:else if $route.page === 'vulnerabilities'}
        <Vulnerabilities />
      {:else if $route.page === 'license-policy'}
        <LicensePolicy />
      {:else if $route.page === 'profile'}
        <Profile />
      {:else if $route.page === 'saml-test-result'}
        <SamlTestResult />
      {/if}
    </main>

  </div>
{/if}

<style>
  .app-loading {
    display: flex;
    align-items: center;
    justify-content: center;
    height: 100vh;
  }

  .layout { display: flex; flex-direction: column; min-height: 100vh; }

  .navbar {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 0 16px;
    height: 48px;
    background: var(--bg2);
    border-bottom: 1px solid var(--border);
    position: sticky;
    top: 0;
    z-index: 50;
  }

  .nav-org-label {
    padding: 4px 8px;
    font-size: 13px;
    color: var(--text2);
    border: 1px solid var(--border);
    border-radius: var(--radius);
  }

  /* #46 air-gap badge: surfaces AIR_GAPPED=true so operators always see the deployment
     mode without checking config. Amber to signal "the proxy fetch path is disabled" */
  .air-gap-badge {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    padding: 4px 10px;
    font-size: 12px;
    font-weight: 600;
    background: var(--warning-bg);
    color: var(--warning-text);
    border: 1px solid var(--warning-border);
    border-radius: var(--radius);
    cursor: help;
  }

  .nav-links { display: flex; gap: 2px; flex: 1; }

  .nav-link {
    border: none;
    background: none;
    color: var(--text2);
    padding: 4px 10px;
    font-size: 13px;
    border-radius: var(--radius);
  }
  .nav-link:hover { background: var(--bg3); color: var(--text); }
  .nav-link.active { color: var(--accent); background: var(--bg); }

  .brand-btn {
    border: none;
    background: none;
    padding: 4px 8px;
    border-radius: var(--radius);
    cursor: pointer;
  }
  .brand-btn:hover { background: var(--bg3); }

  .nav-actions { display: flex; gap: 6px; margin-left: auto; align-items: center; }

  .main-content { flex: 1; }

  .http-banner {
    display: flex;
    align-items: center;
    padding: 8px 40px 8px 16px;
    background: var(--warning-bg);
    border-bottom: 1px solid var(--warning-border);
    color: var(--warning-text);
    font-size: 13px;
    position: relative;
  }

  .http-banner-text {
    flex: 1;
    text-align: center;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 6px;
  }

  .http-banner-close {
    position: absolute;
    right: 10px;
    top: 50%;
    transform: translateY(-50%);
    background: none;
    border: none;
    color: var(--warning-text);
    font-size: 20px;
    line-height: 1;
    padding: 2px 6px;
    cursor: pointer;
    opacity: 0.7;
  }
  .http-banner-close:hover { opacity: 1; }
</style>
