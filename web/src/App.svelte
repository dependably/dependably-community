<script>
  import { onMount } from 'svelte'
  import { t, isLoading, locale } from 'svelte-i18n'
  import { route, user, navigate, bootstrapInfo, pendingRoute, noticesOpen } from './lib/store.js'
  import { useRouter, routeFor, ADMIN_ONLY_PAGES } from './lib/routes.js'
  import { api } from './lib/api.js'
  import { setupI18n } from './i18n/index.js'
  import { applyLocale } from './lib/locale.js'
  import { get } from 'svelte/store'
  import { activeBanners, loadActiveBanners, dismissBanner } from './lib/banners.js'
  import { armSessionWatch, disarmSessionWatch } from './lib/session.js'
  import Banner from './lib/Banner.svelte'

  import Login from './pages/Login.svelte'
  import Join from './pages/Join.svelte'
  import Packages from './pages/Packages.svelte'
  import VersionDetail from './pages/VersionDetail.svelte'
  import Audit from './pages/Audit.svelte'
  import Tokens from './pages/Tokens.svelte'
  import OrgSettings from './pages/OrgSettings.svelte'
  import Users from './pages/Users.svelte'
  import Setup from './pages/Setup.svelte'
  import Upload from './pages/Upload.svelte'
  import Vulnerabilities from './pages/Vulnerabilities.svelte'
  import Quarantine from './pages/Quarantine.svelte'
  import LicensePolicy from './pages/LicensePolicy.svelte'
  import Dashboard from './pages/Dashboard.svelte'
  import Profile from './pages/Profile.svelte'
  import SamlTestResult from './pages/SamlTestResult.svelte'
  import SystemApp from './system/SystemApp.svelte'
  import Sidebar from './lib/Sidebar.svelte'
  import TopBar from './lib/TopBar.svelte'
  import Licenses from './pages/Licenses.svelte'

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

  // Guard: if an MFA-required user (who has already rotated their password) navigates
  // anywhere else, bounce to profile so they can enroll. Rotation takes priority.
  $: if ($user?.mfaEnrollmentRequired
        && !$user?.mustChangePassword
        && !($bootstrapInfo?.mode === 'multi' && $bootstrapInfo?.isApex)
        && $route.page !== 'profile' && $route.page !== 'login') {
    navigate('profile', {}, { replace: true })
  }

  // Guard: admin/owner-only pages must not render for other roles. The sidebar hides these
  // links, but a non-admin can still deep-link or bookmark the URL — without this bounce the
  // page mounts, fires its API call, and surfaces a raw backend 403. Send them to the dashboard
  // instead. Runs after the rotation/MFA guards so those keep priority; the backend remains the
  // real authority (this is UX, not the security boundary). Apex mode is exempt: SystemApp owns
  // its own page names and never uses these.
  $: if ($user
        && !($user.role === 'admin' || $user.role === 'owner')
        && !($bootstrapInfo?.mode === 'multi' && $bootstrapInfo?.isApex)
        && ADMIN_ONLY_PAGES.has($route.page)) {
    navigate('dashboard', {}, { replace: true })
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
      // Load active banners once after auth. One-shot — no polling.
      loadActiveBanners()
      // Arm the proactive session-expiry watcher with the exp claim surfaced by me().
      armSessionWatch(me.sessionExpiresAt, api.me)
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
    } else if (me.mfaEnrollmentRequired) {
      finalPage = 'profile'
    } else if (intended.page === 'login') {
      finalPage = 'dashboard'
    } else if (ADMIN_ONLY_PAGES.has(intended.page)
        && !(me.role === 'admin' || me.role === 'owner')) {
      // Non-admin deep-linked/bookmarked an admin-only page — land on the dashboard so the
      // admin page never mounts. The reactive guard above covers runtime navigations.
      finalPage = 'dashboard'
    } else {
      finalPage = intended.page
      finalParams = intended.params
    }

    // Single replacing navigate seats URL + state + store with no flicker, no extra entry.
    // The query string is preserved whenever the user lands on the page they asked for:
    // list pages hydrate their table state from it, and saml-test-result/join read their
    // params from window.location.search on mount. Redirected landings (login bounce,
    // dashboard fallback) get a clean URL.
    navigate(finalPage, finalParams, { replace: true, preserveSearch: finalPage === intended.page })

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
    disarmSessionWatch()
    user.set(null)
    pendingRoute.set(null)
    activeBanners.set([])
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
    <Sidebar />
    <div class="content-area">
    <TopBar on:logout={logout} />

    {#if $bootstrapInfo?.insecureHttp && !httpBannerDismissed}
      <div class="http-banner" role="alert">
        <span class="http-banner-text">
          <svg width="12" height="12" aria-hidden="true"><use href="/icons.svg#icon-alert"/></svg>
          {$t('nav.insecureHttpHint')}
        </span>
        <button class="http-banner-close" on:click={() => { httpBannerDismissed = true; localStorage.setItem('httpBannerDismissed', '1') }} aria-label="Dismiss">&#215;</button>
      </div>
    {/if}

    {#each $activeBanners as b (b.id)}
      <Banner
        id={b.id}
        severity={b.severity}
        body={b.body}
        linkUrl={b.linkUrl}
        linkLabel={b.linkLabel}
        on:dismiss={(e) => dismissBanner(e.detail.id)}
      />
    {/each}

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
      {:else if $route.page === 'settings'}
        <OrgSettings />
      {:else if $route.page === 'users'}
        <Users />
      {:else if $route.page === 'setup'}
        <Setup />
      {:else if $route.page === 'upload'}
        <Upload />
      {:else if $route.page === 'vulnerabilities'}
        <Vulnerabilities />
      {:else if $route.page === 'quarantine'}
        <Quarantine />
      {:else if $route.page === 'license-policy'}
        <LicensePolicy />
      {:else if $route.page === 'profile'}
        <Profile />
      {:else if $route.page === 'saml-test-result'}
        <SamlTestResult />
      {/if}
    </main>
    </div>
  </div>
{/if}

{#if $noticesOpen}
  <Licenses on:close={() => noticesOpen.set(false)} />
{/if}

<style>
  .app-loading {
    display: flex;
    align-items: center;
    justify-content: center;
    height: 100vh;
  }

  /* Sidebar (left rail) + content column. The nav/brand/badge styles now live in
     Sidebar.svelte and TopBar.svelte. */
  .layout { display: flex; flex-direction: row; min-height: 100vh; }

  .content-area {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
  }

  .main-content { flex: 1; }

  /* Mobile: the sidebar collapses to a horizontal bar (see Sidebar.svelte) and the
     content column stacks beneath it. */
  @media (max-width: 720px) {
    .layout { flex-direction: column; }
  }

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
