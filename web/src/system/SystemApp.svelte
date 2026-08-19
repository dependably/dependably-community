<script>
  import { onMount } from 'svelte'
  import { t } from 'svelte-i18n'
  import { api, systemApi } from '../lib/api.js'
  import { user, route, activeRoute, navigate, restoreScroll, pendingRoute,
           cancelTransition, transitionPending } from '../lib/store.js'
  import RouteView from '../lib/RouteView.svelte'
  import { armSessionWatch, disarmSessionWatch } from '../lib/session.js'
  import { useRouter, routeFor } from '../lib/routes.js'
  import { applyUserContext } from '../lib/userContext.js'
  import SystemLogin from './SystemLogin.svelte'
  import SystemDashboard from './SystemDashboard.svelte'
  import SystemTenants from './SystemTenants.svelte'
  import SystemUserLookup from './SystemUserLookup.svelte'
  import SystemAudit from './SystemAudit.svelte'
  import SystemSettings from './SystemSettings.svelte'
  import SystemProfile from './SystemProfile.svelte'
  import SystemAdmins from './SystemAdmins.svelte'
  import SystemBanners from './SystemBanners.svelte'

  useRouter('system')

  let initialized = false

  onMount(async () => {
    if (typeof window !== 'undefined' && window.history && 'scrollRestoration' in window.history) {
      // The SPA owns scroll placement: navigate() seats new pages at the top and stamps the
      // offset it is leaving onto the outgoing history entry, and the popstate handler below
      // reapplies it. The browser's own restore fires before the arriving page has fetched its
      // data and clamps the offset against the short document.
      window.history.scrollRestoration = 'manual'
    }

    const intended = routeFor(window.location.pathname) || { page: 'system-dashboard', params: {} }

    let me = null
    try { me = await systemApi.me() } catch { /* unauthenticated */ }
    if (me) {
      await applyUserContext(me)
      // Arm the proactive session-expiry watcher with the exp claim surfaced by me().
      armSessionWatch(me.sessionExpiresAt, systemApi.me)
    }

    let finalPage
    if (!me) {
      // Stash the intended deep link so post-login returns the user there.
      if (intended.page !== 'system-login') pendingRoute.set(intended)
      finalPage = 'system-login'
    }
    else if (me.mustChangePassword) finalPage = 'system-profile'
    else if (me.mfaEnrollmentRequired) finalPage = 'system-profile'
    else if (intended.page === 'system-login') finalPage = 'system-dashboard'
    else finalPage = intended.page

    // Preserve the query string when the user lands on the page they asked for —
    // system list pages hydrate their table state from it. Redirected landings get
    // a clean URL.
    navigate(finalPage, {}, { replace: true, preserveSearch: finalPage === intended.page })

    window.addEventListener('popstate', (e) => {
      const next = (e.state && e.state.page) ? e.state : routeFor(window.location.pathname)
      if (next) {
        // The user moved history themselves, so whatever was being held for a deferred commit is
        // no longer where they are going — drop it and show the popped entry directly.
        cancelTransition()
        route.set({ page: next.page, params: next.params ?? {} })
        restoreScroll(e.state)
      }
    })

    initialized = true
  })

  // The guards below read $activeRoute, not $route: a deferred navigation holds the outgoing page
  // on screen while the incoming one loads, and a route a guard is going to reject should be
  // rejected before it is ever committed rather than after it lands.

  // Belt-and-suspenders: if anyone navigates away while still on the must-rotate flag,
  // bounce back to the profile page. Replace so they can't back out of it.
  $: if ($user?.mustChangePassword
        && $activeRoute.page !== 'system-profile'
        && $activeRoute.page !== 'system-login') {
    navigate('system-profile', {}, { replace: true })
  }

  // Guard: if an MFA-required system admin (who has already rotated their password)
  // navigates away, bounce to profile so they can enroll. Rotation takes priority.
  $: if ($user?.mfaEnrollmentRequired
        && !$user?.mustChangePassword
        && $activeRoute.page !== 'system-profile'
        && $activeRoute.page !== 'system-login') {
    navigate('system-profile', {}, { replace: true })
  }

  async function logout() {
    await api.logout().catch(() => {})
    cancelTransition()
    disarmSessionWatch()
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
      <button type="button" class="nav-brand" on:click={() => navigate('system-dashboard')}
              aria-label={$t('system.nav.home')}>
        <span class="brand-text">{$t('nav.brand')}</span>
        <span class="apex-badge">{$t('system.badge')}</span>
      </button>
      <!-- Highlighting follows the route the user asked for rather than the one on screen, so a
           held navigation still lights its link the instant it is clicked. -->
      <div class="nav-links">
        <button class="nav-link" class:active={$activeRoute.page === 'system-tenants'} on:click={() => navigate('system-tenants')}>{$t('system.nav.tenants')}</button>
        <button class="nav-link" class:active={$activeRoute.page === 'system-admins'} on:click={() => navigate('system-admins')}>{$t('system.nav.admins')}</button>
        <button class="nav-link" class:active={$activeRoute.page === 'system-users'} on:click={() => navigate('system-users')}>{$t('system.nav.users')}</button>
        <button class="nav-link" class:active={$activeRoute.page === 'system-audit'} on:click={() => navigate('system-audit')}>{$t('system.nav.audit')}</button>
        <button class="nav-link" class:active={$activeRoute.page === 'system-banners'} on:click={() => navigate('system-banners')}>{$t('system.nav.banners')}</button>
        <button class="nav-link" class:active={$activeRoute.page === 'system-settings'} on:click={() => navigate('system-settings')}>{$t('system.nav.settings')}</button>
      </div>
      <div class="nav-actions">
        <button class="nav-link" class:active={$activeRoute.page === 'system-profile'} on:click={() => navigate('system-profile')}>{$t('system.nav.profile')}</button>
        <button on:click={logout}>{$t('system.nav.signOut')}</button>
      </div>
    </nav>

    <div class="nav-progress" class:visible={$transitionPending} aria-hidden="true"></div>

    <main class="main-content">
      <!-- `pageToken` goes to the pages that fetch on arrival: it is how they hold the transition
           open until their data lands. Pages without an initial fetch take none and are committed
           on the auto-commit frame. -->
      <RouteView let:page let:token>
        {#if page === 'system-dashboard'}
          <SystemDashboard pageToken={token} />
        {:else if page === 'system-tenants'}
          <SystemTenants pageToken={token} />
        {:else if page === 'system-admins'}
          <SystemAdmins pageToken={token} />
        {:else if page === 'system-users'}
          <SystemUserLookup />
        {:else if page === 'system-audit'}
          <SystemAudit pageToken={token} />
        {:else if page === 'system-banners'}
          <SystemBanners pageToken={token} />
        {:else if page === 'system-settings'}
          <SystemSettings />
        {:else if page === 'system-profile'}
          <SystemProfile pageToken={token} />
        {/if}
      </RouteView>
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
  /* Brand block doubles as a home link — button reset to keep it looking like text/badges. */
  .nav-brand {
    display: flex; align-items: center; gap: 8px;
    background: none; border: none; padding: 0; margin: 0;
    color: inherit; font: inherit; cursor: pointer;
  }
  .nav-brand:hover .brand-text { color: var(--accent); }
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
  /* No padding here: the shell owns no gutter. Every system page roots at `.page`,
     which sets the 24px gutter — matching the tenant shell in App.svelte. */
  .main-content { flex: 1; }
</style>
