<script>
  import { createEventDispatcher } from 'svelte'
  import { t } from 'svelte-i18n'
  import { activeRoute, user, navigate } from './store.js'
  import GlobalSearch from './GlobalSearch.svelte'
  import AlertsPanel from './AlertsPanel.svelte'

  const dispatch = createEventDispatcher()

  // The alert center is admin/owner only — read:tenant and tenant:configure are not granted to
  // member/auditor (Capabilities.cs), the same gate QuarantineController enforces server-side.
  // Gating the component mount (not just its contents) keeps the bell fully absent from the DOM
  // for a member, not merely hidden.
  $: isAdmin = $user?.role === 'admin' || $user?.role === 'owner'
</script>

<header class="topbar">
  <div class="topbar-search">
    <GlobalSearch />
  </div>

  <div class="nav-actions">
    {#if isAdmin}
      <AlertsPanel />
    {/if}
    {#if $user}
      <button
        class="nav-link"
        class:active={$activeRoute.page === 'profile'}
        on:click={() => navigate('profile')}
        title={$t('nav.profile')}
      >
        <svg width="16" height="16" aria-hidden="true"><use href="/icons.svg#icon-user"/></svg>
        <span class="nav-actions-label">{$t('nav.profile')}</span>
      </button>
    {/if}
    <button on:click={() => dispatch('logout')}>{$t('nav.signOut')}</button>
  </div>
</header>

<style>
  /* Three-track grid so the search box sits on the column's true centre: the outer tracks share
     the leftover space equally, whatever width the actions on the right take. */
  .topbar {
    display: grid;
    grid-template-columns: 1fr minmax(0, 440px) 1fr;
    align-items: center;
    gap: 12px;
    height: 48px;
    padding: 0 16px;
    background: var(--bg2);
    border-bottom: 1px solid var(--border);
    position: sticky;
    top: 0;
    z-index: 40;
  }

  /* The search box (input + overlay) is owned by GlobalSearch.svelte. */
  .topbar-search { grid-column: 2; min-width: 0; }

  .nav-actions { display: flex; gap: 6px; align-items: center; grid-column: 3; justify-self: end; }

  .nav-link {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    border: none;
    background: none;
    color: var(--text2);
    padding: 5px 10px;
    font-size: 13px;
    border-radius: var(--radius);
    cursor: pointer;
  }
  .nav-link:hover { background: var(--bg3); color: var(--text); }
  .nav-link.active { color: var(--accent); background: var(--bg); }

  /* Narrow shells drop the centring: the search box takes all the room the actions leave. */
  @media (max-width: 720px) {
    .topbar { grid-template-columns: minmax(0, 1fr) auto; }
    .topbar-search { grid-column: 1; }
    .nav-actions { grid-column: 2; }
    .nav-actions-label { display: none; }
  }
</style>
