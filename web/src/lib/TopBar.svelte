<script>
  import { createEventDispatcher } from 'svelte'
  import { t } from 'svelte-i18n'
  import { route, user, navigate } from './store.js'
  import GlobalSearch from './GlobalSearch.svelte'

  const dispatch = createEventDispatcher()
</script>

<header class="topbar">
  <div class="topbar-search">
    <GlobalSearch />
  </div>

  <div class="nav-actions">
    <button class="icon-btn" aria-label={$t('nav.notifications')} title={$t('nav.notifications')}>
      <svg width="16" height="16" aria-hidden="true"><use href="/icons.svg#icon-bell"/></svg>
    </button>
    {#if $user}
      <button
        class="nav-link"
        class:active={$route.page === 'profile'}
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
  .topbar {
    display: flex;
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
  .topbar-search {
    flex: 1;
    max-width: 440px;
    margin: 0 auto;
  }

  .nav-actions { display: flex; gap: 6px; align-items: center; }

  .icon-btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 30px;
    height: 30px;
    padding: 0;
    border: none;
    background: none;
    color: var(--text2);
    border-radius: var(--radius);
    cursor: pointer;
  }
  .icon-btn:hover { background: var(--bg3); color: var(--text); }

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

  @media (max-width: 720px) {
    .nav-actions-label { display: none; }
    .topbar-search { max-width: none; }
  }
</style>
