<script>
  import { t } from 'svelte-i18n'
  import { route, user, currentOrg, bootstrapInfo, navigate, sidebarCollapsed, noticesOpen } from './store.js'

  // Primary nav (all authenticated users). Ported 1:1 from the old top navbar.
  const mainItems = [
    { page: 'packages', icon: 'icon-package', label: 'nav.packages' },
    { page: 'vulnerabilities', icon: 'icon-bug', label: 'nav.vulnerabilities' },
    { page: 'license-policy', icon: 'icon-license', label: 'nav.licensePolicy' },
    { page: 'tokens', icon: 'icon-key', label: 'nav.tokens' },
  ]
  // Admin/owner-only. Same gate as the old navbar. The page names here must stay in sync with
  // ADMIN_ONLY_PAGES in routes.js, which App.svelte uses to bounce non-admins off these routes.
  const adminItems = [
    { page: 'quarantine', icon: 'icon-quarantine', label: 'nav.quarantine' },
    { page: 'users', icon: 'icon-users', label: 'nav.users' },
    { page: 'audit', icon: 'icon-audit', label: 'nav.audit' },
    { page: 'upload', icon: 'icon-upload', label: 'nav.upload' },
    { page: 'settings', icon: 'icon-settings', label: 'nav.settings' },
  ]
  const setupItem = { page: 'setup', icon: 'icon-setup', label: 'nav.setup' }

  $: isAdmin = $user?.role === 'admin' || $user?.role === 'owner'

  // Web build version (Vite define). Show major.minor only when collapsed.
  const version = __APP_VERSION__
  const versionShort = version.split('.').slice(0, 2).join('.')

  function toggle() {
    sidebarCollapsed.update((c) => !c)
  }
</script>

<nav class="sidebar" class:collapsed={$sidebarCollapsed} aria-label={$t('nav.brand')}>
  <div class="sidebar-head">
    <button class="brand-btn" on:click={() => navigate('dashboard')} title={$t('nav.brand')}>
      <svg viewBox="0 0 64 64" width="18" height="18" fill="none" aria-hidden="true">
        <path d="M32 32L14 14M32 32L50 14M32 32L32 54" stroke="currentColor" stroke-width="4" stroke-linecap="round"/>
        <circle cx="14" cy="14" r="5" fill="currentColor"/>
        <circle cx="50" cy="14" r="5" fill="currentColor"/>
        <circle cx="32" cy="54" r="5" fill="currentColor"/>
        <circle cx="32" cy="32" r="9" fill="var(--accent)"/>
      </svg>
      <span class="nav-label brand-text">{$t('nav.brand')}</span>
    </button>
    <button
      class="icon-btn collapse-btn"
      on:click={toggle}
      aria-label={$sidebarCollapsed ? $t('nav.expand') : $t('nav.collapse')}
      aria-expanded={!$sidebarCollapsed}
      title={$sidebarCollapsed ? $t('nav.expand') : $t('nav.collapse')}
    >
      <svg width="16" height="16" aria-hidden="true"><use href="/icons.svg#icon-sidebar"/></svg>
    </button>
  </div>

  {#if $user && $currentOrg && $bootstrapInfo?.mode === 'multi'}
    <div class="nav-org">
      <span class="nav-org-label nav-label">{$currentOrg.slug}</span>
    </div>
  {/if}

  {#if $bootstrapInfo?.airGapped}
    <div class="air-gap-badge" title={$t('nav.airGappedHint')} aria-label="air-gapped">
      <svg width="12" height="12" aria-hidden="true"><use href="/icons.svg#icon-plane"/></svg>
      <span class="nav-label">{$t('nav.airGapped')}</span>
    </div>
  {/if}

  {#if $user && !$user?.mustChangePassword}
    <div class="nav-links">
      {#each mainItems as item (item.page)}
        <button
          class="nav-link"
          class:active={$route.page === item.page}
          on:click={() => navigate(item.page)}
          title={$t(item.label)}
        >
          <svg class="nav-icon" width="16" height="16" aria-hidden="true"><use href={`/icons.svg#${item.icon}`}/></svg>
          <span class="nav-label">{$t(item.label)}</span>
        </button>
      {/each}
    </div>

    {#if isAdmin}
      <div class="nav-section">
        <span class="nav-section-label nav-label">{$t('nav.adminSection')}</span>
        <div class="nav-links">
          {#each adminItems as item (item.page)}
            <button
              class="nav-link"
              class:active={$route.page === item.page}
              on:click={() => navigate(item.page)}
              title={$t(item.label)}
            >
              <svg class="nav-icon" width="16" height="16" aria-hidden="true"><use href={`/icons.svg#${item.icon}`}/></svg>
              <span class="nav-label">{$t(item.label)}</span>
            </button>
          {/each}
        </div>
      </div>
    {/if}
  {/if}

  <div class="sidebar-footer">
    {#if $user && !$user?.mustChangePassword}
      <button
        class="nav-link"
        class:active={$route.page === setupItem.page}
        on:click={() => navigate(setupItem.page)}
        title={$t(setupItem.label)}
      >
        <svg class="nav-icon" width="16" height="16" aria-hidden="true"><use href={`/icons.svg#${setupItem.icon}`}/></svg>
        <span class="nav-label">{$t(setupItem.label)}</span>
      </button>
    {/if}
    <button class="nav-link" on:click={() => noticesOpen.set(true)} title={$t('nav.notices')}>
      <svg class="nav-icon" width="16" height="16" aria-hidden="true"><use href="/icons.svg#icon-file"/></svg>
      <span class="nav-label">{$t('nav.notices')}</span>
    </button>
    <span class="sidebar-version" title={`${$t('nav.version')} ${version}`}>
      <span class="nav-label">{$t('nav.version')} {version}</span>
      <span class="version-compact" aria-hidden="true">{versionShort}</span>
    </span>
  </div>
</nav>

<style>
  .sidebar {
    display: flex;
    flex-direction: column;
    width: 216px;
    flex: none;
    height: 100vh;
    position: sticky;
    top: 0;
    background: var(--bg2);
    border-right: 1px solid var(--border);
    padding: 8px;
    gap: 2px;
    overflow-y: auto;
    transition: width 160ms ease;
  }
  .sidebar.collapsed { width: 56px; }

  .sidebar-head {
    display: flex;
    align-items: center;
    gap: 4px;
    margin-bottom: 6px;
  }

  .brand-btn {
    display: flex;
    align-items: center;
    gap: 8px;
    flex: 1;
    min-width: 0;
    border: none;
    background: none;
    padding: 6px 8px;
    border-radius: var(--radius);
    color: var(--text);
    cursor: pointer;
    overflow: hidden;
  }
  .brand-btn:hover { background: var(--bg3); }
  .brand-text { font-weight: 700; font-size: 16px; letter-spacing: -0.01em; white-space: nowrap; }

  .icon-btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 28px;
    height: 28px;
    flex: none;
    padding: 0;
    border: none;
    background: none;
    color: var(--text2);
    border-radius: var(--radius);
    cursor: pointer;
  }
  .icon-btn:hover { background: var(--bg3); color: var(--text); }

  .nav-org { padding: 2px 8px 6px; }
  .nav-org-label {
    display: inline-block;
    padding: 3px 8px;
    font-size: 12px;
    color: var(--text2);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    white-space: nowrap;
  }

  .air-gap-badge {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    margin: 0 4px 6px;
    padding: 4px 8px;
    font-size: 12px;
    font-weight: 600;
    background: var(--warning-bg);
    color: var(--warning-text);
    border: 1px solid var(--warning-border);
    border-radius: var(--radius);
    cursor: help;
    white-space: nowrap;
  }

  .nav-links { display: flex; flex-direction: column; gap: 2px; }

  /* Admin group: labelled, divided. The divider (top border) persists when the
     rail is collapsed; the mono eyebrow label hides with the other .nav-labels. */
  .nav-section {
    display: flex;
    flex-direction: column;
    gap: 2px;
    margin-top: 8px;
    padding-top: 8px;
    border-top: 1px solid var(--border);
  }
  .nav-section-label {
    padding: 2px 8px 4px;
    font-family: 'JetBrains Mono', ui-monospace, monospace;
    font-size: 11px;
    font-weight: 500;
    text-transform: uppercase;
    letter-spacing: 0.12em;
    color: var(--text2);
    white-space: nowrap;
  }

  .nav-link {
    display: flex;
    align-items: center;
    gap: 10px;
    width: 100%;
    border: none;
    background: none;
    color: var(--text2);
    padding: 7px 8px;
    font-size: 13px;
    border-radius: var(--radius);
    text-align: left;
    cursor: pointer;
    white-space: nowrap;
    overflow: hidden;
  }
  .nav-link:hover { background: var(--bg3); color: var(--text); }
  .nav-link.active { color: var(--accent); background: var(--bg); }
  .nav-icon { flex: none; }

  .sidebar-footer {
    margin-top: auto;
    padding-top: 8px;
    display: flex;
    flex-direction: column;
    gap: 2px;
    border-top: 1px solid var(--border);
  }
  .sidebar-version {
    display: flex;
    align-items: center;
    padding: 6px 8px;
    font-size: 12px;
    color: var(--text2);
    white-space: nowrap;
  }
  .version-compact { display: none; }

  /* Collapsed rail: hide labels, centre icons, swap version for its compact form. */
  .sidebar.collapsed .nav-label { display: none; }
  .sidebar.collapsed .brand-btn,
  .sidebar.collapsed .nav-link { justify-content: center; gap: 0; padding-left: 0; padding-right: 0; }
  .sidebar.collapsed .sidebar-head { flex-direction: column; gap: 2px; }
  .sidebar.collapsed .air-gap-badge { justify-content: center; padding: 4px; }
  .sidebar.collapsed .sidebar-version { justify-content: center; }
  .sidebar.collapsed .version-compact { display: inline; }

  /* Mobile: rail becomes an off-canvas drawer (full sidebar work lands later;
     this keeps small viewports usable rather than eating 60% of the screen). */
  @media (max-width: 720px) {
    .sidebar {
      flex-direction: row;
      align-items: center;
      width: 100%;
      height: auto;
      overflow-x: auto;
      border-right: none;
      border-bottom: 1px solid var(--border);
    }
    .sidebar .nav-label { display: none; }
    .sidebar .nav-links { flex-direction: row; }
    .sidebar-footer {
      margin-top: 0;
      margin-left: auto;
      flex-direction: row;
      border-top: none;
      padding-top: 0;
    }
    .collapse-btn, .sidebar-version { display: none; }
  }
</style>
