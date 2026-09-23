<!--
  Policies page: the two ways this org's serve/publish path can refuse an artefact.

    - Licences tab (also reachable at the /license-policy alias): the licence allow/block lists
      and enforcement mode.
    - Controls tab: every other serve-path block-gate control (malicious/KEV/EPSS/CVSS/
      provenance/…), read-only and keyed by the same reason token the 403
      X-Dependably-Block-Reason header carries.

  Not role-restricted: both tabs' endpoints gate on read:packages, the same capability that
  serves the dashboard tiles, so every role that can browse packages can open this page.

  pageToken passes straight through to whichever tab is mounted — only one of the two ever is
  (the {#if}/{:else} below never renders both), so exactly one PolicyLicences/PolicyControls
  instance ever claims the route transition via reportPageLoad, the same as OrgSettings/
  Vulnerabilities/Setup. This shell itself declares no loading state of its own: the mounted
  tab's own fetch is what the incoming navigation waits on.
-->
<script>
  import { t } from 'svelte-i18n'
  import { readQuery, writeQuery } from '../lib/tableState.js'
  import PolicyLicences from '../lib/policies/PolicyLicences.svelte'
  import PolicyControls from '../lib/policies/PolicyControls.svelte'

  /** The route transition this page was mounted for, supplied by RouteView. @type {number | null} */
  export let pageToken = null

  const DEFAULTS = { tab: 'licences' }
  const init = readQuery(DEFAULTS)

  let activeTab = init.tab === 'controls' ? 'controls' : 'licences'

  function selectTab(tab) {
    if (tab === activeTab) return
    activeTab = tab
    writeQuery({ tab: activeTab }, DEFAULTS)
  }
</script>

<div class="page">
  <header class="page-header">
    <h1 class="page-title">{$t('policies.title')}</h1>
  </header>

  <div class="tabs" role="tablist">
    <button class="tab" class:active={activeTab === 'licences'} role="tab"
            aria-selected={activeTab === 'licences'}
            on:click={() => selectTab('licences')}>{$t('policies.tabs.licences')}</button>
    <button class="tab" class:active={activeTab === 'controls'} role="tab"
            aria-selected={activeTab === 'controls'}
            on:click={() => selectTab('controls')}>{$t('policies.tabs.controls')}</button>
  </div>

  {#if activeTab === 'licences'}
    <PolicyLicences {pageToken} />
  {:else}
    <PolicyControls {pageToken} />
  {/if}
</div>
