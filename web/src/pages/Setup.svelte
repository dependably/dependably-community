<script>
  /**
   * Setup — two tabs over one question: how do I use this registry?
   *
   * The Connect tab takes one developer from "I have no credential and no config" to "my
   * client resolves through Dependably", in three steps rather than a reference sheet: it
   * asks what they are doing and mints the token for it, narrows to the one recipe that
   * applies, and ends on a command that proves it worked. The Skills tab lists the curated
   * remediation skills this instance ships, which are otherwise reachable only from an
   * advisory that happens to map to one.
   *
   * The steps are ordered by what each answer binds. Operation selects the token's preset,
   * so it sits with the mint; scope and variant only reshape the rendered configuration, so
   * they sit with it; the package manager binds neither and stands alone between them.
   *
   * One ecosystem is fetched per selection and memoized, rather than all eleven on mount.
   */
  import { t } from 'svelte-i18n'
  import { api } from '../lib/api.js'
  import { currentOrg } from '../lib/store.js'
  import { reportPageLoad } from '../lib/pageLoad.js'
  import { readQuery, writeQuery } from '../lib/tableState.js'
  import ErrorBanner from '../lib/ErrorBanner.svelte'
  import SetupTokenStep from '../lib/setup/SetupTokenStep.svelte'
  import SetupSelectors from '../lib/setup/SetupSelectors.svelte'
  import SetupRecipe from '../lib/setup/SetupRecipe.svelte'
  import SetupSkills from '../lib/setup/SetupSkills.svelte'
  import { selectRecipe, reconcileSelection, OPERATION_PRESET } from '../lib/setup/recipes.js'

  /** The route transition this page was mounted for, supplied by RouteView. @type {number | null} */
  export let pageToken = null

  // Tab state lives in the URL query so a link into either half is a link, and the default
  // leaves /setup clean.
  const DEFAULTS = { tab: 'connect' }
  const init = readQuery(DEFAULTS)
  let activeTab = init.tab === 'skills' ? 'skills' : 'connect'
  // The skills tab fetches on first selection rather than on mount — a reader who never
  // opens it costs nothing.
  let skillsVisited = activeTab === 'skills'

  function selectTab(tab) {
    activeTab = tab
    if (tab === 'skills') skillsVisited = true
    writeQuery({ tab }, DEFAULTS)
  }

  let ecosystem = 'npm'
  let operation = 'install'
  let scope = 'project'
  let variant = ''

  /** The just-minted secret. Component state only — never persisted, lost on reload. */
  let token = null

  /** Per-ecosystem payload cache, so revisiting a selection costs no request. */
  let payloads = {}
  let loading = true
  let error = ''

  /**
   * The curated-skill index, fetched once. Null while in flight or after a failure, which is
   * what makes step 3's shortcut fail closed: it renders only for a skill this index names,
   * so an unreachable index offers nothing rather than a command that might 404.
   */
  let skillIndex = null

  $: org = $currentOrg
  // Holds the deferred navigation that mounted this page until the first payload is here,
  // so the route swap shows a loaded page rather than an empty one. The skills tab loads on
  // its own and deliberately does not re-enter this.
  $: reportPageLoad(pageToken, loading)
  $: if (org) load(ecosystem)

  $: payload = payloads[ecosystem] ?? null

  // Switching ecosystem routinely invalidates the lower axes — Docker has no project scope,
  // Go has no publish path — so every payload change re-lands the selection on a cell that
  // exists before step 3 tries to render it.
  $: if (payload) {
    const next = reconcileSelection(payload, { operation, scope, variant })
    operation = next.operation
    scope = next.scope
    variant = next.variant
  }

  $: recipe = selectRecipe(payload, operation, scope, variant)

  // Step 1 mints for whatever step 1 is set to do. The two share this one value rather than
  // asking the reader the same question twice.
  $: preset = OPERATION_PRESET[operation] ?? 'pull'

  // The token names itself from the operation, which is the only choice made above the mint.
  // Naming the package manager too would put a not-yet-made choice in the description, and
  // leave it stale the moment the reader switches.
  $: autoDescription = $t('setup.operation.' + operation)

  async function load(eco) {
    if (payloads[eco]) {
      loading = false
      return
    }
    loading = true
    error = ''
    try {
      payloads[eco] = await api.getSetup(eco)
      payloads = payloads
    } catch (e) {
      error = e.message
    } finally {
      loading = false
    }
    void loadSkillIndex()
  }

  async function loadSkillIndex() {
    if (skillIndex !== null) return
    try {
      skillIndex = await api.getSkills()
    } catch (e) {
      // A missing index costs the shortcut, not the page — step 3's copy path is complete
      // on its own.
      console.error(e)
    }
  }
</script>

<div class="page">
  <div class="page-header"><h1 class="page-title">{$t('setup.title')}</h1></div>

  <div class="tabs" role="tablist">
    <button
      class="tab"
      class:active={activeTab === 'connect'}
      role="tab"
      aria-selected={activeTab === 'connect'}
      data-testid="tab-connect"
      on:click={() => selectTab('connect')}
    >{$t('setup.tabs.connect')}</button>
    <button
      class="tab"
      class:active={activeTab === 'skills'}
      role="tab"
      aria-selected={activeTab === 'skills'}
      data-testid="tab-skills"
      on:click={() => selectTab('skills')}
    >{$t('setup.tabs.skills')}</button>
  </div>

  {#if activeTab === 'connect'}
    <ErrorBanner message={error} />

    <div class="card steps">
      <SetupTokenStep {preset} {autoDescription} {payload} {ecosystem} bind:operation bind:token />

      <SetupSelectors bind:ecosystem />

      <SetupRecipe
        {recipe}
        {token}
        {payload}
        {ecosystem}
        {operation}
        {skillIndex}
        bind:scope
        bind:variant
      />
    </div>
  {:else if skillsVisited}
    <SetupSkills />
  {/if}
</div>

<style>
  /* The steps share one surface so the numbered sequence reads as a single flow; .step
     draws its own top border between them. */
  .steps { padding: 0; }
</style>
