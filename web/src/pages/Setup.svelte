<script>
  /**
   * Setup — connect a package manager to this registry.
   *
   * Three steps rather than a reference sheet: the page's job is to get one developer from
   * "I have no credential and no config" to "my client resolves through Dependably", so it
   * mints the token, narrows to the one recipe that applies, and ends on a command that
   * proves it worked.
   *
   * One ecosystem is fetched per selection and memoized, rather than all ten on mount.
   */
  import { t } from 'svelte-i18n'
  import { api } from '../lib/api.js'
  import { currentOrg } from '../lib/store.js'
  import { reportPageLoad } from '../lib/pageLoad.js'
  import ErrorBanner from '../lib/ErrorBanner.svelte'
  import SetupTokenStep from '../lib/setup/SetupTokenStep.svelte'
  import SetupSelectors from '../lib/setup/SetupSelectors.svelte'
  import SetupRecipe from '../lib/setup/SetupRecipe.svelte'
  import { selectRecipe, reconcileSelection, OPERATION_PRESET } from '../lib/setup/recipes.js'
  import { ECO_LABEL } from '../lib/ecosystems.js'

  /** The route transition this page was mounted for, supplied by RouteView. @type {number | null} */
  export let pageToken = null

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

  $: org = $currentOrg
  // Holds the deferred navigation that mounted this page until the first payload is here,
  // so the route swap shows a loaded page rather than an empty one.
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

  // Step 1 mints for whatever step 2 is set to do. The two share this one value rather than
  // asking the reader the same question twice.
  $: preset = OPERATION_PRESET[operation] ?? 'pull'

  // The token names itself from the selection. Asking for a description is a free-text
  // question with no right answer, which is where a reader stalls; the selection already
  // says what the token is for.
  $: autoDescription = `${ECO_LABEL[ecosystem] ?? ecosystem} — ${operation}`

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
  }
</script>

<div class="page">
  <div class="page-header"><h1 class="page-title">{$t('setup.title')}</h1></div>

  <ErrorBanner message={error} />

  <div class="card steps">
    <SetupTokenStep {preset} {autoDescription} bind:token />

    <SetupSelectors
      {payload}
      bind:ecosystem
      bind:operation
      bind:scope
      bind:variant
    />

    <SetupRecipe {recipe} {token} />
  </div>

</div>

<style>
  /* The steps share one surface so the numbered sequence reads as a single flow; .step
     draws its own top border between them. */
  .steps { padding: 0; }
</style>
