<script>
  /**
   * Step 2 — the four axes, disclosed in the order a reader decides them.
   *
   * Only the ecosystem is a free choice; the other three are constrained by what the server
   * actually emitted for it, so each control renders only the options that resolve to a
   * recipe. The variant control renders only when the ecosystem has more than one tool —
   * a picker with a single option is noise.
   */
  import { t } from 'svelte-i18n'
  import { ECOSYSTEMS, ECO_LABEL } from '../ecosystems.js'
  import { availableOperations, availableScopes, availableVariants } from './recipes.js'

  /** The server payload for the selected ecosystem, or null while it is in flight. */
  export let payload = null
  export let ecosystem = 'npm'
  export let operation = 'install'
  export let scope = 'project'
  export let variant = ''

  $: operations = availableOperations(payload)
  $: scopes = availableScopes(payload, operation)
  $: variants = availableVariants(payload, operation, scope)

  // A single-variant ecosystem needs no control; the one variant is already selected.
  $: showVariants = variants.length > 1

  // Publish is absent for the proxy-only ecosystems. Saying why beats an option that
  // silently is not there.
  $: proxyOnly = payload !== null && operations.length > 0 && !operations.includes('publish')
</script>

<div class="step">
  <div class="num">2</div>
  <div>
    <h4>{$t('setup.step.choose.title')}</h4>

    <div class="axis">
      <label class="axis-label" for="setup-ecosystem">{$t('setup.axis.ecosystem')}</label>
      <select id="setup-ecosystem" class="eco-select" bind:value={ecosystem}>
        {#each ECOSYSTEMS as eco (eco)}
          <option value={eco}>{ECO_LABEL[eco]}</option>
        {/each}
      </select>
    </div>

    {#if operations.length > 0}
      <div class="axis">
        <span class="axis-label" id="setup-operation-label">{$t('setup.axis.operation')}</span>
        <div class="tabs inline-tabs" role="tablist" aria-labelledby="setup-operation-label">
          {#each operations as op (op)}
            <button
              class="tab"
              class:active={operation === op}
              role="tab"
              aria-selected={operation === op}
              on:click={() => (operation = op)}
            >{$t('setup.operation.' + op)}</button>
          {/each}
        </div>
        {#if proxyOnly}
          <p class="form-hint">{$t('setup.proxyOnly', { values: { ecosystem: ECO_LABEL[ecosystem] } })}</p>
        {/if}
      </div>
    {/if}

    {#if scopes.length > 0}
      <div class="axis">
        <span class="axis-label" id="setup-scope-label">{$t('setup.axis.scope')}</span>
        <div class="tabs inline-tabs" role="tablist" aria-labelledby="setup-scope-label">
          {#each scopes as sc (sc)}
            <button
              class="tab"
              class:active={scope === sc}
              role="tab"
              aria-selected={scope === sc}
              on:click={() => (scope = sc)}
            >{$t('setup.scope.' + sc)}</button>
          {/each}
        </div>
      </div>
    {/if}

    {#if showVariants}
      <div class="axis">
        <span class="axis-label" id="setup-variant-label">{$t('setup.axis.variant')}</span>
        <div class="tabs inline-tabs" role="tablist" aria-labelledby="setup-variant-label">
          {#each variants as v (v.id)}
            <button
              class="tab"
              class:active={variant === v.id}
              role="tab"
              aria-selected={variant === v.id}
              on:click={() => (variant = v.id)}
            >{v.label}</button>
          {/each}
        </div>
      </div>
    {/if}
  </div>
</div>

<style>
  .axis { margin-bottom: 16px; }
  .axis:last-child { margin-bottom: 0; }

  .axis-label {
    display: block;
    font-size: 12px;
    font-weight: 600;
    color: var(--text2);
    margin-bottom: 6px;
  }

  /* The page-level .tabs rule spans the full width under a bottom border, which reads as
     page navigation. These are inline controls inside a step, so they shrink to their
     content and drop the rule. */
  .inline-tabs {
    display: inline-flex;
    border-bottom: 0;
    margin-bottom: 0;
  }
</style>
