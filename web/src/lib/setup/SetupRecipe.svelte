<script>
  /**
   * Step 3 — the configuration for the chosen cell, and the two axes that shape it.
   *
   * Scope and variant live here rather than with the package-manager choice because neither
   * binds anything else: they select which files this step renders, so they belong beside
   * the files. Whether the ecosystem offers them at all is decided by what the server
   * emitted, so each control renders only values that resolve to a recipe, and the variant
   * control renders only when there is more than one tool — a picker with a single option
   * is noise.
   *
   * Each file is its own card headed by the path it is written to, because the path is the
   * instruction: the previous page rendered a single blob whose first line was a comment
   * naming the file, which is the same information doing less work.
   *
   * The token is substituted into the token line, and into a file body only when that file
   * is secret-bearing — the case where the tool does no interpolation and the value has
   * nowhere else to live. A committable file always keeps its variable reference.
   */
  import { t } from 'svelte-i18n'
  import { copyToClipboard } from '../clipboard.js'
  import { tokenCommand, fileBody, availableScopes, availableVariants } from './recipes.js'
  import SetupSkillAlternative from './SetupSkillAlternative.svelte'

  /** @type {import('./recipes.js').SetupRecipe|null} */
  export let recipe = null
  /** The minted secret, or null when step 1 has not been completed. */
  export let token = null
  /** The server payload for the selected ecosystem, or null while it is in flight. */
  export let payload = null
  /** Selected ecosystem — used to find the curated skill covering this cell. */
  export let ecosystem = ''
  /** What the reader is doing, chosen in step 1; constrains which scopes exist. */
  export let operation = 'install'
  /** Where the configuration applies. Bound by the page. */
  export let scope = 'project'
  /** Which tool's configuration to render. Bound by the page. */
  export let variant = ''
  /** The `/api/v1/skills` index, threaded through to the assistant alternative. */
  export let skillIndex = null

  $: scopes = availableScopes(payload, operation)
  $: variants = availableVariants(payload, operation, scope)

  // A single-variant ecosystem needs no control; the one variant is already selected.
  $: showVariants = variants.length > 1

  let copiedKey = null

  async function copy(key, text) {
    const ok = await copyToClipboard(text)
    copiedKey = ok ? key : null
    setTimeout(() => { if (copiedKey === key) copiedKey = null }, 2000)
  }

  function label(key) {
    return copiedKey === key ? $t('common.actions.copied') : $t('common.actions.copy')
  }

  $: tokenLine = tokenCommand(recipe?.tokenDelivery, token)
  $: files = recipe?.files ?? []
  $: caveats = recipe?.caveats ?? []
</script>

<div class="step">
  <div class="num">3</div>
  <div>
    <h4>{$t('setup.step.config.title')}</h4>

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

    {#if !recipe}
      <p class="step-hint">{$t('setup.step.config.none')}</p>
    {:else}
      {#each caveats as caveat (caveat)}
        <div class="warning-card mb-2"><p>{$t('setup.caveat.' + caveat)}</p></div>
      {/each}

      {#each files as file, i (file.path + i)}
        {@const body = fileBody(file, token)}
        <section class="file">
          <div class="file-head">
            <code class="file-path">{file.path}</code>
            {#if file.locationHint}
              <span class="file-where text-muted">{$t('setup.location.' + file.locationHint)}</span>
            {/if}
          </div>
          <div class="copy-block">
            <span class="copy-block-text">{body}</span>
            <button class="copy-btn" on:click={() => copy('file-' + i, body)}>{label('file-' + i)}</button>
          </div>
          {#if file.secretBearing}
            <p class="form-hint secret-note">{$t('setup.file.secretBearing')}</p>
          {/if}
        </section>
      {/each}

      {#if tokenLine}
        <section class="file">
          <div class="file-head">
            <span class="file-path">{$t('setup.token.lineTitle')}</span>
          </div>
          <div class="copy-block">
            <span class="copy-block-text">{tokenLine}</span>
            <button class="copy-btn" on:click={() => copy('token', tokenLine)}>{label('token')}</button>
          </div>
          <p class="form-hint">
            {token ? $t('setup.token.lineHint') : $t('setup.token.lineHintNoToken')}
          </p>
        </section>
      {/if}

      {#if recipe.verify}
        <section class="file">
          <div class="file-head">
            <span class="file-path">{$t('setup.verify.title')}</span>
          </div>
          <div class="copy-block">
            <span class="copy-block-text">{recipe.verify}</span>
            <button class="copy-btn" on:click={() => copy('verify', recipe.verify)}>{label('verify')}</button>
          </div>
        </section>
      {/if}

      <SetupSkillAlternative {skillIndex} {ecosystem} {scope} />
    {/if}
  </div>
</div>

<style>
  .axis { margin-bottom: 16px; }

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

  .file { margin-bottom: 18px; }
  .file:last-child { margin-bottom: 0; }

  .file-head {
    display: flex;
    align-items: baseline;
    gap: 10px;
    flex-wrap: wrap;
    margin-bottom: 6px;
  }

  .file-path {
    font-size: 13px;
    font-weight: 600;
    color: var(--text);
  }

  .file-where { font-size: 12px; }

  /* The one note that changes what the reader may safely do with the file they just
     copied, so it carries the warning colour rather than the muted hint colour. */
  .secret-note { color: var(--warning); }
</style>
