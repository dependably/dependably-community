<script>
  /**
   * Step 1 — what the reader is doing, and the token that lets them do it.
   *
   * The operation lives here rather than with the other axes because it is the only one that
   * changes the credential: install mints a read-only token, publish a push one. Asking it
   * anywhere below the mint button would put the question after the answer.
   *
   * The token is held in this component's state and handed upward, never persisted: it is
   * shown once, exactly as the Tokens page shows it, and the page pairs it with the recipe
   * below. Reloading the page loses it, which is the same contract the Tokens page already
   * sets and the reason the copy button sits beside it.
   */
  import { t } from 'svelte-i18n'
  import { createEventDispatcher } from 'svelte'
  import { api } from '../api.js'
  import { navigate } from '../store.js'
  import ErrorBanner from '../ErrorBanner.svelte'
  import { copyToClipboard } from '../clipboard.js'
  import { presetToCapabilities } from '../tokenCapabilities.js'
  import { ECO_LABEL } from '../ecosystems.js'
  import { availableOperations } from './recipes.js'

  /** Preset the recipe below needs — 'pull' for install, 'push' for publish. */
  export let preset = 'pull'
  /** Name the token carries in the Tokens table, derived from the current selection. */
  export let autoDescription = ''
  /** The minted secret, bound by the page so later steps can use it. */
  export let token = null
  /** The server payload for the selected ecosystem, or null while it is in flight. */
  export let payload = null
  /** Selected ecosystem — named only to explain an absent publish option. */
  export let ecosystem = ''
  /** What the reader is doing. Bound by the page; the only axis that selects the preset. */
  export let operation = 'install'

  $: operations = availableOperations(payload)

  // Publish is absent for the proxy-only ecosystems. Saying why beats an option that
  // silently is not there.
  $: proxyOnly = payload !== null && operations.length > 0 && !operations.includes('publish')

  const dispatch = createEventDispatcher()

  let creating = false, error = ''
  let copied = false
  /** The preset the held token was actually minted with, so a later switch can be flagged. */
  let mintedPreset = null

  // A push recipe cannot be exercised with a read-only token: the verify step would 403 at
  // the exact moment the reader is trying to confirm the setup works. Say so rather than
  // letting them discover it from the CLI.
  $: presetMismatch = token !== null && mintedPreset !== null && mintedPreset !== preset

  async function create() {
    creating = true
    error = ''
    try {
      const data = await api.createToken(
        presetToCapabilities(preset),
        null,
        autoDescription || null,
      )
      token = data.token
      mintedPreset = preset
      copied = false
      dispatch('minted')
    } catch (e) {
      // Two failures are routine here and both name a real constraint: the per-tenant active
      // token cap, and the token-create rate limit. Neither is worth swallowing.
      error = e.message
    } finally {
      creating = false
    }
  }

  async function copy() {
    copied = await copyToClipboard(token)
    setTimeout(() => { copied = false }, 2000)
  }

  function discard() {
    token = null
    mintedPreset = null
  }
</script>

<div class="step">
  <div class="num">1</div>
  <div>
    <h4>{$t('setup.step.token.title')}</h4>

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
          <p class="form-hint">{$t('setup.proxyOnly', { values: { ecosystem: ECO_LABEL[ecosystem] ?? ecosystem } })}</p>
        {/if}
      </div>
    {/if}

    <ErrorBanner message={error} />

    {#if token}
      <div class="copy-block">
        <span class="copy-block-text t-mono">{token}</span>
        <button class="copy-btn" on:click={copy}>
          {copied ? $t('common.actions.copied') : $t('common.actions.copy')}
        </button>
      </div>
      <p class="form-hint">{$t('setup.step.token.shownOnce')}</p>

      {#if presetMismatch}
        <div class="warning-card mt-2">
          <p>{$t('setup.step.token.presetMismatch', { values: { preset: $t('tokenScopes.' + preset) } })}</p>
        </div>
      {/if}

      <button class="mt-2" on:click={discard}>{$t('setup.step.token.createAnother')}</button>
    {:else}
      <div class="mint-row">
        <button class="primary" on:click={create} disabled={creating}>
          {creating ? $t('common.actions.creating') : $t('setup.step.token.create')}
        </button>
        <button class="link-btn" on:click={() => navigate('tokens')}>{$t('setup.step.token.useExisting')}</button>
      </div>
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

  /* The mint button and the escape hatch for an existing token sit on one row. */
  .mint-row {
    display: flex;
    gap: 14px;
    flex-wrap: wrap;
    align-items: center;
  }

  /* An inline navigation that belongs in running hint text, so it carries a link's
     appearance rather than a button's box. */
  .link-btn {
    background: none;
    border: 0;
    padding: 0;
    min-height: 0;
    font: inherit;
    color: var(--accent);
    cursor: pointer;
    text-decoration: underline;
  }
</style>
