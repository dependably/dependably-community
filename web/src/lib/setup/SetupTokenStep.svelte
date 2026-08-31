<script>
  /**
   * Step 1 — mint the access token every client needs to authenticate.
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

  /** Preset the recipe below needs — 'pull' for install, 'push' for publish. */
  export let preset = 'pull'
  /** Name the token carries in the Tokens table, derived from the current selection. */
  export let autoDescription = ''
  /** The minted secret, bound by the page so later steps can use it. */
  export let token = null

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
