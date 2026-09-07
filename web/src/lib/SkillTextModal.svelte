<script>
  /**
   * Reads one curated skill in place.
   *
   * A skill is a document a developer is about to hand an AI assistant, and installing it is
   * the one moment they cannot see what it says — the install one-liner writes it straight
   * into the assistant's directory. This is the read-before-you-run surface, so it carries
   * both ways to take the file away with you: the text on the clipboard, or the file itself.
   */
  import { createEventDispatcher, onMount } from 'svelte'
  import { t } from 'svelte-i18n'
  import { api } from './api.js'
  import { copyToClipboard } from './clipboard.js'
  import { renderMarkdown, stripFrontmatter } from './markdown.js'
  import ErrorBanner from './ErrorBanner.svelte'
  import LoadingSpinner from './LoadingSpinner.svelte'

  /** Skill id, e.g. `fix-xss`. */
  export let skillId
  /** One-line description from the index, shown under the title while the body loads. */
  export let description = ''

  const dispatch = createEventDispatcher()

  let markdown = null
  let loading = true
  let error = ''
  let copied = false

  // The header already shows the name and description the frontmatter carries, so rendering it
  // again as body text would duplicate it under a stray rule. Copy and download below still hand
  // over the whole file — an assistant reads the frontmatter to know what the skill is.
  $: html = renderMarkdown(stripFrontmatter(markdown))
  $: downloadUrl = `/api/v1/skills/${encodeURIComponent(skillId)}`

  onMount(async () => {
    try {
      markdown = await api.getSkillMarkdown(skillId)
    } catch (e) {
      error = e.message ?? 'failed to load skill'
    } finally {
      loading = false
    }
  })

  async function copy() {
    copied = await copyToClipboard(markdown)
    setTimeout(() => { copied = false }, 2000)
  }

  function close() { dispatch('close') }
  function onKeydown(e) { if (e.key === 'Escape') close() }
  function onBackdropClick(e) { if (e.target === e.currentTarget) close() }
</script>

<svelte:window on:keydown={onKeydown} />

<div class="overlay" on:click={onBackdropClick} role="presentation">
  <div class="dialog" role="dialog" aria-modal="true" aria-labelledby="skill-text-title">
    <header>
      <div class="titles">
        <span class="eyebrow">{$t('skills.modal.eyebrow')}</span>
        <h2 id="skill-text-title" class="t-mono">{skillId}</h2>
        {#if description}<p class="desc">{description}</p>{/if}
      </div>
      <button class="close" on:click={close} aria-label={$t('skills.modal.close')}>&times;</button>
    </header>

    <div class="body">
      {#if error}
        <ErrorBanner message={error} />
      {:else if loading}
        <LoadingSpinner label={$t('skills.modal.loading')} />
      {:else}
        <!-- The value is HTML by construction, so this is the one form that can render it.
             renderMarkdown puts it through DOMPurify against a closed tag/attribute allowlist
             first, and markdown.test.js pins that with the vectors the rule is warning about. -->
        <!-- eslint-disable-next-line svelte/no-at-html-tags -->
        <div class="markdown">{@html html}</div>
      {/if}
    </div>

    <footer>
      <a class="btn-link" href={downloadUrl} download={`${skillId}-SKILL.md`}>
        {$t('skills.modal.download')}
      </a>
      <button on:click={copy} disabled={loading || !!error}>
        {copied ? $t('common.actions.copied') : $t('skills.modal.copy')}
      </button>
      <button class="primary" on:click={close}>{$t('skills.modal.close')}</button>
    </footer>
  </div>
</div>

<style>
  .overlay {
    position: fixed;
    inset: 0;
    background: var(--overlay-scrim);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 100;
    padding: 24px;
  }
  .dialog {
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 8px;
    width: 100%;
    max-width: 860px;
    max-height: 90vh;
    display: flex;
    flex-direction: column;
    overflow: hidden;
    box-shadow: var(--shadow);
  }
  header {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 12px;
    padding: 12px 20px;
    border-bottom: 1px solid var(--border);
  }
  .titles { display: flex; flex-direction: column; gap: 2px; min-width: 0; }
  .eyebrow { font-size: 11px; text-transform: uppercase; letter-spacing: 0.04em; color: var(--text2); }
  h2 { margin: 0; font-size: 15px; font-weight: 600; }
  .desc { margin: 2px 0 0; font-size: 12px; color: var(--text2); }
  .close {
    background: transparent;
    border: 0;
    font-size: 22px;
    line-height: 1;
    color: var(--text2);
    cursor: pointer;
    padding: 4px 8px;
    min-height: 0;
  }
  .close:hover { color: var(--text); }
  .body { padding: 16px 20px; overflow-y: auto; flex: 1; }

  footer {
    display: flex;
    justify-content: flex-end;
    align-items: center;
    gap: 8px;
    padding: 12px 20px;
    border-top: 1px solid var(--border);
  }

  /* An anchor that has to sit in a row of buttons, so it borrows their box. */
  .btn-link {
    display: inline-flex;
    align-items: center;
    min-height: 36px;
    padding: 0 14px;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    background: var(--bg2);
    color: var(--text);
    font-size: 13px;
    text-decoration: none;
  }
  .btn-link:hover { background: var(--bg3); }

  /* The rendered document. Scoped selectors need :global because the markup is injected
     rather than compiled, so Svelte cannot see these elements to add its scope class. */
  .markdown { font-size: 13px; line-height: 1.6; color: var(--text); }
  .markdown :global(h1),
  .markdown :global(h2),
  .markdown :global(h3),
  .markdown :global(h4) { margin: 20px 0 8px; font-weight: 600; line-height: 1.3; }
  .markdown :global(h1) { font-size: 18px; }
  .markdown :global(h2) { font-size: 15px; }
  .markdown :global(h3) { font-size: 14px; }
  .markdown :global(h4) { font-size: 13px; }
  .markdown :global(> :first-child) { margin-top: 0; }
  .markdown :global(p) { margin: 0 0 10px; }
  .markdown :global(ul),
  .markdown :global(ol) { margin: 0 0 10px; padding-left: 22px; }
  .markdown :global(li) { margin-bottom: 4px; }
  .markdown :global(a) { color: var(--accent); }
  .markdown :global(code) {
    font-family: 'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 12px;
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 1px 4px;
  }
  .markdown :global(pre) {
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 10px 12px;
    margin: 0 0 12px;
    overflow-x: auto;
  }
  .markdown :global(pre code) {
    background: none;
    border: 0;
    padding: 0;
    font-size: 12px;
  }
  .markdown :global(blockquote) {
    margin: 0 0 12px;
    padding: 8px 12px;
    border-left: 3px solid var(--accent);
    background: var(--bg2);
    color: var(--text2);
  }
  .markdown :global(blockquote p:last-child) { margin-bottom: 0; }
  /* Wide tables scroll inside their own box rather than widening the dialog. */
  .markdown :global(table) {
    display: block;
    width: max-content;
    max-width: 100%;
    overflow-x: auto;
    border-collapse: collapse;
    margin: 0 0 12px;
    font-size: 12px;
  }
  .markdown :global(th),
  .markdown :global(td) {
    border: 1px solid var(--border);
    padding: 5px 9px;
    text-align: left;
    vertical-align: top;
  }
  .markdown :global(th) { background: var(--bg2); font-weight: 600; }
  .markdown :global(hr) { border: 0; border-top: 1px solid var(--border); margin: 16px 0; }
</style>
