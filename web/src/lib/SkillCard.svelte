<script>
  /**
   * One curated skill: what it covers, the one-liner that installs it into the selected
   * assistant, and optionally the prompt that runs it. Shared by the Setup page's skills tab
   * and its configure-with-an-assistant alternative, so the two cannot drift in what they
   * tell a reader to run.
   *
   * The name opens the document. Installing a skill writes it straight into the assistant's
   * directory, so without this the one moment a reader would want to see what they are about
   * to run is the one moment the page does not offer it.
   */
  import { t } from 'svelte-i18n'
  import { copyToClipboard } from './clipboard.js'
  import { skillInstallCommand } from './skills.js'
  import SkillTextModal from './SkillTextModal.svelte'

  /** Index entry from `/api/v1/skills` — `{ id, name, description }`. */
  export let skill
  /** Assistant id the install command targets. */
  export let assistant = 'claude'
  /** Optional second copy block: a ready-to-paste prompt that invokes the skill. */
  export let prompt = ''

  let copiedKey = null
  let reading = false

  $: installCommand = skillInstallCommand(skill.id, window.location.origin, assistant)

  async function copy(key, text) {
    const ok = await copyToClipboard(text)
    copiedKey = ok ? key : null
    setTimeout(() => { if (copiedKey === key) copiedKey = null }, 2000)
  }

  function label(key) {
    return copiedKey === key ? $t('common.actions.copied') : $t('common.actions.copy')
  }
</script>

<div class="skill-block">
  <div class="skill-heading">
    <button
      type="button"
      class="skill-name t-mono"
      on:click|stopPropagation={() => (reading = true)}
      title={$t('skills.readTitle')}
    >{skill.id}</button>
    {#if skill.description}<span class="skill-desc text-muted">{skill.description}</span>{/if}
  </div>

  <span class="skill-copy-label text-muted">{$t('skills.installLabel')}</span>
  <div class="copy-block skill-copy-block">
    <span class="copy-block-text">{installCommand}</span>
    <button class="copy-btn" on:click={() => copy('install', installCommand)}>{label('install')}</button>
  </div>

  {#if prompt}
    <span class="skill-copy-label text-muted">{$t('skills.promptLabel')}</span>
    <div class="copy-block skill-copy-block">
      <span class="copy-block-text">{prompt}</span>
      <button class="copy-btn" on:click={() => copy('prompt', prompt)}>{label('prompt')}</button>
    </div>
  {/if}
</div>

{#if reading}
  <SkillTextModal skillId={skill.id} description={skill.description} on:close={() => (reading = false)} />
{/if}

<style>
  .skill-block {
    display: flex;
    flex-direction: column;
    gap: 4px;
    padding: 10px 12px;
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: var(--radius);
  }
  .skill-heading { display: flex; flex-wrap: wrap; gap: 6px 10px; align-items: baseline; }
  /* A control that reads as the heading it replaces: the name is still the label, it just
     now opens the document. */
  .skill-name {
    min-height: 0;
    padding: 0;
    border: 0;
    background: none;
    font-size: 13px;
    font-weight: 600;
    color: var(--accent);
    cursor: pointer;
    text-align: left;
    text-decoration: underline;
    text-underline-offset: 2px;
  }
  .skill-name:hover { color: var(--accent-strong, var(--accent)); }
  .skill-desc { font-size: 12px; }
  .skill-copy-label { font-size: 11px; text-transform: uppercase; letter-spacing: 0.03em; margin-top: 2px; }
  .skill-copy-block { font-size: 12px; }
</style>
