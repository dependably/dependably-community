<script>
  /**
   * The other way to complete step 3: instead of copying the configuration by hand, install
   * the curated skill that covers this cell and let an AI assistant write it.
   *
   * The skill is found in the index the instance actually served, keyed on (ecosystem, scope)
   * — never reconstructed from a naming rule here. A cell with no skill renders nothing at
   * all: the copy-the-configuration path above is always complete, so an absent shortcut
   * needs no explanation, and advertising an install command for a skill this binary cannot
   * hand back would be worse than silence.
   */
  import { t } from 'svelte-i18n'
  import AssistantPicker from '../AssistantPicker.svelte'
  import SkillCard from '../SkillCard.svelte'
  import { configSkillPrompt, findConfigSkill, readStoredAssistant } from '../skills.js'

  /** The `/api/v1/skills` index, or null while it is in flight or after it failed. */
  export let skillIndex = null
  export let ecosystem = ''
  export let scope = ''

  let assistant = readStoredAssistant()

  $: skill = findConfigSkill(skillIndex, ecosystem, scope)
  $: prompt = skill ? configSkillPrompt(skill.id, window.location.origin, assistant, scope) : ''
</script>

{#if skill}
  <section class="alternative">
    <div class="alternative-head">
      <span class="alternative-title">{$t('setup.skillAlternative.title')}</span>
      <AssistantPicker bind:assistant label={$t('setup.skillAlternative.assistantLabel')} />
    </div>
    <p class="form-hint">{$t('setup.skillAlternative.hint')}</p>
    <SkillCard {skill} {assistant} {prompt} />
  </section>
{/if}

<style>
  .alternative {
    margin-top: 18px;
    padding-top: 16px;
    border-top: 1px solid var(--border);
  }

  .alternative-head {
    display: flex;
    flex-wrap: wrap;
    gap: 6px 16px;
    align-items: center;
    margin-bottom: 4px;
  }

  .alternative-title {
    font-size: 13px;
    font-weight: 600;
    color: var(--text);
  }
</style>
