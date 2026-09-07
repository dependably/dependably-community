<script>
  /**
   * The Skills tab — the curated remediation skills this instance ships, browsable rather
   * than reachable only from an advisory that happens to map to one.
   *
   * The client-config skills are deliberately absent: one is selected by (ecosystem, scope),
   * which is exactly what the Connect tab has already asked, so they appear there as an
   * alternative to copying a configuration instead of as a second grid re-asking both.
   */
  import { onMount } from 'svelte'
  import { t } from 'svelte-i18n'
  import { api } from '../api.js'
  import AssistantPicker from '../AssistantPicker.svelte'
  import SkillCard from '../SkillCard.svelte'
  import ErrorBanner from '../ErrorBanner.svelte'
  import LoadingSpinner from '../LoadingSpinner.svelte'
  import { copyToClipboard } from '../clipboard.js'
  import { readStoredAssistant, skillInstallAllCommand, skillsBundleUrl } from '../skills.js'

  let skills = []
  let loading = true
  let error = ''
  let assistant = readStoredAssistant()
  let copiedAll = false

  // Two ways to take the whole set, answering different questions. The command installs every
  // skill where the chosen assistant already looks for it — the normal case, and the reason it
  // comes first. The zip is for carrying the corpus somewhere this instance cannot reach.
  $: installAllCommand = skillInstallAllCommand(skills.map(s => s.id), window.location.origin, assistant)
  const bundleUrl = skillsBundleUrl('remediation')

  async function copyAll() {
    copiedAll = await copyToClipboard(installAllCommand)
    setTimeout(() => { copiedAll = false }, 2000)
  }

  onMount(async () => {
    try {
      skills = (await api.getRemediationSkills()) ?? []
    } catch (e) {
      error = e.message
    } finally {
      loading = false
    }
  })
</script>

<div class="card skills-card">
  <p class="intro">{$t('setup.skills.intro')}</p>

  <ErrorBanner message={error} />

  {#if loading}
    <LoadingSpinner />
  {:else if skills.length === 0}
    {#if !error}
      <p class="text-muted">{$t('setup.skills.none')}</p>
    {/if}
  {:else}
    <div class="picker-row">
      <span class="picker-label">{$t('setup.skills.assistantLabel')}</span>
      <AssistantPicker bind:assistant label={$t('setup.skills.assistantLabel')} />
    </div>

    <section class="bulk">
      <div class="bulk-head">
        <span class="bulk-title">{$t('setup.skills.allTitle')}</span>
        <a class="btn-link" href={bundleUrl} download data-testid="download-all-skills">
          {$t('setup.skills.downloadAll')}
        </a>
      </div>
      <div class="copy-block skill-copy-block">
        <span class="copy-block-text">{installAllCommand}</span>
        <button class="copy-btn" on:click={copyAll}>
          {copiedAll ? $t('common.actions.copied') : $t('common.actions.copy')}
        </button>
      </div>
      <p class="form-hint">{$t('setup.skills.allHint')}</p>
    </section>

    <div class="skill-list">
      {#each skills as skill (skill.id)}
        <SkillCard {skill} {assistant} />
      {/each}
    </div>
  {/if}
</div>

<style>
  .skills-card { padding: 20px; }

  .intro {
    margin: 0 0 16px;
    color: var(--text2);
    max-width: 70ch;
  }

  .picker-row {
    display: flex;
    flex-wrap: wrap;
    gap: 6px 12px;
    align-items: center;
    margin-bottom: 14px;
  }

  .picker-label {
    font-size: 12px;
    font-weight: 600;
    color: var(--text2);
  }

  .skill-list {
    display: flex;
    flex-direction: column;
    gap: 10px;
  }

  .bulk {
    margin-bottom: 18px;
    padding-bottom: 16px;
    border-bottom: 1px solid var(--border);
  }

  .bulk-head {
    display: flex;
    flex-wrap: wrap;
    gap: 8px 16px;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 6px;
  }

  .bulk-title { font-size: 13px; font-weight: 600; color: var(--text); }

  .skill-copy-block { font-size: 12px; }

  /* An anchor doing a button's job, so it borrows a button's box. */
  .btn-link {
    display: inline-flex;
    align-items: center;
    min-height: 30px;
    padding: 0 12px;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    background: var(--bg2);
    color: var(--text);
    font-size: 12px;
    text-decoration: none;
  }
  .btn-link:hover { background: var(--bg3); }
</style>
