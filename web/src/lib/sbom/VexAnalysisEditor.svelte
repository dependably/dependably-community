<!--
  VEX analysis for one advisory: a read view every member sees, and an edit form admins and
  owners get.

  The editor always writes CycloneDX vocabulary. An OpenVEX statement that arrived through an
  upload is displayed through the same normalized enum, so the reader never has to know which
  document format the statement came from — and an edit made here is recorded in the vocabulary
  the exports emit.

  Only changed fields are submitted (see `triagePatch`): the endpoint carries its partial-update
  fields as Optional<T>, where an absent field means "leave unchanged" and an explicit null
  means "clear". Sending the whole object back would overwrite fields another uploader owns.

  Props:
    advisory   the advisory as it arrived in the analysis payload
    purlKey    the component key the analysis row is stored under
    canEdit    admin/owner — the parent resolves the role and passes the answer down
    saving     true while the parent's PUT is in flight
    error      message from a failed save, rendered inline beside the form
    saveToken  the parent increments this after a successful save; the form closes on the
               change rather than on a guess about the refreshed values

  Events:
    save    { body } — the request body for PUT …/analysis
    cancel  the operator dismissed the form
-->
<script>
  import { createEventDispatcher } from 'svelte'
  import { t } from 'svelte-i18n'
  import { formatDate } from '../format.js'
  import {
    VEX_JUSTIFICATIONS,
    VEX_RESPONSES,
    VEX_STATES,
    justificationEnabled,
    triagePatch,
    triagePatchIsEmpty,
  } from './analysis.js'

  /** @type {Record<string, any>} */
  export let advisory = {}
  export let purlKey = ''
  export let canEdit = false
  export let saving = false
  export let error = ''
  export let saveToken = 0

  const dispatch = createEventDispatcher()

  let editing = false
  let draftState = ''
  let draftJustification = ''
  let draftResponse = ''
  let draftDetail = ''

  function beginEdit() {
    draftState = advisory.vexState ?? ''
    draftJustification = advisory.vexJustification ?? ''
    draftResponse = advisory.vexResponse ?? ''
    draftDetail = advisory.vexDetail ?? ''
    editing = true
  }

  function cancel() {
    editing = false
    dispatch('cancel')
  }

  function save() {
    dispatch('save', { body })
  }

  // A bare helper call in markup is not reactive — mirror both through `$:` so the disabled
  // state and the submitted body track every keystroke.
  $: draft = {
    vexState: draftState,
    vexJustification: draftJustification,
    vexResponse: draftResponse,
    vexDetail: draftDetail,
  }
  $: body = triagePatch({ purlKey, vulnKey: advisory.vulnKey }, advisory, draft)
  $: unchanged = triagePatchIsEmpty(body)
  $: justificationOn = justificationEnabled(draftState)

  // The parent bumps `saveToken` once its PUT has landed. Closing on that signal — rather than
  // on the shape of the refreshed values — keeps a form the operator reverted by hand open, and
  // keeps a failed save from looking like a successful one.
  let seenSaveToken = saveToken
  function closeOnSave(token) {
    if (token === seenSaveToken) return
    seenSaveToken = token
    editing = false
  }
  $: closeOnSave(saveToken)
</script>

<div class="vex-analysis">
  <div class="vex-head">
    <span class="detail-label">{$t('sbomAnalysis.vex.title')}</span>
    {#if advisory.vexState}
      <span class="badge vex-{advisory.vexState}" aria-label={$t(`sbomAnalysis.vex.state.${advisory.vexState}`)}>
        {$t(`sbomAnalysis.vex.state.${advisory.vexState}`)}
      </span>
    {:else}
      <span class="text-muted t-sm">{$t('sbomAnalysis.vex.noState')}</span>
    {/if}
    {#if canEdit && !editing}
      <span class="btn-row vex-edit-trigger">
        <button type="button" on:click|stopPropagation={beginEdit}>{$t('sbomAnalysis.vex.edit')}</button>
      </span>
    {/if}
  </div>

  {#if !editing}
    <div class="vex-read">
      {#if advisory.vexJustification}
        <div class="vex-field">
          <span class="detail-label">{$t('sbomAnalysis.vex.justification')}</span>
          <span class="detail-value">{$t(`sbomAnalysis.vex.justificationValue.${advisory.vexJustification}`)}</span>
        </div>
      {/if}
      {#if advisory.vexResponse}
        <div class="vex-field">
          <span class="detail-label">{$t('sbomAnalysis.vex.response')}</span>
          <span class="detail-value">{$t(`sbomAnalysis.vex.responseValue.${advisory.vexResponse}`)}</span>
        </div>
      {/if}
      {#if advisory.vexDetail}
        <div class="vex-field">
          <span class="detail-label">{$t('sbomAnalysis.vex.detail')}</span>
          <span class="detail-value">{advisory.vexDetail}</span>
        </div>
      {/if}
      <p class="vex-provenance">
        {#if advisory.vexSource === 'manual'}
          {#if advisory.vexUpdatedBy && advisory.vexUpdatedAt}
            {$t('sbomAnalysis.vex.provenance.manual', { values: { actor: advisory.vexUpdatedBy, at: $formatDate(advisory.vexUpdatedAt) } })}
          {:else}
            {$t('sbomAnalysis.vex.provenance.manualPlain')}
          {/if}
        {:else if advisory.vexSource === 'sarif'}
          {$t('sbomAnalysis.vex.provenance.sarif')}
        {:else if advisory.vexSource}
          {$t('sbomAnalysis.vex.provenance.uploaded')}
        {:else}
          {$t('sbomAnalysis.vex.provenance.none')}
        {/if}
      </p>
      {#if advisory.inherited}
        <!-- A decision carried forward from an earlier release keeps its original provenance
             rather than being restamped, so its date alone would read as a fresh call for this
             release. The server marks it inherited whenever that date predates this version. -->
        <p class="vex-inherited" title={$t('sbomAnalysis.panel.inheritedHelp')}>
          {$t('sbomAnalysis.panel.inherited', { values: { at: $formatDate(advisory.vexUpdatedAt) } })}
        </p>
      {/if}
    </div>
  {:else}
    <div class="vex-form">
      <label class="vex-field">
        <span class="detail-label">{$t('sbomAnalysis.vex.state.label')}</span>
        <select bind:value={draftState} on:click|stopPropagation disabled={saving}>
          <option value="">{$t('sbomAnalysis.vex.noState')}</option>
          {#each VEX_STATES as s (s)}
            <option value={s}>{$t(`sbomAnalysis.vex.state.${s}`)}</option>
          {/each}
        </select>
      </label>

      <label class="vex-field">
        <span class="detail-label">{$t('sbomAnalysis.vex.justification')}</span>
        <select bind:value={draftJustification} on:click|stopPropagation disabled={saving || !justificationOn}>
          <option value="">{$t('sbomAnalysis.vex.none')}</option>
          {#each VEX_JUSTIFICATIONS as j (j)}
            <option value={j}>{$t(`sbomAnalysis.vex.justificationValue.${j}`)}</option>
          {/each}
        </select>
      </label>
      {#if !justificationOn}
        <p class="form-hint vex-hint">{$t('sbomAnalysis.vex.justificationHint')}</p>
      {/if}

      <label class="vex-field">
        <span class="detail-label">{$t('sbomAnalysis.vex.response')}</span>
        <select bind:value={draftResponse} on:click|stopPropagation disabled={saving}>
          <option value="">{$t('sbomAnalysis.vex.none')}</option>
          {#each VEX_RESPONSES as r (r)}
            <option value={r}>{$t(`sbomAnalysis.vex.responseValue.${r}`)}</option>
          {/each}
        </select>
      </label>

      <label class="vex-field col">
        <span class="detail-label">{$t('sbomAnalysis.vex.detail')}</span>
        <textarea rows="2" bind:value={draftDetail} on:click|stopPropagation disabled={saving}></textarea>
      </label>

      {#if error}
        <p class="vex-error">{error}</p>
      {/if}

      <div class="btn-row">
        <button type="button" class="primary" disabled={saving || unchanged} on:click|stopPropagation={save}>
          {saving ? $t('common.actions.saving') : $t('common.actions.save')}
        </button>
        <button type="button" disabled={saving} on:click|stopPropagation={cancel}>{$t('common.actions.cancel')}</button>
      </div>
    </div>
  {/if}
</div>

<style>
  .vex-analysis {
    display: flex;
    flex-direction: column;
    gap: 6px;
    border-top: 1px solid var(--border);
    padding-top: 8px;
  }
  .vex-head { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
  .vex-edit-trigger button { min-height: 26px; }
  .vex-read, .vex-form { display: flex; flex-direction: column; gap: 6px; }
  .vex-field { display: flex; gap: 10px; align-items: baseline; }
  .vex-field.col { flex-direction: column; gap: 4px; align-items: stretch; }
  .vex-field select { width: auto; max-width: 320px; }
  .vex-field textarea { font: inherit; resize: vertical; }
  .vex-hint { margin: 0; }
  .vex-provenance { margin: 0; color: var(--text2); font-size: 12px; }
  .vex-inherited { margin: 0; color: var(--warning-text); font-size: 12px; font-style: italic; }
  .vex-error { margin: 0; color: var(--danger); font-size: 12px; }
</style>
