<!--
  Create-a-folder / edit-a-project modal for the projects plane.

  One component covers both because they are the same form: a folder IS a project with
  `kind: 'collection'`, and "relocate" is just the folder field of an edit. Splitting them would
  duplicate the picker, which is the only non-trivial part.

  Mode is inferred from `project`:
    project == null  → create, POSTing `kind: 'collection'` (the "New folder" entry point)
    project != null  → edit, PATCHing only the fields that actually changed

  The PATCH is deliberately sparse. The endpoint is leave-unchanged-on-absent, so sending an
  untouched field back is harmless but sending `parentId` when the reader never opened the folder
  select would make a stale option value silently relocate the project. Only changed keys go.

  Events:
    on:saved  detail: the created/updated project payload. The parent reloads its own list.
    on:close  Escape, backdrop, or Cancel. Ignored mid-save.
-->
<script>
  import { createEventDispatcher, onMount } from 'svelte'
  import { t } from 'svelte-i18n'
  import { api } from './api.js'
  import { extractErrorMessage } from './form.js'
  import { relocationTargets } from './projectPaths.js'
  import ErrorBanner from './ErrorBanner.svelte'

  /**
   * The row being edited, or null to create a new folder.
   * @type {{ id: string, name: string, description?: string | null, parentId?: string | null, kind?: string, isActive?: boolean } | null}
   */
  export let project = null

  const dispatch = createEventDispatcher()

  const isEdit = project !== null
  const isCollection = project?.kind === 'collection'

  // The list row this modal is opened from carries no description (the list API does not project
  // one), so an edit re-reads the project. Without that, the field would render empty for a
  // project that has a description — and an empty field that looks authoritative invites someone
  // to submit a change they believe is a rename and is silently also a description edit.
  // isActive defaults to true for a row that predates the field rather than to false: the modal
  // sends only what changed, and a checkbox that rendered unchecked for an active project would
  // let a plain rename retire it.
  let baseline = {
    name: project?.name ?? '',
    description: '',
    parentId: project?.parentId ?? '',
    isActive: project?.isActive ?? true,
  }

  let name = baseline.name
  let description = baseline.description
  let isActive = baseline.isActive
  // '' is the root. A select's option values are strings, so the root cannot be modelled as null
  // here; it is converted back to an explicit null on submit, which is what moves a row to root.
  let parentId = baseline.parentId

  let targets = []
  let loading = true
  let targetsError = ''
  let saving = false
  let error = ''

  $: canSubmit = name.trim().length > 0 && !saving && !loading

  onMount(async () => {
    const collections = api.listProjectCollections()
    const detail = project ? api.getProject(project.id) : Promise.resolve(null)

    try {
      const full = await detail
      if (full) {
        baseline = {
          name: full.name ?? baseline.name,
          description: full.description ?? '',
          parentId: full.parentId ?? '',
          isActive: full.isActive ?? true,
        }
        name = baseline.name
        description = baseline.description
        parentId = baseline.parentId
        isActive = baseline.isActive
      }
    } catch (e) {
      error = extractErrorMessage(e)
    }

    try {
      const data = await collections
      targets = relocationTargets(data.items ?? [], project?.id ?? null)
    } catch (e) {
      // A folder list that will not load must not block a rename. The select is disabled and
      // says so; the rest of the form still submits, and an untouched select sends no parentId.
      targetsError = extractErrorMessage(e)
      targets = []
    } finally {
      loading = false
    }
  })

  // The current parent may be absent from the picker — a failed load leaves `targets` empty, and
  // the exclusion rule itself never removes a project's own parent. Falling through to the root
  // option would then quietly offer to move the project out of its folder, so the current folder
  // is rendered as its own option instead.
  $: parentMissing = parentId !== '' && !loading && !targets.some((x) => x.id === parentId)

  async function submit() {
    if (!canSubmit) return
    saving = true
    error = ''
    try {
      const trimmedName = name.trim()
      const trimmedDescription = description.trim()

      if (!project) {
        const created = await api.createProject({
          name: trimmedName,
          kind: 'collection',
          description: trimmedDescription || null,
          parentId: parentId || null,
        })
        dispatch('saved', created)
        return
      }

      /** @type {Record<string, any>} */
      const patch = {}
      if (trimmedName !== baseline.name) patch.name = trimmedName
      if (trimmedDescription !== baseline.description) patch.description = trimmedDescription || null
      if (parentId !== baseline.parentId) patch.parentId = parentId || null
      if (isActive !== baseline.isActive) patch.isActive = isActive

      const updated = Object.keys(patch).length === 0
        ? project
        : await api.updateProject(project.id, patch)
      dispatch('saved', updated)
    } catch (e) {
      error = extractErrorMessage(e)
    } finally {
      saving = false
    }
  }

  function close() { if (!saving) dispatch('close') }
  function onKeydown(e) { if (e.key === 'Escape') close() }
  function onBackdropClick(e) { if (e.target === e.currentTarget) close() }

  $: title = isEdit
    ? (isCollection ? $t('projects.folders.editFolderTitle') : $t('projects.folders.editProjectTitle'))
    : $t('projects.folders.newFolderTitle')
</script>

<svelte:window on:keydown={onKeydown} />

<div class="overlay" on:click={onBackdropClick} role="presentation">
  <div class="dialog" role="dialog" aria-modal="true" aria-labelledby="project-edit-title">
    <header>
      <h2 id="project-edit-title">{title}</h2>
      <button class="close" on:click={close} aria-label={$t('common.actions.cancel')}>×</button>
    </header>

    <div class="body">
      <ErrorBanner message={error} />

      <label>
        {$t('projects.folders.nameLabel')}
        <!-- svelte-ignore a11y-autofocus -->
        <input
          type="text"
          bind:value={name}
          maxlength="200"
          autofocus
          placeholder={$t('projects.folders.namePlaceholder')}
          disabled={saving || loading}
        />
      </label>

      <label>
        {$t('projects.folders.descriptionLabel')}
        <input type="text" bind:value={description} maxlength="2000" disabled={saving || loading} />
      </label>

      <label>
        {$t('projects.folders.parentLabel')}
        <select bind:value={parentId} disabled={saving || loading || !!targetsError}>
          <option value="">{$t('projects.folders.rootOption')}</option>
          {#if parentMissing}
            <option value={parentId}>{$t('projects.folders.currentFolder')}</option>
          {/if}
          {#each targets as target (target.id)}
            <option value={target.id}>{target.label}</option>
          {/each}
        </select>
      </label>
      {#if targetsError}
        <p class="hint error-hint">{$t('projects.folders.targetsFailed', { values: { message: targetsError } })}</p>
      {:else}
        <p class="hint">{$t('projects.folders.parentHint')}</p>
      {/if}

      <!-- Offered on an edit only: a project is created active, and a create form that opened with
           the box already ticked would present a state nobody chose as a decision they made. -->
      {#if isEdit}
        <label class="check-row">
          <input type="checkbox" bind:checked={isActive} disabled={saving || loading} />
          <span>{$t('projects.status.activeLabel')}</span>
        </label>
        <p class="hint">
          {isCollection ? $t('projects.status.collectionHint') : $t('projects.status.projectHint')}
        </p>
      {/if}
    </div>

    <footer>
      <button type="button" on:click={close} disabled={saving}>{$t('common.actions.cancel')}</button>
      <button type="button" class="primary" on:click={submit} disabled={!canSubmit}>
        {saving ? $t('common.actions.saving') : $t('common.actions.save')}
      </button>
    </footer>
  </div>
</div>

<style>
  /* Checkbox and its label on one baseline; the block `label` rule above stacks them otherwise. */
  .body label.check-row {
    display: flex;
    align-items: center;
    gap: 8px;
    margin-bottom: 4px;
  }
  .body label.check-row input { width: auto; }

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
    max-width: 460px;
    max-height: 90vh;
    display: flex;
    flex-direction: column;
    overflow: hidden;
    box-shadow: var(--shadow);
  }
  header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 12px 20px;
    border-bottom: 1px solid var(--border);
  }
  h2 { margin: 0; font-size: 16px; font-weight: 600; }
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
  .body { padding: 16px 20px; overflow-y: auto; }
  .body label { display: block; margin-bottom: 12px; }
  .hint { margin: -6px 0 0; font-size: 12px; color: var(--text2); }
  .error-hint { color: var(--badge-red-text); }
  footer {
    display: flex;
    justify-content: flex-end;
    gap: 8px;
    padding: 12px 20px;
    border-top: 1px solid var(--border);
  }
</style>
