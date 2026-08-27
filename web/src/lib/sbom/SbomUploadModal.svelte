<!--
  SbomUploadModal — shared multi-file SBOM/VEX/SARIF upload modal.

  Not a page: mounted by the caller with an `{#if}` block, the same pattern as
  LicenseTextModal.svelte — this component renders unconditionally once instantiated, so the
  parent controls visibility by mounting/unmounting it.

  Import (relative from web/src/pages/*.svelte):
    import SbomUploadModal from '../lib/sbom/SbomUploadModal.svelte'

  Usage:
    {#if showUpload}
      <SbomUploadModal
        presetProjectId={project?.id}
        presetProjectName={project?.name}
        presetVersionLabel={version?.version}
        presetIsCollection={project?.kind === 'collection'}
        on:uploaded={(e) => { showUpload = e.detail.anyAccepted ? showUpload : showUpload; reload() }}
        on:close={() => showUpload = false}
      />
    {/if}

  Props (all optional):
    presetProjectId    {string|null}  pre-selects this project in the picker (project-detail
                                       entry point). The picker stays editable — this only sets
                                       the initial selection.
    presetProjectName  {string|null}  display label paired with presetProjectId, used before the
                                       project list finishes loading (avoids a flash of "").
    presetVersionLabel {string|null}  pre-fills the version text input (version-detail entry
                                       point). Still a plain editable text input, not a lock.
    presetIsCollection {boolean}      defensive backstop: collections accept no uploads (the
                                       server 409s), so this renders a notice instead of the form
                                       instead of round-tripping a guaranteed rejection. Callers
                                       are expected to hide their trigger button on collections
                                       entirely; collections are hidden from the upload
                                       entry points that would otherwise pass this prop.

  Events:
    on:uploaded  detail: { anyAccepted: boolean,
                            results: Array<{ filename: string, kind: string, status: string }> }
                 Dispatched once per submitted batch, after every staged file has resolved
                 (accepted or rejected) — never mid-batch. The mounting page uses this to refresh
                 its own list/detail data; the modal does not close itself.
    on:close     Dispatched on Escape, a backdrop click, or the Cancel button. Ignored while a
                 batch is mid-upload (uploading is a state the operator should not silently lose).

  Gating: the component checks the session's role and renders a notice (not the form) for
  everyone except admin/owner, as a defensive backstop — callers are expected to hide the
  trigger button entirely for non-admin/owner sessions (API tokens are the CI upload path).
-->
<script>
  import { createEventDispatcher, onMount } from 'svelte'
  import { t } from 'svelte-i18n'
  import { api } from '../api.js'
  import { user } from '../store.js'
  import { extractErrorMessage } from '../form.js'
  import { copyToClipboard } from '../clipboard.js'
  import { sniffDocumentText, DOCUMENT_KIND_ENDPOINT } from './sniff.js'
  import { orderStagedFiles, describeSuccess, describeFailure } from './outcome.js'
  import { buildCurlSnippet } from './curlSnippet.js'

  /** @type {string | null} */
  export let presetProjectId = null
  /** @type {string | null} */
  export let presetProjectName = null
  /** @type {string | null} */
  export let presetVersionLabel = null
  export let presetIsCollection = false

  /**
   * The folder an upload launched from a collection page files into, and the label to show for it.
   * A project name is unique within its parent scope rather than across the org, so this is what
   * makes "upload into THIS folder" expressible at all — without it the server resolves the name
   * in the root scope and a new project silently lands at the top level instead of in the folder
   * the operator was looking at.
   * @type {string | null}
   */
  export let presetParentId = null
  /** @type {string | null} */
  export let presetParentName = null

  const dispatch = createEventDispatcher()

  $: isAdmin = $user?.role === 'admin' || $user?.role === 'owner'

  // ── Project / version target ────────────────────────────────────────────────
  let projects = []
  let loadingProjects = false
  let projectsError = ''
  let newProjectMode = !presetProjectId
  let selectedProjectId = presetProjectId ?? ''
  // The folder every request in this batch targets. Fixed for the modal's lifetime: it is the page
  // the operator opened it from, not something the form lets them re-point.
  const parentId = presetParentId
  let newProjectName = ''
  let versionInput = presetVersionLabel ?? ''
  let autoCreate = true
  // Off by default — promoting a version to "latest" is a side effect on the whole project,
  // not something an upload should do implicitly. The checkbox lets an operator opt in per batch.
  let isLatest = false

  onMount(() => {
    loadProjects()
  })

  async function loadProjects() {
    loadingProjects = true
    projectsError = ''
    try {
      // Scoped to the folder this modal was opened from, because that is the scope the upload
      // targets: `listProjects` unfiltered returns ROOT-level rows only, so offering it inside a
      // folder would list projects the upload cannot reach while hiding the folder's own.
      const data = parentId
        ? { items: (await api.getProject(parentId))?.children ?? [] }
        : await api.listProjects({ limit: 200 })
      // Collections accept no uploads (409) — keep them out of the picker entirely.
      projects = (data?.items ?? []).filter((p) => p.kind !== 'collection')
    } catch (e) {
      projectsError = extractErrorMessage(e)
    } finally {
      loadingProjects = false
    }
  }

  let versionOptions = []
  let loadingVersions = false
  async function loadVersionsFor(projectId) {
    loadingVersions = true
    try {
      const data = await api.getProject(projectId)
      versionOptions = (data?.versions ?? []).map((v) => v.version)
    } catch {
      versionOptions = []
    } finally {
      loadingVersions = false
    }
  }
  // Directly reactive to newProjectMode/selectedProjectId (not routed through a helper call) so
  // the version datalist actually refreshes on selection change.
  $: if (!newProjectMode && selectedProjectId) loadVersionsFor(selectedProjectId)
  $: if (newProjectMode) versionOptions = []

  // Resolves inline (not via a called helper) so every dependency — newProjectMode,
  // newProjectName, projects, selectedProjectId, the preset props — is visible to Svelte's
  // reactivity tracker; a bare `resolveProjectName()` call here would silently go stale.
  $: currentProjectName = newProjectMode
    ? newProjectName.trim()
    : (projects.find((p) => p.id === selectedProjectId)?.name
        ?? (selectedProjectId && selectedProjectId === presetProjectId ? (presetProjectName ?? '') : ''))

  // ── Staged files ─────────────────────────────────────────────────────────────
  let staged = []   // { id, file, text, kind, parseError, status, outcomeText, outcomeKey, outcomeValues }
  let nextId = 0
  let dragOver = false
  let uploading = false
  let formError = ''

  async function addFiles(fileList) {
    const files = fileList ? Array.from(fileList) : []
    for (const file of files) {
      const text = await file.text()
      const { kind } = sniffDocumentText(text)
      staged = [...staged, {
        id: nextId++, file, text, kind,
        status: 'pending', outcomeText: null, outcomeKey: null, outcomeValues: {},
      }]
    }
  }

  function onDragEnter(e) { e.preventDefault(); dragOver = true }
  function onDragLeave(e) { e.preventDefault(); dragOver = false }
  function onDragOver(e)  { e.preventDefault(); dragOver = true }
  function onDrop(e) {
    e.preventDefault()
    dragOver = false
    addFiles(e.dataTransfer?.files)
  }
  function onFileInput(e) {
    addFiles(e.target.files)
    e.target.value = ''
  }
  function removeFile(id) {
    staged = staged.filter((f) => f.id !== id)
  }
  function setKind(id, kind) {
    staged = staged.map((f) => (f.id === id ? { ...f, kind } : f))
  }

  $: submittableCount = staged.filter((f) => f.status !== 'accepted').length
  $: canSubmit = !uploading && submittableCount > 0
    && currentProjectName.length > 0 && versionInput.trim().length > 0

  async function submit() {
    if (!canSubmit) return
    formError = ''
    uploading = true
    const projectName = currentProjectName
    const projectVersion = versionInput.trim()
    const ordered = orderStagedFiles(staged.filter((f) => f.status !== 'accepted'))

    for (const item of ordered) {
      staged = staged.map((f) => (f.id === item.id ? { ...f, status: 'uploading' } : f))
      const submitKind = DOCUMENT_KIND_ENDPOINT[item.kind] ?? 'sbom'
      try {
        let response
        if (submitKind === 'vex') {
          response = await api.uploadVexDocument(projectName, projectVersion, parentId, item.text)
        } else if (submitKind === 'sarif') {
          response = await api.uploadSarifDocument(projectName, projectVersion, parentId, item.text)
        } else {
          response = await api.uploadSbomDocument(
            projectName, projectVersion, { autoCreate, isLatest, parentId }, item.text)
        }
        const d = describeSuccess(submitKind, response)
        staged = staged.map((f) => (f.id === item.id
          ? { ...f, status: 'accepted', outcomeKey: d.key, outcomeValues: d.values, outcomeText: null }
          : f))
      } catch (e) {
        const d = describeFailure(e)
        staged = staged.map((f) => (f.id === item.id
          ? { ...f, status: 'rejected', outcomeKey: d.key, outcomeValues: d.values, outcomeText: d.text }
          : f))
      }
    }

    uploading = false
    const results = staged.map((f) => ({ filename: f.file.name, kind: f.kind, status: f.status }))
    dispatch('uploaded', { anyAccepted: results.some((r) => r.status === 'accepted'), results })
  }

  // ── Curl snippet ─────────────────────────────────────────────────────────────
  // Not reactive — window.location.origin cannot change during the modal's lifetime.
  const curlOrigin = typeof window !== 'undefined' ? window.location.origin : ''
  $: curlSnippet = buildCurlSnippet({
    origin: curlOrigin, projectName: currentProjectName, projectVersion: versionInput,
    autoCreate, isLatest, parentId,
  })
  let copyState = ''
  async function copyCurl() {
    const ok = await copyToClipboard(curlSnippet)
    copyState = ok ? 'copied' : 'failed'
    setTimeout(() => { copyState = '' }, 2000)
  }

  // ── Modal chrome ─────────────────────────────────────────────────────────────
  function close() {
    if (uploading) return
    dispatch('close')
  }
  function onKeydown(e) {
    if (e.key === 'Escape') close()
  }
</script>

<div
  class="modal-backdrop"
  role="dialog"
  aria-modal="true"
  aria-labelledby="sbom-upload-title"
  tabindex="-1"
  on:click|self={close}
  on:keydown={onKeydown}
>
  <div class="modal scrollable modal-flex sbom-upload-modal">
    <h2 id="sbom-upload-title">{$t('sbomUpload.title')}</h2>

    {#if presetIsCollection}
      <div class="info-card"><p>{$t('sbomUpload.collectionNotice')}</p></div>
      <div class="modal-actions">
        <button type="button" on:click={close}>{$t('common.actions.cancel')}</button>
      </div>
    {:else if !isAdmin}
      <div class="info-card"><p>{$t('sbomUpload.notAllowed')}</p></div>
      <div class="modal-actions">
        <button type="button" on:click={close}>{$t('common.actions.cancel')}</button>
      </div>
    {:else}
      <p class="form-hint">{$t('sbomUpload.hint')}</p>

      <label
        class="dropzone"
        class:dragOver
        on:dragenter={onDragEnter}
        on:dragleave={onDragLeave}
        on:dragover={onDragOver}
        on:drop={onDrop}
      >
        <input type="file" multiple accept=".json,.sarif" on:change={onFileInput} hidden disabled={uploading} />
        <svg width="20" height="20" aria-hidden="true"><use href="/icons.svg#icon-upload" /></svg>
        <div class="dropzone-text">{$t('sbomUpload.drop')}</div>
      </label>

      {#if staged.length > 0}
        <ul class="staged-list">
          {#each staged as item (item.id)}
            <li class="staged-item">
              <span class="file-name mono">{item.file.name}</span>
              <select
                class="kind-select"
                value={item.kind}
                on:change={(e) => setKind(item.id, (/** @type {HTMLSelectElement} */ (e.target)).value)}
                disabled={uploading || item.status === 'accepted'}
                aria-label={$t('sbomUpload.kindLabel')}
              >
                {#if item.kind === 'unknown'}
                  <option value="unknown" disabled>{$t('sbomUpload.kind.unknown')}</option>
                {/if}
                <option value="sbom">{$t('sbomUpload.kind.sbom')}</option>
                <option value="vex">{$t('sbomUpload.kind.vex')}</option>
                <option value="sarif">{$t('sbomUpload.kind.sarif')}</option>
              </select>
              {#if item.status === 'uploading'}
                <span class="spinner" aria-hidden="true"></span>
              {:else if item.status === 'accepted'}
                <span class="badge outcome-accepted">{$t('sbomUpload.outcome.accepted')}</span>
              {:else if item.status === 'rejected'}
                <span class="badge outcome-rejected">{$t('sbomUpload.outcome.rejected')}</span>
              {:else}
                <button
                  type="button"
                  class="file-remove"
                  title={$t('common.actions.remove')}
                  aria-label={$t('common.actions.remove')}
                  on:click={() => removeFile(item.id)}
                  disabled={uploading}
                >×</button>
              {/if}
            </li>
          {/each}
        </ul>
      {/if}

      <label>
        {$t('sbomUpload.project.label')}
        {#if newProjectMode}
          <input
            type="text"
            bind:value={newProjectName}
            placeholder={$t('sbomUpload.project.newPlaceholder')}
            disabled={uploading}
          />
        {:else}
          <select bind:value={selectedProjectId} disabled={uploading || loadingProjects}>
            <option value="">{$t('sbomUpload.project.choose')}</option>
            {#each projects as p (p.id)}
              <option value={p.id}>{p.name}</option>
            {/each}
          </select>
        {/if}
      </label>
      {#if presetParentName}
        <!-- Say where this lands. The picker below lists only this folder's projects and a new one
             is created inside it, neither of which is visible from the form alone. -->
        <p class="form-hint">{$t('sbomUpload.project.intoFolder', { values: { folder: presetParentName } })}</p>
      {/if}
      {#if projectsError}<div class="error-msg">{projectsError}</div>{/if}
      <button
        type="button"
        class="link-btn"
        on:click={() => { newProjectMode = !newProjectMode }}
        disabled={uploading}
      >
        {newProjectMode ? $t('sbomUpload.project.chooseExisting') : $t('sbomUpload.project.createNew')}
      </button>

      <label>
        {$t('sbomUpload.version.label')}
        <input
          type="text"
          list="sbom-upload-version-options"
          bind:value={versionInput}
          placeholder={$t('sbomUpload.version.placeholder')}
          disabled={uploading}
        />
        <datalist id="sbom-upload-version-options">
          {#each versionOptions as v (v)}<option value={v}></option>{/each}
        </datalist>
        {#if loadingVersions}<span class="text-muted t-sm">{$t('common.loading')}</span>{/if}
      </label>

      <label class="checkbox-row">
        <input type="checkbox" bind:checked={autoCreate} disabled={uploading} />
        {$t('sbomUpload.autoCreate')}
      </label>
      <label class="checkbox-row">
        <input type="checkbox" bind:checked={isLatest} disabled={uploading} />
        {$t('sbomUpload.isLatest')}
      </label>

      {#if formError}<div class="error-msg">{formError}</div>{/if}

      <button class="primary upload-submit" on:click={submit} disabled={!canSubmit}>
        {uploading ? $t('sbomUpload.uploading') : $t('sbomUpload.submit')}
      </button>

      {#if staged.some((f) => f.status === 'accepted' || f.status === 'rejected')}
        <div class="result-card">
          <table class="table-auto outcome-table">
            <thead>
              <tr>
                <th>{$t('sbomUpload.outcome.file')}</th>
                <th>{$t('sbomUpload.outcome.type')}</th>
                <th>{$t('sbomUpload.outcome.status')}</th>
                <th>{$t('sbomUpload.outcome.detailColumn')}</th>
              </tr>
            </thead>
            <tbody>
              {#each staged.filter((f) => f.status === 'accepted' || f.status === 'rejected') as item (item.id)}
                <tr class="outcome-row outcome-{item.status}">
                  <td class="mono file-name">{item.file.name}</td>
                  <td><span class="badge">{$t(`sbomUpload.kind.${item.kind}`)}</span></td>
                  <td>
                    <span class="badge outcome-{item.status}">
                      {$t(item.status === 'accepted' ? 'sbomUpload.outcome.accepted' : 'sbomUpload.outcome.rejected')}
                    </span>
                  </td>
                  <td class="text-muted">
                    {item.outcomeText ?? $t(item.outcomeKey, { values: item.outcomeValues })}
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}

      <details class="curl-details">
        <summary>{$t('sbomUpload.curl.summary')}</summary>
        <div class="copy-block snippet-block">
          <span class="copy-block-text">{curlSnippet}</span>
          <button type="button" class="copy-btn" on:click={copyCurl}>
            {copyState === 'copied' ? $t('common.actions.copied') : copyState === 'failed' ? $t('common.actions.copyFailed') : $t('common.actions.copy')}
          </button>
        </div>
      </details>

      <div class="modal-actions">
        <button type="button" on:click={close} disabled={uploading}>{$t('common.actions.cancel')}</button>
      </div>
    {/if}
  </div>
</div>

<style>
  .sbom-upload-modal { width: min(640px, 92vw); }

  .dropzone {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 6px;
    cursor: pointer;
    border: 2px dashed var(--border);
    border-radius: var(--radius);
    padding: 20px 14px;
    text-align: center;
    background: var(--bg2);
    transition: border-color 0.15s, background 0.15s;
    color: var(--text2);
  }
  .dropzone:hover, .dropzone.dragOver {
    border-color: var(--accent);
    background: var(--accent-soft);
  }
  .dropzone-text { font-size: 13px; font-weight: 500; }

  .staged-list {
    list-style: none;
    padding: 0;
    margin: 0;
    max-height: 180px;
    overflow-y: auto;
    border: 1px solid var(--border);
    border-radius: 4px;
  }
  .staged-item {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 6px 10px;
    font-size: 13px;
    border-bottom: 1px solid var(--border);
  }
  .staged-item:last-child { border-bottom: none; }
  .file-name { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .kind-select { flex-shrink: 0; font-size: 12px; padding: 2px 4px; min-height: 26px; }
  .file-remove {
    flex-shrink: 0;
    width: 24px; height: 24px; min-height: 24px;
    padding: 0;
    line-height: 1;
    font-size: 16px;
    border: 1px solid var(--border);
    background: var(--bg);
    color: var(--text2);
    border-radius: 3px;
    cursor: pointer;
  }
  .file-remove:hover { background: var(--danger-bg); border-color: var(--danger-border); color: var(--danger); }

  .link-btn {
    align-self: flex-start;
    background: none;
    border: none;
    padding: 0;
    min-height: 0;
    color: var(--accent);
    font-size: 12px;
    cursor: pointer;
    text-decoration: underline;
  }

  .checkbox-row {
    flex-direction: row !important;
    align-items: center;
    gap: 6px !important;
    cursor: pointer;
  }
  .checkbox-row input { width: auto; margin: 0; }

  .upload-submit { align-self: flex-start; }

  .result-card { font-size: 13px; }
  .outcome-table { font-size: 12px; }
  .mono { font-family: var(--mono, monospace); }

  .curl-details { font-size: 13px; }
  .curl-details summary { cursor: pointer; color: var(--text2); }
</style>
