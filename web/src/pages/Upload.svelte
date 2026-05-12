<script>
  import { t } from 'svelte-i18n'
  import { api } from '../lib/api.js'

  let files = []
  let dragOver = false
  let uploading = false
  let lastResult = null
  let error = ''

  // Index of original File objects keyed by filename. We need it to re-submit a single
  // file after a claim-and-upload action without re-prompting the operator.
  let fileIndex = new Map()

  // Claim-and-upload modal state. Triggered when an outcome row has code === 'claim_required'.
  // The server fills in ecosystem + name on the rejection so we never have to guess.
  let claimModal = null   // null | { filename, ecosystem, name }
  let claimState = 'local_only', claimReason = '', claimAck = false
  let claimError = '', claimSubmitting = false

  function pickFiles(list) {
    files = list ? Array.from(list) : []
    fileIndex = new Map(files.map(f => [f.name, f]))
    error = ''
    lastResult = null
  }

  function onDragEnter(e) { e.preventDefault(); dragOver = true }
  function onDragLeave(e) { e.preventDefault(); dragOver = false }
  function onDragOver(e)  { e.preventDefault(); dragOver = true }
  function onDrop(e) {
    e.preventDefault()
    dragOver = false
    pickFiles(e.dataTransfer?.files)
  }

  function onFileInput(e) {
    pickFiles(e.target.files)
  }

  function removeFile(file) {
    files = files.filter(f => !(f.name === file.name && f.size === file.size))
    fileIndex = new Map(files.map(f => [f.name, f]))
    // Drop any result tied to the previous staging — once the user has edited the list,
    // the outcome table no longer reflects what they're about to submit.
    lastResult = null
  }

  async function submit() {
    if (files.length === 0 || uploading) return
    uploading = true
    error = ''
    lastResult = null
    try {
      lastResult = await api.upload(files)
      if ((lastResult?.rejected ?? 0) === 0) files = []
    } catch (e) {
      error = e.body?.detail || e.message
    } finally {
      uploading = false
    }
  }

  function openClaimModal(outcome) {
    if (!outcome.name || !outcome.ecosystem) return
    claimModal = { filename: outcome.filename, ecosystem: outcome.ecosystem, name: outcome.name }
    claimState = 'local_only'
    claimReason = ''
    claimAck = false
    claimError = ''
  }

  function closeClaimModal() {
    claimModal = null
    claimError = ''
  }

  async function submitClaimAndReupload() {
    if (claimSubmitting) return
    if (!claimReason.trim()) { claimError = 'Reason is required.'; return }
    if (claimState === 'mixed' && !claimAck) {
      claimError = $t('claims.modal.mixedWarning'); return
    }
    claimSubmitting = true
    claimError = ''
    try {
      await api.createClaim({
        ecosystem: claimModal.ecosystem,
        name: claimModal.name,
        state: claimState,
        reason: claimReason.trim(),
      })
      const file = fileIndex.get(claimModal.filename)
      if (!file) {
        claimError = `Original file '${claimModal.filename}' is no longer in the staging list. Re-upload manually.`
        return
      }
      const reupload = await api.upload([file])
      if (lastResult && reupload?.outcomes?.length === 1) {
        const newOutcome = reupload.outcomes[0]
        lastResult = {
          ...lastResult,
          accepted: lastResult.accepted + (newOutcome.status === 'accepted' ? 1 : 0),
          rejected: lastResult.rejected
            + (newOutcome.status === 'rejected' ? 1 : 0)
            - 1,
          outcomes: lastResult.outcomes.map(o =>
            o.filename === newOutcome.filename ? newOutcome : o),
        }
      }
      closeClaimModal()
    } catch (e) {
      claimError = e.body?.detail || e.message
    } finally {
      claimSubmitting = false
    }
  }

  $: totalBytes = files.reduce((acc, f) => acc + (f.size ?? 0), 0)

  function formatBytes(n) {
    if (n < 1024) return `${n} B`
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
    if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`
    return `${(n / 1024 / 1024 / 1024).toFixed(2)} GB`
  }
</script>

<div class="page">
  <div class="page-header">
    <h1 class="page-title">{$t('upload.title')}</h1>
  </div>
  <p class="text-muted desc">{$t('upload.description')}</p>

  <label
    class="dropzone"
    class:dragOver
    on:dragenter={onDragEnter}
    on:dragleave={onDragLeave}
    on:dragover={onDragOver}
    on:drop={onDrop}
  >
    <input type="file" multiple on:change={onFileInput} hidden />
    <div class="dropzone-text">{$t('upload.drop')}</div>
    <div class="dropzone-count">
      {$t('upload.selected', { values: { count: files.length } })}
    </div>
  </label>

  {#if files.length > 0}
    <ul class="file-list">
      {#each files as f (f.name + f.size)}
        <li>
          <span class="file-name">{f.name}</span>
          <span class="file-size">{(f.size / 1024).toFixed(1)} KB</span>
          <button
            type="button"
            class="file-remove"
            title={$t('upload.remove')}
            aria-label={$t('upload.remove')}
            on:click={() => removeFile(f)}
          >×</button>
        </li>
      {/each}
    </ul>

    <div class="preview-card">
      <div class="preview-title">{$t('upload.preview.title')}</div>
      <dl class="preview-grid">
        <dt>{$t('upload.preview.fileCount')}</dt>
        <dd>{files.length}</dd>
        <dt>{$t('upload.preview.totalSize')}</dt>
        <dd>{formatBytes(totalBytes)}</dd>
      </dl>
      <div class="preview-note">{$t('upload.preview.serverValidationNote')}</div>
    </div>
  {/if}

  <button class="primary upload-submit" on:click={submit} disabled={uploading || files.length === 0}>
    {uploading ? $t('upload.uploading') : $t('upload.submit')}
  </button>

  {#if error}
    <div class="error-msg mt-3">{error}</div>
  {/if}

  {#if lastResult}
    <div class="result-card">
      <div class="result-summary">
        {$t('upload.summary', { values: {
          batchId: lastResult.batch_id,
          accepted: lastResult.accepted,
          rejected: lastResult.rejected,
        }})}
      </div>
      <table class="table-auto outcome-table">
        <thead>
          <tr>
            <th>File</th>
            <th>Ecosystem</th>
            <th>Status</th>
            <th>Detail</th>
          </tr>
        </thead>
        <tbody>
          {#each lastResult.outcomes as o (o.filename)}
            <tr class="outcome-row outcome-{o.status}">
              <td class="file-name mono">{o.filename}</td>
              <td>
                {#if o.ecosystem}
                  <span class="eco-badge">{o.ecosystem}</span>
                {:else}
                  <span class="text-muted">—</span>
                {/if}
              </td>
              <td>
                <span class="outcome-badge outcome-{o.status}">{$t(`upload.outcome.${o.status}`)}</span>
              </td>
              <td class="text-muted">
                {o.code ? `${o.code} — ${o.message}` : o.purl ?? ''}
                {#if o.code === 'claim_required' && o.name && fileIndex.has(o.filename)}
                  <button class="action-btn claim-btn" on:click={() => openClaimModal(o)}>
                    {$t('upload.claimAndUpload')}
                  </button>
                {/if}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</div>

{#if claimModal}
  <div
    class="modal-backdrop"
    role="dialog"
    aria-modal="true"
    tabindex="-1"
    on:click|self={closeClaimModal}
    on:keydown={(e) => { if (e.key === 'Escape') closeClaimModal() }}
  >
    <div class="modal">
      <h2>{$t('upload.claimModal.title')}</h2>
      <p class="text-muted">
        {claimModal.ecosystem} / <span class="mono">{claimModal.name}</span>
      </p>
      <label>
        {$t('claims.modal.state')}
        <select bind:value={claimState}>
          <option value="local_only">{$t('claims.states.local_only')}</option>
          <option value="mixed">{$t('claims.states.mixed')}</option>
        </select>
      </label>
      {#if claimState === 'mixed'}
        <div class="warning-card">
          <p>{$t('claims.modal.mixedWarning')}</p>
          <label class="ack"><input type="checkbox" bind:checked={claimAck} /> {$t('claims.modal.mixedAck')}</label>
        </div>
      {/if}
      {#if claimState === 'local_only'}
        <div class="info-card"><p>{$t('claims.modal.purgeWarning')}</p></div>
      {/if}
      <label>
        {$t('claims.modal.reason')}
        <textarea
          bind:value={claimReason}
          placeholder={$t('claims.modal.reasonPlaceholder')}
          rows="3"
          required
        ></textarea>
      </label>
      {#if claimError}<div class="error-msg">{claimError}</div>{/if}
      <div class="modal-actions">
        <button on:click={closeClaimModal} disabled={claimSubmitting}>{$t('claims.modal.cancel')}</button>
        <button class="primary" on:click={submitClaimAndReupload} disabled={claimSubmitting}>
          {claimSubmitting ? $t('upload.uploading') : $t('upload.claimModal.submit')}
        </button>
      </div>
    </div>
  </div>
{/if}

<style>
  .desc { max-width: 720px; }

  .dropzone {
    display: block;
    cursor: pointer;
    border: 2px dashed var(--border);
    border-radius: 6px;
    padding: 36px 18px;
    text-align: center;
    background: var(--bg2);
    transition: border-color 0.15s, background 0.15s;
    max-width: 720px;
  }
  .dropzone:hover, .dropzone.dragOver {
    border-color: var(--info);
    background: var(--info-bg);
  }
  .dropzone-text { font-weight: 500; }
  .dropzone-count { margin-top: 4px; font-size: 12px; color: var(--text2); }

  .upload-submit { margin-top: 24px; }

  .file-list {
    list-style: none;
    padding: 0;
    margin: 12px 0;
    max-width: 720px;
    max-height: 200px;
    overflow-y: auto;
    border: 1px solid var(--border);
    border-radius: 4px;
  }
  .file-list li {
    display: flex;
    justify-content: space-between;
    padding: 6px 12px;
    font-size: 13px;
    border-bottom: 1px solid var(--border);
  }
  .file-list li:last-child { border-bottom: none; }
  .file-name { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; flex: 1; }
  .file-size { color: var(--text2); flex-shrink: 0; margin-left: 12px; }
  .file-remove {
    flex-shrink: 0;
    margin-left: 12px;
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
  .file-remove:hover {
    background: var(--danger-bg);
    border-color: var(--danger-border);
    color: var(--danger);
  }

  .preview-card {
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 12px 16px;
    margin: 12px 0;
    max-width: 720px;
    font-size: 13px;
  }
  .preview-title {
    font-weight: 600;
    margin-bottom: 8px;
  }
  .preview-grid {
    display: grid;
    grid-template-columns: 140px 1fr;
    gap: 6px 12px;
    margin: 0;
  }
  .preview-grid dt { color: var(--text2); }
  .preview-grid dd { margin: 0; }
  .preview-note {
    margin-top: 10px;
    padding-top: 8px;
    border-top: 1px solid var(--border);
    font-size: 11px;
    color: var(--text2);
  }

  .result-card {
    margin-top: 16px;
    max-width: 720px;
  }
  .result-summary {
    margin-bottom: 8px;
    font-weight: 500;
  }
  .outcome-table { font-size: 13px; }
  .eco-badge {
    display: inline-block;
    padding: 1px 8px;
    border-radius: 3px;
    background: var(--bg);
    border: 1px solid var(--border);
    font-size: 11px;
    font-family: var(--mono, monospace);
    text-transform: lowercase;
  }
  .outcome-badge {
    display: inline-block;
    padding: 1px 8px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
  }
  .outcome-badge.outcome-accepted,
  .outcome-badge.outcome-would_accept {
    background: var(--success-bg);
    color: var(--success);
    border: 1px solid var(--success-border);
  }
  .outcome-badge.outcome-rejected,
  .outcome-badge.outcome-would_reject {
    background: var(--danger-bg);
    color: var(--danger);
    border: 1px solid var(--danger-border);
  }
  .mono { font-family: var(--mono, monospace); }

  .action-btn { padding: 3px 8px; font-size: 11px; min-height: 26px; margin-left: 6px; }
  .claim-btn { background: var(--info); color: var(--on-accent); border-color: var(--info); }
  .claim-btn:hover { background: var(--info); filter: brightness(0.9); }

  .modal-backdrop {
    position: fixed; inset: 0;
    background: var(--overlay-scrim);
    display: flex; align-items: center; justify-content: center;
    z-index: 1000;
  }
  .modal {
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 24px;
    width: min(520px, 90vw);
    max-height: 85vh;
    overflow-y: auto;
    display: flex; flex-direction: column; gap: 12px;
  }
  .modal h2 { margin: 0; font-size: 16px; }
  .modal label { display: flex; flex-direction: column; gap: 4px; font-size: 13px; }
  .modal-actions { display: flex; justify-content: flex-end; gap: 8px; margin-top: 8px; }
  .warning-card {
    background: var(--warning-bg);
    border: 1px solid var(--warning-border);
    border-radius: 4px;
    padding: 8px 12px;
    font-size: 12px;
  }
  .warning-card p { margin: 0 0 6px 0; }
  .ack { flex-direction: row !important; align-items: center; gap: 6px !important; cursor: pointer; }
  .ack input { width: auto; margin: 0; }
  .info-card {
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 8px 12px;
    font-size: 12px;
  }
  .info-card p { margin: 0; }
</style>
