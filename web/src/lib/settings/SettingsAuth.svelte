<!--
  Authentication tab of OrgSettings — IdP metadata upload, popup test flow, SAML toggle,
  connection-field disclosure, sticky dirty-save bar.

  Self-contained: owns its own state, API calls, popup listener lifecycle. The component
  mounts → loadAuthConfig; revisiting the tab remounts the component (parent uses
  {#if tab === 'authentication'}<SettingsAuth />{/if}) and refetches — a refetch on
  every revisit is the right trade-off for keeping the boundary clean. Styling lives
  in global app.css under .auth-tab scopes; this component renders that wrapper class.
-->
<script>
  import { onMount, onDestroy } from 'svelte'
  import { t } from 'svelte-i18n'
  import { api } from '../api.js'

  let authConfig = null
  let metadataUploading = false, authSaving = false
  let authError = '', authSuccess = ''
  let metadataFileInput = null

  // Snapshot of the last server-confirmed connection-field values; anything that
  // diverges surfaces the dirty-only sticky save bar.
  let pristineConnection = null

  $: connectionDirty = !!authConfig && !!pristineConnection && (
    (authConfig.buttonLabel    || '') !== (pristineConnection.buttonLabel    || '') ||
    (authConfig.nameIdFormat   || '') !== (pristineConnection.nameIdFormat   || '') ||
    (authConfig.emailAttribute || '') !== (pristineConnection.emailAttribute || '') ||
    (authConfig.spEntityId     || '') !== (pristineConnection.spEntityId     || '')
  )

  onMount(async () => {
    window.addEventListener('message', onSamlTestMessage)
    await loadAuthConfig()
  })

  onDestroy(() => window.removeEventListener('message', onSamlTestMessage))

  async function loadAuthConfig() {
    authError = ''; authSuccess = ''
    try {
      authConfig = await api.getAuthConfig()
      pristineConnection = snapshotConnection(authConfig)
    } catch (e) { authError = e.message }
  }

  function snapshotConnection(cfg) {
    return {
      buttonLabel:    cfg.buttonLabel    || '',
      nameIdFormat:   cfg.nameIdFormat   || '',
      emailAttribute: cfg.emailAttribute || '',
      spEntityId:     cfg.spEntityId     || '',
    }
  }

  function authPayload() {
    return {
      enabled: !!authConfig.enabled,
      formsLoginEnabled: !!authConfig.formsLoginEnabled,
      spEntityId: authConfig.spEntityId || null,
      nameIdFormat: authConfig.nameIdFormat,
      emailAttribute: authConfig.emailAttribute || null,
      buttonLabel: authConfig.buttonLabel || null,
    }
  }

  async function saveAuthConnectionFields() {
    authSaving = true; authError = ''; authSuccess = ''
    try {
      await api.putAuthConfig(authPayload())
      pristineConnection = snapshotConnection(authConfig)
      authSuccess = $t('settings.saved')
    } catch (e) { authError = e.message }
    finally { authSaving = false }
  }

  function discardConnectionEdits() {
    if (!pristineConnection) return
    authConfig = { ...authConfig, ...pristineConnection }
  }

  async function saveAuthMethod(field, value) {
    const prev = authConfig[field]
    authConfig = { ...authConfig, [field]: value }  // optimistic
    authError = ''; authSuccess = ''
    try {
      await api.putAuthConfig(authPayload())
      // The PUT carries the *current* connection-field values too; refresh the
      // pristine snapshot so the dirty bar reflects the server's real state.
      pristineConnection = snapshotConnection(authConfig)
      authSuccess = $t('settings.saved')
    } catch {
      authError = $t('settings.auth.methodSaveError')
      authConfig = { ...authConfig, [field]: prev }  // revert
    }
  }

  async function resetAuthConfig() {
    if (!confirm($t('settings.auth.resetConfirm'))) return
    authError = ''; authSuccess = ''
    try {
      await api.deleteAuthConfig()
      authSuccess = $t('settings.auth.resetSuccess')
      await loadAuthConfig()
    } catch (e) { authError = e.message }
  }

  async function uploadMetadata(ev) {
    const file = ev.target.files?.[0]
    if (!file) return
    metadataUploading = true; authError = ''; authSuccess = ''
    try {
      const xml = await file.text()
      const parsed = await api.uploadSamlMetadata(xml)
      authSuccess = $t('settings.auth.metadataUploaded')
      authConfig = { ...authConfig,
        idpEntityId: parsed.idpEntityId,
        idpSsoUrl: parsed.idpSsoUrl,
        idpSigningCertThumbprint: parsed.idpSigningCertThumbprint,
      }
    } catch (e) { authError = e.message }
    finally { metadataUploading = false; ev.target.value = '' }
  }

  function testSso() {
    // Open the SAML round-trip in a popup so the settings page state is preserved. The
    // popup navigates to the IdP, returns to /saml/acs, and lands on /saml-test-result,
    // which posts the result back to this window via postMessage and closes itself.
    //
    // Spec-canonical minimal feature string: bare `popup` keyword (presence is the hint
    // per the HTML spec) plus width/height. left/top are omitted so the browser centres
    // on the primary screen — multi-monitor coordinates can bias popup heuristics. If
    // the browser still opens this as a tab regardless, that's a browser/OS-level setting
    // (e.g. macOS "Prefer tabs when opening documents") and not a feature-string issue.
    // The flow itself still completes in tab mode since postMessage works for tabs
    // spawned via window.open from the same origin.
    authError = ''; authSuccess = ''
    const w = 560, h = 720
    const popup = window.open(
      '/saml/login?test=1',
      'dependably-saml-test-popup',
      `popup,width=${w},height=${h}`)
    if (!popup) authError = $t('settings.auth.testPopupBlocked')
  }

  function onSamlTestMessage(ev) {
    if (ev.origin !== window.location.origin) return
    if (ev.data?.type !== 'saml-test-result') return
    if (ev.data.error) {
      authSuccess = ''
      authError = $t('settings.auth.testFailed', {
        values: { reason: ev.data.detail || ev.data.error },
      })
    } else {
      authError = ''
      authSuccess = $t('settings.auth.testSucceeded', {
        values: { email: ev.data.email || '—' },
      })
      // Re-fetch so lastTestAt + lastTestEmail are reflected immediately and the
      // formsLoginEnabled toggle's lockout guard releases without a manual refresh.
      loadAuthConfig()
    }
  }

  async function copyText(text) {
    try { await navigator.clipboard.writeText(text) } catch { /* clipboard unavailable */ }
  }

  function recentTestOk(at) {
    if (!at) return false
    const ts = new Date(at).getTime()
    if (Number.isNaN(ts)) return false
    return (Date.now() - ts) < 10 * 60 * 1000
  }
</script>

{#if !authConfig}
  <span class="spinner"></span>
{:else}
  <div class="auth-tab">
    {#if authError}<div class="error-msg">{authError}</div>{/if}
    {#if authSuccess}<div class="text-success mb-3">{authSuccess}</div>{/if}

    <!-- ─── Sign-in methods ─────────────────────────────────────── -->
    <div class="card card-wide">
      <h3 class="mt-0">{$t('settings.auth.methodsTitle')}</h3>
      <p class="form-hint mb-3 mt-0">
        {$t('settings.auth.methodsIntro')}
      </p>

      <div class="method">
        <div class="label">
          <p class="name">{$t('settings.auth.formsLogin')}</p>
          <p class="desc">{$t('settings.auth.formsLoginHint')}</p>
        </div>
        <label class="toggle">
          <input type="checkbox"
                 checked={authConfig.formsLoginEnabled}
                 on:change={(e) => saveAuthMethod('formsLoginEnabled', e.currentTarget.checked)} />
          <span class="track"></span>
        </label>
      </div>

      <div class="method">
        <div class="label">
          <p class="name">
            {$t('settings.auth.samlLogin')}
            {#if !authConfig.idpEntityId}
              <span class="badge">{$t('settings.auth.stateNotConfigured')}</span>
            {:else if authConfig.enabled}
              <span class="badge success">{$t('settings.auth.stateEnabled')}</span>
            {:else if !recentTestOk(authConfig.lastTestAt)}
              <span class="badge warning">{$t('settings.auth.stateNotReady')}</span>
            {:else}
              <span class="badge accent">{$t('settings.auth.stateReadyDisabled')}</span>
            {/if}
          </p>
          <p class="desc">
            {#if !authConfig.idpEntityId}
              {$t('settings.auth.samlEnableNeedsIdp')}
            {:else if authConfig.enabled}
              {$t('settings.auth.samlLoginHint')}
            {:else if !recentTestOk(authConfig.lastTestAt)}
              {$t('settings.auth.samlEnableNeedsTest')}
            {:else}
              {$t('settings.auth.samlLoginHint')}
            {/if}
          </p>
        </div>
        <label class="toggle">
          <input type="checkbox"
                 data-testid="saml-toggle"
                 checked={authConfig.enabled}
                 disabled={!authConfig.idpEntityId || (!authConfig.enabled && !recentTestOk(authConfig.lastTestAt))}
                 on:change={(e) => saveAuthMethod('enabled', e.currentTarget.checked)} />
          <span class="track"></span>
        </label>
      </div>
    </div>

    <!-- ─── Grouped SAML configuration ──────────────────────────── -->
    <section class="saml-group">
      <header class="saml-group-header">
        <span class="ico" aria-hidden="true">
          <svg viewBox="0 0 20 20" width="20" height="20" fill="none"
               stroke="currentColor" stroke-width="1.5"
               stroke-linecap="round" stroke-linejoin="round">
            <path d="M10 1.5L3 4v6c0 3.5 3 6.5 7 8 4-1.5 7-4.5 7-8V4l-7-2.5z"/>
            <path d="M7 10l2 2 4-4"/>
          </svg>
        </span>
        <div>
          <h3 class="saml-group-title">{$t('settings.auth.groupTitle')}</h3>
          <p class="saml-group-sub">{$t('settings.auth.groupSubtitle')}</p>
        </div>
        <div class="saml-group-status">
          {#if !authConfig.idpEntityId}
            <span class="status-pill">
              <span class="dot"></span> {$t('settings.auth.stateNotConfigured')}
            </span>
          {:else if authConfig.enabled}
            <span class="status-pill enabled">
              <span class="dot"></span> {$t('settings.auth.stateEnabled')}
            </span>
          {:else if !recentTestOk(authConfig.lastTestAt)}
            <span class="status-pill draft">
              <span class="dot"></span> {$t('settings.auth.stateNotReady')}
            </span>
          {:else}
            <span class="status-pill ready">
              <span class="dot"></span> {$t('settings.auth.stateReadyDisabled')}
            </span>
          {/if}
        </div>
      </header>

      <!-- Step 1 — SP info -->
      <div class="step done">
        <div class="num">1</div>
        <div>
          <h4>{$t('settings.auth.spInfoTitle')}
            <span class="badge success">{$t('settings.auth.ready')}</span>
          </h4>
          <p class="step-hint">{$t('settings.auth.spInfoHint')}</p>
          <table class="kv-table">
            <tbody>
              <tr>
                <th>{$t('settings.auth.spInfoAcs')}</th>
                <td><code>{authConfig.spInfo.acsUrl}</code>
                  <button class="link-btn"
                          on:click={() => copyText(authConfig.spInfo.acsUrl)}>{$t('common.actions.copy')}</button>
                </td>
              </tr>
              <tr>
                <th>{$t('settings.auth.spInfoEntityId')}</th>
                <td><code>{authConfig.spEntityId || authConfig.spInfo.defaultSpEntityId}</code>
                  <button class="link-btn"
                          on:click={() => copyText(authConfig.spEntityId || authConfig.spInfo.defaultSpEntityId)}>{$t('common.actions.copy')}</button>
                </td>
              </tr>
              <tr>
                <th>{$t('settings.auth.spInfoMetadata')}</th>
                <td><code>{authConfig.spInfo.metadataUrl}</code>
                  <button class="link-btn"
                          on:click={() => copyText(authConfig.spInfo.metadataUrl)}>{$t('common.actions.copy')}</button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Step 2 — Upload IdP metadata -->
      <div class="step" class:done={!!authConfig.idpEntityId}>
        <div class="num">2</div>
        <div>
          <h4>{$t('settings.auth.idpMetadataTitle')}
            {#if authConfig.idpEntityId}
              <span class="badge success">{$t('settings.auth.uploaded')}</span>
            {/if}
          </h4>
          <p class="step-hint">{$t('settings.auth.idpMetadataHint')}</p>

          <div class="file-input">
            <span class="ico" aria-hidden="true">
              <svg viewBox="0 0 16 16" width="16" height="16" fill="none"
                   stroke="currentColor" stroke-width="1.5"
                   stroke-linecap="round" stroke-linejoin="round">
                <path d="M9 2H4a1 1 0 0 0-1 1v10a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1V6L9 2z"/>
                <path d="M9 2v4h4M5 9h6M5 11.5h4"/>
              </svg>
            </span>
            <div class="copy">
              {#if authConfig.idpEntityId}
                <b>{$t('settings.auth.metadataUploaded')}</b>
                {$t('settings.auth.metadataReplaceHint')}
              {:else}
                <b>{$t('settings.auth.metadataChoose')}</b>
                {$t('settings.auth.idpMetadataHint')}
              {/if}
            </div>
            <button type="button"
                    on:click={() => metadataFileInput?.click()}
                    disabled={metadataUploading}>
              {authConfig.idpEntityId ? $t('settings.auth.replaceFile') : $t('settings.auth.chooseFile')}
            </button>
            <input bind:this={metadataFileInput}
                   type="file"
                   accept=".xml,application/xml,text/xml"
                   on:change={uploadMetadata}
                   disabled={metadataUploading}
                   hidden />
          </div>

          {#if authConfig.idpEntityId}
            <table class="kv-table mt-3">
              <tbody>
                <tr><th>{$t('settings.auth.idpEntityId')}</th><td><code>{authConfig.idpEntityId}</code></td></tr>
                <tr><th>{$t('settings.auth.idpSsoUrl')}</th><td><code>{authConfig.idpSsoUrl}</code></td></tr>
                <tr><th>{$t('settings.auth.idpCertThumbprint')}</th><td><code>{authConfig.idpSigningCertThumbprint || '—'}</code></td></tr>
              </tbody>
            </table>
          {/if}
        </div>
      </div>

      <!-- Step 3 — Test the round-trip -->
      <div class="step" class:done={recentTestOk(authConfig.lastTestAt)}>
        <div class="num">3</div>
        <div>
          <h4>{$t('settings.auth.testTitle')}
            {#if !recentTestOk(authConfig.lastTestAt)}
              <span class="badge warning">{$t('settings.auth.testRequired')}</span>
            {:else}
              <span class="badge success">{$t('settings.auth.testRecentOk')}</span>
            {/if}
          </h4>
          <p class="step-hint">{$t('settings.auth.testHint')}</p>

          <div class="test-card" class:idle={!recentTestOk(authConfig.lastTestAt)}>
            <span class="ico" aria-hidden="true">
              <svg viewBox="0 0 16 16" width="16" height="16" fill="none"
                   stroke="currentColor" stroke-width="1.5"
                   stroke-linecap="round" stroke-linejoin="round">
                <path d="M3 8l3 3 7-7"/>
              </svg>
            </span>
            <div class="body">
              {#if authConfig.lastTestAt && recentTestOk(authConfig.lastTestAt)}
                <p class="title">{$t('settings.auth.testLastRunRecent', {
                  values: { when: authConfig.lastTestAt }
                })}</p>
                <p class="meta">
                  {$t('settings.auth.testLastRunMetaReady', {
                    values: { email: authConfig.lastTestEmail || '—' }
                  })}
                </p>
              {:else if authConfig.lastTestAt}
                <p class="title">{$t('settings.auth.testLastRunStale')}</p>
                <p class="meta">{$t('settings.auth.testLastRunMetaStale', {
                  values: { when: authConfig.lastTestAt }
                })}</p>
              {:else}
                <p class="title">{$t('settings.auth.testNeverRun')}</p>
                <p class="meta">{$t('settings.auth.testNeverRunMeta')}</p>
              {/if}
            </div>
            <div class="actions">
              <button data-testid="saml-test-button" on:click={testSso} disabled={!authConfig.idpEntityId}>
                {authConfig.lastTestAt ? $t('settings.auth.testRerun') : $t('settings.auth.testButton')}
              </button>
            </div>
          </div>
        </div>
      </div>

      <!-- Advanced — disclosure -->
      <details class="disclosure">
        <summary class="disclosure-summary">
          <span class="chev">
            <svg viewBox="0 0 16 16" width="16" height="16" fill="none"
                 stroke="currentColor" stroke-width="1.5"
                 stroke-linecap="round" stroke-linejoin="round">
              <path d="M6 4l4 4-4 4"/>
            </svg>
          </span>
          {$t('settings.auth.advancedTitle')}
          <span class="sub">— {$t('settings.auth.advancedSub')}</span>
        </summary>
        <div class="disclosure-body">
          <p class="form-hint mt-2 mb-3">{$t('settings.auth.advancedHint')}</p>

          <div class="form-row">
            <label>{$t('settings.auth.buttonLabel')}</label>
            <input type="text" bind:value={authConfig.buttonLabel}
                   placeholder={$t('settings.auth.buttonLabelPlaceholder')} />
          </div>
          <div class="form-row">
            <label>{$t('settings.auth.nameIdFormat')}</label>
            <select bind:value={authConfig.nameIdFormat}>
              <option value="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">emailAddress</option>
              <option value="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">persistent</option>
              <option value="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">transient</option>
              <option value="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">unspecified</option>
            </select>
          </div>
          <div class="form-row">
            <label>{$t('settings.auth.emailAttribute')}</label>
            <input type="text" bind:value={authConfig.emailAttribute}
                   placeholder={$t('settings.auth.emailAttributePlaceholder')} />
            <div class="form-hint">{$t('settings.auth.emailAttributeHint')}</div>
          </div>
          <div class="form-row">
            <label>{$t('settings.auth.spEntityIdOverride')}</label>
            <input type="text" bind:value={authConfig.spEntityId}
                   placeholder={authConfig.spInfo.defaultSpEntityId} />
            <div class="form-hint">{$t('settings.auth.spEntityIdHint')}</div>
          </div>

          <div class="save-row">
            <button class="primary" on:click={saveAuthConnectionFields} disabled={authSaving}>
              {authSaving ? $t('common.actions.saving') : $t('settings.auth.saveConnectionFields')}
            </button>
            <span class="form-hint">
              {$t('settings.auth.connectionFieldsHint')}
            </span>
          </div>

          <div class="reset-row">
            <button class="danger" on:click={resetAuthConfig}>{$t('settings.auth.resetButton')}</button>
            <div class="form-hint reset-hint">{$t('settings.auth.resetHint')}</div>
          </div>
        </div>
      </details>
    </section>

    {#if connectionDirty}
      <div class="save-bar" role="region" aria-label={$t('settings.auth.saveBarLabel')}>
        <span class="changed">
          <b>{$t('settings.auth.saveBarUnsaved')}</b>
          · {$t('settings.auth.saveBarFields')}
        </span>
        <button on:click={discardConnectionEdits}>{$t('common.actions.discard')}</button>
        <button class="primary" on:click={saveAuthConnectionFields} disabled={authSaving}>
          {authSaving ? $t('common.actions.saving') : $t('settings.auth.saveConnectionFields')}
        </button>
      </div>
    {/if}
  </div>
{/if}

<style>
  .kv-table { width: 100%; border-collapse: collapse; }
  .kv-table th, .kv-table td {
    padding: 6px 8px;
    border-bottom: 1px solid var(--border);
    text-align: left;
    vertical-align: top;
    font-size: 13px;
  }
  .kv-table th { width: 180px; color: var(--text2); font-weight: 500; }
  .kv-table td code { font-family: var(--mono, monospace); word-break: break-all; }
  .link-btn {
    background: none;
    border: none;
    color: var(--accent);
    padding: 0 0 0 6px;
    font-size: 12px;
    cursor: pointer;
  }
  .reset-row { margin-top: 12px; }
  .reset-hint { margin-top: 6px; }
</style>

