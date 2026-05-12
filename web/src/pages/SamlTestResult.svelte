<script>
  import { onMount } from 'svelte'
  import { t } from 'svelte-i18n'
  import { navigate } from '../lib/store.js'

  // Populated from the redirect query string set by the backend ACS handler when running
  // in test mode. Persisted nowhere — this page is purely a confirmation surface.
  let email = ''
  let nameId = ''
  let testTime = null
  let error = ''
  let detail = ''
  let success = false
  let isPopup = false
  let countdown = 0

  onMount(() => {
    const search = new URLSearchParams(window.location.search)
    email = search.get('email') || ''
    nameId = search.get('nameid') || ''
    error = search.get('error') || ''
    detail = search.get('detail') || ''
    testTime = new Date()
    success = !error
    isPopup = !!(window.opener && !window.opener.closed)

    if (isPopup) {
      // Notify the settings tab so it can refresh lastTestAt + show inline feedback. Origin
      // is restricted to our own — the message is delivered same-origin only.
      try {
        window.opener.postMessage(
          { type: 'saml-test-result', email, nameId, error, detail },
          window.location.origin)
      } catch { /* opener may have navigated; nothing to do */ }

      // Auto-close: success closes faster (the user's confirmation is in the parent),
      // failure stays open longer so the operator can read the error message.
      countdown = success ? 3 : 8
      const timer = setInterval(() => {
        countdown -= 1
        if (countdown <= 0) {
          clearInterval(timer)
          window.close()
        }
      }, 1000)
    }
  })

  function closeNow() {
    if (isPopup) window.close()
    else navigate('settings')
  }
</script>

<div class="page">
  <div class="page-header">
    <h1 class="page-title">
      {success ? $t('settings.auth.testResultTitle') : $t('settings.auth.testResultFailedTitle')}
    </h1>
  </div>

  <div class="card result-card">
    {#if success}
      <div class="success-banner">{$t('settings.auth.testResultSuccess')}</div>

      <h3 class="mt-4">{$t('settings.auth.testResultAttributes')}</h3>
      <table class="kv-table">
        <tbody>
          <tr>
            <th>{$t('settings.auth.testResultEmail')}</th>
            <td>{email || '—'}</td>
          </tr>
          <tr>
            <th>{$t('settings.auth.testResultNameId')}</th>
            <td>{nameId || '—'}</td>
          </tr>
          {#if testTime}
            <tr>
              <th>{$t('settings.auth.testResultTime')}</th>
              <td>{testTime.toISOString()}</td>
            </tr>
          {/if}
        </tbody>
      </table>

      <p class="hint mt-4">
        {$t('settings.auth.testResultHint')}
      </p>
    {:else}
      <div class="error-banner">
        {$t('settings.auth.testResultFailedBanner')}
      </div>
      <h3 class="mt-4">{$t('settings.auth.testResultFailureDetails')}</h3>
      <table class="kv-table">
        <tbody>
          <tr>
            <th>{$t('settings.auth.testResultErrorCode')}</th>
            <td>{error}</td>
          </tr>
          {#if detail}
            <tr>
              <th>{$t('settings.auth.testResultErrorDetail')}</th>
              <td>{detail}</td>
            </tr>
          {/if}
        </tbody>
      </table>
      <p class="hint mt-4">
        {$t('settings.auth.testResultFailedHint')}
      </p>
    {/if}

    <div class="actions-row">
      <button class="primary" on:click={closeNow}>
        {isPopup ? $t('settings.auth.testResultCloseWindow') : $t('settings.auth.testResultBack')}
      </button>
      {#if isPopup && countdown > 0}
        <span class="hint">{$t('settings.auth.testResultAutoClose', { values: { seconds: countdown } })}</span>
      {/if}
    </div>
  </div>
</div>

<style>
  .success-banner {
    padding: 12px 14px;
    border-radius: var(--radius);
    background: var(--success-bg);
    color: var(--success);
    border: 1px solid var(--success-border);
    font-weight: 500;
  }
  .error-banner {
    padding: 12px 14px;
    border-radius: var(--radius);
    background: var(--danger-bg);
    color: var(--danger);
    border: 1px solid var(--danger-border);
    font-weight: 500;
  }
  .kv-table { width: 100%; border-collapse: collapse; }
  .kv-table th, .kv-table td {
    padding: 8px 10px;
    border-bottom: 1px solid var(--border);
    text-align: left;
    vertical-align: top;
    font-size: 14px;
  }
  .kv-table th { width: 160px; color: var(--text2); font-weight: 500; }
  .kv-table td { font-family: var(--mono, monospace); word-break: break-all; }
  .hint { color: var(--text2); font-size: 13px; }
  .result-card { max-width: 560px; }
  .actions-row { margin-top: 20px; display: flex; gap: 8px; align-items: center; }
</style>
