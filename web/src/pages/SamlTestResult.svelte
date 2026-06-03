<script>
  import { onMount } from 'svelte'
  import { t } from 'svelte-i18n'
  import { navigate } from '../lib/store.js'

  let email = ''
  let nameId = ''
  let testTime = null
  let error = ''
  let detail = ''
  let success = false
  let isPopup = false
  let claims = []   // [{ type, values[] }] from GET /api/v1/auth-config

  // Claim types the app actually uses for sign-in (email resolution). Flagged in the table.
  const EMAIL_CLAIM_TYPES = new Set([
    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
    'urn:oid:0.9.2342.19200300.100.1.3',
    'email',
    'mail',
    'emailaddress',
  ])

  function isEmailClaim(type) {
    return EMAIL_CLAIM_TYPES.has(type?.toLowerCase())
  }

  onMount(async () => {
    const search = new URLSearchParams(window.location.search)
    email = search.get('email') || ''
    nameId = search.get('nameid') || ''
    error = search.get('error') || ''
    detail = search.get('detail') || ''
    testTime = new Date()
    success = !error
    isPopup = !!(window.opener && !window.opener.closed)

    if (isPopup) {
      try {
        window.opener.postMessage(
          { type: 'saml-test-result', email, nameId, error, detail },
          window.location.origin)
      } catch { /* opener may have navigated; nothing to do */ }
      // No auto-close — admin needs to read the claims at their own pace.
    }

    // Fetch claims from the server (stored from the last test run).
    if (success) {
      try {
        const res = await fetch('/api/v1/auth-config', { credentials: 'include' })
        if (res.ok) {
          const data = await res.json()
          claims = data.lastTestClaims || []
        }
      } catch { /* claims unavailable — show empty state */ }
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

      <h3 class="mt-4">{$t('settings.auth.testResultAllClaimsHeader')}</h3>
      {#if claims.length > 0}
        <table class="kv-table">
          <tbody>
            {#each claims as claim (claim.type)}
              <tr>
                <th class="claim-type">
                  {claim.type}
                  {#if isEmailClaim(claim.type)}
                    <span class="badge success badge-inline">{$t('settings.auth.testResultUsedForSignIn')}</span>
                  {/if}
                </th>
                <td>
                  {#if claim.values && claim.values.length > 1}
                    <ul class="claim-values">
                      {#each claim.values as v (v)}<li>{v}</li>{/each}
                    </ul>
                  {:else}
                    {claim.values?.[0] || '—'}
                  {/if}
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      {:else}
        <p class="hint">{$t('settings.auth.testResultNoAdditionalAttributes')}</p>
      {/if}

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
  .kv-table th { width: 260px; color: var(--text2); font-weight: 500; }
  .kv-table td { font-family: var(--mono, monospace); word-break: break-all; }
  .claim-type { font-family: var(--mono, monospace); font-size: 12px; }
  .badge-inline { margin-left: 6px; font-size: 11px; vertical-align: middle; }
  .claim-values { margin: 0; padding-left: 16px; }
  .claim-values li { margin: 2px 0; }
  .hint { color: var(--text2); font-size: 13px; }
  .result-card { max-width: 680px; }
  .actions-row { margin-top: 20px; display: flex; gap: 8px; align-items: center; }
</style>
