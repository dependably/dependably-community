<!--
  Read-only summary of every serve-path block-gate control, for a member who has no reason to
  open Settings → Gates (or, on the community edition, no permission to). Each row is keyed by
  the same reason token GET /api/v1/policies carries and the 403 X-Dependably-Block-Reason
  header names, so a blocked download can be matched straight back to the row that explains it.

  Data comes from api.getPolicies() (read:packages) rather than /proxy-settings or /settings
  (read:tenant) — this is a deliberately narrower projection with no upstream URLs, credentials,
  anchor material, PURL patterns, or the install-script allowlist. Editing still happens only in
  Settings → Gates; this tab is read-only by design.
-->
<script>
  import { onMount } from 'svelte'
  import { t } from 'svelte-i18n'
  import { api } from '../api.js'
  import { extractErrorMessage } from '../form.js'
  import { reportPageLoad } from '../pageLoad.js'
  import { formattingLocale } from '../format.js'
  import { ECO_LABEL } from '../ecosystems.js'
  import { POLICY_CONTROL_GROUPS } from './policyControlTokens.js'
  import ErrorBanner from '../ErrorBanner.svelte'
  import InfoTip from '../InfoTip.svelte'

  /** The route transition this tab was mounted for, forwarded by Policies.svelte. @type {number | null} */
  export let pageToken = null

  let policy = null
  let loading = true
  let error = ''

  $: reportPageLoad(pageToken, loading)

  onMount(async () => {
    try {
      policy = await api.getPolicies()
    } catch (e) {
      error = extractErrorMessage(e)
    } finally {
      loading = false
    }
  })

  // token -> the settings.proxy.<field> prefix whose Off/Warn/Block(New/All) suffix labels this
  // control's raw mode. Controls with no entry (license, terraform's provenance row) fall back
  // to the generic licensePolicy.modes.<mode> label — terraform signature verification has no
  // Settings UI yet, so there is no settings.proxy label to reuse for it.
  const PROXY_FIELD = {
    malicious: 'blockMalicious',
    malicious_live: 'blockMaliciousLive',
    kev: 'blockKev',
    kev_ransomware: 'blockKevRansomware',
    deprecated: 'blockDeprecated',
    revoked: 'blockRevoked',
    install_script: 'blockInstallScripts',
    ssvc_exploitation: 'blockSsvcExploitation',
  }
  const PROVENANCE_PROXY_FIELD = {
    npm: 'verifyNpmSignatures',
    nuget: 'verifyNuGetSignatures',
    pypi: 'verifyPyPiAttestations',
    rpm: 'verifyRpmSignatures',
    maven: 'verifyMavenSignatures',
  }

  // 'block_new' -> 'BlockNew', matching the settings.proxy.blockDeprecated<Suffix> key shape.
  function modeSuffix(mode) {
    return mode.split('_').map(s => s.charAt(0).toUpperCase() + s.slice(1)).join('')
  }

  function modeLabelKey(field, mode) {
    return field ? `settings.proxy.${field}${modeSuffix(mode)}` : `licensePolicy.modes.${mode}`
  }

  // Locale-formatted threshold values (Intl, current locale) — reused across the threshold-based
  // rows below rather than reformatted inline per row.
  //
  // A fraction strictly between 0 and 1 must never format to the boundary strings "0%"/"100%" —
  // either misstates the shape of the ceiling (0% reads as "blocks everything", 100% as "blocks
  // nothing", and this control is neither: it is off, or it blocks above a real threshold).
  // Below 1%, maximumSignificantDigits keeps a small value (0.0004 -> "0.04%") visibly non-zero,
  // where a fixed fraction-digit count would round it to "0%". Above 99.9%, the value is clamped
  // before formatting so one that rounds up to "100%" at one fraction digit (0.9996) instead
  // reads "99.9%" — the value is still under 1 and therefore block-worthy, so the display must
  // stay visibly under 100 too.
  function formatPercent(fraction, $locale) {
    if (fraction <= 0) return new Intl.NumberFormat($locale, { style: 'percent', maximumFractionDigits: 1 }).format(0)
    if (fraction >= 1) return new Intl.NumberFormat($locale, { style: 'percent', maximumFractionDigits: 1 }).format(1)
    const clamped = fraction > 0.999 ? 0.999 : fraction
    return clamped < 0.01
      ? new Intl.NumberFormat($locale, { style: 'percent', maximumSignificantDigits: 2 }).format(clamped)
      : new Intl.NumberFormat($locale, { style: 'percent', maximumFractionDigits: 1 }).format(clamped)
  }
  function formatCvss(score, $locale) {
    return new Intl.NumberFormat($locale, { maximumFractionDigits: 1 }).format(score)
  }
  // Days when the hour count divides evenly, otherwise hours — "72h" reads as "3 days" once it
  // crosses a day boundary, and a non-multiple (like 18h) stays in hours rather than "0.75 days".
  function formatReleaseAge(hours, $locale) {
    return hours > 0 && hours % 24 === 0
      ? new Intl.NumberFormat($locale, { style: 'unit', unit: 'day', unitDisplay: 'long' }).format(hours / 24)
      : new Intl.NumberFormat($locale, { style: 'unit', unit: 'hour', unitDisplay: 'long' }).format(hours)
  }

  // en-CA ordinal suffixes via Intl.PluralRules' ordinal category. French has only two forms
  // ("1er", every other rank "Xe" — no distinct 2nd/3rd/… suffix the way English has), so it is
  // handled directly rather than through PluralRules' (cardinal-shaped) category set.
  const EN_ORDINAL_SUFFIXES = { one: 'st', two: 'nd', few: 'rd', other: 'th' }
  function formatOrdinal(n, $locale) {
    const rank = Math.round(n)
    if ($locale.startsWith('fr')) return rank === 1 ? `${rank}er` : `${rank}e`
    const category = new Intl.PluralRules($locale, { type: 'ordinal' }).select(rank)
    return `${rank}${EN_ORDINAL_SUFFIXES[category] ?? 'th'}`
  }
  // The percentile ceiling as a rank, not a probability — 0.95 reads "95th", not "95%". No
  // never-0/never-100 clamp here: unlike formatPercent's probability ceiling, a rank of "0th" or
  // "100th" is a legitimate (if extreme) percentile position, not a boundary that misstates
  // whether the gate can fire.
  function formatPercentileRank(fraction, $locale) {
    return formatOrdinal(fraction * 100, $locale)
  }

  // Row descriptors grouped the way the table renders them, built from POLICY_CONTROL_GROUPS
  // (the shared source of truth policyControls.parity.test.js also reads) plus the
  // policy.controls data policy.controls.<token> supplies at runtime. `provenance` is a single
  // BlockGateService reason token backing six per-ecosystem rows (the 403 header cannot
  // distinguish which ecosystem's verification failed), so it is spliced in between the
  // lifecycle and access groups by its own rule rather than from a fixed token list — each
  // provenance row still shows the shared "provenance" code but reads its own
  // mode/effect/anchorsConfigured. A flat array of { key, rows } rather than an object keyed by
  // group name so the template's #each has one plain shape to iterate and svelte-check can
  // narrow `policy` (guarded by the {#if policy} below) without re-deriving it per group. Every
  // row carries the same { token, ecosystem, control } shape — ecosystem is null outside the
  // provenance group — so the template's #each sees one row type rather than a union only some
  // rows satisfy.
  function toStaticGroup(g) {
    return {
      key: g.key,
      rows: g.tokens.map(token => ({ token, ecosystem: null, control: policy.controls[token] })),
    }
  }
  $: groups = !policy ? [] : [
    toStaticGroup(POLICY_CONTROL_GROUPS[0]), // vulnerability
    toStaticGroup(POLICY_CONTROL_GROUPS[1]), // lifecycle
    {
      key: 'provenance',
      rows: Object.entries(policy.controls.provenance).map(([eco, control]) => ({
        token: 'provenance', ecosystem: eco, control,
      })),
    },
    toStaticGroup(POLICY_CONTROL_GROUPS[2]), // access
  ]

  // Glossary text per token, appended to the control's hover tip. Reuses the vulnerabilities-page
  // and settings-page help copy that already documents these terms. epss_percentile gets its
  // own copy — it is a relative rank among scored CVEs, not the probability epssHelp describes —
  // rather than reusing epss's text. A token with no entry gets no glossary sentence.
  $: glossaryText = {
    kev: $t('vulnerabilities.kevHelp'),
    kev_ransomware: $t('vulnerabilities.kevRansomwareHelp'),
    epss: $t('vulnerabilities.detail.epssHelp'),
    epss_percentile: $t('policies.glossary.epssPercentile'),
    ssvc_exploitation: $t('policies.glossary.ssvc'),
    vuln_score: $t('policies.glossary.cvss'),
  }

  // One hover tip per control: what it does, the glossary entry for its metric where one exists,
  // and the X-Dependably-Block-Reason value a refused request carries for it.
  function controlTip(token, glossary, tr) {
    return [
      tr(`policies.controls.${token}.what`),
      glossary[token],
      tr('policies.blockReasonValue', { values: { token } }),
    ].filter(Boolean).join(' ')
  }
</script>

{#if error}
  <ErrorBanner message={error} />
{:else if loading}
  <span class="spinner"></span>
{:else if policy}
  <p class="allowlist-note">
    <strong>{$t('settings.proxy.allowlistMode')}:</strong>
    <span class="badge" class:on={policy.allowlistMode === 'on'}>
      {policy.allowlistMode === 'on' ? $t('licensePolicy.modes.block') : $t('policies.offBadge')}
    </span>
    <InfoTip text={$t('policies.allowlistMode.what')} />
  </p>

  <div class="table-scroll">
    <table class="list-table policy-controls-table">
      <colgroup>
        <col class="col-control">
        <col>
      </colgroup>
      <thead>
        <tr>
          <th>{$t('policies.columns.control')}</th>
          <th>{$t('policies.columns.setting')}</th>
        </tr>
      </thead>
      {#each groups as group (group.key)}
        <tbody>
          <tr class="group-row">
            <th colspan="2" scope="colgroup">{$t(`policies.groups.${group.key}`)}</th>
          </tr>
          {#each group.rows as row (row.ecosystem ?? row.token)}
            {@const c = row.control}
            <tr>
              <td>
                <div class="control-cell">
                  <span class="control-name">
                    {row.ecosystem ? (ECO_LABEL[row.ecosystem] ?? row.ecosystem) : $t(`policies.controls.${row.token}.name`)}
                  </span>
                  <InfoTip text={controlTip(row.token, glossaryText, $t)} />
                </div>
              </td>
              <td>
                {#if c.effect === 'off'}
                  <span class="badge">{$t('policies.offBadge')}</span>
                {:else if row.token === 'release_age'}
                  {$t('policies.thresholds.releaseAge', { values: { value: formatReleaseAge(c.minHours, $formattingLocale) } })}
                {:else if row.token === 'vuln_score'}
                  {$t('policies.thresholds.above', { values: { value: formatCvss(c.maxScore, $formattingLocale) } })}
                {:else if row.token === 'epss'}
                  {$t('policies.thresholds.above', { values: { value: formatPercent(c.maxProbability, $formattingLocale) } })}
                {:else if row.token === 'epss_percentile'}
                  {$t('policies.thresholds.percentile', { values: { value: formatPercentileRank(c.maxPercentile, $formattingLocale) } })}
                {:else if row.ecosystem}
                  {$t(modeLabelKey(PROVENANCE_PROXY_FIELD[row.ecosystem], c.mode))}
                {:else}
                  {$t(modeLabelKey(PROXY_FIELD[row.token], c.mode))}
                {/if}

                {#if row.ecosystem}
                  {#if c.mode === 'block' && !c.anchorsConfigured}
                    <div class="control-warning">
                      <svg width="12" height="12" aria-hidden="true"><use href="/icons.svg#icon-alert"/></svg>
                      {$t('policies.warnings.unbackedSignature')}
                    </div>
                  {/if}
                {:else if c.active === false && c.effect !== 'off'}
                  <div class="control-warning">
                    <svg width="12" height="12" aria-hidden="true"><use href="/icons.svg#icon-alert"/></svg>
                    {$t('policies.warnings.inactive')}
                  </div>
                {/if}
              </td>
            </tr>
          {/each}
        </tbody>
      {/each}
    </table>
  </div>
{/if}

<style>
  /* .table-scroll and the base .badge are global (app.css). */
  .allowlist-note { font-size: 13px; margin: 0 0 16px; }
  .allowlist-note { display: flex; align-items: center; gap: 6px; }
  .badge.on { background: var(--badge-warning-bg); color: var(--badge-warning-text); }
  /* app.css sets table-layout: fixed globally, so a floor set on an individual <col>/<td> is
     inert — fixed layout sizes columns only from explicit <col> widths (or the first row, for an
     unstyled column) and never grows a column to fit its content. The table's own min-width is
     what keeps this table from squeezing narrower than a comfortable read on a small viewport:
     .table-scroll (app.css) scrolls the table itself once it hits that floor, rather than
     collapsing every column toward one glyph per line. */
  :global(table.policy-controls-table) { min-width: 520px; }
  .col-control { width: 320px; }
  .group-row th {
    padding-top: 16px;
    font-size: 12px;
    font-weight: 600;
    color: var(--text);
    background: var(--bg2);
  }
  .control-cell { display: flex; align-items: center; gap: 6px; }
  .control-warning {
    display: flex;
    align-items: center;
    gap: 4px;
    margin-top: 4px;
    font-size: 11px;
    color: var(--badge-warning-text);
  }
</style>
