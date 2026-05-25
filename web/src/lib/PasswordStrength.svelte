<script>
  import { t } from 'svelte-i18n'
  import { evaluatePassword, MIN_LENGTH } from './passwordPolicy.js'

  export let value = ''
  export let context = {}
  // Bound out so the parent can disable submit when not OK.
  export let valid = false

  // zxcvbn-ts is fast enough on a 12–72 char input to run synchronously per
  // keystroke; the debounce we'd otherwise reach for would trip the
  // svelte/infinite-reactive-loop lint without adding meaningful UX.
  $: result = evaluatePassword(value, context)
  $: valid = result.verdict === 'ok'
  $: visibleScore = value.length === 0 ? -1 : (result.score ?? 0)

  $: messageKey = (() => {
    if (value.length === 0) return null
    switch (result.verdict) {
      case 'ok': return 'password.strength.ok'
      case 'too_short': return 'password.tooShort'
      case 'too_long': return 'password.tooLong'
      case 'low_entropy': return 'password.lowEntropy'
      case 'contains_context': return 'password.containsContext'
      default: return null
    }
  })()

  $: messageValues = (() => {
    if (!messageKey) return {}
    if (result.verdict === 'too_short') return { min: MIN_LENGTH }
    if (result.verdict === 'contains_context') return { term: result.matchedTerm }
    if (result.verdict === 'low_entropy') return { warning: result.warning || '' }
    return {}
  })()
</script>

<div class="pw-strength" aria-live="polite">
  <div class="pw-bar" role="progressbar"
       aria-valuemin="0" aria-valuemax="4" aria-valuenow={Math.max(visibleScore, 0)}>
    {#each [0, 1, 2, 3] as i (i)}
      <span class="pw-segment"
            class:filled={visibleScore > i}
            class:s-weak={visibleScore <= 1}
            class:s-fair={visibleScore === 2}
            class:s-good={visibleScore >= 3}>
      </span>
    {/each}
  </div>
  {#if messageKey}
    <div class="pw-message"
         class:pw-ok={result.verdict === 'ok'}
         class:pw-warn={result.verdict !== 'ok'}>
      {$t(messageKey, { values: messageValues })}
    </div>
  {/if}
</div>

<style>
  .pw-strength { margin-top: 6px; }
  .pw-bar { display: flex; gap: 4px; }
  .pw-segment {
    flex: 1;
    height: 4px;
    background: var(--border);
    border-radius: 2px;
    transition: background 120ms ease;
  }
  .pw-segment.filled.s-weak { background: var(--danger); }
  .pw-segment.filled.s-fair { background: var(--warning); }
  .pw-segment.filled.s-good { background: var(--success); }
  .pw-message { font-size: 12px; margin-top: 4px; }
  .pw-message.pw-ok { color: var(--success); }
  .pw-message.pw-warn { color: var(--text2); }
</style>
