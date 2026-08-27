<!--
  Three-pillar risk strip. Signal display only — each pillar reports one independently-sourced
  fact and they are never combined into a composite score, because a single number hides which
  of the three is the problem.

  The caller decides what the pillars are and what they say; this component owns the strip's
  layout, the loading placeholders, and the tone vocabulary. Package version detail passes
  Security / License / Operational plus the version the three describe as the trailing subject;
  project version detail passes Security / License / Policy — versions-behind has no meaning
  for an arbitrary SBOM component, so Policy is the honest third signal there.

  Props:
    pillars  [{ key, label, text, tone?, sev?, title? }]
             tone   'clean' | 'warn' | 'review' | 'muted' | '' (neutral)
             sev    a severity name — renders the value as a `.sev` chip instead of coloured text
             title  hover text naming what the value was measured over, when that is narrower
                    than the pillar's label implies
    subject  { label, value } rendered at the trailing edge, or null
    loading  renders a placeholder in every pillar value
-->
<script>
  import Skeleton from './Skeleton.svelte'

  /** @type {Array<{ key: string, label: string, text: string, tone?: string, sev?: string|null, title?: string }>} */
  export let pillars = []
  /** @type {{ label: string, value: string } | null} */
  export let subject = null
  export let loading = false
</script>

<div class="risk-pillars">
  {#each pillars as p (p.key)}
    <div class="pillar">
      <span class="pillar-label">{p.label}</span>
      {#if loading}
        <span class="pillar-value"><Skeleton width="80px" height="16px" /></span>
      {:else if p.sev}
        <span class="pillar-value sev sev-{p.sev}" title={p.title}>{p.text}</span>
      {:else}
        <span
          class="pillar-value"
          title={p.title}
          class:pillar-clean={p.tone === 'clean'}
          class:pillar-warn={p.tone === 'warn'}
          class:pillar-review={p.tone === 'review'}
          class:text-muted={p.tone === 'muted'}
        >{p.text}</span>
      {/if}
    </div>
  {/each}
  <!-- Names the subject of the pillars. Without it a clean headline is ambiguous: a reader
       cannot tell a subject with no advisories anywhere from one whose current state is clean
       while its history is not. -->
  {#if !loading && subject}
    <div class="pillar pillar-subject">
      <span class="pillar-label">{subject.label}</span>
      <span class="pillar-value">{subject.value}</span>
    </div>
  {/if}
</div>

<style>
  .risk-pillars {
    display: flex;
    gap: 20px;
    margin-bottom: 14px;
    padding: 10px 14px;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    background: var(--bg2);
  }
  .pillar { display: flex; flex-direction: column; gap: 2px; }
  .pillar-label {
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.02em;
    color: var(--text2);
  }
  .pillar-value { font-size: 13px; font-weight: 600; }
  /* The subject the pillars describe, pushed to the trailing edge so it reads as the strip's
     subject rather than an extra pillar. */
  .pillar-subject { margin-left: auto; text-align: right; }
  .pillar-clean { color: var(--success); }
  .pillar-warn { color: var(--badge-warning-text); }
  /* Distinct from pillar-warn: the subject is usable, the org just wrote a condition on it. */
  .pillar-review { color: var(--badge-sky-text); }
</style>
