<!--
  Dependency-path breadcrumb: the chain of components that pulled a transitive dependency in,
  rendered as mono chips joined by arrows ("webapp → express → qs"). The last chip is the
  component the row is about.

  The path comes from the SBOM's own dependency graph, so an SBOM that declared no graph
  renders nothing at all rather than a fabricated single-node path.

  Props:
    path   the raw dependencyPath array from the analysis payload (strings or nodes)
-->
<script>
  import { t } from 'svelte-i18n'
  import { dependencyPathLabels } from './analysis.js'

  /** @type {any[]} */
  export let path = []

  $: labels = dependencyPathLabels(path)
</script>

{#if labels.length}
  <div class="dep-path" aria-label={$t('sbomAnalysis.panel.dependencyPath')}>
    {#each labels as label, i (i)}
      {#if i > 0}<span class="dep-arrow" aria-hidden="true">&#8594;</span>{/if}
      <span class="dep-node mono" class:leaf={i === labels.length - 1}>{label}</span>
    {/each}
  </div>
{/if}

<style>
  .dep-path {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 4px;
  }
  .dep-node {
    background: var(--bg3);
    border-radius: 4px;
    padding: 1px 6px;
    font-size: 12px;
    color: var(--text2);
    overflow-wrap: anywhere;
  }
  .dep-node.leaf { color: var(--text); font-weight: 600; }
  .dep-arrow { color: var(--text2); font-size: 12px; }
</style>
