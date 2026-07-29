<!--
  Shimmer placeholder that reserves the box its real content will occupy. Thin wrapper over the
  global `.skeleton` class in app.css, adding an explicit width/height and optional stacked lines
  so a caller declares the reserved space in one place instead of re-deriving inline widths.

  Reserving is the point: a page whose body collapses while its data is in flight retracts the
  document scrollbar and shifts the whole layout, so a loading page renders its real chrome with
  these standing in for the values.

  Decorative — aria-hidden, with the loading state announced by aria-busy on the region that
  contains it. Tables keep their own row-level placeholders (DataTable, VersionTable); this is
  for cards, panels, page headers, stat tiles, and form blocks.

  Props:
    width   any CSS length; defaults to filling the container
    height  any CSS length; defaults to one text line
    count   number of stacked lines (>1 renders a flex column)
    gap     spacing between stacked lines
-->
<script>
  export let width = '100%'
  export let height = '0.9em'
  export let count = 1
  export let gap = '8px'

  $: lines = Array.from({ length: Math.max(1, count) }, (_, i) => i)
</script>

{#if count > 1}
  <span class="skeleton-stack" style:gap aria-hidden="true">
    {#each lines as i (i)}
      <span class="skeleton" style:width style:height></span>
    {/each}
  </span>
{:else}
  <span class="skeleton" style:width style:height aria-hidden="true"></span>
{/if}

<style>
  .skeleton-stack {
    display: flex;
    flex-direction: column;
    width: 100%;
  }
</style>
