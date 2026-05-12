// Returns ' ↑' / ' ↓' / '' for table-header sort arrows.
//
// Why current+direction are passed in: Svelte 5 (legacy mode) only treats a
// `let` variable as reactive when the compiler sees it read in a reactive
// position — template, $:, $effect. If the indicator function reads sortCol
// internally and is called from the template, the compiler does not recurse
// through the function body, the variable is never wrapped in a signal, and
// the arrow stays stuck on whichever column was active at mount.
//
// Passing them as args makes the template call site read them directly
// (`sortIndicator('foo', sortCol, sortDir)`), which is the read the compiler
// tracks. See https://svelte.dev/docs/svelte/v5-migration-guide for the
// reactivity model change.
export function sortIndicator(col, current, direction) {
  if (current !== col) return ''
  return direction === 'asc' ? ' ↑' : ' ↓'
}
