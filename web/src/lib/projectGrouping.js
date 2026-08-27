// Projects.svelte grouping for search results — Claims-style grouped/indented rows, no tree
// widget. The list API returns root-level projects only when unfiltered, but a search matches
// at any depth: a matched child carries `parentId`/`parentName` from a project that may or may
// not itself be in the same result page (its own name may not have matched the query). This
// module turns that flat, possibly-out-of-order array into a display order where every child
// renders directly under its parent — a real parent row when the parent matched too, otherwise
// a synthesized, unclickable header row carrying just the parent's name.

/** @param {{ id: string, parentId?: string | null }} it */
const groupKey = (it) => it.parentId ?? it.id

/**
 * Orders `{ it, i }` pairs so rows sharing a parent sit together, the root heads its own group,
 * and the server's original order survives everywhere else. Array#sort is stable in every engine
 * this app targets, and `i` is the explicit tiebreaker regardless.
 *
 * @param {{ it: { id: string, parentId?: string | null }, i: number }} a
 * @param {{ it: { id: string, parentId?: string | null }, i: number }} b
 */
function byGroupThenRootFirst(a, b) {
  const ga = groupKey(a.it)
  const gb = groupKey(b.it)
  if (ga !== gb) return ga < gb ? -1 : 1
  const ra = a.it.parentId ? 1 : 0
  const rb = b.it.parentId ? 1 : 0
  if (ra !== rb) return ra - rb
  return a.i - b.i
}

/**
 * @param {Array<{ id: string, parentId?: string | null, parentName?: string | null }>} items
 * @param {boolean} grouping whether to group at all — false (no active search) returns items
 *   unchanged with `indent: false`, matching the root-only listing the API returns by default.
 * @returns {Array<{ id: string, indent?: boolean, isHeader?: boolean, name?: string }>}
 */
export function buildProjectDisplayRows(items, grouping) {
  if (!grouping) return items.map((it) => ({ ...it, indent: false }))

  const ranked = items.map((it, i) => ({ it, i }))
  ranked.sort(byGroupThenRootFirst)

  const rows = []
  let lastGroup = null
  for (const { it } of ranked) {
    const g = groupKey(it)
    if (it.parentId && g !== lastGroup) {
      // First row in this group is a child, not the root — the parent itself did not match the
      // search. Give the child somewhere to visibly belong instead of floating unexplained.
      rows.push({ id: `parent-header-${g}`, isHeader: true, name: it.parentName ?? '' })
    }
    rows.push({ ...it, indent: !!it.parentId })
    lastGroup = g
  }
  return rows
}
