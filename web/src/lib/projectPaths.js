// Folder-path helpers for the projects plane. A "folder" in the UI is a `kind: 'collection'`
// project — the same row shape, distinguished only by the discriminator — so the picker and the
// breadcrumb both work off the flat collection list `GET /api/v1/projects/collections` returns.
//
// Kept apart from the DOM so the two rules that matter can be unit-tested directly: a path label
// is built by walking parentId to the root, and a project can never be relocated into its own
// subtree (the server refuses that too, but the picker must not offer the move in the first
// place — an option that always errors is worse than an absent one).

/** The separator between path segments, matching the breadcrumb's own visual separator. */
export const PATH_SEPARATOR = ' / '

/**
 * Full root-to-leaf label for one collection, e.g. `Platform / Payments`.
 *
 * @param {string} id collection id to label
 * @param {Map<string, { id: string, name: string, parentId?: string | null }>} byId
 * @returns {string} the joined path, or the bare name when an ancestor is missing from `byId`
 */
export function collectionPath(id, byId) {
  const segments = []
  const seen = new Set()
  /** @type {string | null} */
  let cursor = id
  // A cycle is impossible through the API, but this runs against whatever the server sent — a
  // bounded walk degrades to a shorter label instead of hanging the tab.
  while (cursor && !seen.has(cursor)) {
    seen.add(cursor)
    const node = byId.get(cursor)
    if (!node) break
    segments.unshift(node.name)
    cursor = node.parentId ?? null
  }
  return segments.join(PATH_SEPARATOR)
}

/**
 * The collections offered as relocation targets for `projectId`, each with its full path label,
 * sorted by that label. The root itself is NOT included — callers render it as their own first
 * option, because its label is a translated string this module has no business owning.
 *
 * `projectId` and every collection beneath it are excluded: moving a folder into itself or into
 * one of its own descendants would cut the whole subtree loose from the root.
 *
 * @param {Array<{ id: string, name: string, parentId?: string | null }>} collections
 * @param {string | null} projectId the project being moved, or null when creating a new one
 * @returns {Array<{ id: string, label: string }>}
 */
export function relocationTargets(collections, projectId) {
  const byId = new Map(collections.map((c) => [c.id, c]))

  const excluded = (id) => {
    if (!projectId) return false
    const seen = new Set()
    /** @type {string | null} */
    let cursor = id
    while (cursor && !seen.has(cursor)) {
      if (cursor === projectId) return true
      seen.add(cursor)
      cursor = byId.get(cursor)?.parentId ?? null
    }
    return false
  }

  return collections
    .filter((c) => !excluded(c.id))
    .map((c) => ({ id: c.id, label: collectionPath(c.id, byId) }))
    .sort((a, b) => a.label.localeCompare(b.label))
}
