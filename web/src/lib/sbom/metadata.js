/**
 * Component presentation metadata helpers for the expanded analysis row.
 *
 * The server decides what a component's SBOM entry said; these helpers only decide whether
 * there is anything to render and in what order. Keeping the emptiness test here — rather than
 * as a chain of `||` in the template — is what makes "the producer omitted every field" and
 * "this row predates the columns" render identically: as no section at all, rather than as a
 * heading with nothing under it.
 */

/** The external-reference kinds a component renders, in the order they are shown. */
const LINK_KINDS = [
  { key: 'website', field: 'websiteUrl' },
  { key: 'vcs', field: 'vcsUrl' },
  { key: 'issueTracker', field: 'issueTrackerUrl' },
  { key: 'distribution', field: 'distributionUrl' },
]

/**
 * The links one component row carries, as `{ key, url }`, skipping every kind the document
 * omitted. Only http(s) URLs survive ingest, so nothing here re-validates the scheme; a value
 * that is not a string is still dropped, because a payload shape is not a guarantee.
 */
export function componentLinksOf(item) {
  if (!item) return []
  return LINK_KINDS
    .filter(({ field }) => typeof item[field] === 'string' && item[field].length > 0)
    .map(({ key, field }) => ({ key, url: item[field] }))
}

/**
 * Whether the row has any presentation metadata worth a section. Hashes count: a component
 * whose document carried only digests still has something to show.
 */
export function hasComponentMetadata(item) {
  if (!item) return false
  return Boolean(
    item.description ||
    item.author ||
    item.copyright ||
    item.group ||
    componentLinksOf(item).length ||
    (Array.isArray(item.hashes) && item.hashes.length),
  )
}
