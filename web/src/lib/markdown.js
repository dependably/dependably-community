// Markdown → sanitized HTML, for the curated skill documents the instance serves.
//
// The content is our own embedded corpus, not user input, so this is defence in depth rather
// than a boundary. It is worth having anyway: the renderer is the one place in the app that
// turns text into markup, and a later caller pointed at content of less certain provenance
// would inherit the guarantee instead of having to remember to add it. Sanitizing is also the
// only honest posture for a product whose own `fix-xss` skill tells people to do exactly this.

import { marked } from 'marked'
import DOMPurify from 'dompurify'

/**
 * Tags a SKILL.md can legitimately produce. Anything outside this list is dropped rather than
 * escaped, so an unexpected construct degrades to its text content instead of rendering.
 * Deliberately absent: `style`, `script`, `iframe`, `object`, `embed`, `form`, and every
 * media tag — a skill document has no reason to load anything over the network, and a page
 * that cannot request a remote resource cannot leak a reader's address either.
 */
const ALLOWED_TAGS = [
  'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
  'p', 'br', 'hr',
  'strong', 'em', 'del', 'code', 'pre', 'blockquote',
  'ul', 'ol', 'li',
  'table', 'thead', 'tbody', 'tr', 'th', 'td',
  'a', 'span',
]

/**
 * `href` is the only URL-bearing attribute allowed through, and DOMPurify's own protocol
 * filter rejects `javascript:` and `data:` on it. `title` and `align` are cosmetic; `class`
 * survives so fenced blocks keep the `language-*` hook their styling uses.
 *
 * This list alone does not make the set closed. `ALLOW_DATA_ATTR` and `ALLOW_ARIA_ATTR`
 * default to true in DOMPurify and are applied *in addition to* an explicit allowlist, so
 * arbitrary `data-*` and `aria-*` attributes pass unless they are turned off — see the
 * options below. Neither is anything `marked` emits, so refusing them costs nothing.
 */
const ALLOWED_ATTR = ['href', 'title', 'align', 'class']

/**
 * Drops a leading `---` delimited YAML frontmatter block.
 *
 * Markdown has no notion of frontmatter, so a renderer treats it as a horizontal rule followed
 * by prose — a skill document then opens with its own `name:` and `description:` keys spilled
 * across the page as body text, above the heading it should have started on. Stripping is for
 * *display* only: the copy and download actions hand over the whole file, because the
 * frontmatter is exactly what an assistant reads to know what the skill is.
 *
 * @param {string|null|undefined} markdown
 * @returns {string} The document body, or the input unchanged when it has no frontmatter.
 */
export function stripFrontmatter(markdown) {
  if (!markdown) return ''
  const text = markdown.replace(/^\uFEFF/, '')
  if (!/^---[ \t]*\r?\n/.test(text)) return text
  // The closing delimiter, on its own line. An unterminated block is not frontmatter — leaving
  // it alone renders something odd, where guessing would silently eat the whole document.
  const end = text.slice(4).search(/(?:^|\n)---[ \t]*(?:\r?\n|$)/)
  if (end === -1) return text
  const after = text.slice(4 + end)
  return after.replace(/^\r?\n?---[ \t]*\r?\n?/, '').replace(/^\s+/, '')
}

/**
 * Renders one Markdown document to HTML that is safe to inject.
 * @param {string|null|undefined} markdown
 * @returns {string} HTML, or '' for empty input.
 */
export function renderMarkdown(markdown) {
  if (!markdown) return ''
  const html = marked.parse(markdown, { async: false, gfm: true, breaks: false })
  return DOMPurify.sanitize(/** @type {string} */ (html), {
    ALLOWED_TAGS,
    ALLOWED_ATTR,
    // Both default to true and are unioned with ALLOWED_ATTR, so without these the allowlist
    // above is not the whole story: any `data-*` or `aria-*` attribute rides through. Neither
    // is executable on its own, but an attribute nothing here asked for is one more thing a
    // CSS selector or a future script can key off, and "the allowlist is the whole list" is a
    // property worth being true rather than nearly true.
    ALLOW_DATA_ATTR: false,
    ALLOW_ARIA_ATTR: false,
    // Keep the text of a stripped element rather than dropping the subtree, so a document
    // that trips the allowlist loses its formatting and not its content.
    KEEP_CONTENT: true,
  })
}
