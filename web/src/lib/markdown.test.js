import { describe, it, expect } from 'vitest'
import { renderMarkdown, stripFrontmatter } from './markdown.js'

describe('renderMarkdown', () => {
  it('renders the constructs a SKILL.md actually uses', () => {
    const html = renderMarkdown([
      '## When to use this',
      '',
      'Point **npm** at a `dependably` org.',
      '',
      '```ini',
      'registry=https://repo.example.com/npm/',
      '```',
      '',
      '| Ecosystem | Scope |',
      '|---|---|',
      '| npm | project |',
      '',
      '- first',
      '- second',
      '',
      '> A blockquote gotcha.',
    ].join('\n'))

    expect(html).toContain('<h2>When to use this</h2>')
    expect(html).toContain('<strong>npm</strong>')
    expect(html).toContain('<code>dependably</code>')
    expect(html).toContain('<pre>')
    expect(html).toContain('registry=https://repo.example.com/npm/')
    expect(html).toContain('<table>')
    expect(html).toContain('<li>first</li>')
    expect(html).toContain('<blockquote>')
  })

  it('returns empty string for empty input', () => {
    expect(renderMarkdown('')).toBe('')
    expect(renderMarkdown(null)).toBe('')
    expect(renderMarkdown(undefined)).toBe('')
  })

  it('keeps a plain link but drops a javascript: one', () => {
    expect(renderMarkdown('[docs](https://example.com/x)')).toContain('href="https://example.com/x"')
    const evil = renderMarkdown('[click](javascript:alert(1))')
    expect(evil).not.toContain('javascript:')
    expect(evil).toContain('click')
  })

  // The renderer is the app's only text-to-markup path. These are the vectors that make
  // sanitizing worth the dependency rather than a formality — each must lose its capability
  // while keeping whatever text it carried.
  it.each([
    ['raw script tag', '<script>alert(1)</script>', 'alert(1)'],
    ['event handler', '<img src=x onerror="alert(1)">', 'onerror'],
    ['iframe', '<iframe src="https://evil.example"></iframe>', 'iframe'],
    ['inline style', '<span style="position:fixed">hi</span>', 'style='],
    ['svg onload', '<svg onload="alert(1)"></svg>', 'onload'],
    ['form', '<form action="https://evil.example"><input name="p"></form>', '<form'],
  ])('neutralizes %s', (_name, input, forbidden) => {
    const html = renderMarkdown(input)
    expect(html).not.toContain(forbidden)
    expect(html).not.toMatch(/<script|<iframe|<object|<embed|on\w+=/i)
  })

  // DOMPurify unions ALLOW_DATA_ATTR / ALLOW_ARIA_ATTR (both default true) with an explicit
  // ALLOWED_ATTR list, so "we passed an allowlist" is not by itself a closed set. These pin
  // that the list really is the whole list — an ai-review lens asked whether the config was
  // strictly enforced, and before this it was not.
  it.each([
    ['data attribute', '<span data-evil="x">t</span>', 'data-evil'],
    ['aria attribute', '<span aria-label="x">t</span>', 'aria-label'],
    ['id attribute', '<span id="x">t</span>', 'id='],
    ['target attribute', '<a href="https://e.example" target="_blank">t</a>', 'target='],
  ])('drops an unlisted %s while keeping the text', (_name, input, forbidden) => {
    const html = renderMarkdown(input)
    expect(html).not.toContain(forbidden)
    expect(html).toContain('t')
  })

  it('keeps exactly the allowlisted attributes and nothing else', () => {
    const html = renderMarkdown(
      '<a href="https://e.example" title="T" data-x="1" aria-x="1" id="i" rel="me">t</a>',
    )
    const attrs = [...html.matchAll(/\s([a-zA-Z-]+)=/g)].map(m => m[1]).sort()
    expect(attrs).toEqual(['href', 'title'])
  })

  it('strips markup but keeps the text inside it', () => {
    expect(renderMarkdown('<div><b>kept</b></div>')).toContain('kept')
  })
})

describe('stripFrontmatter', () => {
  const DOC = [
    '---',
    'name: fix-xss',
    'description: Remediate cross-site scripting.',
    'cwe:',
    '  - CWE-79',
    '---',
    '',
    '## When to use this',
    '',
    'Body.',
  ].join('\n')

  it('removes the block and starts the document at its first heading', () => {
    const body = stripFrontmatter(DOC)
    expect(body.startsWith('## When to use this')).toBe(true)
    expect(body).not.toContain('name: fix-xss')
    expect(body).not.toContain('CWE-79')
    expect(body).toContain('Body.')
  })

  // The whole reason this exists: without it the keys render as prose under a stray rule.
  it('keeps those keys out of the rendered output', () => {
    const html = renderMarkdown(stripFrontmatter(DOC))
    expect(html).not.toContain('name: fix-xss')
    expect(html).not.toContain('<hr>')
    expect(html).toContain('<h2>When to use this</h2>')
  })

  it('leaves a document with no frontmatter untouched', () => {
    expect(stripFrontmatter('## Heading\n\nBody.')).toBe('## Heading\n\nBody.')
  })

  // An unterminated block is not frontmatter. Guessing would silently eat the whole document,
  // which is a worse failure than rendering something odd.
  it('leaves an unterminated block alone', () => {
    const odd = '---\nname: half\n\n## Heading'
    expect(stripFrontmatter(odd)).toBe(odd)
  })

  it('does not mistake a leading horizontal rule for frontmatter', () => {
    const html = renderMarkdown(stripFrontmatter('---\n\n## Heading\n\nBody.'))
    expect(html).toContain('<h2>Heading</h2>')
  })

  it('handles CRLF line endings', () => {
    expect(stripFrontmatter('---\r\nname: x\r\n---\r\n\r\n## H')).toBe('## H')
  })

  it('returns empty string for empty input', () => {
    expect(stripFrontmatter('')).toBe('')
    expect(stripFrontmatter(null)).toBe('')
  })
})
