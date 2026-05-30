#!/usr/bin/env node
// Reads CycloneDX SBOM JSON files, deduplicates components by purl, and emits
// a curated third-party attribution document on stdout. Used by the Docker
// build to embed notices.json into the .NET assembly for the /api/v1/licenses
// endpoint.

import fs from 'node:fs'

if (process.argv.length < 3) {
  console.error('usage: extract-notices.mjs <sbom1.json> [sbom2.json ...]')
  process.exit(2)
}

const components = process.argv.slice(2).flatMap((path) => {
  // deepcode ignore PT: argv from the build pipeline, not user input. This script is invoked
  // by the Docker build with SBOM paths under build/; there is no runtime exposure.
  const bom = JSON.parse(fs.readFileSync(path, 'utf8'))
  return bom.components ?? []
})

const seen = new Map()
let missing = 0

for (const c of components) {
  const purl = c.purl ?? `${c.type ?? 'lib'}:${c.group ?? ''}/${c.name}@${c.version}`
  if (seen.has(purl)) continue
  const license = extractLicense(c)
  if (!license) {
    console.error(`WARN: no license for ${c.name}@${c.version} (${purl})`)
    missing++
  }
  seen.set(purl, {
    name: c.name,
    version: c.version ?? null,
    purl: c.purl ?? null,
    license,
    copyright: typeof c.copyright === 'string' && c.copyright.trim() ? c.copyright.trim() : null,
  })
}

const notices = [...seen.values()].sort((a, b) =>
  a.name.localeCompare(b.name) || (a.version ?? '').localeCompare(b.version ?? ''),
)

console.log(
  JSON.stringify(
    { generatedAt: new Date().toISOString(), count: notices.length, components: notices },
    null,
    2,
  ),
)

console.error(`extracted ${notices.length} components (${missing} missing license)`)

function extractLicense(c) {
  const entries = c.licenses ?? []
  if (!entries.length) return null
  const first = entries[0]
  if (first.license?.id) return { spdx: first.license.id, url: first.license.url ?? null }
  if (first.expression) return { spdx: first.expression, url: null }
  if (first.license?.name) return { name: first.license.name, url: first.license.url ?? null }
  return null
}
