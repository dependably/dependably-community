#!/usr/bin/env node
// Builds the embedded SPDX license-text bundle from the SPDX license-list-data
// repository at a pinned tag. dependably is air-gapped at runtime, so full license
// texts are bundled at build time rather than fetched on demand. Emits a MINIFIED
// JSON { licenseListVersion, texts: { <id>: <text> } } on stdout.
//
// Usage:
//   node build/generate-spdx-license-texts.mjs <path-to-json/details-dir> > out.json
//
// The details directory is the `json/details/` folder from a checkout / tarball of
// https://github.com/spdx/license-list-data at the target tag; each *.json file has
// a `licenseId` and a `licenseText` field.

import fs from 'node:fs'
import path from 'node:path'

const LICENSE_LIST_VERSION = '3.28.0'

if (process.argv.length < 3) {
  console.error('usage: generate-spdx-license-texts.mjs <json/details dir>')
  process.exit(2)
}

const detailsDir = process.argv[2]
const files = fs.readdirSync(detailsDir).filter((f) => f.endsWith('.json'))

const texts = {}
let missing = 0
for (const file of files) {
  const doc = JSON.parse(fs.readFileSync(path.join(detailsDir, file), 'utf8'))
  const id = doc.licenseId
  const text = doc.licenseText
  if (!id || typeof text !== 'string' || text.length === 0) {
    missing++
    continue
  }
  texts[id] = text
}

// Sort keys for a deterministic, diff-stable artifact.
const sorted = {}
for (const id of Object.keys(texts).sort()) {
  sorted[id] = texts[id]
}

process.stdout.write(
  JSON.stringify({ licenseListVersion: LICENSE_LIST_VERSION, texts: sorted }),
)

console.error(`bundled ${Object.keys(sorted).length} license texts (${missing} skipped)`)
