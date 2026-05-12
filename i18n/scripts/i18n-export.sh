#!/usr/bin/env bash
# i18n-export.sh — Export translatable strings to XLIFF 2.0 for translator handoff.
#
# Outputs:
#   i18n/handoff/frontend.en.xlf  (from web/src/locales/en.json)
#   i18n/handoff/backend.en.xlf   (from src/Dependably/Resources/SharedResource.resx)
#
# Usage:
#   i18n/scripts/i18n-export.sh
#
# Idempotent: re-running overwrites the previous output with identical content.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

FRONTEND_JSON="$REPO_ROOT/web/src/locales/en.json"
BACKEND_RESX="$REPO_ROOT/src/Dependably/Resources/SharedResource.resx"
HANDOFF_DIR="$REPO_ROOT/i18n/handoff"

mkdir -p "$HANDOFF_DIR"

FRONTEND_XLF="$HANDOFF_DIR/frontend.en.xlf"
BACKEND_XLF="$HANDOFF_DIR/backend.en.xlf"

# ── Frontend export (JSON → XLIFF) ────────────────────────────────────────────

if [ ! -f "$FRONTEND_JSON" ]; then
  echo "WARNING: $FRONTEND_JSON not found — skipping frontend export." >&2
else
  echo "Exporting frontend strings: $FRONTEND_JSON → $FRONTEND_XLF"

  node - "$FRONTEND_JSON" "$FRONTEND_XLF" <<'EOF'
const fs = require('fs');
const path = require('path');

const [,, inputPath, outputPath] = process.argv;

const json = JSON.parse(fs.readFileSync(inputPath, 'utf8'));

// Flatten nested object to dot-separated keys
function flatten(obj, prefix = '') {
  const result = {};
  for (const [k, v] of Object.entries(obj)) {
    const key = prefix ? `${prefix}.${k}` : k;
    if (v !== null && typeof v === 'object' && !Array.isArray(v)) {
      Object.assign(result, flatten(v, key));
    } else {
      result[key] = String(v);
    }
  }
  return result;
}

const flat = flatten(json);

// Escape XML special characters
function escapeXml(str) {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

const units = Object.entries(flat)
  .sort(([a], [b]) => a.localeCompare(b))
  .map(([id, value]) => `    <unit id="${escapeXml(id)}">
      <segment>
        <source>${escapeXml(value)}</source>
        <target/>
      </segment>
    </unit>`)
  .join('\n');

const xliff = `<?xml version="1.0" encoding="UTF-8"?>
<xliff version="2.0" xmlns="urn:oasis:names:tc:xliff:document:2.0" srcLang="en" trgLang="fr">
  <file id="frontend" original="web/src/locales/en.json">
${units}
  </file>
</xliff>
`;

fs.writeFileSync(outputPath, xliff, 'utf8');
console.log(`Wrote ${Object.keys(flat).length} units to ${outputPath}`);
EOF

fi

# ── Backend export (ResX → XLIFF) ─────────────────────────────────────────────

if [ ! -f "$BACKEND_RESX" ]; then
  echo "WARNING: $BACKEND_RESX not found — skipping backend export." >&2
else
  echo "Exporting backend strings: $BACKEND_RESX → $BACKEND_XLF"

  node - "$BACKEND_RESX" "$BACKEND_XLF" <<'EOF'
const fs = require('fs');

const [,, inputPath, outputPath] = process.argv;

const xml = fs.readFileSync(inputPath, 'utf8');

// Escape XML special characters
function escapeXml(str) {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

// Extract <data name="..."><value>...</value></data> entries.
// Skips entries whose name starts with ">>" (ResX metadata comments).
const dataPattern = /<data\s+name="([^"]+)"[^>]*>\s*<value>([\s\S]*?)<\/value>/g;
const entries = [];
let match;
while ((match = dataPattern.exec(xml)) !== null) {
  const name = match[1];
  const value = match[2].trim();
  if (!name.startsWith('>>')) {
    entries.push({ name, value });
  }
}

entries.sort((a, b) => a.name.localeCompare(b.name));

const units = entries
  .map(({ name, value }) => `    <unit id="${escapeXml(name)}">
      <segment>
        <source>${escapeXml(value)}</source>
        <target/>
      </segment>
    </unit>`)
  .join('\n');

const xliff = `<?xml version="1.0" encoding="UTF-8"?>
<xliff version="2.0" xmlns="urn:oasis:names:tc:xliff:document:2.0" srcLang="en" trgLang="fr">
  <file id="backend" original="src/Dependably/Resources/SharedResource.resx">
${units}
  </file>
</xliff>
`;

fs.writeFileSync(outputPath, xliff, 'utf8');
console.log(`Wrote ${entries.length} units to ${outputPath}`);
EOF

fi

echo "Export complete."
