#!/usr/bin/env bash
# i18n-export.sh — Export translatable strings to XLIFF 2.0 for translator handoff.
#
# Outputs:
#   i18n/handoff/frontend.en.xlf  (from web/src/locales/en.json)
#   i18n/handoff/backend.en.xlf   (from the SharedResource.resx in the owning src/Dependably* root)
#
# Existing French translations (web/src/locales/fr.json, SharedResource.fr.resx) are
# pre-filled as <target> with segment state="translated", so CAT tools see the current
# translation as the base; untranslated keys export state="initial" with an empty target.
#
# Usage:
#   i18n/scripts/i18n-export.sh
#
# Idempotent: re-running overwrites the previous output with identical content.
# i18n-validate.js fails CI when these files fall out of step with the source keys, so
# re-run this script whenever a key is added, renamed, or removed.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

FRONTEND_JSON="$REPO_ROOT/web/src/locales/en.json"
FRONTEND_FR_JSON="$REPO_ROOT/web/src/locales/fr.json"
# The backend resources live in exactly one src/Dependably* project root; resolve
# the owning root by content rather than hardcoding a project name.
BACKEND_RESX="$(ls "$REPO_ROOT"/src/Dependably*/Resources/SharedResource.resx 2>/dev/null | head -1)"
BACKEND_FR_RESX="$(dirname "${BACKEND_RESX:-$REPO_ROOT/src/Dependably/Resources/x}")/SharedResource.fr.resx"
BACKEND_RESX_REL="${BACKEND_RESX#"$REPO_ROOT"/}"
HANDOFF_DIR="$REPO_ROOT/i18n/handoff"

mkdir -p "$HANDOFF_DIR"

FRONTEND_XLF="$HANDOFF_DIR/frontend.en.xlf"
BACKEND_XLF="$HANDOFF_DIR/backend.en.xlf"

# ── Frontend export (JSON → XLIFF) ────────────────────────────────────────────

if [ ! -f "$FRONTEND_JSON" ]; then
  echo "WARNING: $FRONTEND_JSON not found — skipping frontend export." >&2
else
  echo "Exporting frontend strings: $FRONTEND_JSON → $FRONTEND_XLF"

  node - "$FRONTEND_JSON" "$FRONTEND_FR_JSON" "$FRONTEND_XLF" <<'EOF'
const fs = require('fs');

const [,, inputPath, frPath, outputPath] = process.argv;

const json = JSON.parse(fs.readFileSync(inputPath, 'utf8'));
const frJson = fs.existsSync(frPath) ? JSON.parse(fs.readFileSync(frPath, 'utf8')) : {};

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
const frFlat = flatten(frJson);

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
  .map(([id, value]) => {
    const fr = frFlat[id];
    const segment = fr === undefined
      ? `<segment state="initial">
        <source>${escapeXml(value)}</source>
        <target/>
      </segment>`
      : `<segment state="translated">
        <source>${escapeXml(value)}</source>
        <target>${escapeXml(fr)}</target>
      </segment>`;
    return `    <unit id="${escapeXml(id)}">
      ${segment}
    </unit>`;
  })
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

  node - "$BACKEND_RESX" "$BACKEND_FR_RESX" "$BACKEND_XLF" "$BACKEND_RESX_REL" <<'EOF'
const fs = require('fs');

const [,, inputPath, frPath, outputPath, resxRel] = process.argv;

const xml = fs.readFileSync(inputPath, 'utf8');
const frXml = fs.existsSync(frPath) ? fs.readFileSync(frPath, 'utf8') : '';

// Escape XML special characters
function escapeXml(str) {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

// Extract <data name="..."><value>...</value>[<comment>...</comment>]</data> entries.
// Skips entries whose name starts with ">>" (ResX metadata comments). A <comment>
// becomes a translator note in the XLIFF unit.
function parseResx(resxXml) {
  const dataPattern = /<data\s+name="([^"]+)"[^>]*>([\s\S]*?)<\/data>/g;
  const entries = [];
  let match;
  while ((match = dataPattern.exec(resxXml)) !== null) {
    const name = match[1];
    const inner = match[2];
    // The value is exported verbatim — trimming would drop deliberate leading/trailing
    // whitespace (the invite email body ends with a newline) and break round-tripping.
    const value = (inner.match(/<value>([\s\S]*?)<\/value>/) ?? [, ''])[1];
    const comment = (inner.match(/<comment>([\s\S]*?)<\/comment>/) ?? [, ''])[1].trim();
    if (!name.startsWith('>>')) {
      entries.push({ name, value, comment });
    }
  }
  return entries;
}

const entries = parseResx(xml);
const frValues = new Map(parseResx(frXml).map(({ name, value }) => [name, value]));

entries.sort((a, b) => a.name.localeCompare(b.name));

// resx <value> text is XML-escaped already; unescape before re-escaping for XLIFF so
// entities are not double-encoded (&amp;amp;).
function unescapeXml(str) {
  return str
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, '&');
}

const units = entries
  .map(({ name, value, comment }) => {
    const notes = comment
      ? `\n      <notes>\n        <note category="translator">${escapeXml(unescapeXml(comment))}</note>\n      </notes>`
      : '';
    const fr = frValues.get(name);
    const segment = fr === undefined
      ? `<segment state="initial">
        <source>${escapeXml(unescapeXml(value))}</source>
        <target/>
      </segment>`
      : `<segment state="translated">
        <source>${escapeXml(unescapeXml(value))}</source>
        <target>${escapeXml(unescapeXml(fr))}</target>
      </segment>`;
    return `    <unit id="${escapeXml(name)}">${notes}
      ${segment}
    </unit>`;
  })
  .join('\n');

const xliff = `<?xml version="1.0" encoding="UTF-8"?>
<xliff version="2.0" xmlns="urn:oasis:names:tc:xliff:document:2.0" srcLang="en" trgLang="fr">
  <file id="backend" original="${resxRel}">
${units}
  </file>
</xliff>
`;

fs.writeFileSync(outputPath, xliff, 'utf8');
console.log(`Wrote ${entries.length} units to ${outputPath}`);
EOF

fi

echo "Export complete."
