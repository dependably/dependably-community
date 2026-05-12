#!/usr/bin/env bash
# i18n-import.sh — Import a completed XLIFF 2.0 translation file into Dependably's locale sources.
#
# Usage:
#   i18n/scripts/i18n-import.sh path/to/frontend.fr.xlf
#   i18n/scripts/i18n-import.sh path/to/backend.fr.xlf
#
# The script auto-detects whether the file is a frontend (JSON) or backend (ResX) bundle
# by inspecting the <file original="..."> attribute. Translated values replace the
# corresponding placeholders in the live locale files.
#
# Requires: node, xmllint (libxml2-utils)

set -euo pipefail

XLIFF_FILE="${1:-}"
if [[ -z "$XLIFF_FILE" ]]; then
  echo "Usage: $0 path/to/translation.xlf" >&2
  exit 1
fi
if [[ ! -f "$XLIFF_FILE" ]]; then
  echo "Error: file not found: $XLIFF_FILE" >&2
  exit 1
fi

# Detect target locale from trgLang attribute
LOCALE=$(node -e "
const fs = require('fs');
const xml = fs.readFileSync('$XLIFF_FILE', 'utf8');
const m = xml.match(/trgLang=[\"']([^\"']+)[\"']/);
if (!m) { console.error('Error: trgLang attribute not found in XLIFF file'); process.exit(1); }
console.log(m[1]);
")

echo "Detected target locale: $LOCALE"

# Detect bundle type from <file original="...">
ORIGINAL=$(node -e "
const fs = require('fs');
const xml = fs.readFileSync('$XLIFF_FILE', 'utf8');
const m = xml.match(/original=[\"']([^\"']+)[\"']/);
if (!m) { console.error('Error: original attribute not found in XLIFF file'); process.exit(1); }
console.log(m[1]);
")

echo "Bundle type: $ORIGINAL"

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

if [[ "$ORIGINAL" == *"locales/en.json"* ]] || [[ "$ORIGINAL" == *"frontend"* ]]; then
  # ── Frontend import (XLIFF → JSON) ────────────────────────────────────────
  TARGET_JSON="$REPO_ROOT/web/src/locales/${LOCALE}.json"

  if [[ ! -f "$TARGET_JSON" ]]; then
    echo "Error: target file not found: $TARGET_JSON" >&2
    echo "Create the placeholder file first (see i18n/adding-a-locale.md step 4)." >&2
    exit 1
  fi

  echo "Writing translations to $TARGET_JSON..."

  node - "$XLIFF_FILE" "$TARGET_JSON" <<'EOF'
const fs = require('fs');
const [,, xliffPath, jsonPath] = process.argv;

const xml = fs.readFileSync(xliffPath, 'utf8');
const json = JSON.parse(fs.readFileSync(jsonPath, 'utf8'));

// Extract all <unit id="..."> with non-empty <target>
const unitRe = /<unit\s+id="([^"]+)"[\s\S]*?<target>([\s\S]*?)<\/target>/g;
let match;
const translations = {};
while ((match = unitRe.exec(xml)) !== null) {
  const [, id, target] = match;
  const text = target.trim();
  if (text) translations[id] = text;
}

const count = Object.keys(translations).length;
if (count === 0) {
  console.error('Error: no translated <target> elements found in XLIFF file.');
  process.exit(1);
}
console.log(`Found ${count} translated units.`);

// Set nested key in object
function setKey(obj, dotPath, value) {
  const parts = dotPath.split('.');
  let cur = obj;
  for (let i = 0; i < parts.length - 1; i++) {
    if (typeof cur[parts[i]] !== 'object') cur[parts[i]] = {};
    cur = cur[parts[i]];
  }
  cur[parts[parts.length - 1]] = value;
}

let updated = 0;
let skipped = 0;
for (const [id, value] of Object.entries(translations)) {
  setKey(json, id, value);
  updated++;
}

fs.writeFileSync(jsonPath, JSON.stringify(json, null, 2) + '\n', 'utf8');
console.log(`Updated ${updated} keys in ${jsonPath}.`);
EOF

elif [[ "$ORIGINAL" == *"SharedResource"* ]] || [[ "$ORIGINAL" == *"backend"* ]]; then
  # ── Backend import (XLIFF → ResX) ─────────────────────────────────────────
  TARGET_RESX="$REPO_ROOT/src/Dependably/Resources/SharedResource.${LOCALE}.resx"

  if [[ ! -f "$TARGET_RESX" ]]; then
    echo "Error: target file not found: $TARGET_RESX" >&2
    echo "Create the placeholder file first (see i18n/adding-a-locale.md step 4)." >&2
    exit 1
  fi

  echo "Writing translations to $TARGET_RESX..."

  node - "$XLIFF_FILE" "$TARGET_RESX" <<'EOF'
const fs = require('fs');
const [,, xliffPath, resxPath] = process.argv;

const xml = fs.readFileSync(xliffPath, 'utf8');
let resx = fs.readFileSync(resxPath, 'utf8');

const unitRe = /<unit\s+id="([^"]+)"[\s\S]*?<target>([\s\S]*?)<\/target>/g;
let match;
let updated = 0;
while ((match = unitRe.exec(xml)) !== null) {
  const [, id, target] = match;
  const text = target.trim();
  if (!text) continue;
  // Replace the value for this key in the resx
  const dataRe = new RegExp(
    `(<data\\s+name="${id.replace(/\./g, '\\.')}[^"]*"[^>]*>\\s*<value>)[^<]*(</value>)`,
    'g'
  );
  const before = resx;
  resx = resx.replace(dataRe, `$1${text}$2`);
  if (resx !== before) updated++;
}

fs.writeFileSync(resxPath, resx, 'utf8');
console.log(`Updated ${updated} keys in ${resxPath}.`);
EOF

else
  echo "Error: could not determine bundle type from original=\"$ORIGINAL\"." >&2
  echo "Expected the original attribute to contain 'locales/en.json' or 'SharedResource'." >&2
  exit 1
fi

echo ""
echo "Import complete. Run 'node i18n/scripts/i18n-validate.js' to verify completeness."
