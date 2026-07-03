#!/usr/bin/env node
// i18n-validate.js — CI check for missing and orphaned translation keys.
//
// Checks:
//   1. Frontend: web/src/locales/en.json (source) vs all other locale JSON files.
//   2. Backend:  src/Dependably/Resources/SharedResource.resx (source) vs
//               all src/Dependably/Resources/SharedResource.*.resx files.
//
// Exit codes:
//   0 — no missing keys (warnings about orphaned keys are non-fatal)
//   1 — one or more missing keys found
//
// Usage:
//   node scripts/i18n-validate.js

'use strict';

const fs = require('fs');
const path = require('path');

const REPO_ROOT = path.resolve(__dirname, '..', '..');

let errorCount = 0;
let warnCount = 0;

// ── Utilities ─────────────────────────────────────────────────────────────────

/**
 * Recursively flatten a nested object to dot-separated keys.
 * { a: { b: "x" } } → { "a.b": "x" }
 */
function flattenKeys(obj, prefix = '') {
  const result = {};
  for (const [k, v] of Object.entries(obj)) {
    const key = prefix ? `${prefix}.${k}` : k;
    if (v !== null && typeof v === 'object' && !Array.isArray(v)) {
      Object.assign(result, flattenKeys(v, key));
    } else {
      result[key] = true;
    }
  }
  return result;
}

/**
 * Extract all data names from a ResX XML string.
 * Skips ResX metadata entries whose names start with ">>".
 */
function parseResxKeys(xml) {
  const keys = {};
  const pattern = /<data\s+name="([^"]+)"[^>]*>/g;
  let match;
  while ((match = pattern.exec(xml)) !== null) {
    const name = match[1];
    if (!name.startsWith('>>')) {
      keys[name] = true;
    }
  }
  return keys;
}

function error(msg) {
  console.error(`ERROR: ${msg}`);
  errorCount++;
}

function warn(msg) {
  console.warn(`WARNING: ${msg}`);
  warnCount++;
}

function compareKeys(sourceKeys, targetKeys, locale, fileLabel) {
  const missing = Object.keys(sourceKeys).filter(k => !targetKeys[k]);
  const orphaned = Object.keys(targetKeys).filter(k => !sourceKeys[k]);

  for (const key of missing) {
    error(`Missing key in ${locale} (${fileLabel}): ${key}`);
  }
  for (const key of orphaned) {
    warn(`Orphaned key in ${locale} (${fileLabel}): ${key}`);
  }

  return { missing: missing.length, orphaned: orphaned.length };
}

// ── Frontend validation ────────────────────────────────────────────────────────

const localesDir = path.join(REPO_ROOT, 'web', 'src', 'locales');
const sourceJsonPath = path.join(localesDir, 'en.json');

if (!fs.existsSync(sourceJsonPath)) {
  error(`${sourceJsonPath} not found — frontend source locale is required.`);
} else {
  console.log(`\nValidating frontend locales (source: web/src/locales/en.json)`);
  console.log('─'.repeat(60));

  const sourceJson = JSON.parse(fs.readFileSync(sourceJsonPath, 'utf8'));
  const sourceKeys = flattenKeys(sourceJson);
  const sourceKeyCount = Object.keys(sourceKeys).length;
  console.log(`  Source key count: ${sourceKeyCount}`);

  let localeFiles;
  try {
    localeFiles = fs.readdirSync(localesDir)
      .filter(f => f.endsWith('.json') && f !== 'en.json');
  } catch {
    localeFiles = [];
  }

  if (localeFiles.length === 0) {
    console.log('  No translated locale files found — nothing to compare.');
  } else {
    for (const file of localeFiles.sort()) {
      const locale = path.basename(file, '.json');
      const targetPath = path.join(localesDir, file);
      let targetJson;
      try {
        targetJson = JSON.parse(fs.readFileSync(targetPath, 'utf8'));
      } catch (e) {
        error(`Failed to parse ${file}: ${e.message}`);
        continue;
      }
      const targetKeys = flattenKeys(targetJson);
      const { missing, orphaned } = compareKeys(sourceKeys, targetKeys, locale, file);
      if (missing === 0 && orphaned === 0) {
        console.log(`  ${locale}: OK (${Object.keys(targetKeys).length} keys)`);
      } else {
        console.log(`  ${locale}: ${missing} missing, ${orphaned} orphaned`);
      }
    }
  }
}

// ── Backend validation ─────────────────────────────────────────────────────────

const resourcesDir = path.join(REPO_ROOT, 'src', 'Dependably', 'Resources');
const sourceResxPath = path.join(resourcesDir, 'SharedResource.resx');

if (!fs.existsSync(sourceResxPath)) {
  error(`${sourceResxPath} not found — backend source resource is required.`);
} else {
  console.log(`\nValidating backend resources (source: src/Dependably/Resources/SharedResource.resx)`);
  console.log('─'.repeat(60));

  const sourceXml = fs.readFileSync(sourceResxPath, 'utf8');
  const sourceKeys = parseResxKeys(sourceXml);
  const sourceKeyCount = Object.keys(sourceKeys).length;
  console.log(`  Source key count: ${sourceKeyCount}`);

  let resxFiles;
  try {
    // Match SharedResource.fr.resx, SharedResource.de.resx, etc.
    resxFiles = fs.readdirSync(resourcesDir)
      .filter(f => /^SharedResource\.[a-z]{2,}(-[A-Za-z]+)?\.resx$/.test(f));
  } catch {
    resxFiles = [];
  }

  if (resxFiles.length === 0) {
    console.log('  No translated resource files found — nothing to compare.');
  } else {
    for (const file of resxFiles.sort()) {
      // Extract locale from filename: SharedResource.fr.resx → fr
      const locale = file.replace(/^SharedResource\./, '').replace(/\.resx$/, '');
      const targetPath = path.join(resourcesDir, file);
      let targetXml;
      try {
        targetXml = fs.readFileSync(targetPath, 'utf8');
      } catch (e) {
        error(`Failed to read ${file}: ${e.message}`);
        continue;
      }
      const targetKeys = parseResxKeys(targetXml);
      const { missing, orphaned } = compareKeys(sourceKeys, targetKeys, locale, file);
      if (missing === 0 && orphaned === 0) {
        console.log(`  ${locale}: OK (${Object.keys(targetKeys).length} keys)`);
      } else {
        console.log(`  ${locale}: ${missing} missing, ${orphaned} orphaned`);
      }
    }
  }
}

// ── Handoff currency ───────────────────────────────────────────────────────────
// The XLIFF handoff package (i18n/handoff/*.xlf) is generated from the source locale
// files by i18n-export.sh. A unit-id set that no longer matches the source keys means
// the package was not regenerated after keys were added, renamed, or removed — the
// drift that twice left translators working from a stale export. Unit IDs only are
// compared: editing a string's value without renaming its key stays non-blocking.

function parseXlfUnitIds(xlf) {
  const ids = {};
  const pattern = /<unit\s+id="([^"]+)"/g;
  let match;
  while ((match = pattern.exec(xlf)) !== null) {
    ids[match[1]] = true;
  }
  return ids;
}

function checkHandoff(label, xlfPath, sourceKeys) {
  if (sourceKeys === null) {
    return; // source file missing — already reported above
  }
  console.log(`\nValidating handoff currency (${label}: ${path.relative(REPO_ROOT, xlfPath)})`);
  console.log('─'.repeat(60));
  if (!fs.existsSync(xlfPath)) {
    error(`${xlfPath} not found — run i18n/scripts/i18n-export.sh to (re)generate the handoff package.`);
    return;
  }

  const unitIds = parseXlfUnitIds(fs.readFileSync(xlfPath, 'utf8'));
  const missing = Object.keys(sourceKeys).filter(k => !unitIds[k]);
  const stale = Object.keys(unitIds).filter(k => !sourceKeys[k]);
  for (const key of missing) {
    error(`Handoff (${label}) is missing unit: ${key} — run i18n/scripts/i18n-export.sh.`);
  }
  for (const key of stale) {
    error(`Handoff (${label}) has a stale unit: ${key} — run i18n/scripts/i18n-export.sh.`);
  }
  if (missing.length === 0 && stale.length === 0) {
    console.log(`  ${label}: OK (${Object.keys(unitIds).length} units)`);
  }
}

const frontendSourceKeys = fs.existsSync(sourceJsonPath)
  ? flattenKeys(JSON.parse(fs.readFileSync(sourceJsonPath, 'utf8')))
  : null;
const backendSourceKeys = fs.existsSync(sourceResxPath)
  ? parseResxKeys(fs.readFileSync(sourceResxPath, 'utf8'))
  : null;

checkHandoff('frontend', path.join(REPO_ROOT, 'i18n', 'handoff', 'frontend.en.xlf'), frontendSourceKeys);
checkHandoff('backend', path.join(REPO_ROOT, 'i18n', 'handoff', 'backend.en.xlf'), backendSourceKeys);

// ── Summary ────────────────────────────────────────────────────────────────────

console.log('\n' + '─'.repeat(60));
if (errorCount === 0 && warnCount === 0) {
  console.log('All locale files are complete.');
} else {
  if (warnCount > 0) {
    console.log(`${warnCount} warning(s) — orphaned keys should be cleaned up.`);
  }
  if (errorCount > 0) {
    console.error(`${errorCount} error(s) — missing keys or a stale handoff must be fixed before merging.`);
  }
}

process.exit(errorCount > 0 ? 1 : 0);
