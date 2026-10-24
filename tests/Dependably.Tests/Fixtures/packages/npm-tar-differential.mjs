#!/usr/bin/env node
// Prints the top-level package.json that npm would install from a tarball: node-tar extraction
// with pacote's options (strip: 1, only `*File` entries pass the filter, non-strict so invalid
// headers are warned about and skipped). Warnings go to stderr; the installed manifest, or
// "(no package.json installed)", goes to stdout.
//
// A reviewer tool for regenerating the expectations in NpmTarNodeTarParityTests, not a CI test.
//
//   node npm-tar-differential.mjs <tarball.tgz>
//   node npm-tar-differential.mjs --chunk 65536 <tarball.tgz>
//   TESTING_TAR_FAKE_PLATFORM=win32 node npm-tar-differential.mjs <tarball.tgz>
//
// --chunk <bytes> writes the compressed archive to the extractor in pieces of that size, the way
// pacote streams a registry response (libuv reads sockets 64 KiB at a time). zlib's handling of a
// further gzip member depends on where those boundaries fall, so some archives install a
// different manifest per chunk size. Without it the whole file is read through node-tar's own
// file reader.
//
// node-tar resolves from NODE_TAR_PATH, else from the npm installation on PATH.

import { execFileSync } from 'node:child_process'
import { createRequire } from 'node:module'
import { mkdtempSync, readFileSync, existsSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, basename } from 'node:path'

const args = process.argv.slice(2)
let chunk
const chunkAt = args.indexOf('--chunk')
if (chunkAt >= 0) {
  chunk = Number(args[chunkAt + 1])
  args.splice(chunkAt, 2)
  if (!Number.isInteger(chunk) || chunk <= 0) {
    console.error('--chunk needs a positive byte count')
    process.exit(2)
  }
}

const tarball = args[0]
if (!tarball) {
  console.error('usage: node npm-tar-differential.mjs [--chunk <bytes>] <tarball.tgz>')
  process.exit(2)
}

const tarPath = process.env.NODE_TAR_PATH ??
  join(execFileSync('npm', ['root', '-g'], { encoding: 'utf8' }).trim(), 'npm', 'node_modules', 'tar')
const require = createRequire(join(tarPath, 'package.json'))
const tar = require(tarPath)
console.error(`node-tar ${require(join(tarPath, 'package.json')).version}, platform ${process.env.TESTING_TAR_FAKE_PLATFORM ?? process.platform}, ${chunk ? `${chunk}-byte writes` : 'file reader'}`)

const dest = mkdtempSync(join(tmpdir(), 'npm-tar-differential-'))
try {
  const options = {
    cwd: dest,
    strip: 1,
    noChmod: true,
    noMtime: true,
    preserveOwner: false,
    filter: (_name, entry) => {
      if (/Link$/.test(entry.type)) return false
      if (/File$/.test(entry.type)) {
        console.error(`extract ${JSON.stringify(entry.path)}`)
        return true
      }
      return false
    },
    onwarn: (code, message) => console.error(`warn ${code}: ${message instanceof Error ? message.message : message}`),
  }

  if (chunk) {
    const bytes = readFileSync(tarball)
    const extractor = tar.x(options)
    const done = new Promise((resolve, reject) => {
      extractor.on('close', resolve)
      extractor.on('error', reject)
    })
    for (let offset = 0; offset < bytes.length; offset += chunk) {
      extractor.write(bytes.subarray(offset, offset + chunk))
    }
    extractor.end()
    await done
  } else {
    await tar.x({ ...options, file: tarball })
  }

  const manifest = join(dest, 'package.json')
  console.log(existsSync(manifest) ? readFileSync(manifest, 'utf8') : `(no package.json installed from ${basename(tarball)})`)
} finally {
  rmSync(dest, { recursive: true, force: true })
}
