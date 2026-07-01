import { defineConfig } from 'vite'
import { svelte } from '@sveltejs/vite-plugin-svelte'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

// Single source of truth for the displayed app version: the repo-root
// Directory.Build.props <Version>. web/package.json is a private placeholder and
// drifts from the real (.NET) build version — read the props file so the sidebar
// footer always matches the rest of the project.
function appVersion() {
  try {
    const props = readFileSync(fileURLToPath(new URL('../Directory.Build.props', import.meta.url)), 'utf8')
    const m = props.match(/<Version>\s*([^<\s]+)\s*<\/Version>/)
    if (m) return m[1]
  } catch {
    // Fall through to the npm-provided version below.
  }
  return process.env.npm_package_version || '0.0.0'
}

export default defineConfig({
  plugins: [svelte()],
  // Surface the project version to the SPA (sidebar footer) — see appVersion().
  define: {
    __APP_VERSION__: JSON.stringify(appVersion()),
  },
  build: {
    outDir: '../src/Dependably/wwwroot',
    emptyOutDir: true,
    // esbuild avoids lightningcss's per-platform native binary, whose
    // optional-dep install is unreliable under `npm ci` in cross-platform
    // Docker builds (e.g. linux-arm64-musl missing from a macOS lockfile).
    cssMinify: 'esbuild',
    // Emit every asset as a file under /assets instead of inlining small ones as
    // base64 data: URIs. Fonts in particular must stay real files so the strict
    // Content-Security-Policy (font-src 'self') admits them — an inlined
    // data:font/woff2 is blocked.
    assetsInlineLimit: 0,
  },
})
