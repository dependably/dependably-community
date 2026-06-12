import { defineConfig } from 'vite'
import { svelte } from '@sveltejs/vite-plugin-svelte'

export default defineConfig({
  plugins: [svelte()],
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
