import { mount } from 'svelte'
// Self-hosted fonts (woff2 bundled into /assets by Vite) — no Google Fonts CDN at runtime.
// Weights match what was previously requested from fonts.googleapis.com.
import '@fontsource/inter/400.css'
import '@fontsource/inter/500.css'
import '@fontsource/inter/600.css'
import '@fontsource/inter/700.css'
import '@fontsource/jetbrains-mono/400.css'
import '@fontsource/jetbrains-mono/500.css'
import '@fontsource/jetbrains-mono/600.css'
import './app.css'
import App from './App.svelte'

const target = document.getElementById('app')
if (!target) throw new Error('Mount target #app missing from index.html')
const app = mount(App, { target })

export default app
