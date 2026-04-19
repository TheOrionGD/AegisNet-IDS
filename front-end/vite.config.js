import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],

  // ── Central .env ────────────────────────────────────────────────────────────
  // Vite normally looks for .env files in the same folder as vite.config.js
  // (i.e. front-end/).  Setting envDir to '..' tells it to read from the
  // project root instead, so the single E:\PROJECTS\CNS\.env is used.
  //
  // ⚠️  VITE_ PREFIX REQUIRED
  // Only variables whose names start with VITE_ are embedded into the browser
  // bundle.  Variables without this prefix stay server-side and are invisible
  // to import.meta.env in your React components.
  //
  //   ✅  VITE_API_BASE_URL=http://10.169.17.117:2345   → import.meta.env.VITE_API_BASE_URL
  //   ✅  VITE_WS_URL=ws://10.169.17.117:2345/ws/events → import.meta.env.VITE_WS_URL
  //   ❌  MONGODB_URL=...                               → never exposed to the browser
  // ────────────────────────────────────────────────────────────────────────────
  envDir: '..', // one level up → E:\PROJECTS\CNS

  server: {
    port: 1234,
  },
})
