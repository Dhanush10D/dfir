/// <reference types="vitest/config" />
import { fileURLToPath, URL } from 'node:url'

import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// Dev server proxies /api to the backend (uvicorn on 127.0.0.1:8000 or the compose api).
const apiTarget = process.env.VITE_API_PROXY ?? 'http://127.0.0.1:8000'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) },
  },
  server: {
    host: '127.0.0.1',
    port: 5173,
    proxy: { '/api': { target: apiTarget, changeOrigin: false } },
  },
  // Source maps only when asked for (VITE_SOURCEMAP=1); nginx would otherwise serve them publicly.
  build: { sourcemap: process.env.VITE_SOURCEMAP === '1' },
  test: {
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
    css: false,
    globals: true,
    unstubGlobals: true,
    restoreMocks: true,
  },
})
