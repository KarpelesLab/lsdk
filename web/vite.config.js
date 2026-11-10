import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// Relative base so the build works from any GitHub Pages sub-path.
export default defineConfig({
  base: './',
  plugins: [vue()],
  build: { target: 'es2022' },
  server: { fs: { allow: ['..'] } },
})
