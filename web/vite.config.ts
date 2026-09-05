import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: {
    host: '0.0.0.0',
    port: Number(process.env.PORT) || 9157,
    proxy: {
      '/routermonitor.v1.': {
        target: process.env.VITE_ROUTER_URL || 'http://router:9156',
        changeOrigin: true,
      },
      '/metrics': {
        target: process.env.VITE_ROUTER_URL || 'http://router:9156',
        changeOrigin: true,
      },
    },
  },
})
