import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  base: '/admin/',
  appType: 'spa',
  server: {
    port: 5173,
    proxy: {
      '/iam': {
        target: 'http://localhost:9096',
        changeOrigin: true,
      },
      '/oauth': {
        target: 'http://localhost:9096',
        changeOrigin: true,
      },
      '/swagger': {
        target: 'http://localhost:9096',
        changeOrigin: true,
      },
      '/.well-known': {
        target: 'http://localhost:9096',
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: 'dist',
    assetsDir: 'assets',
    manifest: true,
  },
});
