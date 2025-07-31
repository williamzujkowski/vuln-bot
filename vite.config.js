import { defineConfig } from 'vite';
import path from 'path';

// NIST-IG: Build Configuration Management (CM-2)
export default defineConfig({
  root: 'src',
  build: {
    outDir: '../public',
    emptyOutDir: false, // Don't delete Eleventy output
    rollupOptions: {
      input: {
        main: path.resolve(__dirname, 'src/assets/ts/main.ts'),
        dashboard: path.resolve(__dirname, 'src/assets/ts/dashboard.ts'),
        analytics: path.resolve(__dirname, 'src/assets/ts/analytics.ts')
      },
      output: {
        entryFileNames: 'assets/js/[name]-[hash].js',
        chunkFileNames: 'assets/js/[name]-[hash].js',
        assetFileNames: 'assets/[ext]/[name]-[hash].[ext]'
      }
    },
    // Optimize for production
    minify: 'terser',
    terserOptions: {
      compress: {
        drop_console: true,
        drop_debugger: true
      }
    },
    reportCompressedSize: true,
    chunkSizeWarningLimit: 500
  },
  server: {
    port: 3000,
    open: true,
    cors: true
  },
  optimizeDeps: {
    include: ['alpinejs', 'fuse.js']
  },
  plugins: []
});