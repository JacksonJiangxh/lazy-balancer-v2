import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import { resolve } from 'path'
import Components from 'unplugin-vue-components/vite'
import { ElementPlusResolver } from 'unplugin-vue-components/resolvers'

// 面板默认 admin_tls_enabled=0；仅开发机明确启用 HTTPS 时设置
// VITE_DEV_BACKEND_HTTPS=1（secure:false 用于自签证书）。
const devBackendTarget = process.env.VITE_DEV_BACKEND_HTTPS === '1'
  ? 'https://localhost:8000'
  : 'http://localhost:8000'

export default defineConfig({
  plugins: [
    vue(),
    Components({
      dts: false,
      resolvers: [ElementPlusResolver({ importStyle: 'css' })],
    }),
  ],
  resolve: {
    alias: {
      '@': resolve(__dirname, 'src'),
    },
  },
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: devBackendTarget,
        changeOrigin: true,
        secure: false,
      },
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    rollupOptions: {
      output: {
        manualChunks(moduleId) {
          if (moduleId.includes('/node_modules/echarts/') || moduleId.includes('/node_modules/zrender/')) return 'charts'
        },
      },
    },
  },
})
