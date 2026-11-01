import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
// Built output is served same-origin by api.py at /coordinator/. In dev, /v1 is proxied to the
// local API so the session cookie stays same-origin (no CORS).
export default defineConfig({
  base: '/coordinator/',
  plugins: [react()],
  server: { host: '127.0.0.1', proxy: { '/v1': 'http://127.0.0.1:8765' } },
  preview: { host: '127.0.0.1' },
});
