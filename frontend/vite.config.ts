import { sveltekit } from "@sveltejs/kit/vite";
import { defineConfig } from "vite";

// Dev: `luoto ui --no-open` serves the API on :7878 and Vite proxies /api to it. The backend
// checks the Host header, hence changeOrigin.
export default defineConfig({
  plugins: [sveltekit()],
  server: {
    proxy: {
      "/api": { target: "http://127.0.0.1:7878", changeOrigin: true },
    },
  },
});
