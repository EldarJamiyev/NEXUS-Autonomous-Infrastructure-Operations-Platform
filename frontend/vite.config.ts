import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "node:path";

const api = process.env.NEXUS_API ?? "http://localhost:8000";

export default defineConfig({
  plugins: [react()],
  resolve: { alias: { "@": path.resolve(__dirname, "src") } },
  server: {
    port: 5173,
    proxy: {
      "/api": api,
      "/health": api,
      "/metrics": api,
      "/ws": { target: api.replace("http", "ws"), ws: true },
    },
  },
  build: { outDir: "dist", sourcemap: false, chunkSizeWarningLimit: 1600 },
  test: { environment: "node" },
});
