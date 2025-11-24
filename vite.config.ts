import { defineConfig } from "vite";

export default defineConfig({
  build: {
    outDir: "dist-web",
    emptyOutDir: true,
  },
  server: {
    port: 3000,
    open: true,
  },
  assetsInclude: ["**/*.wasm"],
});
