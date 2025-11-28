import { defineConfig } from "vite";

export default defineConfig({
  base: "./", // 相対パスで出力（GitHub Pagesの任意のパスで動作）
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
