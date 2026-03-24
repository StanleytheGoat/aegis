import { defineConfig } from "astro/config";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  outDir: "./dist/site",
  vite: {
    plugins: [tailwindcss()],
  },
});
