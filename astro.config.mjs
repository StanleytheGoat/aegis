import { defineConfig } from "astro/config";
import tailwindcss from "@tailwindcss/vite";
import starlight from "@astrojs/starlight";
import mdx from "@astrojs/mdx";

export default defineConfig({
  outDir: "./dist/site",
  integrations: [
    starlight({
      title: "Aegis Docs",
      description: "Documentation for the Aegis DeFi safety layer",
      favicon: "/og.svg",
      social: [
        { icon: "github", label: "GitHub", href: "https://github.com/StanleytheGoat/aegis" },
      ],
      sidebar: [
        {
          label: "Getting Started",
          items: [
            { label: "Introduction", slug: "docs" },
            { label: "Quick Start", slug: "docs/quickstart" },
          ],
        },
        {
          label: "Integration",
          items: [
            { label: "MCP Agent Integration", slug: "docs/agent-integration" },
            { label: "Project Integration", slug: "docs/project-integration" },
          ],
        },
        {
          label: "Reference",
          items: [
            { label: "API Reference", slug: "docs/api" },
            { label: "Pattern Library", link: "/patterns" },
          ],
        },
      ],
      customCss: [],
      disable404Route: true,
    }),
    mdx(),
  ],
  vite: {
    plugins: [tailwindcss()],
  },
});
