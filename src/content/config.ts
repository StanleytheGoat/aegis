import { defineCollection, z } from "astro:content";

const blog = defineCollection({
  type: "content",
  schema: z.object({
    title: z.string(),
    description: z.string(),
    date: z.string(),
    author: z.string().default("Aegis Team"),
    tags: z.array(z.string()).default([]),
  }),
});

export const collections = { blog };
