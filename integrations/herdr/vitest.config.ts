import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["test/*.test.ts"],
    fileParallelism: false,
    maxConcurrency: 1,
    testTimeout: 120_000,
    hookTimeout: 30_000,
  },
});
