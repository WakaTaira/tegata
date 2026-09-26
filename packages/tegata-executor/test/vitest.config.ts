import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["packages/tegata-executor/test/**/*.test.ts"],
  },
});
