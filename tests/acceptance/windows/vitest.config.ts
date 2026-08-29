import { defineConfig } from "vitest/config";

// The Windows/WSL rig suite runs strictly serially: every test drives the
// single tegatad service instance on the rig, and the leak guard's interop
// samplers must not overlap between tests. Timeouts are generous because each
// step crosses the WSL->Windows interop boundary (PowerShell startup alone
// costs seconds). Run from the repo root:
//   npm run test:acceptance:windows
export default defineConfig({
  test: {
    include: ["tests/acceptance/windows/**/*.test.ts"],
    fileParallelism: false,
    maxConcurrency: 1,
    testTimeout: 300_000,
    hookTimeout: 120_000,
  },
});
