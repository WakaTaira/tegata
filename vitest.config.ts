import { defineConfig } from "vitest/config";

// Acceptance tests spawn a daemon, an MCP server, a browser and a fixture web
// server per test; they must run strictly serially to keep process/port state
// and leak-scan surfaces isolated from each other.
// The Windows/WSL rig suite under tests/acceptance/windows/ has its own
// config (it only runs on the rig); this root config covers the Linux suite.
export default defineConfig({
  test: {
    include: ["tests/acceptance/*.test.ts"],
    fileParallelism: false,
    maxConcurrency: 1,
    testTimeout: 120_000,
    hookTimeout: 60_000,
  },
});
