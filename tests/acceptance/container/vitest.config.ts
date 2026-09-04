import { defineConfig } from "vitest/config";

// The Phase 4b container suite drives a real (rootful) docker daemon: every
// test creates its own bridge network, binds a host daemon to its gateway
// and runs containers on it, so tests must not overlap. Timeouts cover an
// image pull on a cold host and a full login through the bridge. Run from
// the repo root:
//   npm run test:container
//   sudo -v && TEGATA_DOCKER="sudo docker" npm run test:container
// Without a reachable docker daemon (`${TEGATA_DOCKER} info` fails) every
// test in the suite is skipped.
export default defineConfig({
  test: {
    include: ["tests/acceptance/container/*.test.ts"],
    fileParallelism: false,
    maxConcurrency: 1,
    testTimeout: 300_000,
    hookTimeout: 300_000,
  },
});
