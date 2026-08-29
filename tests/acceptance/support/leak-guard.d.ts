/**
 * Pinned API contract for the `@tegata/leak-guard` package (implemented later
 * in `packages/leak-guard`). The acceptance tests compile against this
 * declaration; the implementation MUST satisfy it unchanged.
 *
 * This file is owned by the acceptance suite (gauntlet). Do not modify it
 * during implementation.
 */
declare module "@tegata/leak-guard" {
  export interface LeakGuardOptions {
    /** Path to the `leakscan` binary used for all content scans. */
    leakscanBin: string;
    /**
     * Directories treated as agent-visible. A filesystem snapshot is taken at
     * creation time; at assert time, files created or modified under these
     * roots are content-scanned for canaries. The isolated daemon's private
     * directory must NOT be listed here (it simulates the far side of the
     * boundary).
     */
    agentVisibleRoots: string[];
    /**
     * While the guard is live, `ps -eo args` is sampled at this interval and
     * every sample is scanned at assert time. Defaults to 200ms.
     */
    psSampleIntervalMs?: number;
    /**
     * Process-listing sampler commands, each an argv array whose stdout is
     * recorded as a "ps" surface sample at every interval. Defaults to
     * `[["ps", "-eo", "args"]]`. The Windows rig adds a WMI command-line
     * sampler (`Get-CimInstance Win32_Process`) run through WSL interop.
     */
    psSampleCommands?: string[][];
  }

  export interface LeakHit {
    /** Which observed surface leaked: recorded value, filesystem, or ps. */
    surface: "observed" | "fs" | "ps";
    /** Label of the observed value or path of the offending file. */
    label: string;
    /** Canary label that was found (e.g. "password"). */
    canaryLabel: string;
    /** Encoding under which the canary matched (raw, base64, url, hex, json). */
    encoding: string;
  }

  export interface LeakGuard {
    /** Opaque per-run id, usable in test-scoped names. */
    readonly runId: string;
    /**
     * Return the canary value for `label`, generating and registering it on
     * first use. Format: `LEAK_CANARY_<runId>_<label>_<random32hex>`.
     */
    canary(label: string): string;
    /**
     * Record an agent-observable value (MCP response, DOM dump, endpoint
     * string...). Values are JSON-serialized and recursively scanned at
     * assert time, in raw form plus base64 / URL / hex / JSON-escape variants
     * of every canary.
     */
    observe(label: string, value: unknown): void;
    /** Run every scan and return all hits without throwing. */
    collectLeaks(): Promise<LeakHit[]>;
    /** Run every scan; throw with a hit summary if any canary is found. */
    assertNoLeaks(): Promise<void>;
    /** Stop background sampling and release resources. Idempotent. */
    dispose(): Promise<void>;
  }

  export function createLeakGuard(opts: LeakGuardOptions): Promise<LeakGuard>;
}
