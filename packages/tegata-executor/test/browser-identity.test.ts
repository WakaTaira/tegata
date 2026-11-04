import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, test } from "vitest";
import {
  browserUserAgent,
  checkFullChromium,
  chromiumVersionFromManifest,
  fallbackUserAgentMetadata,
  helloResponse,
} from "../src/index.js";

describe("browserUserAgent", () => {
  test("keeps only the major version on Linux", () => {
    expect(browserUserAgent("149.0.7827.55", "linux")).toBe(
      "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36",
    );
  });

  test("uses the Windows platform token on win32", () => {
    expect(browserUserAgent("150.1.2.3", "win32")).toBe(
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36",
    );
  });

  test("never announces a headless browser", () => {
    expect(browserUserAgent("149.0.7827.55", "linux")).not.toContain(
      "Headless",
    );
  });

  test("rejects a malformed browser version", () => {
    expect(() => browserUserAgent("latest", "linux")).toThrow();
  });

  test("rejects an unsupported platform", () => {
    expect(() => browserUserAgent("149.0.7827.55", "aix")).toThrow();
  });
});

describe("chromiumVersionFromManifest", () => {
  test("reads the full chromium entry, not the headless shell", () => {
    expect(
      chromiumVersionFromManifest({
        browsers: [
          { name: "chromium-headless-shell", browserVersion: "1.0.0.0" },
          { name: "chromium", browserVersion: "149.0.7827.55" },
        ],
      }),
    ).toBe("149.0.7827.55");
  });

  test("fails when the chromium entry is missing", () => {
    expect(() =>
      chromiumVersionFromManifest({
        browsers: [{ name: "chromium-headless-shell", browserVersion: "1" }],
      }),
    ).toThrow();
    expect(() => chromiumVersionFromManifest(null)).toThrow();
  });
});

describe("fallbackUserAgentMetadata", () => {
  test("keeps the GREASE brand next to Chromium", () => {
    const metadata = fallbackUserAgentMetadata("Chrome/149.0.7827.55");
    expect(metadata.brands).toEqual([
      { brand: "Chromium", version: "149" },
      { brand: "Not)A;Brand", version: "24" },
    ]);
    expect(metadata.fullVersionList).toEqual([
      { brand: "Chromium", version: "149.0.7827.55" },
      { brand: "Not)A;Brand", version: "24.0.0.0" },
    ]);
  });

  test("never lists a headless brand", () => {
    const metadata = fallbackUserAgentMetadata("HeadlessChrome/149.0.7827.55");
    for (const { brand } of [...metadata.brands, ...metadata.fullVersionList]) {
      expect(brand).not.toContain("Headless");
    }
  });
});

describe("checkFullChromium", () => {
  const tempDirs: string[] = [];

  afterEach(() => {
    for (const dir of tempDirs.splice(0)) {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  function tempDir(): string {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tegata-chromium-"));
    tempDirs.push(dir);
    return dir;
  }

  function expectRefusal(
    result: ReturnType<typeof checkFullChromium>,
    browsersPath: string,
  ): string {
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("unreachable");
    expect(result.reason).toMatch(/chromium/i);
    expect(result.reason).toContain("required");
    expect(result.reason).toContain("--only-shell");
    expect(result.reason).toContain(browsersPath);
    return result.reason;
  }

  test("accepts an executable file", () => {
    const executable = path.join(tempDir(), "chrome");
    fs.writeFileSync(executable, "#!/bin/sh\n", { mode: 0o755 });
    expect(checkFullChromium(() => executable, "/browsers")).toEqual({
      ok: true,
    });
  });

  test("refuses a missing executable and names the browsers path", () => {
    const browsersPath = tempDir();
    const missing = path.join(browsersPath, "chromium-1228", "chrome");
    const reason = expectRefusal(
      checkFullChromium(() => missing, browsersPath),
      browsersPath,
    );
    expect(reason).toContain(missing);
  });

  test.skipIf(process.platform === "win32")(
    "refuses a file without execute permission",
    () => {
      const browsersPath = tempDir();
      const executable = path.join(browsersPath, "chrome");
      fs.writeFileSync(executable, "#!/bin/sh\n", { mode: 0o644 });
      expectRefusal(
        checkFullChromium(() => executable, browsersPath),
        browsersPath,
      );
    },
  );

  test("refuses a directory even when it is searchable", () => {
    const browsersPath = tempDir();
    const directory = path.join(browsersPath, "chrome");
    fs.mkdirSync(directory, { mode: 0o755 });
    expectRefusal(
      checkFullChromium(() => directory, browsersPath),
      browsersPath,
    );
  });

  test("refuses when the executable path cannot be resolved", () => {
    expectRefusal(
      checkFullChromium(() => {
        throw new Error("unsupported platform");
      }, "/browsers"),
      "/browsers",
    );
  });

  test("reports an unset browsers path explicitly", () => {
    const result = checkFullChromium(() => "/nonexistent/chrome", undefined);
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("unreachable");
    expect(result.reason).toContain("PLAYWRIGHT_BROWSERS_PATH=(unset)");
  });
});

describe("helloResponse", () => {
  test("keeps the success shape unchanged", () => {
    expect(helloResponse({ ok: true })).toEqual({
      ok: true,
      uid: process.getuid?.() ?? null,
      pid: process.pid,
    });
  });

  test("adds the reason to a refusal and still reports the identity", () => {
    expect(helloResponse({ ok: false, reason: "missing" })).toEqual({
      ok: false,
      uid: process.getuid?.() ?? null,
      pid: process.pid,
      reason: "missing",
    });
  });
});
