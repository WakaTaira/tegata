// CDP probe run inside the agent container: connect Playwright to the CDP
// endpoint the MCP `login` returned (the bridge's local tunnel) and report
// the title of the page whose URL starts with <urlPrefix> as one JSON line.
//   node cdp-title.mjs <endpoint> <urlPrefix>
// Resolves `playwright-core` from /app/node_modules, so it must run from a
// path below /app.
import { chromium } from "playwright-core";

const [endpoint, urlPrefix] = process.argv.slice(2);
const browser = await chromium.connectOverCDP(endpoint, { timeout: 20_000 });
try {
  const pages = browser.contexts().flatMap((context) => context.pages());
  const page = pages.find((candidate) => candidate.url().startsWith(urlPrefix));
  if (page === undefined) {
    process.stdout.write(
      `${JSON.stringify({ error: "no page for prefix", urls: pages.map((p) => p.url()) })}\n`,
    );
    process.exitCode = 2;
  } else {
    process.stdout.write(
      `${JSON.stringify({ url: page.url(), title: await page.title() })}\n`,
    );
  }
} finally {
  await browser.close();
}
