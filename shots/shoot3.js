const { chromium } = require("playwright");
const BASE = "http://localhost:3000";
(async () => {
  const browser = await chromium.launch({ args: ["--no-sandbox"] });
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 1000 }, deviceScaleFactor: 2 });
  // NOTE: deliberately NOT setting localStorage tl_api_key — proves the site
  // is browsable with no key at all.
  const page = await ctx.newPage();
  await page.goto(BASE + "/", { waitUntil: "domcontentloaded" });
  await page.waitForSelector("text=Threat Actors", { timeout: 30000 });
  await page.waitForLoadState("networkidle").catch(() => {});
  await page.waitForTimeout(1500);
  await page.screenshot({ path: "/work/08-public-no-key.png", fullPage: true });
  console.log("shot: public homepage (no key)");
  await browser.close();
})().catch((e) => { console.error(e); process.exit(1); });
