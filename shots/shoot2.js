const { chromium } = require("playwright");
const KEY = process.env.TL_KEY;
const BASE = "http://localhost:3000";

async function ready(page) {
  await page.waitForLoadState("networkidle").catch(() => {});
  await page.waitForTimeout(1500);
}

(async () => {
  const browser = await chromium.launch({ args: ["--no-sandbox"] });
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 1000 }, deviceScaleFactor: 2 });
  await ctx.addInitScript((k) => window.localStorage.setItem("tl_api_key", k), KEY);
  const page = await ctx.newPage();

  // Search "cobalt" — submit via Enter key (reliable)
  await page.goto(BASE + "/search", { waitUntil: "domcontentloaded" });
  await page.waitForSelector("text=Intelligence Search");
  await page.fill("input", "cobalt");
  await page.press("input", "Enter");
  await page.waitForSelector("text=Threat Actors (", { timeout: 30000 });
  await ready(page);
  await page.screenshot({ path: "/work/05-search.png", fullPage: true });
  console.log("shot: search results");

  // IOC Pivot on a real ingested IP
  await page.goto(BASE + "/search", { waitUntil: "domcontentloaded" });
  await page.waitForSelector("text=Intelligence Search");
  await page.click("button:has-text('IOC Pivot')");
  await page.fill("input", "77.90.153.30");
  await page.press("input", "Enter");
  await page.waitForSelector("text=Indicator found", { timeout: 30000 });
  await ready(page);
  await page.screenshot({ path: "/work/07-pivot.png", fullPage: true });
  console.log("shot: pivot");

  await browser.close();
  console.log("DONE");
})().catch((e) => { console.error(e); process.exit(1); });
