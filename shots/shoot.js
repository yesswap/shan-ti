const { chromium } = require("playwright");

const KEY = process.env.TL_KEY;
const BASE = "http://localhost:3000";

async function ready(page) {
  // wait for client-side fetches to settle
  await page.waitForLoadState("networkidle").catch(() => {});
  await page.waitForTimeout(1200);
}

(async () => {
  const browser = await chromium.launch({ args: ["--no-sandbox"] });
  const ctx = await browser.newContext({
    viewport: { width: 1440, height: 1000 },
    deviceScaleFactor: 2,
  });
  // Inject API key into localStorage before any page script runs
  await ctx.addInitScript((k) => {
    window.localStorage.setItem("tl_api_key", k);
  }, KEY);

  const page = await ctx.newPage();

  // 1) Actor registry (home)
  await page.goto(BASE + "/", { waitUntil: "domcontentloaded" });
  await page.waitForSelector("text=Threat Actors", { timeout: 30000 });
  await ready(page);
  await page.screenshot({ path: "/work/01-actor-registry.png", fullPage: true });
  console.log("shot 1: actor registry");

  // 2) Actor profile — APT28 (id 37), overview w/ ATT&CK heatmap
  await page.goto(BASE + "/actors/37", { waitUntil: "domcontentloaded" });
  await page.waitForSelector("text=ATT&CK Technique Heatmap", { timeout: 30000 });
  await ready(page);
  await page.screenshot({ path: "/work/02-actor-profile-overview.png", fullPage: true });
  console.log("shot 2: actor profile overview");

  // 2b) TTPs tab
  await page.click("button:has-text('ttps')");
  await ready(page);
  await page.screenshot({ path: "/work/03-actor-ttps.png", fullPage: true });
  console.log("shot 3: actor ttps tab");

  // 2c) Malware tab
  await page.click("button:has-text('malware')");
  await ready(page);
  await page.screenshot({ path: "/work/04-actor-malware.png", fullPage: true });
  console.log("shot 4: actor malware tab");

  // 3) Search — cross-entity ("cobalt")
  await page.goto(BASE + "/search", { waitUntil: "domcontentloaded" });
  await page.waitForSelector("text=Intelligence Search", { timeout: 30000 });
  await page.fill("input", "cobalt");
  await page.click("button:has-text('Search')");
  await ready(page);
  await page.screenshot({ path: "/work/05-search.png", fullPage: true });
  console.log("shot 5: search");

  // 4) Register page
  await page.goto(BASE + "/register", { waitUntil: "domcontentloaded" });
  await ready(page);
  await page.screenshot({ path: "/work/06-register.png", fullPage: true });
  console.log("shot 6: register");

  await browser.close();
  console.log("ALL SHOTS DONE");
})().catch((e) => { console.error(e); process.exit(1); });
