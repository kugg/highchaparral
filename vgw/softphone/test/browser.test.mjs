import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

const chrome = process.env.CHROME_EXECUTABLE || "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const site = new URL("../site/", import.meta.url);
const source = (file) => readFileSync(fileURLToPath(new URL(file, site)), "utf8");
const bundled = fileURLToPath(new URL("vendor/sip.min.js", site));
const available = existsSync(chrome) && existsSync(bundled);
const required = process.env.SOFTPHONE_REQUIRE_BROWSER === "1";
const skip = !required && !available;

async function pageWithSIP(context, enabled = false, registrationFailures = 0) {
  const page = await context.newPage();
  const body = source("index.html").replace(/<script[^>]*><\/script>/g, "").replace(/<link[^>]*>/g, "");
  await page.goto("https://127.0.0.1/softphone/"); // fulfilled by local test route
  await page.setContent(body);
  await page.addScriptTag({ path: bundled });
  assert.equal(await page.evaluate(() => typeof SIP.UserAgent), "function");
  await page.addScriptTag({ content: source("config.js") });
  if (enabled) await page.evaluate(() => {
    window.WEBRTC_CONFIG = { ...window.WEBRTC_CONFIG, eventphoneEnabled: true };
  });
  await page.addScriptTag({ content: source("dial.js") });
  await page.addScriptTag({ content: source("byok.js") });
  await page.addScriptTag({ content: `(() => {
    window.__seen = { calls: [], headers: [], agents: [], registrationFailures: ${registrationFailures} };
    const listeners = () => ({ callback: null, addListener(f) { this.callback = f; } });
    class UA {
      static makeURI(s) { return s; }
      constructor(options) { this.options = options; this.delegate = {}; window.__seen.agents.push(this); }
      async start() {}
      async stop() { this.stopped = true; }
    }
    class Registerer {
      constructor() { this.stateChange = listeners(); }
      async register() {
        if (window.__seen.registrationFailures-- > 0) throw Error('synthetic REGISTER refusal');
        this.stateChange.callback('Registered');
      }
    }
    class Inviter {
      constructor(ua, target, options) {
        this.target = target; this.state = 'Initial'; this.stateChange = listeners();
        this.delegate = {}; window.__seen.headers.push(options?.extraHeaders || []);
      }
      async invite() {
        window.__seen.calls.push(this.target);
        this.state = 'Established'; this.stateChange.callback('Established');
      }
      async bye() { this.state = 'Terminated'; this.stateChange.callback('Terminated'); }
    }
    window.SIP = { UserAgent: UA, Registerer, Inviter,
      SessionState: { Establishing: 'Establishing', Established: 'Established', Terminated: 'Terminated' },
      RegistererState: { Registered: 'Registered', Unregistered: 'Unregistered' } };
  })();` });
  await page.addScriptTag({ content: source("app.js") });
  return page;
}

test("failed REGISTER stops the agent and permits an explicit retry", { skip }, async () => {
  assert.ok(available, "required Chrome and SIP.js bundle unavailable");
  const browser = await chromium.launch({ executablePath: chrome, headless: true,
    args: ["--disable-background-networking", "--no-first-run"] });
  try {
    const context = await browser.newContext({ serviceWorkers: "block" });
    await context.route("**/*", (route) => route.request().url() === "https://127.0.0.1/softphone/"
      ? route.fulfill({ status: 200, contentType: "text/html", body: "<!doctype html><title>test</title>" })
      : route.abort());
    const page = await pageWithSIP(context, false, 1);
    await page.locator("#sip-user").fill("180");
    await page.locator("#sip-password").fill("synthetic-pbx-only");
    await page.locator("#connect").click();
    await page.waitForFunction(() => document.querySelector("#status")?.textContent ===
      "PBX registration failed; check WSS trust and account");
    assert.equal(await page.locator("#connect").isEnabled(), true);
    assert.deepEqual(await page.evaluate(() => window.__seen.agents.map((a) => !!a.stopped)), [true]);
    await page.locator("#sip-password").fill("synthetic-pbx-retry");
    await page.locator("#connect").click();
    await page.waitForFunction(() => document.querySelector("#status")?.textContent === "Available");
    assert.equal(await page.locator("#connect").isDisabled(), true);
    assert.deepEqual(await page.evaluate(() => window.__seen.agents.map((a) => !!a.stopped)), [true, false]);
  } finally { await browser.close(); }
});

test("failed start cleans up before manual retry", { skip }, async () => {
  assert.ok(available, "required Chrome and SIP.js bundle unavailable");
  const browser = await chromium.launch({ executablePath: chrome, headless: true,
    args: ["--disable-background-networking", "--no-first-run"] });
  try {
    const context = await browser.newContext({ serviceWorkers: "block" });
    await context.route("**/*", (route) => route.request().url() === "https://127.0.0.1/softphone/"
      ? route.fulfill({ status: 200, contentType: "text/html", body: "<!doctype html>" })
      : route.abort());
    const page = await pageWithSIP(context);
    await page.evaluate(() => { SIP.UserAgent.prototype.start = async () => { throw Error("synthetic start failure"); }; });
    await page.locator("#sip-user").fill("180");
    await page.locator("#connect").click();
    await page.waitForFunction(() => document.querySelector("#status")?.textContent ===
      "PBX registration failed; check WSS trust and account");
    assert.equal(await page.locator("#connect").isEnabled(), true);
    assert.deepEqual(await page.evaluate(() => window.__seen.agents.map((a) => !!a.stopped)), [true]);
  } finally { await browser.close(); }
});

test("uncertain stop does not admit a second credential-bearing agent", { skip }, async () => {
  assert.ok(available, "required Chrome and SIP.js bundle unavailable");
  const browser = await chromium.launch({ executablePath: chrome, headless: true,
    args: ["--disable-background-networking", "--no-first-run"] });
  try {
    const context = await browser.newContext({ serviceWorkers: "block" });
    await context.route("**/*", (route) => route.request().url() === "https://127.0.0.1/softphone/"
      ? route.fulfill({ status: 200, contentType: "text/html", body: "<!doctype html>" })
      : route.abort());
    const page = await pageWithSIP(context, false, 1);
    await page.evaluate(() => { SIP.UserAgent.prototype.stop = async () => { throw Error("synthetic stop failure"); }; });
    await page.locator("#sip-user").fill("180");
    await page.locator("#connect").click();
    await page.waitForFunction(() => document.querySelector("#status")?.textContent ===
      "PBX cleanup uncertain; reload before retrying");
    assert.equal(await page.locator("#connect").isDisabled(), true);
    assert.equal(await page.evaluate(() => window.__seen.agents.length), 1);
  } finally { await browser.close(); }
});

test("built page connects to PBX and places a numeric extension call", { skip }, async () => {
  assert.ok(available, "required Chrome and SIP.js bundle unavailable");
  const browser = await chromium.launch({ executablePath: chrome, headless: true,
    args: ["--disable-background-networking", "--no-first-run"] });
  try {
    const context = await browser.newContext({ serviceWorkers: "block" });
    await context.route("**/*", (route) => route.request().url() === "https://127.0.0.1/softphone/"
      ? route.fulfill({ status: 200, contentType: "text/html", body: "<!doctype html><title>test</title>" })
      : route.abort());
    const page = await pageWithSIP(context);
    assert.equal(await page.locator('option[value="eventphone"]').isDisabled(), true);
    await page.locator("#sip-user").fill("180");
    await page.locator("#sip-password").fill("synthetic-pbx-only");
    await page.locator("#connect").click();
    await page.waitForFunction(() => document.querySelector("#status")?.textContent === "Available");
    assert.equal(await page.locator("#sip-password").inputValue(), "");
    await page.locator("#dial-number").fill("100");
    await page.locator("#dial-submit").click();
    await page.waitForFunction(() => window.__seen.calls.length === 1);
    assert.deepEqual(await page.evaluate(() => window.__seen.calls), ["sip:100@127.0.0.1"]);
    assert.deepEqual(await page.evaluate(() => window.__seen.headers), [[]]);
    await page.locator("#hangup").click();
    await page.waitForFunction(() => document.querySelector("#status")?.textContent === "Call ended");
  } finally { await browser.close(); }
});

test("BYOK keeps provider password out of SIP and ignores injected server response", { skip }, async () => {
  assert.ok(available, "required Chrome and SIP.js bundle unavailable");
  const seen = [];
  let refuse = false;
  const browser = await chromium.launch({ executablePath: chrome, headless: true,
    args: ["--disable-background-networking", "--no-first-run"] });
  try {
    const context = await browser.newContext({ serviceWorkers: "block" });
    await context.route("**/*", (route) => {
      const url = route.request().url();
      if (url === "https://127.0.0.1/softphone/")
        return route.fulfill({ status: 200, contentType: "text/html", body: "<!doctype html>" });
      if (url === "https://127.0.0.1/cgi-bin/vgw") {
        seen.push(route.request().postDataJSON());
        if (refuse) return route.fulfill({ status: 400, contentType: "application/json",
          body: '{"message":"Authorization: synthetic-password\\r\\nX-Log: forged"}' });
        return route.fulfill({ status: 201, contentType: "application/json", body: '{"reserved":true}' });
      }
      return route.abort();
    });
    const page = await pageWithSIP(context, true);
    await page.locator("#sip-user").fill("180");
    await page.locator("#connect").click();
    await page.waitForFunction(() => document.querySelector("#status")?.textContent === "Available");
    await page.locator("#dial-route").selectOption("eventphone");
    await page.locator("#dial-number").fill("1234");
    await page.locator("#eventphone-user").fill("synthetic");
    await page.locator("#eventphone-password").fill("test-only=password");
    await page.locator("#dial-submit").click();
    await page.waitForFunction(() => window.__seen.calls.length === 1);
    assert.equal(seen.length, 1);
    assert.equal(seen[0].password, "test-only=password");
    assert.match(seen[0].nonce, /^[a-f0-9]{32}$/);
    assert.deepEqual(await page.evaluate(() => window.__seen.calls), ["sip:e-1234@127.0.0.1"]);
    assert.deepEqual(await page.evaluate(() => window.__seen.headers), [["X-VGW-Nonce: " + seen[0].nonce]]);
    assert.equal(await page.locator("#eventphone-password").inputValue(), "");
    await page.locator("#hangup").click();
    await page.waitForFunction(() => document.querySelector("#status")?.textContent === "Call ended");
    refuse = true;
    await page.locator("#eventphone-password").fill("synthetic-password");
    await page.locator("#dial-submit").click();
    await page.waitForFunction(() => document.querySelector("#status")?.textContent === "Eventphone reservation failed");
    assert.deepEqual(await page.evaluate(() => window.__seen.calls), ["sip:e-1234@127.0.0.1"]);
    assert.equal(await page.locator("#eventphone-password").inputValue(), "");
  } finally { await browser.close(); }
});
