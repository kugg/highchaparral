import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { runInNewContext } from "node:vm";

const site = new URL("../site/", import.meta.url);
const source = (file) => readFileSync(new URL(file, site), "utf8");
const configured = { sipDomain: "pbx.example", officeDialEnabled: true,
  eventphoneEnabled: true, byokApiPath: "/cgi-bin/vgw" };

function policy() {
  const sandbox = { window: {} };
  runInNewContext(source("dial.js"), sandbox);
  return sandbox.window.SOFTPHONE_DIAL.plan;
}

test("numeric PBX dialing requires registration and Eventphone is gated by default", () => {
  const sandbox = { window: { location: { hostname: "localhost" } } };
  runInNewContext(source("config.js"), sandbox);
  const cfg = sandbox.window.WEBRTC_CONFIG;
  assert.equal(cfg.wssUrl, "wss://localhost:8089/ws");
  assert.equal(cfg.eventphoneEnabled, false);
  assert.equal(policy()("office", "100", cfg, true).extension, "100");
  assert.equal(policy()("eventphone", "1234", cfg, true).ok, false);
  assert.equal(policy()("office", "100", cfg, false).ok, false);
  for (const number of ["sip:100@evil.invalid", "100;transport=tcp", "100\r\nX-Log: forged", "+49030", "1234567"]) {
    assert.equal(policy()("office", number, cfg, true).ok, false);
  }
  assert.equal(policy()("office", "100", { ...cfg, sipDomain: "pbx.example@evil.invalid" }, true).ok, false);
});

test("BYOK credentials only enter a bounded same-origin POST; SIP uses a nonce", () => {
  const sandbox = { window: {}, AbortSignal };
  runInNewContext(source("byok.js"), sandbox);
  const planned = policy()("eventphone", "1234", configured, true);
  assert.equal(planned.extension, "e-1234");
  const request = sandbox.window.SOFTPHONE_BYOK.prepare("synthetic", "test-only=password", planned, configured, "a".repeat(32));
  assert.equal(request.ok, true);
  assert.equal(request.path, "/cgi-bin/vgw");
  assert.equal(request.options.method, "POST");
  assert.equal(request.options.redirect, "error");
  assert.equal(request.options.credentials, "same-origin");
  assert.equal(JSON.parse(request.options.body).password, "test-only=password");
  assert.equal(JSON.stringify(request.options.headers).includes("test-only"), false);
  assert.equal(sandbox.window.SOFTPHONE_BYOK.prepare("synthetic", "bad\r\nX-Log: forged", planned, configured, "a".repeat(32)).ok, false);
  assert.equal(sandbox.window.SOFTPHONE_BYOK.prepare("synthetic", "test-only=password", planned,
    { ...configured, byokApiPath: "https://evil.invalid/collect" }, "a".repeat(32)).ok, false);
});

test("HTML loads local built SIP.js and policies before the app", () => {
  const html = source("index.html");
  const order = ["vendor/sip.min.js", "config.js", "dial.js", "byok.js", "app.js"];
  let previous = -1;
  for (const entry of order) {
    const position = html.indexOf(`src="${entry}"`);
    assert.ok(position > previous);
    previous = position;
  }
  assert.equal(/https?:\/\/[^"']+\.js/.test(html), false);
});
