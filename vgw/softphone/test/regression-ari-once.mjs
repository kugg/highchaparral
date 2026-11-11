// Disposable real-browser SIP/WSS→Asterisk→VGW synthetic mock fixture.
// No provider password, raw SIP/SDP, exception text, audio or automatic redial.
// Called explicitly by the owner-pinned regression runner; not an npm page test.
import { createHash, X509Certificate } from "node:crypto";
import { lstat, readFile } from "node:fs/promises";
import { createServer } from "node:https";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

const FILE = fileURLToPath(import.meta.url);
const hash = (body) => createHash("sha256").update(body).digest("hex");
let phase = "inputs";

async function bounded(path, max) {
  const info = await lstat(path);
  if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1 || info.size < 1 || info.size > max)
    throw Error("regression input changed");
  return readFile(path);
}

async function record() {
  const data = JSON.parse((await bounded("/intent/stage.json", 8192)).toString("utf8"));
  if (!/^[a-f0-9]{32}$/.test(data.owner) || !/^[a-f0-9]{32}$/.test(data.nonce) ||
      data.browser_sha !== hash(await bounded(FILE, 16384))) throw Error("owned browser source changed");
  return data;
}

async function goBarrier() {
  return Promise.race([
    new Promise((done) => {
      let seen = "";
      process.stdin.setEncoding("ascii");
      process.stdin.on("data", (part) => {
        seen += part;
        if (seen.length > 4 || seen.includes("\n")) done(seen === "GO\n");
      });
      process.stdin.once("end", () => done(false));
    }),
    new Promise((done) => setTimeout(() => done(false), 50_000))
  ]);
}

async function run() {
  const initial = await record();
  if (initial.phase !== "browser-preparing") return "BROWSER_OWNER_REFUSED";
  const credentials = JSON.parse((await bounded("/fixture/credentials.json", 4096)).toString("utf8"));
  if (!/^[A-Za-z0-9_-]{32,64}$/.test(credentials.browser)) return "BROWSER_CREDENTIAL_REFUSED";
  const cert = await bounded("/fixture/asterisk/keys/home.crt", 16384);
  const key = await bounded("/fixture/asterisk/keys/home.key", 16384);
  const bundle = await bounded("/bundle/sip.min.js", 2_000_000);
  if (initial.bundle_sha !== hash(bundle) || initial.cert_sha !== hash(cert)) return "BROWSER_BUNDLE_REFUSED";
  const x509 = new X509Certificate(cert);
  if (x509.checkIP("127.0.0.1") !== "127.0.0.1" || !x509.verify(x509.publicKey))
    return "BROWSER_TLS_REFUSED";
  const spki = createHash("sha256").update(x509.publicKey.export({ format: "der", type: "spki" })).digest("base64");
  const server = createServer({ cert, key }, (req, res) => {
    if (req.method === "GET" && req.url === "/") {
      res.writeHead(200, { "content-type": "text/html" });
      res.end("<!doctype html><title>isolated browser regression</title><script src='/sip.min.js'></script>");
    } else if (req.method === "GET" && req.url === "/sip.min.js") {
      res.writeHead(200, { "content-type": "application/javascript" });
      res.end(bundle);
    } else { res.writeHead(404); res.end(); }
  });
  let browser;
  try {
    phase = "https";
    await new Promise((done, fail) => { server.once("error", fail); server.listen(28487, "127.0.0.1", done); });
    phase = "chromium";
    browser = await chromium.launch({ headless: true, timeout: 45_000,
      args: [`--ignore-certificate-errors-spki-list=${spki}`, "--use-fake-ui-for-media-stream",
             "--use-fake-device-for-media-stream", "--disable-background-networking", "--no-first-run"] });
    const context = await browser.newContext({ ignoreHTTPSErrors: false });
    const page = await context.newPage();
    phase = "page";
    const response = await page.goto("https://127.0.0.1:28487/", { waitUntil: "domcontentloaded", timeout: 25_000 });
    if (response.status() !== 200 || !await page.evaluate(() => window.isSecureContext && typeof SIP.UserAgent === "function"))
      return "BROWSER_PAGE_REFUSED";
    phase = "register";
    const registered = await page.evaluate(async (password) => {
      try {
        const ua = new SIP.UserAgent({ uri: SIP.UserAgent.makeURI("sip:180@127.0.0.1"),
          authorizationUsername: "180", authorizationPassword: password,
          logBuiltinEnabled: false, logConfiguration: false, logLevel: "error",
          transportOptions: { server: "wss://127.0.0.1:8089/ws" },
          sessionDescriptionHandlerFactoryOptions: { iceGatheringTimeout: 3000 } });
        window.__ua = ua;
        await ua.start();
        const reg = new SIP.Registerer(ua, { expires: 90 });
        window.__reg = reg;
        reg.stateChange.addListener((state) => { window.__registered = state === SIP.RegistererState.Registered; });
        await reg.register();
        for (let i = 0; i < 600 && !window.__registered; i++) await new Promise(done => setTimeout(done, 50));
        return window.__registered === true;
      } catch { return false; }
    }, credentials.browser);
    if (!registered) return "BROWSER_REGISTER_REFUSED";
    console.log("BROWSER_READY");
    if (!await goBarrier()) return "BROWSER_GO_REFUSED";
    const during = await record();
    if (during.phase !== "invite-intent" || during.owner !== initial.owner || during.nonce !== initial.nonce)
      return "BROWSER_INTENT_REFUSED";
    phase = "invite";
    const result = await page.evaluate(async (nonce) => {
      let answered = false, ended = false, byeSent = false, trying = false;
      try {
        const session = new SIP.Inviter(window.__ua, SIP.UserAgent.makeURI("sip:e-1234@127.0.0.1"),
          { extraHeaders: ["X-VGW-Nonce: " + nonce] });
        session.stateChange.addListener((state) => {
          if (state === SIP.SessionState.Established) answered = true;
          if (state === SIP.SessionState.Terminated) ended = true;
        });
        await session.invite({ requestDelegate: { onTrying: () => { trying = true; } } });
        for (let i = 0; i < 200 && !answered && !ended; i++) await new Promise(done => setTimeout(done, 50));
        if (answered && !ended) {
          await new Promise(done => setTimeout(done, 500));
          if (!ended && session.state === SIP.SessionState.Established) {
            try { await session.bye(); byeSent = true; }
            catch { return "SIP_BYE_REFUSED"; }
          }
        }
        for (let i = 0; i < 400 && !ended; i++) await new Promise(done => setTimeout(done, 50));
        if (answered && ended && byeSent) return "SIP_ANSWERED_ENDED";
        if (answered && ended) return "SIP_REMOTE_ENDED_BEFORE_BYE";
        if (answered) return "SIP_ANSWERED_OPEN";
        return trying ? "SIP_100_NO_ANSWER" : "SIP_NO_RESPONSE";
      } catch { return "SIP_UNCERTAIN"; }
    }, during.nonce);
    await page.evaluate(async () => { try { await window.__reg?.unregister(); } catch {}
      try { await window.__ua?.stop(); } catch {} }).catch(() => {});
    await context.close();
    return result;
  } finally {
    await browser?.close().catch(() => {});
    server.closeAllConnections();
    await new Promise(done => server.close(done));
  }
}

if (process.argv.length === 2) console.log("DRY RUN: isolated synthetic browser call; no Docker or SIP");
else if (process.argv.length === 3 && process.argv[2] === "--run") {
  try { const category = await run(); console.log("BROWSER_RESULT phase=" + phase + " category=" + category); }
  catch { console.log("BROWSER_RESULT phase=" + phase + " category=BROWSER_PREPARE_REFUSED"); process.exitCode = 2; }
} else { console.log("BROWSER_ARGUMENT_REFUSED"); process.exitCode = 2; }
