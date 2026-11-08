import { build } from "esbuild";

// The SIP.js npm package ships source modules, not the browser-global bundle
// expected by the page. Build it locally from the locked npm dependencies.
await build({
  entryPoints: ["node_modules/sip.js/lib/index.js"],
  outfile: "site/vendor/sip.min.js",
  bundle: true,
  minify: true,
  format: "iife",
  globalName: "SIP",
  platform: "browser",
  target: "es2020"
});
