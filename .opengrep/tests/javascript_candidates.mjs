async function render(page, untrusted) {
  // ruleid: highchaparral.javascript.browser-html-sink
  await page.setContent(untrusted);
  // ok: highchaparral.javascript.browser-html-sink
  await page.goto("https://127.0.0.1/");
}
