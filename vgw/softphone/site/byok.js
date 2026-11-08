// Caller-provided provider credentials travel only in this same-origin HTTPS POST.
(() => {
  const path = "/cgi-bin/vgw";
  function prepare(identity, password, planned, cfg, nonce) {
    const refused = { ok: false, category: "byok-request-refused" };
    if (cfg?.eventphoneEnabled !== true || cfg.byokApiPath !== path ||
        planned?.ok !== true || planned.route !== "eventphone" ||
        !/^e-[0-9]{2,5}$/.test(planned.extension) ||
        typeof identity !== "string" || !/^[A-Za-z0-9._-]{1,64}$/.test(identity) ||
        typeof password !== "string" || password.length < 1 || password.length > 256 ||
        !/^[!-~]+$/.test(password) || !/^[a-f0-9]{32}$/.test(nonce)) return refused;
    return {
      ok: true, path,
      options: {
        method: "POST", credentials: "same-origin", redirect: "error", cache: "no-store",
        signal: AbortSignal.timeout(8000),
        headers: { "Content-Type": "application/json", "X-VGW-Client": "softphone-v1" },
        body: JSON.stringify({ identity, password, destination: planned.extension.slice(2), nonce })
      }
    };
  }
  window.SOFTPHONE_BYOK = Object.freeze({ prepare });
})();
