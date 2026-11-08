// Browser-only route selection. No untrusted URI fragments or passwords in a SIP target.
(() => {
  function plan(route, number, cfg, registered) {
    const refuse = (category) => ({ ok: false, category });
    if (typeof number !== "string" || typeof cfg?.sipDomain !== "string" ||
        !/^[a-zA-Z0-9.-]{1,253}$/.test(cfg.sipDomain)) return refuse("dial-input-refused");
    if (registered !== true) return refuse("registration-required");
    if (route === "office") {
      if (!/^[0-9]{2,6}$/.test(number) || cfg.officeDialEnabled !== true) return refuse("office-route-refused");
      return { ok: true, extension: number, route, label: "PBX extension" };
    }
    if (route === "eventphone") {
      if (!/^[0-9]{2,5}$/.test(number) || cfg.eventphoneEnabled !== true) return refuse("eventphone-route-refused");
      return { ok: true, extension: "e-" + number, route, label: "Eventphone extension" };
    }
    return refuse("unknown-route");
  }
  window.SOFTPHONE_DIAL = Object.freeze({ plan });
})();
