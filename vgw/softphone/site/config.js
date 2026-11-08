// Public, non-secret deployment settings. Edit to match YOUR PBX and HTTPS host.
// Never put a SIP password or provider identity in this file.
(() => {
  const host = window.location.hostname;
  window.WEBRTC_CONFIG = Object.freeze({
    sipDomain: host,
    wssUrl: `wss://${host}:8089/ws`,
    officeDialEnabled: true,
    eventphoneEnabled: false, // requires a separately released PBX route + VGW BYOK service
    byokApiPath: "/cgi-bin/vgw"
  });
})();
