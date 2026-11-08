// Browser SIP.js client for an operator-provisioned WebRTC PBX endpoint.
// The provider BYOK leg requires a separate, explicitly enabled VGW deployment.
(() => {
  const cfg = window.WEBRTC_CONFIG || {};
  const $ = (id) => document.getElementById(id);
  const status = $("status");
  const accountForm = $("account-form");
  const accountUser = $("sip-user");
  const accountPassword = $("sip-password");
  const connectButton = $("connect");
  const dialForm = $("dial-form");
  const dialRoute = $("dial-route");
  const dialNumber = $("dial-number");
  const dialButton = $("dial-submit");
  const byokPanel = $("eventphone-byok");
  const byokUser = $("eventphone-user");
  const byokPassword = $("eventphone-password");
  const acceptButton = $("accept");
  const rejectButton = $("reject");
  const muteButton = $("mute");
  const hangupButton = $("hangup");
  const audio = $("remoteAudio");

  let ua;
  let registered = false;
  let session;
  let incoming;
  let muted = false;

  function setStatus(text, kind = "") {
    status.textContent = text; // no provider response, SIP header or password in the DOM
    status.className = "status " + kind;
  }
  function controls() {
    const busy = !!(session || incoming);
    dialButton.disabled = !registered || busy ||
      (cfg.officeDialEnabled !== true && cfg.eventphoneEnabled !== true);
    connectButton.disabled = !!ua;
    acceptButton.hidden = !incoming;
    rejectButton.hidden = !incoming;
    muteButton.disabled = !session || session.state !== SIP.SessionState.Established;
    hangupButton.disabled = !session;
    if (!session) { muted = false; muteButton.textContent = "Mute"; }
  }
  function finish(s) {
    if (session === s) session = undefined;
    if (incoming === s) incoming = undefined;
    audio.srcObject = null;
    setStatus("Call ended");
    controls();
  }
  function attachRemote(s) {
    const pc = s.sessionDescriptionHandler?.peerConnection;
    if (!pc) return;
    const stream = new MediaStream();
    for (const receiver of pc.getReceivers()) {
      if (receiver.track) stream.addTrack(receiver.track);
    }
    audio.srcObject = stream;
    audio.play().catch(() => {});
  }
  function watch(s) {
    s.stateChange.addListener((state) => {
      if (state === SIP.SessionState.Established) {
        session = s;
        incoming = undefined;
        setStatus("Connected", "ok");
        attachRemote(s);
        controls();
      } else if (state === SIP.SessionState.Terminated) {
        finish(s);
      }
    });
  }
  function acceptIncoming(invitation) {
    if (session || incoming) {
      invitation.reject().catch(() => {});
      return;
    }
    incoming = invitation;
    watch(invitation);
    setStatus("Incoming call", "busy");
    controls();
  }
  async function connect() {
    if (ua) return;
    if (!window.isSecureContext || typeof SIP === "undefined" ||
        !/^[a-zA-Z0-9.-]{1,253}$/.test(cfg.sipDomain || "") ||
        !/^wss:\/\/[a-zA-Z0-9.-]+(:[0-9]{1,5})?\/ws$/.test(cfg.wssUrl || "") ||
        !/^[0-9]{2,6}$/.test(accountUser.value)) {
      setStatus("Secure PBX configuration required", "err");
      return;
    }
    connectButton.disabled = true;
    const user = accountUser.value;
    const password = accountPassword.value;
    accountPassword.value = "";
    try {
      const uri = SIP.UserAgent.makeURI(`sip:${user}@${cfg.sipDomain}`);
      if (!uri) throw Error("invalid URI");
      const agent = new SIP.UserAgent({
        uri,
        authorizationUsername: user,
        authorizationPassword: password,
        displayName: "Browser softphone",
        logBuiltinEnabled: false,
        logConfiguration: false,
        logLevel: "error",
        transportOptions: { server: cfg.wssUrl },
        sessionDescriptionHandlerFactoryOptions: { iceGatheringTimeout: 3000 }
      });
      agent.delegate = {
        onInvite: acceptIncoming,
        onDisconnect: () => {
          registered = false;
          setStatus("PBX connection lost; call status may be uncertain", "err");
          controls();
        }
      };
      await agent.start();
      ua = agent;
      const registerer = new SIP.Registerer(agent, { expires: 300 });
      registerer.stateChange.addListener((state) => {
        registered = state === SIP.RegistererState.Registered;
        if (!session && !incoming) setStatus(registered ? "Available" : "Not registered", registered ? "ok" : "err");
        controls();
      });
      await registerer.register();
      controls();
    } catch {
      setStatus("PBX registration failed; check WSS trust and account", "err");
      // Never automatically retry a failed SIP transaction.
      if (!ua) connectButton.disabled = false;
    }
  }
  async function reserve(planned) {
    const identity = byokUser.value;
    const password = byokPassword.value;
    byokPassword.value = "";
    const nonce = Array.from(crypto.getRandomValues(new Uint8Array(16)),
      (byte) => byte.toString(16).padStart(2, "0")).join("");
    const request = window.SOFTPHONE_BYOK.prepare(identity, password, planned, cfg, nonce);
    if (!request.ok || window.location.protocol !== "https:") throw Error("reservation unavailable");
    const response = await fetch(request.path, request.options);
    if (response.status !== 201 || response.headers.get("Content-Type")?.split(";")[0] !== "application/json") {
      throw Error("reservation refused");
    }
    const text = await response.text();
    if (text.length > 128 || JSON.parse(text)?.reserved !== true) throw Error("reservation invalid");
    return nonce;
  }
  async function call(planned, nonce) {
    if (!registered || session || incoming) return;
    dialButton.disabled = true;
    setStatus("Calling...", "busy");
    try {
      const target = SIP.UserAgent.makeURI(`sip:${planned.extension}@${cfg.sipDomain}`);
      if (!target) throw Error("invalid target");
      const inviter = new SIP.Inviter(ua, target, nonce ? { extraHeaders: ["X-VGW-Nonce: " + nonce] } : undefined);
      session = inviter;
      inviter.delegate = { onProgress: () => setStatus("Ringing...", "busy") };
      watch(inviter);
      controls();
      await inviter.invite();
    } catch {
      // A failed INVITE can have ambiguous delivery; leave its Hang up control
      // available and never retry it automatically.
      setStatus("Call failed or status uncertain", "err");
      if (session?.state === SIP.SessionState.Terminated) session = undefined;
      controls();
    }
  }

  const eventphoneOption = dialRoute.querySelector('option[value="eventphone"]');
  if (cfg.eventphoneEnabled === true) {
    eventphoneOption.disabled = false;
    eventphoneOption.textContent = "Eventphone";
  }
  dialRoute.addEventListener("change", () => {
    byokPanel.hidden = dialRoute.value !== "eventphone" || cfg.eventphoneEnabled !== true;
    dialNumber.maxLength = dialRoute.value === "eventphone" ? 5 : 6;
  });
  accountForm.addEventListener("submit", (event) => { event.preventDefault(); connect(); });
  dialForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const planned = window.SOFTPHONE_DIAL.plan(dialRoute.value, dialNumber.value, cfg, registered);
    if (!planned.ok || session || incoming) { setStatus("Route unavailable", "err"); return; }
    let nonce;
    if (planned.route === "eventphone") {
      dialButton.disabled = true;
      try { nonce = await reserve(planned); }
      catch { setStatus("Eventphone reservation failed", "err"); controls(); return; }
    }
    await call(planned, nonce);
  });
  acceptButton.addEventListener("click", async () => {
    if (!incoming) return;
    const s = incoming;
    acceptButton.disabled = true;
    try { await s.accept(); }
    catch { setStatus("Accept failed or status uncertain", "err"); }
    finally { acceptButton.disabled = false; }
  });
  rejectButton.addEventListener("click", async () => {
    if (!incoming) return;
    const s = incoming;
    try { await s.reject(); }
    catch { setStatus("Reject status uncertain", "err"); return; }
    finish(s);
  });
  muteButton.addEventListener("click", () => {
    const sender = session?.sessionDescriptionHandler?.peerConnection?.getSenders()
      .find((s) => s.track?.kind === "audio");
    if (!sender?.track) return;
    muted = !muted;
    sender.track.enabled = !muted;
    muteButton.textContent = muted ? "Unmute" : "Mute";
  });
  hangupButton.addEventListener("click", async () => {
    if (!session) return;
    try {
      if (session.state === SIP.SessionState.Established) await session.bye();
      else if (session.state === SIP.SessionState.Establishing) await session.cancel();
    } catch { setStatus("Hangup status uncertain", "err"); }
  });
  if (!window.isSecureContext) $("hint").textContent = "Microphone access requires HTTPS or loopback localhost.";
  controls();
})();
